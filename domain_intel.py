"""domain_intel.py -- DNS + RDAP domain intelligence for Algorithmistic.

Collects DNS records (A, AAAA, MX, NS, TXT, CNAME) and RDAP registration data
for the domains an email claims or links to, analyses them for suspicious
indicators, and ties the result to the IP / origin intelligence the app already
has. It ADDS to analyzer.py / origin_intel.py / tracker.py; it replaces nothing.

Design rules
  * Email-supplied domains are UNTRUSTED. Every one is normalised and validated
    (no IP literals, no single labels, no internal suffixes, IDNA-safe, length
    capped) before it is ever placed in a request. A domain is only ever a
    *query parameter / path segment* sent to a FIXED, https-only service
    (Cloudflare DNS-over-HTTPS, the IANA RDAP bootstrap and the registry hosts
    it names). The app never connects to the domain itself or to an IP found in
    the email. Redirects are re-validated hop by hop; responses are size-capped.
  * Never changes the threat score. Nothing here is a scoring weight.
  * Never invents data: a missing record or failed lookup is reported as such.
  * Every finding says whether it is a VERIFIED FACT (a lookup result) or an
    INFERENCE (our reading of it). Domain age alone is never called malicious.
  * Pure stdlib; Streamlit is not imported, so it is unit-testable offline
    (all network access goes through an injectable `fetch_json`).
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parseaddr

# ---------------------------------------------------------------------------
# Tunables (all visible and documented)
# ---------------------------------------------------------------------------
MODULE_VERSION = "1"
MAX_DOMAINS = 8                 # lookups per email
TIMEOUT_S = 6
MAX_BYTES = 1_000_000           # response size cap
CACHE_TTL_S = 6 * 3600          # a looked-up domain is reused for 6 h
YOUNG_DAYS = 30                 # "recently registered"
NEWISH_DAYS = 90                # young enough to count alongside other signals
EXPIRING_DAYS = 30
HISTORY_MEDIUM_SCORE = 70       # a prior sighting at/above this is "medium"
MEMORY_REP_MEDIUM = 0.7         # threat-memory reputation (0..1) at/above this is "medium"
DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
_TYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
_NUM_TYPE = {v: k for k, v in _TYPE_NUM.items()}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}

SCORE_NOTE = ("Domain findings are context for the analyst. They do not change the threat score, "
              "and no domain is called malicious on age or DNS layout alone.")

_BLOCKED_SUFFIXES = (
    "localhost", "local", "localdomain", "internal", "intranet", "lan", "home", "corp", "private",
    "invalid", "test", "arpa", "onion", "i2p", "example", "onmicrosoft.local",
)
_MULTIPART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "co.jp", "or.jp", "ne.jp", "co.in",
    "net.in", "org.in", "co.nz", "org.nz", "com.au", "net.au", "org.au", "edu.au", "gov.au", "com.br",
    "com.cn", "com.mx", "co.za", "com.tr", "com.sg", "com.hk", "com.tw", "com.ar", "co.il", "co.kr",
    "com.my", "com.ph", "com.pk", "com.ng", "com.eg", "com.ua", "com.vn", "co.id", "co.th", "com.co",
}
# Name servers shared by millions of unrelated domains: a shared one is a weak signal.
_GENERIC_NS = ("cloudflare.com", "awsdns", "domaincontrol.com", "registrar-servers.com", "googledomains.com",
               "google.com", "azure-dns", "worldnic.com", "wixdns.net", "squarespacedns.com", "nsone.net",
               "dnsmadeeasy.com", "hichina.com", "name-services.com", "dns-parking.com", "parkingcrew.net")

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d")


class LookupFailure(Exception):
    """A lookup could not complete. `kind` is one of: blocked, timeout, rate_limited,
    http_error, bad_response, unavailable."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind, self.message = kind, message


# ---------------------------------------------------------------------------
# Untrusted-input handling
# ---------------------------------------------------------------------------
def normalize_domain(text):
    """Return a safe lowercase ASCII (IDNA) domain, or None. Rejects IP literals,
    single labels, internal / reserved suffixes and anything with URL/userinfo/port
    syntax, so it can never be used to steer a request at an internal host."""
    if not isinstance(text, str):
        return None
    d = text.strip().strip(".").lower()
    if not d or len(d) > 253 or any(c in d for c in "/\\@:?#[]()<>\"' \t\r\n%*,;="):
        # IDN text can legally contain non-ASCII; only the ASCII separators above are refused.
        return None
    try:
        d = d.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    if len(d) > 253:
        return None
    try:
        ipaddress.ip_address(d)
        return None
    except ValueError:
        pass
    labels = d.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels):
        return None
    if labels[-1].isdigit():
        return None
    for suf in _BLOCKED_SUFFIXES:
        if d == suf or d.endswith("." + suf):
            return None
    return d


def registrable(domain):
    """Best-effort registrable domain (no public-suffix list is bundled, so a short
    table of common multi-part suffixes is used). Heuristic -- shown as such."""
    labels = (domain or "").split(".")
    if len(labels) <= 2:
        return domain
    if ".".join(labels[-2:]) in _MULTIPART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_public_ip(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def _addr_domain(value):
    addr = parseaddr(str(value or ""))[1]
    return normalize_domain(addr.rsplit("@", 1)[1]) if "@" in addr else None


def _host_of(url_or_host):
    s = str(url_or_host or "").strip()
    if "://" not in s:
        s = "//" + s
    try:
        return urllib.parse.urlsplit(s).hostname
    except ValueError:
        return None


def collect_domains(parsed, iocs, limit=MAX_DOMAINS):
    """Ordered, de-duplicated domains an email claims or links to, each with the
    role(s) it plays. Identity roles (From / Reply-To / Return-Path) come first.
    Returns (domains, skipped) where domains = [{"domain", "roles"}]."""
    parsed, iocs = parsed or {}, iocs or {}
    order, roles = [], {}

    def add(dom, role):
        if not dom:
            return
        if dom not in roles:
            roles[dom] = []
            order.append(dom)
        if role not in roles[dom]:
            roles[dom].append(role)

    add(_addr_domain(parsed.get("from_addr") or parsed.get("from")), "From")
    add(_addr_domain(parsed.get("reply_to")), "Reply-To")
    add(_addr_domain(parsed.get("return_path")), "Return-Path")
    for u in iocs.get("urls") or []:
        raw = u.get("host") or u.get("url") if isinstance(u, dict) else u
        add(normalize_domain(_host_of(raw) or ""), "Link host")
    for d in iocs.get("domains") or []:
        raw = d.get("domain") if isinstance(d, dict) else d
        add(normalize_domain(str(raw or "")), "Body domain")
    domains = [{"domain": d, "roles": roles[d]} for d in order]
    return domains[:limit], max(0, len(domains) - limit)


# ---------------------------------------------------------------------------
# Network layer -- fixed https services only
# ---------------------------------------------------------------------------
class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Re-validates every redirect target: https only, a real public hostname."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        p = urllib.parse.urlsplit(newurl)
        if p.scheme != "https" or p.username or (p.port not in (None, 443)) or not normalize_domain(p.hostname or ""):
            raise LookupFailure("blocked", "redirect to a disallowed target was refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_json(url, headers=None, timeout=TIMEOUT_S):
    """GET `url` (https only) and return parsed JSON. Raises LookupFailure."""
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or p.username or (p.port not in (None, 443)) or not normalize_domain(p.hostname or ""):
        raise LookupFailure("blocked", "only https requests to public hostnames are allowed")
    req = urllib.request.Request(url, headers=dict({"User-Agent": "Algorithmistic-domain-intel/1"}, **(headers or {})))
    opener = urllib.request.build_opener(_SafeRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            data = r.read(MAX_BYTES + 1)
    except LookupFailure:
        raise
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise LookupFailure("rate_limited", "the service rate-limited this request (HTTP 429)")
        raise LookupFailure("http_error", f"HTTP {e.code}")
    except (socket.timeout, TimeoutError):
        raise LookupFailure("timeout", "the lookup timed out")
    except (urllib.error.URLError, OSError) as e:
        raise LookupFailure("unavailable", f"network unavailable ({getattr(e, 'reason', e)})")
    if len(data) > MAX_BYTES:
        raise LookupFailure("bad_response", "response larger than the size cap")
    try:
        return json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        raise LookupFailure("bad_response", "response was not valid JSON")


def _now_iso(now=None):
    return (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# DNS (DNS-over-HTTPS)
# ---------------------------------------------------------------------------
def _parse_answer(rtype, ans):
    data = str(ans.get("data", "")).strip()
    ttl = ans.get("TTL")
    if rtype == "TXT":
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
        data = "".join(parts) if parts else data.strip('"')
        return {"value": data[:2000], "ttl": ttl}
    if rtype == "MX":
        m = re.match(r"^(\d+)\s+(\S+)$", data)
        if m:
            return {"value": m.group(2).rstrip(".").lower(), "priority": int(m.group(1)), "ttl": ttl}
        return {"value": data.rstrip(".").lower(), "priority": None, "ttl": ttl}
    if rtype in ("NS", "CNAME"):
        return {"value": data.rstrip(".").lower(), "ttl": ttl}
    return {"value": data.lower(), "ttl": ttl}


def _doh_query(name, rtype, fetch):
    """-> (status, [records]); status in ok | nxdomain | error:<kind>."""
    url = DOH_ENDPOINT + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
    try:
        j = fetch(url, {"Accept": "application/dns-json"})
    except LookupFailure as e:
        return f"error:{e.kind}", [], e.message
    if not isinstance(j, dict):
        return "error:bad_response", [], "unexpected DoH response"
    rcode = j.get("Status")
    if rcode == 3:
        return "nxdomain", [], ""
    if rcode not in (0, None):
        return "error:rcode", [], f"resolver returned status {rcode}"
    recs = []
    for a in j.get("Answer") or []:
        if not isinstance(a, dict) or _NUM_TYPE.get(a.get("type")) != rtype:
            continue
        recs.append(_parse_answer(rtype, a))
    return "ok", recs[:50], ""


def _getaddrinfo_fallback(domain):
    """Only used when DNS-over-HTTPS is unreachable. A resolver query only --
    never a connection to the domain."""
    out = {"A": [], "AAAA": []}
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM):
            t = "A" if fam == socket.AF_INET else "AAAA" if fam == socket.AF_INET6 else None
            if t and not any(r["value"] == sa[0] for r in out[t]):
                out[t].append({"value": sa[0], "ttl": None})
    except (socket.gaierror, OSError):
        pass
    return out


def dns_lookup(domain, fetch=None, want_dmarc=False, now=None):
    """DNS records for an already-validated domain. Never raises."""
    fetch = fetch or fetch_json
    d = normalize_domain(domain)
    res = {"domain": d or str(domain)[:100], "records": {t: [] for t in RECORD_TYPES}, "status": {},
           "errors": [], "nxdomain": False, "source": "DNS-over-HTTPS (cloudflare-dns.com)",
           "looked_up_at": _now_iso(now)}
    if not d:
        res["errors"].append("not a valid public domain name -- not looked up")
        res["status"] = {t: "error:blocked" for t in RECORD_TYPES}
        return res
    jobs = [(t, d) for t in RECORD_TYPES] + ([("TXT", "_dmarc." + d)] if want_dmarc else [])
    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(lambda j: _doh_query(j[1], j[0], fetch), jobs))
    res["dmarc"] = []
    for (rtype, name), (status, recs, err) in zip(jobs, results):
        if name != d:
            res["status"]["_dmarc"] = status
            res["dmarc"] = recs
            continue
        res["status"][rtype] = status
        res["records"][rtype] = recs
        if err:
            res["errors"].append(f"{rtype}: {err}")
    res["nxdomain"] = all(res["status"].get(t) == "nxdomain" for t in ("A", "NS", "MX")) \
        or res["status"].get("A") == "nxdomain"
    if res["status"].get("A", "").startswith("error") and res["status"].get("AAAA", "").startswith("error"):
        fb = _getaddrinfo_fallback(d)
        if fb["A"] or fb["AAAA"]:
            res["records"]["A"], res["records"]["AAAA"] = fb["A"], fb["AAAA"]
            res["status"]["A"] = res["status"]["AAAA"] = "ok"
            res["source"] += " unreachable -> system resolver used for A/AAAA only"
    return res


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------
_BOOT = {"at": 0.0, "data": None}
_BOOT_LOCK = threading.Lock()


def _bootstrap(fetch):
    with _BOOT_LOCK:
        if _BOOT["data"] and time.time() - _BOOT["at"] < 24 * 3600:
            return _BOOT["data"]
    j = fetch(RDAP_BOOTSTRAP, {"Accept": "application/json"})
    if not isinstance(j, dict) or not isinstance(j.get("services"), list):
        raise LookupFailure("bad_response", "unexpected RDAP bootstrap format")
    with _BOOT_LOCK:
        _BOOT["data"], _BOOT["at"] = j, time.time()
    return j


def _rdap_base(tld, boot):
    for svc in boot.get("services", []):
        try:
            tlds, urls = svc[0], svc[1]
        except (IndexError, TypeError):
            continue
        if tld in [str(t).lower() for t in tlds]:
            https = [u for u in urls if str(u).startswith("https://")]
            return (https or [None])[0]
    return None


def _parse_dt(text):
    s = str(text or "").strip()
    if not s:
        return None
    s = re.sub(r"Z$", "+0000", s)
    s = re.sub(r"([+-]\d\d):(\d\d)$", r"\1\2", s)
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _vcard_name(entity):
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "fn":
                return str(item[3])
    except (KeyError, IndexError, TypeError):
        pass
    return None


def parse_rdap(j, now=None):
    """Registrar / dates / nameservers / status from an RDAP domain object."""
    now = now or datetime.now(timezone.utc)
    ev = {}
    for e in j.get("events") or []:
        if isinstance(e, dict) and e.get("eventAction") and e.get("eventDate"):
            ev.setdefault(str(e["eventAction"]).lower(), _parse_dt(e["eventDate"]))
    registrar, iana_id = None, None
    for ent in j.get("entities") or []:
        if isinstance(ent, dict) and "registrar" in [str(r).lower() for r in ent.get("roles") or []]:
            registrar = _vcard_name(ent) or registrar
            for pid in ent.get("publicIds") or []:
                if isinstance(pid, dict) and "iana" in str(pid.get("type", "")).lower():
                    iana_id = pid.get("identifier")
    ns = sorted({str(n.get("ldhName", "")).rstrip(".").lower() for n in j.get("nameservers") or []
                 if isinstance(n, dict) and n.get("ldhName")})
    created, expires, changed = ev.get("registration"), ev.get("expiration"), ev.get("last changed")
    return {
        "registrar": registrar, "registrar_iana_id": iana_id,
        "created": created.strftime("%Y-%m-%d") if created else None,
        "expires": expires.strftime("%Y-%m-%d") if expires else None,
        "updated": changed.strftime("%Y-%m-%d") if changed else None,
        "age_days": (now - created).days if created else None,
        "days_to_expiry": (expires - now).days if expires else None,
        "nameservers": ns, "status": [str(s) for s in (j.get("status") or [])][:12],
    }


def rdap_lookup(domain, fetch=None, now=None):
    """Registration data for the REGISTRABLE part of `domain`. Never raises.
    state: ok | not_found | rate_limited | no_service | error"""
    fetch = fetch or fetch_json
    d = normalize_domain(domain)
    out = {"domain": d, "queried": None, "state": "error", "data": None, "error": "",
           "source": "RDAP (IANA bootstrap -> registry)", "looked_up_at": _now_iso(now)}
    if not d:
        out["error"] = "not a valid public domain name -- not looked up"
        return out
    reg = registrable(d)
    out["queried"] = reg
    try:
        boot = _bootstrap(fetch)
        base = _rdap_base(reg.rsplit(".", 1)[-1], boot)
        if not base:
            out["state"], out["error"] = "no_service", "no RDAP service is published for this TLD"
            return out
        host = urllib.parse.urlsplit(base).hostname or ""
        if not normalize_domain(host):
            out["state"], out["error"] = "error", "bootstrap named a disallowed RDAP host"
            return out
        out["source"] = f"RDAP ({host})"
        j = fetch(base.rstrip("/") + "/domain/" + urllib.parse.quote(reg, safe=""),
                  {"Accept": "application/rdap+json, application/json"})
        if not isinstance(j, dict):
            raise LookupFailure("bad_response", "unexpected RDAP response")
        out["data"], out["state"] = parse_rdap(j, now), "ok"
    except LookupFailure as e:
        if e.kind == "http_error" and "404" in e.message:
            out["state"], out["error"] = "not_found", "registry reports no such domain"
        elif e.kind == "rate_limited":
            out["state"], out["error"] = "rate_limited", e.message
        else:
            out["state"], out["error"] = "error", e.message
    except Exception as e:  # defensive: a lookup must never take the page down
        out["state"], out["error"] = "error", f"{type(e).__name__}: {e}"
    return out


def lookup_domain(domain, roles=(), fetch=None, cache=None, now=None, skip_rdap=False):
    """DNS + RDAP for one domain, cached in the supplied dict for CACHE_TTL_S."""
    d = normalize_domain(domain)
    key = (d, "dmarc" if "From" in roles else "")
    if cache is not None and d:
        hit = cache.get(key)
        if hit and time.time() - hit["_t"] < CACHE_TTL_S:
            return dict(hit["rec"], roles=list(roles), cached=True)
    rec = {"domain": d or str(domain)[:100], "roles": list(roles), "cached": False,
           "dns": dns_lookup(d or domain, fetch, want_dmarc=("From" in roles), now=now)}
    rec["rdap"] = (rdap_lookup(d, fetch, now) if not skip_rdap else
                   {"state": "rate_limited", "error": "skipped after an earlier rate-limit in this batch",
                    "data": None, "looked_up_at": _now_iso(now), "queried": registrable(d or ""), "source": "RDAP"})
    if cache is not None and d:
        cache[key] = {"_t": time.time(), "rec": rec}
    return rec


def lookup_all(domains, fetch=None, cache=None, now=None):
    """Look up the collected domains; stops RDAP calls after a rate-limit."""
    out, limited = [], False
    for item in domains:
        rec = lookup_domain(item["domain"], item.get("roles", ()), fetch, cache, now, skip_rdap=limited)
        if (rec.get("rdap") or {}).get("state") == "rate_limited" and not rec.get("cached"):
            limited = True
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Analysis -- facts vs inferences
# ---------------------------------------------------------------------------
def _flag(sev, code, dom, title, evidence, basis):
    return {"severity": sev, "code": code, "domain": dom, "title": title, "evidence": evidence, "basis": basis}


def _ips(rec):
    r = rec["dns"]["records"]
    return [x["value"] for t in ("A", "AAAA") for x in r.get(t, []) if x.get("value")]


def _spf(rec):
    for t in rec["dns"]["records"].get("TXT", []):
        if t["value"].lower().startswith("v=spf1"):
            return t["value"]
    return None


def _spf_networks(spf):
    nets = []
    for tok in (spf or "").split():
        m = re.match(r"^[+?~-]?ip[46]:(\S+)$", tok.lower())
        if m:
            try:
                nets.append(ipaddress.ip_network(m.group(1), strict=False))
            except ValueError:
                pass
    return nets


def analyze(records, ctx=None, history=None, memory=None):
    """Findings for a list of lookup records.

    ctx: {"route_ips": [...], "origin_ip": str|None}
    history: {ip: (prior_count, max_score)} from the threat-memory DB.
    memory: {domain: {"prior", "reputation", "first_seen", "last_seen", "source"}}
            from tracker.lookup_indicator(domain, "domain").
    Returns a list of flags sorted by severity (highest first)."""
    ctx, history = ctx or {}, history or {}
    route_ips = set(ctx.get("route_ips") or [])
    origin_ip = ctx.get("origin_ip")
    flags = []
    by_role = {}
    for rec in records:
        for r in rec.get("roles", []):
            by_role.setdefault(r, rec)

    for rec in records:
        d, roles = rec["domain"], rec.get("roles", [])
        dns, rd = rec["dns"], rec.get("rdap") or {}
        rdd = rd.get("data") or {}
        identity = any(r in ("From", "Reply-To", "Return-Path") for r in roles)
        mine = []

        def add(*a):
            mine.append(_flag(*a))

        recs = dns["records"]
        ok_dns = any(dns["status"].get(t) == "ok" for t in RECORD_TYPES)
        if dns.get("nxdomain") or rd.get("state") == "not_found":
            both = dns.get("nxdomain") and rd.get("state") == "not_found"
            ev = ("DNS answered NXDOMAIN" if dns.get("nxdomain") else "") + \
                 (" and " if both else "") + ("the RDAP registry reports no such domain" if rd.get("state") == "not_found" else "")
            add("medium" if (identity and (both or dns.get("nxdomain"))) else "low", "DOMAIN_NOT_FOUND", d,
                "Domain does not exist" if both else "Domain not found in " + ("DNS" if dns.get("nxdomain") else "the registry"),
                ev.capitalize() + (". A sender-claimed domain that does not exist cannot receive replies and is a "
                                   "common sign of spoofing (or a typo)." if identity else "."), "fact")
        if rdd.get("age_days") is not None:
            a = rdd["age_days"]
            if a < YOUNG_DAYS:
                add("low", "NEW_DOMAIN", d, f"Recently registered ({a} day(s) ago)",
                    f"Registration date {rdd['created']}. Young age alone is not evidence of malice -- legitimate "
                    "campaigns and brands register new domains too.", "fact")
        if rdd.get("days_to_expiry") is not None:
            x = rdd["days_to_expiry"]
            if x < 0:
                add("low", "EXPIRED", d, "Registration date has passed", f"Expiry {rdd['expires']} is in the past.", "fact")
            elif x < EXPIRING_DAYS:
                add("info", "EXPIRING_SOON", d, f"Registration expires in {x} day(s)", f"Expiry {rdd['expires']}.", "fact")
        holds = [s for s in rdd.get("status", []) if re.search(r"hold|pendingdelete|redemption|inactive", s.replace(" ", ""), re.I)]
        if holds:
            add("low", "REG_STATUS", d, "Unusual registration status", "RDAP status: " + ", ".join(holds) + ".", "fact")
        if d.split(".")[0].startswith("xn--") or any(l.startswith("xn--") for l in d.split(".")):
            try:
                uni = d.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                uni = d
            add("low", "PUNYCODE", d, "Internationalised (punycode) domain",
                f"Decodes to '{uni}'. Look for characters that imitate a known brand.", "inference")
        priv = [ip for ip in _ips(rec) if not is_public_ip(ip)]
        if priv:
            add("medium", "PRIVATE_IP_RECORD", d, "Resolves to a private/reserved address",
                "A/AAAA record(s): " + ", ".join(priv[:4]) + ". Public domains should not point at internal ranges.", "fact")
        if identity and ok_dns and not dns.get("nxdomain"):
            has_mx, has_addr = bool(recs["MX"]), bool(_ips(rec))
            if not has_mx and not has_addr:
                add("medium", "NO_MAIL_PATH", d, "No MX and no address records",
                    "The domain has no MX and no A/AAAA record, so mail to it (e.g. replies) has nowhere to go.", "fact")
            elif not has_mx and "Reply-To" in roles:
                add("low", "NO_MX_REPLYTO", d, "Reply-To domain publishes no MX",
                    "Replies would fall back to the A record (implicit MX); unusual for a real mailbox domain.", "inference")
        spf = _spf(rec)
        if "From" in roles and ok_dns and not dns.get("nxdomain"):
            if not spf:
                add("low", "NO_SPF", d, "From domain publishes no SPF record",
                    "No TXT record beginning v=spf1 was returned.", "fact")
            else:
                if re.search(r"(?:^|\s)\+?all(?:\s|$)|\s\?all(?:\s|$)", spf.lower()):
                    add("medium", "SPF_PERMISSIVE", d, "SPF allows any sender",
                        f"SPF ends in a permissive 'all' mechanism: {spf[:120]}", "fact")
            if dns.get("status", {}).get("_dmarc") == "ok" and not any(
                    r["value"].lower().startswith("v=dmarc1") for r in dns.get("dmarc", [])):
                add("low", "NO_DMARC", d, "From domain publishes no DMARC policy",
                    "No v=DMARC1 record at _dmarc." + d + ".", "fact")
            nets = _spf_networks(spf)
            if origin_ip and nets:
                try:
                    oip = ipaddress.ip_address(origin_ip)
                    inside = any(oip in n for n in nets if n.version == oip.version)
                except ValueError:
                    inside = False
                if inside:
                    add("info", "ORIGIN_IN_SPF", d, "Origin IP is listed in the domain's SPF",
                        f"{origin_ip} falls inside an ip4/ip6 range in the From domain's SPF record (supports the claimed identity).", "fact")
                elif not any(re.match(r"^[+?~-]?(include:|redirect=|a(:|/|$)|mx(:|/|$)|exists:|ptr)", tok)
                             for tok in spf.lower().split()[1:]):
                    add("low", "ORIGIN_NOT_IN_SPF", d, "Origin IP is not in the domain's SPF",
                        f"SPF lists only fixed IP ranges and {origin_ip} is not among them. The route may still be "
                        "legitimate if a forwarder was used.", "inference")
        if len(recs["NS"]) == 1:
            add("low", "SINGLE_NS", d, "Only one name server published",
                "DNS returned a single NS record: " + recs["NS"][0]["value"] + ".", "fact")
        dns_ns = {x["value"] for x in recs["NS"]}
        rd_ns = set(rdd.get("nameservers", []))
        if dns_ns and rd_ns and dns_ns != rd_ns:
            add("low", "NS_MISMATCH", d, "DNS name servers differ from registry delegation",
                "Registry: " + ", ".join(sorted(rd_ns)[:4]) + " / DNS: " + ", ".join(sorted(dns_ns)[:4]) +
                ". Can indicate a recent change, caching, or a split configuration.", "inference")
        ttls = [x.get("ttl") for x in recs["A"] if isinstance(x.get("ttl"), int)]
        if ttls and max(ttls) <= 60 and len(recs["A"]) >= 1:
            add("info", "SHORT_TTL", d, "Very short DNS TTL",
                f"A-record TTL {max(ttls)}s. Common for CDNs/failover; also used for rapidly-rotating infrastructure.", "inference")
        both = route_ips & set(_ips(rec))
        if both:
            add("info", "IP_IN_ROUTE", d, "Domain's IP appears in this message's route",
                "Shared IP(s): " + ", ".join(sorted(both)) + ". Connects the domain to the Received-chain infrastructure.", "fact")
        for ip in _ips(rec):
            c, m = history.get(ip, (0, 0))
            if c:
                add("medium" if m >= HISTORY_MEDIUM_SCORE else "low", "IP_IN_THREAT_MEMORY", d,
                    "Domain's IP is in the scored-email log from earlier analyses",
                    f"{ip} appears {c} time(s) in the scored-email log (highest score {m:.0f}).", "fact")
        mem = (memory or {}).get(d)
        if mem:
            rep = float(mem.get("reputation") or 0)
            # "prior" = recordings OTHER than this email's own analysis (caller computes it);
            # without it we cannot tell, so we do not claim an earlier sighting.
            prior = int(mem.get("prior") or 0)
            if rep >= MEMORY_REP_MEDIUM or prior >= 1:
                add("medium" if rep >= MEMORY_REP_MEDIUM else "info", "DOMAIN_IN_THREAT_MEMORY", d,
                    "Domain is already in threat memory",
                    f"{prior} earlier recording(s) besides this email's own analysis, reputation {rep:.2f}, "
                    f"first seen {mem.get('first_seen') or '?'}, last seen {mem.get('last_seen') or '?'} "
                    f"(source: {mem.get('source') or '?'}). A default 0.50 reputation only means 'observed', not 'bad'.", "fact")
        # composite: young + something else (still an inference, never "malicious")
        age = rdd.get("age_days")
        others = [f for f in mine if f["code"] not in ("NEW_DOMAIN", "EXPIRING_SOON", "IP_IN_ROUTE", "ORIGIN_IN_SPF", "SHORT_TTL")
                  and _SEV_RANK[f["severity"]] >= 1]
        if age is not None and age < NEWISH_DAYS and others:
            add("medium", "YOUNG_PLUS_SIGNALS", d, "Recently registered AND other irregularities",
                f"Registered {age} day(s) ago and also: " + "; ".join(sorted({f['title'] for f in others})[:3]) +
                ". The combination is more telling than either alone, but is still an inference.", "inference")
        flags.extend(mine)

    # identity consistency across From / Reply-To / Return-Path
    frm = by_role.get("From")
    if frm:
        fr = registrable(frm["domain"])
        rt = by_role.get("Reply-To")
        if rt and registrable(rt["domain"]) != fr:
            age = ((rt.get("rdap") or {}).get("data") or {}).get("age_days")
            young = age is not None and age < NEWISH_DAYS
            flags.append(_flag("medium" if young else "low", "REPLYTO_MISMATCH", rt["domain"],
                               "Reply-To domain differs from the From domain",
                               f"From {frm['domain']} but replies go to {rt['domain']}"
                               + (f", registered only {age} day(s) ago" if young else "")
                               + ". Common in mailing lists, but also a classic diversion tactic.", "fact"))
        rp = by_role.get("Return-Path")
        if rp and registrable(rp["domain"]) != fr:
            flags.append(_flag("info", "RETURNPATH_MISMATCH", rp["domain"],
                               "Return-Path domain differs from the From domain",
                               f"Envelope sender {rp['domain']} vs From {frm['domain']}. Normal for bulk-mail providers.", "fact"))
    flags.sort(key=lambda f: -_SEV_RANK[f["severity"]])
    return flags


def overall(flags):
    if not flags:
        return "none", "No domain irregularities were found in the data that could be retrieved."
    top = max(flags, key=lambda f: _SEV_RANK[f["severity"]])["severity"]
    real = [f for f in flags if _SEV_RANK[f["severity"]] >= 1]
    if not real:
        return "info", "Only informational context was found; nothing suspicious in the retrieved data."
    return top, f"{len(real)} indicator(s) worth a look (highest: {top}). These are leads, not a verdict."


# ---------------------------------------------------------------------------
# Correlation with IP intelligence, the session and threat memory
# ---------------------------------------------------------------------------
def local_asn(ip):
    """(asn, org) from the SAME GeoLite2-ASN.mmdb geolocate.py uses; (None, None)
    if the package/file is unavailable. Offline."""
    try:
        import maxminddb
        import origin_intel as _oi
        st = _oi.geodb_status()
        if not (st["maxminddb"] and st["asn_db"]):
            return None, None
        import os
        with maxminddb.open_database(os.path.join(st["dir"], "GeoLite2-ASN.mmdb")) as db:
            r = db.get(ip) or {}
        n = r.get("autonomous_system_number")
        return (f"AS{n}" if n else None), r.get("autonomous_system_organization")
    except Exception:
        return None, None


def ip_rows(records, geo=None, history=None, asn_fn=None):
    """One row per (domain, resolved IP) joined with existing IP intelligence."""
    gidx = {}
    for h in ((geo or {}).get("hops") or []) + [(geo or {}).get("origin") or {}]:
        if isinstance(h, dict) and h.get("ip"):
            gidx.setdefault(h["ip"], h)
    asn_fn = asn_fn or local_asn
    rows = []
    for rec in records:
        for ip in _ips(rec)[:6]:
            g = gidx.get(ip, {})
            asn, org = None, None
            a = str(g.get("asn") or "")
            m = re.match(r"^(AS\d+)\s*(.*)$", a, re.I)
            if m:
                asn, org = m.group(1).upper(), m.group(2) or None
            if not asn and is_public_ip(ip):
                asn, org = asn_fn(ip)
            c, mx = (history or {}).get(ip, (0, 0))
            rows.append({
                "Domain": rec["domain"], "IP": ip,
                "ASN": asn or "unavailable", "Network": org or g.get("isp") or "unavailable",
                "Infrastructure": g.get("infra_label") or "not in this email's route",
                "Scored-email log": f"{c} entr{'y' if c == 1 else 'ies'}, max score {mx:.0f}" if c else "none",
            })
    return rows


def correlate(records, cases, current_name=None, current_hash=None, cache=None):
    """Other emails / cached domains that share a domain, IP, name server or
    registration fingerprint with the current lookups. Evidence rows only.

    Deduplicated, never lossy: an email appears once per related domain (strongest
    relation, with every matching domain and role listed); an email supplied twice,
    or a domain cached under two keys, is counted once."""
    mine = {r["domain"]: r for r in records}
    my_reg = {}
    for d in mine:
        my_reg.setdefault(registrable(d), d)
    found, done = {}, set()
    for case in cases or []:
        if not isinstance(case, dict):
            continue
        ck = str(case.get("_evidence_hash") or case.get("name") or id(case))
        if ck in done or case.get("name") == current_name or (current_hash and case.get("_evidence_hash") == current_hash):
            continue
        done.add(ck)
        p, io = case.get("parsed", {}) or {}, case.get("iocs", {}) or {}
        try:
            doms, _ = collect_domains(p, io, limit=60)
        except Exception:
            continue
        for item in doms:
            d = item["domain"]
            rel = "same domain" if d in mine else "same registrable domain" if registrable(d) in my_reg else None
            if not rel:
                continue
            mine_dom = d if d in mine else my_reg[registrable(d)]
            key = (mine_dom, ck)
            detail = f"{d}: {', '.join(item['roles'])}"
            cur = found.get(key)
            if cur is None:
                found[key] = {"case": case, "rel": rel, "details": [detail]}
            else:
                if detail not in cur["details"]:
                    cur["details"].append(detail)
                if rel == "same domain":
                    cur["rel"] = rel
    rows = [{"Domain": k[0], "Relation": v["rel"], "Other email": v["case"].get("name", "-"),
             "Their role": "; ".join(v["details"]), "Verdict": str(v["case"].get("level", "-")).upper(),
             "Score": round(float(v["case"].get("score", 0) or 0), 1)} for k, v in found.items()]
    # infrastructure shared with other domains already looked up this session
    seen_other, shared_rows = set(), set()
    for (od, _), hit in list((cache or {}).items()):
        other = hit.get("rec") if isinstance(hit, dict) else None
        if not other or od in mine or od in seen_other:   # one cached domain may sit under two keys
            continue
        seen_other.add(od)
        for d, rec in mine.items():
            if registrable(od) == registrable(d):
                continue
            ips = set(_ips(rec)) & set(_ips(other))
            ns = {x["value"] for x in rec["dns"]["records"]["NS"]} & {x["value"] for x in other["dns"]["records"]["NS"]}
            r1, r2 = (rec.get("rdap") or {}).get("data") or {}, (other.get("rdap") or {}).get("data") or {}
            fp = bool(r1.get("registrar") and r1.get("registrar") == r2.get("registrar")
                      and r1.get("created") and r1.get("created") == r2.get("created"))
            for shared in sorted(ips):
                shared_rows.add((d, "shared IP", f"{od} ({shared})"))
            for n in sorted(ns):
                weak = any(g in n for g in _GENERIC_NS)
                shared_rows.add((d, "shared name server" + (" (weak: common provider)" if weak else ""), f"{od} ({n})"))
            if fp:
                shared_rows.add((d, "same registrar + creation date", f"{od} ({r1['registrar']}, {r1['created']})"))
    for d, rel, detail in sorted(shared_rows):
        rows.append({"Domain": d, "Relation": rel, "Other email": "-", "Their role": detail, "Verdict": "-", "Score": "-"})
    return rows[:60]


# ---------------------------------------------------------------------------
# Report text
# ---------------------------------------------------------------------------
def _md(v):
    return re.sub(r"\s+", " ", str(v if v is not None else "-")).replace("|", "\\|").strip() or "-"


def to_markdown(records, flags, ip_rows_=None, corr_rows=None, skipped=0):
    if not records:
        return "No domain & DNS lookup was run for this email, so no domain intelligence is included. " \
               "Run it from the Origin & Route panel to add it to the report."
    sev, text = overall(flags)
    out = [f"**Summary:** {text}", "", f"_{SCORE_NOTE}_", "",
           "### DNS records and registration", "",
           "| Domain | Role | A / AAAA | MX | NS | Registrar | Created | Expires | Looked up |", "|---|---|---|---|---|---|---|---|---|"]
    for r in records:
        rc, rdd = r["dns"]["records"], (r.get("rdap") or {}).get("data") or {}
        rs = (r.get("rdap") or {}).get("state")
        reg = rdd.get("registrar") or ("unavailable (" + str((r.get("rdap") or {}).get("error") or rs) + ")")
        out.append("| " + " | ".join(_md(x) for x in (
            r["domain"], ", ".join(r.get("roles", [])),
            ", ".join(x["value"] for t in ("A", "AAAA") for x in rc[t][:3]) or "none",
            ", ".join(x["value"] for x in rc["MX"][:3]) or "none",
            ", ".join(x["value"] for x in rc["NS"][:3]) or "none",
            reg, rdd.get("created") or "unavailable", rdd.get("expires") or "unavailable",
            r["dns"]["looked_up_at"])) + " |")
    out += ["", "### Indicators", ""]
    if flags:
        out += ["| Severity | Basis | Domain | Finding | Evidence |", "|---|---|---|---|---|"]
        out += ["| " + " | ".join(_md(x) for x in (f["severity"], "verified fact" if f["basis"] == "fact" else "inference",
                                                   f["domain"], f["title"], f["evidence"])) + " |" for f in flags]
    else:
        out.append("None found in the retrievable data.")
    if ip_rows_:
        out += ["", "### Domain-to-IP infrastructure", "", "| Domain | IP | ASN | Network | Infrastructure | Scored-email log |", "|---|---|---|---|---|---|"]
        out += ["| " + " | ".join(_md(r[k]) for k in ("Domain", "IP", "ASN", "Network", "Infrastructure", "Scored-email log")) + " |" for r in ip_rows_]
    if corr_rows:
        out += ["", "### Related emails and domains", "", "| Domain | Relation | Other email / detail | Verdict | Score |", "|---|---|---|---|---|"]
        out += ["| " + " | ".join(_md(x) for x in (r["Domain"], r["Relation"], (r["Other email"] if r["Other email"] != "-" else r["Their role"]),
                                                   r["Verdict"], r["Score"])) + " |" for r in corr_rows]
    out += ["", "**Limitations:** lookups reflect the moment shown, not the moment the email was sent. DNS comes from a public "
            "DNS-over-HTTPS resolver; RDAP data may be redacted or unavailable for some registries. Registrable domain is "
            "estimated without a full public-suffix list" + (f". {skipped} further domain(s) were not looked up (cap {MAX_DOMAINS})." if skipped else ".")]
    return "\n".join(out)