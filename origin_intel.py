"""origin_intel.py -- Email Origin Intelligence for Algorithmistic.

Adds an *evidence-weighted* origin assessment, route reconstruction, route
consistency checks, infrastructure enrichment and historical IP correlation
ON TOP of what geolocate.py / network_trust.py / tor_check.py / tracker.py /
correlate.py already produce. It re-uses their output; it never replaces it.

Design rules (match the rest of the app):
  * Offline. No network call is ever made here. ASN/org data comes only from
    an optional local MaxMind GeoLite2-ASN file (data/GeoLite2-ASN.mmdb), the
    same "drop a file in data/" convention geolocate.py uses for GeoLite2-City.
  * Pure stdlib. Streamlit is not imported, so this is unit-testable.
  * Never touches the threat score. Nothing here is a scoring weight.
  * Never invents intelligence. A field with no source says "unavailable".
  * An IP gives infrastructure location only -- never a person or an address.
"""
from __future__ import annotations

import ipaddress
import os
import re
from datetime import timezone
from email.parser import BytesHeaderParser, HeaderParser
from email.utils import parsedate_to_datetime

# ---------------------------------------------------------------------------
# Constants (all tunables live here, visible and documented)
# ---------------------------------------------------------------------------
CONFIDENCE_CAP = 90          # headers can be forged -> never claim certainty
BAND_HIGH = 70
BAND_MEDIUM = 45
CLOCK_SKEW_SECONDS = 300     # tolerated backwards timestamp jump
LONG_DELAY_SECONDS = 6 * 3600

LOCATION_DISCLAIMER = (
    "Location shown is the registered/observed location of the network "
    "infrastructure that owns this IP (a mail server, ISP, hosting provider, "
    "VPN or relay). It is NOT the sender's physical location. The sender's "
    "real location, identity or address cannot be determined from an IP "
    "address alone."
)

_ANON = ("tor", "vpn", "proxy")

# Claimed-provider -> host suffixes that must appear somewhere in a genuine route.
_PROVIDER_SUFFIXES = {
    "gmail.com": ("google.com", "googlemail.com", "gmail.com"),
    "googlemail.com": ("google.com", "googlemail.com", "gmail.com"),
    "outlook.com": ("outlook.com", "microsoft.com", "hotmail.com"),
    "hotmail.com": ("outlook.com", "microsoft.com", "hotmail.com"),
    "live.com": ("outlook.com", "microsoft.com", "hotmail.com"),
    "yahoo.com": ("yahoo.com", "yahoodns.net", "yahoo.net"),
    "icloud.com": ("icloud.com", "apple.com", "me.com"),
}

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_BRACKET_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_FROM_RE = re.compile(r"\bfrom\s+(\S+)(?:\s*\(([^)]*)\))?", re.I)
_BY_RE = re.compile(r"\bby\s+(\S+)", re.I)
_WITH_RE = re.compile(r"\bwith\s+(\S+)", re.I)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _valid_ip(text):
    try:
        return str(ipaddress.ip_address(str(text).strip().strip("[]")))
    except ValueError:
        return None


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _band(score):
    return "High" if score >= BAND_HIGH else "Medium" if score >= BAND_MEDIUM else "Low"


def _host_suffix(host):
    """Registrable-ish suffix (last 2 labels, 3 for co.uk style)."""
    host = (host or "").lower().strip(".[]")
    if not host or _valid_ip(host):
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _cell(v):
    return str(v if v not in (None, "") else "-").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


# ---------------------------------------------------------------------------
# 1. Received-header parsing (structured; complements geolocate's IP extraction)
# ---------------------------------------------------------------------------
def parse_received(raw_hdr):
    """Parse one Received header into a dict. Never raises."""
    text = re.sub(r"\s+", " ", str(raw_hdr or "")).strip()
    hop = {"raw": text, "helo": "", "rdns": "", "from_ip": None, "by": "",
           "protocol": "", "ts": None, "ts_text": ""}
    body, _, tail = text.rpartition(";")
    if not body:
        body, tail = text, ""
    if tail.strip():
        try:
            dt = parsedate_to_datetime(tail.strip())
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            hop["ts"], hop["ts_text"] = dt, tail.strip()
        except (TypeError, ValueError, IndexError):
            pass
    m = _FROM_RE.search(body)
    if m:
        helo, paren = m.group(1).strip("[]"), (m.group(2) or "")
        hop["helo"] = helo
        ip = None
        for b in _BRACKET_RE.findall(paren):
            ip = _valid_ip(b)
            if ip:
                break
        if not ip:
            for cand in _IPV4_RE.findall(paren):
                ip = _valid_ip(cand)
                if ip:
                    break
        if not ip:
            ip = _valid_ip(helo)
        hop["from_ip"] = ip
        # rDNS is the first hostname-looking token inside the parenthetical
        for tok in re.split(r"[\s()\[\],]+", paren):
            if "." in tok and not _valid_ip(tok) and not tok.lower().startswith(("helo=", "ehlo=")):
                hop["rdns"] = tok.strip(".")
                break
    m = _BY_RE.search(body)
    if m:
        hop["by"] = m.group(1).strip("[]")
    m = _WITH_RE.search(body)
    if m:
        hop["protocol"] = m.group(1)
    return hop


def header_corroboration(raw):
    """Client IPs asserted by independent headers (X-Originating-IP,
    Received-SPF client-ip, Authentication-Results). Each is only as trustworthy
    as the server that stamped it -- reported as such."""
    out = []
    if not raw:
        return out
    try:  # headers only: never decode the body or attachments (can be many MB)
        if isinstance(raw, (bytes, bytearray)):
            msg = BytesHeaderParser().parsebytes(bytes(raw[:262144]))
        else:
            msg = HeaderParser().parsestr(str(raw)[:262144])
    except Exception:
        return out

    def add(ip, kind):
        ip = _valid_ip(ip)
        if ip and (ip, kind) not in out:
            out.append((ip, kind))

    for v in msg.get_all("X-Originating-IP") or []:
        add(str(v).strip().strip("[]"), "X-Originating-IP")
    for v in msg.get_all("Received-SPF") or []:
        for m in re.finditer(r"client-ip=([0-9A-Fa-f:.]+)", str(v)):
            add(m.group(1).rstrip(";"), "Received-SPF client-ip")
    for v in msg.get_all("Authentication-Results") or []:
        s = str(v)
        for m in re.finditer(r"designates\s+([0-9A-Fa-f:.]+)\s+as permitted", s):
            add(m.group(1), "Authentication-Results (SPF)")
        for m in re.finditer(r"(?:sender IP is|client-ip=|smtp\.client-ip=)\s*([0-9A-Fa-f:.]+)", s):
            add(m.group(1).rstrip(";"), "Authentication-Results (SPF)")
    return out


# ---------------------------------------------------------------------------
# 2. Route reconstruction + inconsistency detection
# ---------------------------------------------------------------------------
def _geo_index(geo):
    idx = {}
    for h in (geo or {}).get("hops", []) or []:
        if h.get("ip"):
            idx.setdefault(h["ip"], h)
    o = (geo or {}).get("origin", {}) or {}
    if o.get("ip"):
        idx.setdefault(o["ip"], o)
    return idx


def _flag(sev, code, title, evidence, hops=()):
    return {"severity": sev, "code": code, "title": title, "evidence": evidence, "hops": list(hops)}


def reconstruct_route(parsed, geo, asn_lookup=None):
    """Return (hops, flags). `parsed['received_chain']` is oldest-hop-first,
    as the app already documents."""
    chain = list((parsed or {}).get("received_chain") or [])
    gidx = _geo_index(geo)
    hops = []
    for i, raw_hdr in enumerate(chain, 1):
        h = parse_received(raw_hdr)
        h["n"] = i
        h["public"] = bool(h["from_ip"] and is_public_ip(h["from_ip"]))
        g = gidx.get(h["from_ip"] or "", {})
        h["country"] = g.get("country") or ""
        h["network"] = g.get("isp") or ""
        h["infra"] = (g.get("infra") or "").lower()
        h["infra_label"] = g.get("infra_label") or ""
        h["tor_exit"] = bool(g.get("tor_exit_confirmed"))
        a = asn_lookup(h["from_ip"]) if (asn_lookup and h["public"]) else None
        h["asn"] = (a or {}).get("asn")
        h["as_org"] = (a or {}).get("org")
        h["delta_s"] = None
        h["flags"] = []
        hops.append(h)

    flags = []
    # -- timestamps ---------------------------------------------------------
    for prev, cur in zip(hops, hops[1:]):
        if prev["ts"] and cur["ts"]:
            d = (cur["ts"] - prev["ts"]).total_seconds()
            cur["delta_s"] = d
            if d < -CLOCK_SKEW_SECONDS:
                flags.append(_flag("medium", "TS_BACKWARDS", "Timestamps run backwards",
                    f"Hop {cur['n']} is stamped {abs(int(d))}s EARLIER than hop {prev['n']} "
                    f"({cur['ts_text']} vs {prev['ts_text']}). Beyond normal clock skew; "
                    "suggests a forged or re-injected header."))
                cur["flags"].append("TS_BACKWARDS")
            elif d > LONG_DELAY_SECONDS:
                flags.append(_flag("low", "LONG_DELAY", "Long delay between hops",
                    f"{int(d // 3600)}h gap between hop {prev['n']} and hop {cur['n']} "
                    "(queued, greylisted, or a replayed message)."))
                cur["flags"].append("LONG_DELAY")

    # -- continuity: hop j 'by' should be the next hop's 'from' ---------------
    for prev, cur in zip(hops, hops[1:]):
        a = _host_suffix(prev["by"])
        names = {_host_suffix(cur["helo"]), _host_suffix(cur["rdns"])} - {""}
        if a and names and a not in names:
            flags.append(_flag("low", "CHAIN_BREAK", "Hop handoff does not line up",
                f"Hop {prev['n']} was received by '{prev['by']}', but hop {cur['n']} claims "
                f"it came from '{cur['helo'] or cur['rdns']}'. Can be legitimate (NAT, "
                "forwarding, load balancers) -- or a header inserted mid-route.",
                hops=(prev["n"], cur["n"])))
            prev["flags"].append("CHAIN_BREAK")
            cur["flags"].append("CHAIN_BREAK")

    # -- per-hop HELO checks --------------------------------------------------
    for h in hops:
        if not h["from_ip"] or not h["public"]:
            continue
        helo_ip = _valid_ip(h["helo"])
        if helo_ip and helo_ip != h["from_ip"] and is_public_ip(helo_ip):
            flags.append(_flag("medium", "HELO_IP_MISMATCH", "HELO IP differs from connecting IP",
                f"Hop {h['n']}: server announced itself as [{helo_ip}] but connected from "
                f"{h['from_ip']}."))
            h["flags"].append("HELO_IP_MISMATCH")
        elif h["helo"] and not helo_ip and "." not in h["helo"]:
            flags.append(_flag("low", "HELO_NOT_FQDN", "HELO is not a fully-qualified name",
                f"Hop {h['n']}: HELO '{h['helo']}' from public IP {h['from_ip']} "
                "(common for malware/bulk senders, also some misconfigured legit hosts)."))
            h["flags"].append("HELO_NOT_FQDN")

    # -- anonymising infrastructure anywhere in the route --------------------
    for h in hops:
        if h["infra"] in _ANON or h["tor_exit"]:
            flags.append(_flag("medium", "ANON_HOP", "Route passes through anonymising infrastructure",
                f"Hop {h['n']} ({h['from_ip']}) is classified {h['infra_label'] or h['infra'] or 'Tor exit'}"
                f"{' and is on a published Tor exit list' if h['tor_exit'] else ''}. "
                "This identifies the relay, not the operator."))
            h["flags"].append("ANON_HOP")

    # -- claimed provider absent from the route ------------------------------
    from_addr = str((parsed or {}).get("from_addr") or "").lower()
    dom = from_addr.rsplit("@", 1)[-1].strip(" >") if "@" in from_addr else ""
    suffixes = _PROVIDER_SUFFIXES.get(dom)
    seen_hosts = [x for h in hops for x in (h["by"], h["helo"], h["rdns"]) if x]
    if suffixes and seen_hosts:
        if not any(_host_suffix(x) in suffixes for x in seen_hosts):
            flags.append(_flag("medium", "PROVIDER_ABSENT", f"Claims {dom} but route never touches that provider",
                f"From-domain is {dom}, yet no hop's server name belongs to {', '.join(suffixes)}. "
                f"Hosts seen: {', '.join(sorted(set(seen_hosts))[:6])}. Check SPF/DKIM/DMARC; "
                "forwarders and mailing lists can also cause this."))
    return hops, flags


# ---------------------------------------------------------------------------
# 3. Origin Confidence Engine
# ---------------------------------------------------------------------------
def _ev(effect, indicator, detail):
    return {"effect": effect, "indicator": indicator, "detail": detail}


def assess_origin(parsed, geo, raw=None, asn_lookup=None):
    """Score every public IP seen in the route and explain the best candidate.

    Returns a dict (see keys at the bottom). Confidence expresses how likely it
    is that the selected IP is the externally observable origin of the SMTP
    connection chain -- not who the sender is.
    """
    geo = geo or {}
    hops, flags = reconstruct_route(parsed, geo, asn_lookup)
    corro = header_corroboration(raw)
    existing = ((geo.get("origin") or {}).get("ip")) or None
    limitations = [
        "Received headers added below the first server you control can be forged; "
        "only the hop added by your own receiving server is fully trustworthy.",
        "Confidence rates how likely this IP is the externally observed origin of the mail "
        "route -- it does not identify the person or device behind it.",
        LOCATION_DISCLAIMER,
    ]
    if not hops:
        limitations.append("No parsable Received chain: origin rests only on the existing geolocation result.")

    cands = {}
    last_n = hops[-1]["n"] if hops else 0
    for h in hops:
        if h["public"] and h["from_ip"] not in cands:
            cands[h["from_ip"]] = h
    for ip, _kind in corro:
        if is_public_ip(ip) and ip not in cands:
            cands[ip] = None   # asserted by a header only, not seen as a hop
    if existing and is_public_ip(existing) and existing not in cands:
        cands[existing] = None

    scored = []
    for ip, h in cands.items():
        score, ev = 30, [_ev("base", "Public routable IP", "Observed in the message headers.")]
        if h:
            dist = last_n - h["n"]
            pos = max(0, 25 - 5 * dist)
            if pos:
                score += pos
                ev.append(_ev(f"+{pos}", "Proximity to recipient",
                    f"Recorded by hop {h['n']} of {last_n}"
                    + (" -- the hop added by the final receiving server." if dist == 0
                       else f" -- {dist} hop(s) from the recipient; headers nearer the recipient are harder to forge.")))
            breaks = [f for f in flags if f["code"] == "CHAIN_BREAK" and f["hops"] and f["hops"][0] >= h["n"]]
            downstream_breaks = min(len(breaks), 2)
            if downstream_breaks:
                score -= 8 * downstream_breaks
                ev.append(_ev(f"-{8 * downstream_breaks}", "Handoff gaps downstream",
                    f"{len(breaks)} hop handoff(s) between this hop and the recipient do not line up."))
            elif last_n - h["n"] >= 1:
                score += 15
                ev.append(_ev("+15", "Unbroken handoff chain", "Every handoff from this hop to the recipient lines up."))
            if "TS_BACKWARDS" in h["flags"]:
                score -= 10
                ev.append(_ev("-10", "Timestamp anomaly", "This hop's timestamp precedes the previous hop's."))
            elif h["ts"]:
                score += 5
                ev.append(_ev("+5", "Timestamp consistent", f"Stamped {h['ts_text']}."))
            if "HELO_IP_MISMATCH" in h["flags"]:
                score -= 10
                ev.append(_ev("-10", "HELO/IP mismatch", "Announced IP differs from connecting IP."))
        else:
            ev.append(_ev("0", "Not a Received hop", "IP asserted by a header or by the existing geolocation only."))
        kinds = sorted({k for i2, k in corro if i2 == ip})
        if kinds:
            bonus = min(25, 15 * len(kinds))
            score += bonus
            ev.append(_ev(f"+{bonus}", "Independent header agrees", "; ".join(kinds)
                + " names this same IP (only as trustworthy as the server that stamped it)."))
        if existing and ip == existing:
            score += 5
            ev.append(_ev("+5", "Matches existing geolocation origin", "Same IP the Origin & Route summary uses."))
        scored.append({"ip": ip, "score": max(5, min(CONFIDENCE_CAP, score)), "hop": h["n"] if h else None, "evidence": ev})

    scored.sort(key=lambda c: (-c["score"], c["hop"] if c["hop"] is not None else 10**6))
    best = scored[0] if scored else None
    note = ""
    if best and existing and best["ip"] != existing:
        note = (f"The engine prefers {best['ip']} over the existing Origin IP {existing}; "
                "the existing result is left unchanged. Review both.")
    elif best and not existing:
        note = "No origin was resolved by the existing geolocation; this candidate comes from header evidence only."
    if best and len(scored) > 1 and best["score"] - scored[1]["score"] < 10:
        limitations.append(f"Close call: {scored[1]['ip']} scored within 10 points of the selected IP.")

    return {
        "selected_ip": best["ip"] if best else None,
        "confidence": best["score"] if best else 0,
        "band": _band(best["score"]) if best else "None",
        "evidence": best["evidence"] if best else [],
        "alternatives": scored[1:6],
        "existing_origin_ip": existing,
        "disagreement_note": note,
        "route": hops,
        "flags": flags,
        "corroboration": corro,
        "limitations": limitations,
        "location_disclaimer": LOCATION_DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# 4. Infrastructure intelligence (existing fields + optional local ASN DB)
# ---------------------------------------------------------------------------
_ASN_READER = {"reader": None, "path": None, "failed": False}


def make_asn_lookup(path=None):
    """Return fn(ip) -> {'asn','org'} | None using a local GeoLite2-ASN file,
    or None when no such file/library exists (graceful, offline). Re-checks
    for the file cheaply, so dropping it into data/ works without a restart."""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "GeoLite2-ASN.mmdb")
    if _ASN_READER["path"] != path:
        _ASN_READER.update(reader=None, path=path, failed=False)
    if _ASN_READER["reader"] is None and not _ASN_READER["failed"] and os.path.exists(path):
        try:
            import maxminddb  # type: ignore
            _ASN_READER["reader"] = maxminddb.open_database(path)
        except Exception:
            try:
                import geoip2.database  # type: ignore
                _ASN_READER["reader"] = geoip2.database.Reader(path)
            except Exception:
                _ASN_READER["failed"] = True
    reader = _ASN_READER["reader"]
    if reader is None:
        return None

    def lookup(ip):
        try:
            if hasattr(reader, "get"):
                r = reader.get(ip) or {}
                return {"asn": r.get("autonomous_system_number"), "org": r.get("autonomous_system_organization")}
            r = reader.asn(ip)
            return {"asn": r.autonomous_system_number, "org": r.autonomous_system_organization}
        except Exception:
            return None
    return lookup


def infrastructure_profile(ips, geo, asn_lookup=None, history=None):
    """One row per IP, built only from data we really have. `history` maps
    ip -> (prior_count, max_score) from the threat-memory DB."""
    gidx = _geo_index(geo)
    rows = []
    for ip in ips:
        g = gidx.get(ip, {})
        a = asn_lookup(ip) if (asn_lookup and is_public_ip(ip)) else None
        infra = (g.get("infra_label") or "").strip()
        low = infra.lower()
        signals = []
        if g.get("tor_exit_confirmed"):
            signals.append("Confirmed Tor exit (" + "; ".join(g.get("tor_exit_sources") or ["list"]) + ")")
        if (g.get("infra") or "").lower() in _ANON:
            signals.append(f"Classified {infra or g.get('infra')}")
        hosting = any(k in low for k in ("datacenter", "data center", "hosting", "cloud"))
        if hosting:
            signals.append("Hosting / datacenter range")
        prior, top = (history or {}).get(ip, (0, 0))
        if prior:
            signals.append(f"Seen {prior} time(s) before in threat memory (max score {top:.0f})")
        rows.append({
            "IP": ip,
            "ASN": f"AS{a['asn']}" if a and a.get("asn") else "unavailable",
            "AS organization": (a or {}).get("org") or "unavailable",
            "ISP / network": g.get("isp") or "unavailable",
            "Infrastructure": infra or "unattributed",
            "Hosting provider": "Yes" if hosting else ("No" if infra else "unknown"),
            "Reputation signals": "; ".join(signals) or "none from configured sources",
            "Infra location": ", ".join(p for p in (g.get("city"), g.get("country")) if p) or "unresolved",
        })
    return rows


# ---------------------------------------------------------------------------
# 5. Historical correlation
# ---------------------------------------------------------------------------
def _case_ips(case):
    g = (case or {}).get("geo", {}) or {}
    ips = {h.get("ip") for h in (g.get("hops") or []) if h.get("ip")}
    if (g.get("origin") or {}).get("ip"):
        ips.add(g["origin"]["ip"])
    return ips


def correlate_history(ips, current_name, current_hash, cases, history_fn=None, self_logged_ip=None):
    """Link IPs to threat memory and to other emails analysed this session.

    history_fn(ip) -> (count, max_score)   [tracker.check_history]
    self_logged_ip : the IP the app already logged for the CURRENT email, so its
                     own log entry is not counted as a previous sighting.
    Returns (history_by_ip, session_rows).
    """
    history = {}
    for ip in ips:
        if history_fn and is_public_ip(ip):
            try:
                c, m = history_fn(ip)
                c, m = int(c or 0), float(m or 0)
                if ip == self_logged_ip and c > 0:
                    c -= 1
                history[ip] = (c, m)
            except Exception:
                history[ip] = (0, 0)
    rows = []
    for case in cases or []:
        if case.get("name") == current_name or (current_hash and case.get("_evidence_hash") == current_hash):
            continue
        shared = sorted(set(ips) & _case_ips(case))
        if not shared:
            continue
        p = case.get("parsed", {}) or {}
        iocs = case.get("iocs", {}) or {}
        urls = [u.get("url") if isinstance(u, dict) else u for u in (iocs.get("urls") or [])]
        doms = [d.get("domain") if isinstance(d, dict) else d for d in (iocs.get("domains") or [])]
        rows.append({
            "Shared IP": ", ".join(shared),
            "Email": case.get("name", "-"),
            "From": p.get("from_addr", "-"),
            "Verdict": str(case.get("level", "-")).upper(),
            "Score": round(float(case.get("score", 0) or 0), 1),
            "Domains": ", ".join(str(d) for d in doms[:3] if d) or "-",
            "URLs": len([u for u in urls if u]),
        })
    return history, rows


# ---------------------------------------------------------------------------
# 6. Forensic report text
# ---------------------------------------------------------------------------
def route_ips(assessment):
    ips = []
    for h in assessment.get("route", []):
        if h.get("public") and h["from_ip"] not in ips:
            ips.append(h["from_ip"])
    for c in [assessment.get("selected_ip"), assessment.get("existing_origin_ip")]:
        if c and c not in ips and is_public_ip(c):
            ips.append(c)
    return ips[:12]


def to_markdown(a, infra_rows=None, session_rows=None, history=None):
    """Markdown block for the forensic report. Mirrors what the UI shows."""
    if not a or (not a.get("selected_ip") and not a.get("route")):
        return ("No origin assessment could be produced (no public IP found in the headers).\n\n"
                "_" + LOCATION_DISCLAIMER + "_")
    L = []
    L.append("| Property | Value |\n|---|---|")
    L.append(f"| **Most likely externally observed origin IP** | `{_cell(a['selected_ip'])}` |")
    L.append(f"| **Confidence** | {a['confidence']}/100 ({a['band']}) |")
    L.append(f"| **Existing Origin IP (geolocation)** | `{_cell(a['existing_origin_ip'])}` |")
    if a.get("disagreement_note"):
        L.append(f"| **Note** | {_cell(a['disagreement_note'])} |")
    L.append("\n### Supporting indicators\n| Effect | Indicator | Detail |\n|---|---|---|")
    for e in a["evidence"]:
        L.append(f"| {_cell(e['effect'])} | {_cell(e['indicator'])} | {_cell(e['detail'])} |")
    if a["alternatives"]:
        L.append("\n### Alternative candidates\n| IP | Score | Hop |\n|---|---|---|")
        for c in a["alternatives"]:
            L.append(f"| `{_cell(c['ip'])}` | {c['score']} | {_cell(c['hop'])} |")
    if a["route"]:
        L.append("\n### Reconstructed route (oldest hop first)\n| # | From (HELO / rDNS) | IP | By | Time | Infra | Flags |\n|---|---|---|---|---|---|---|")
        for h in a["route"]:
            L.append(f"| {h['n']} | {_cell(h['helo'] or h['rdns'])} | `{_cell(h['from_ip'])}` | {_cell(h['by'])} | "
                     f"{_cell(h['ts_text'])} | {_cell(h['infra_label'])} | {_cell(', '.join(h['flags']))} |")
    L.append("\n### Route inconsistencies\n" + ("\n".join(
        f"- **{f['severity'].upper()}** {_cell(f['title'])}: {_cell(f['evidence'])}" for f in a["flags"])
        if a["flags"] else "None detected."))
    if infra_rows:
        L.append("\n### Infrastructure intelligence\n| IP | ASN | AS organization | ISP / network | Infrastructure | Reputation signals |\n|---|---|---|---|---|---|")
        for r in infra_rows:
            L.append(f"| `{_cell(r['IP'])}` | {_cell(r['ASN'])} | {_cell(r['AS organization'])} | {_cell(r['ISP / network'])} | "
                     f"{_cell(r['Infrastructure'])} | {_cell(r['Reputation signals'])} |")
    L.append("\n### Historical correlation")
    prior = [(ip, v) for ip, v in (history or {}).items() if v[0]]
    L.append("\n".join(f"- `{ip}` seen {v[0]} time(s) previously in threat memory (max score {v[1]:.0f})." for ip, v in prior)
             or "- No previous sightings of these IPs in threat memory.")
    if session_rows:
        L.append("\n| Shared IP | Email | From | Verdict | Score | Domains | URLs |\n|---|---|---|---|---|---|---|")
        for r in session_rows:
            L.append("| " + " | ".join(_cell(r[k]) for k in ("Shared IP", "Email", "From", "Verdict", "Score", "Domains", "URLs")) + " |")
    else:
        L.append("- No other email analysed this session shares these IPs.")
    L.append("\n### Intelligence sources\nReceived/auth headers of this message; local geolocation + infrastructure "
             "classification; published Tor exit lists; threat-memory database; emails analysed this session; "
             "local GeoLite2-ASN database where installed. No live lookups were made.")
    L.append("\n### Limitations\n" + "\n".join(f"- {_cell(x)}" for x in a["limitations"]))
    return "\n".join(L)