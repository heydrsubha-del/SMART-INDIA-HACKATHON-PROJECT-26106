"""retro_hunt.py -- Retro-Hunt for Algorithmistic.

Takes the indicators found in ONE email (its domains and the IPs they resolve to,
plus the IPs in its route) and hunts BACKWARDS through what the app already knows:

  1. other emails analysed this session (the in-memory case list)
  2. threat memory (tracker.py's SQLite: threat_intel + attackers tables)

Rules (same as the other intelligence modules)
  * Local and read-only: no network, no writes, no new tables.
  * Never changes the threat score.
  * Reports only what is stored. A hit says "seen before"; it does not say "malicious".
  * Matches are labelled exact / subdomain so a reader can see how strong each is.
  * Pure stdlib; the DB connection is injected, so it is testable without Streamlit.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from email.utils import parseaddr

MAX_INDICATORS = 40
MAX_ROWS = 80


def _norm(v):
    return str(v or "").strip().lower().rstrip(".")


def _is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def build_indicators(domains=(), ips=()):
    """[(type, value)] with duplicates removed, capped. Domains are hunted both
    exactly and as a parent of subdomains."""
    out, seen = [], set()
    for d in domains:
        d = _norm(d)
        if d and not _is_ip(d) and ("domain", d) not in seen:
            seen.add(("domain", d)); out.append(("domain", d))
    for ip in ips:
        ip = _norm(ip)
        if ip and _is_ip(ip) and ("ip", ip) not in seen:
            seen.add(("ip", ip)); out.append(("ip", ip))
    return out[:MAX_INDICATORS]


def _host_matches(host, domain):
    """'exact' | 'subdomain' | None."""
    host, domain = _norm(host), _norm(domain)
    if host == domain:
        return "exact"
    if host.endswith("." + domain):
        return "subdomain"
    return None


def _case_artifacts(case):
    """Everything a stored case says about domains and IPs, with the field it came from."""
    p, io, g = case.get("parsed", {}) or {}, case.get("iocs", {}) or {}, case.get("geo", {}) or {}
    doms, ips = [], []
    for field, key in (("From", "from_addr"), ("Reply-To", "reply_to"), ("Return-Path", "return_path")):
        addr = parseaddr(str(p.get(key) or ""))[1]
        if "@" in addr:
            doms.append((addr.rsplit("@", 1)[1], field))
    for key, field in (("from_domain", "From"), ("reply_to_domain", "Reply-To")):
        if p.get(key):
            doms.append((p[key], field))
    for d in io.get("domains") or []:
        doms.append(((d.get("domain") if isinstance(d, dict) else d), "Body domain"))
    for u in io.get("urls") or []:
        raw = (u.get("host") or u.get("url")) if isinstance(u, dict) else u
        s = str(raw or "")
        try:
            h = urllib.parse.urlsplit(s if "://" in s else "//" + s).hostname
        except ValueError:
            h = None
        if h:
            doms.append((h, "Link host"))
    for rec in case.get("domain_dns") or []:
        if isinstance(rec, dict):
            doms.append((rec.get("domain"), "Looked-up domain"))
            ips.extend((ip, "Domain resolves to") for ip in rec.get("ips") or [])
    o = (g.get("origin") or {}).get("ip")
    if o:
        ips.append((o, "Origin IP"))
    ips.extend((h.get("ip"), "Relay hop") for h in (g.get("hops") or []) if isinstance(h, dict) and h.get("ip"))
    ips.extend((i, "IP in body") for i in io.get("ips") or [])
    return doms, ips


def _case_key(case):
    return str(case.get("_evidence_hash") or case.get("name") or id(case))


def _specificity(match, indicator):
    return (1 if match == "exact" else 0, len(indicator))


def hunt_cases(indicators, cases, current_name=None, current_hash=None):
    """Other emails analysed this session that contain any of the indicators.

    One row per (email, matched artifact): an artifact reachable through several
    hunted indicators (exact host AND its registrable parent) or several fields
    (origin IP that is also a relay hop) is ONE sighting, reported with all the
    fields it appeared in and the most specific indicator that matched."""
    found = {}          # (case_key, type, artifact) -> info
    done = set()        # an email supplied twice is hunted once
    for case in cases or []:
        if not isinstance(case, dict) or "error" in case:
            continue
        ck = _case_key(case)
        if ck in done or case.get("name") == current_name or (current_hash and case.get("_evidence_hash") == current_hash):
            continue
        done.add(ck)
        doms, ips = _case_artifacts(case)
        for typ, val in indicators:
            pool = doms if typ == "domain" else ips
            for artifact, field in pool:
                m = _host_matches(artifact, val) if typ == "domain" else ("exact" if _norm(artifact) == val else None)
                if not m:
                    continue
                key = (ck, typ, _norm(artifact))
                cur = found.get(key)
                if cur is None:
                    found[key] = {"case": case, "indicator": val, "match": m, "fields": [field], "artifact": _norm(artifact)}
                else:
                    if field not in cur["fields"]:
                        cur["fields"].append(field)
                    if _specificity(m, val) > _specificity(cur["match"], cur["indicator"]):
                        cur["indicator"], cur["match"] = val, m
    rows = [_case_row(i["case"], i["indicator"], "domain" if _norm(i["artifact"]) and not _is_ip(i["artifact"]) else "ip",
                      ", ".join(i["fields"]), i["match"], i["artifact"]) for i in found.values()]
    rows.sort(key=lambda r: (-float(r["Score"] or 0), r["Where"], r["Indicator"]))
    return rows[:MAX_ROWS]


def _case_row(case, indicator, typ, field, match, found):
    p = case.get("parsed", {}) or {}
    return {"Source": "Earlier email", "Indicator": indicator, "Type": typ, "Match": match,
            "Where": f"{case.get('name', '-')} ({field}" + (f": {found}" if _norm(found) != indicator else "") + ")",
            "First seen": "-", "Last seen": "-", "Times": 1,
            "Verdict": str(case.get("level", "-")).upper(), "Score": round(float(case.get("score", 0) or 0), 1)}


def hunt_memory(indicators, conns, self_logged_ip=None, self_indicators=()):
    """Threat-memory hits. `conns` = iterable of open sqlite3 connections (private DB,
    plus the shared feed DB when the app runs multi-user). Read-only; failures on one
    connection are skipped, never raised.

    self_indicators: {(type, stored_value)} that THIS email's own analysis recorded in
    threat_intel (analyzer.py stores its domains, body IPs and URLs). Each such row
    carries one observation that belongs to this email, so only observations - 1 are
    earlier sightings, and a row with none left is not reported.
    Identical stored records reached by several hunted indicators, or present in both
    databases, are reported once; records that differ in dates/counts/source stay separate."""
    selfset = {(t, _norm(v)) for t, v in (self_indicators or ())}
    rows = []
    for conn in conns or []:
        try:
            c = conn.cursor()
            for typ, val in indicators:
                if typ == "domain":
                    like = "%." + val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                    c.execute("SELECT indicator, reputation, category, first_seen, last_seen, observations, source FROM threat_intel "
                              "WHERE indicator_type='domain' AND (indicator=? OR indicator LIKE ? ESCAPE '\\') LIMIT 25", (val, like))
                    for ind, rep, cat, fs, ls, obs, src in c.fetchall():
                        rows.append(_mem_row(ind, "domain", _host_matches(ind, val) or "exact", rep, cat, fs, ls, obs, src, selfset))
                    c.execute("SELECT indicator, reputation, category, first_seen, last_seen, observations, source FROM threat_intel "
                              "WHERE indicator_type='url' AND instr(indicator, ?) > 0 LIMIT 200", (val,))
                    for ind, rep, cat, fs, ls, obs, src in c.fetchall():
                        try:
                            host = urllib.parse.urlsplit(ind if "://" in ind else "//" + ind).hostname
                        except ValueError:
                            host = None
                        m = _host_matches(host or "", val)
                        if m:
                            rows.append(_mem_row(ind, "url", m, rep, cat, fs, ls, obs, src, selfset))
                else:
                    c.execute("SELECT indicator, reputation, category, first_seen, last_seen, observations, source FROM threat_intel "
                              "WHERE indicator_type='ip' AND indicator=? LIMIT 5", (val,))
                    for ind, rep, cat, fs, ls, obs, src in c.fetchall():
                        rows.append(_mem_row(ind, "ip", "exact", rep, cat, fs, ls, obs, src, selfset))
                    c.execute("SELECT count(*), min(date), max(date), max(score), group_concat(DISTINCT verdict) FROM attackers WHERE ip=?", (val,))
                    n, d0, d1, top, verdicts = c.fetchone() or (0, None, None, None, None)
                    if n:
                        n_prior = n - 1 if val == self_logged_ip else n
                        if n_prior > 0:
                            rows.append({"Source": "Scored-email log", "Indicator": val, "Type": "ip", "Match": "exact",
                                         "Where": f"verdicts: {verdicts or '-'}", "First seen": d0, "Last seen": d1,
                                         "Times": n_prior, "Verdict": "-", "Score": round(float(top or 0), 1)})
        except Exception:
            continue
    return _dedupe_memory([r for r in rows if r])[:MAX_ROWS]


def _dedupe_memory(rows):
    best = {}
    for r in rows:
        key = (r["Source"], r["Type"], r["Indicator"], r["First seen"], r["Last seen"], r["Times"], r["Where"], r["Score"])
        if key not in best or (r["Match"] == "exact" and best[key]["Match"] != "exact"):
            best[key] = r
    out = list(best.values())
    for r in out:   # long URLs are shortened only for display, after identity is settled
        if r["Type"] == "url" and len(r["Indicator"]) > 90:
            r["Indicator"] = r["Indicator"][:90]
    return out


def _mem_row(ind, typ, match, rep, cat, fs, ls, obs, src, selfset=frozenset()):
    if (typ, _norm(ind)) in selfset:
        obs = max(int(obs or 0) - 1, 0)
        if obs == 0:
            return None
    return {"Source": "Threat memory", "Indicator": ind, "Type": typ, "Match": match,
            "Where": f"{cat or 'unknown'} via {src or '?'} (reputation {float(rep or 0):.2f})",
            "First seen": fs or "-", "Last seen": ls or "-", "Times": int(obs or 0), "Verdict": "-", "Score": "-"}


def hunt(indicators, cases, conns, current_name=None, current_hash=None, self_logged_ip=None, self_indicators=()):
    """All hits: earlier emails first, then threat memory. Never raises."""
    try:
        rows = hunt_cases(indicators, cases, current_name, current_hash) + hunt_memory(indicators, conns, self_logged_ip, self_indicators)
    except Exception:
        rows = []
    return rows[:MAX_ROWS]


def counts(rows):
    """The three history buckets, derived from the rows themselves (never separately)."""
    rows = rows or []
    emails = {r["Where"].split(" (")[0] for r in rows if r["Source"] == "Earlier email"}
    return {"emails": len(emails), "email_rows": sum(1 for r in rows if r["Source"] == "Earlier email"),
            "intel": sum(1 for r in rows if r["Source"] == "Threat memory"),
            "log": sum(1 for r in rows if r["Source"] == "Scored-email log")}


def summary(rows, n_indicators):
    c = counts(rows)
    base = (f"Hunted {n_indicators} indicator(s). Earlier emails this session: {c['emails']} email(s) "
            f"({c['email_rows']} matching artifact(s)). Threat-memory indicator records: {c['intel']}. "
            f"Scored-email log entries: {c['log']}.")
    if not rows:
        return base + " No earlier sighting was found; that only means this app has not recorded these indicators before."
    return base + " A sighting means 'seen before', not 'malicious'."


def to_markdown(rows, n_indicators=0):
    def md(v):
        return re.sub(r"\s+", " ", str(v if v is not None else "-")).replace("|", "\\|").strip() or "-"
    out = [summary(rows, n_indicators), ""]
    if rows:
        cols = ("Source", "Indicator", "Match", "Where", "First seen", "Last seen", "Times", "Verdict", "Score")
        out += ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        out += ["| " + " | ".join(md(r[c]) for c in cols) + " |" for r in rows]
    return "\n".join(out)