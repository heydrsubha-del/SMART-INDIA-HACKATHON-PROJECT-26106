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


def hunt_cases(indicators, cases, current_name=None, current_hash=None):
    """Other emails analysed this session that contain any of the indicators."""
    rows = []
    for case in cases or []:
        if not isinstance(case, dict) or "error" in case:
            continue
        if case.get("name") == current_name or (current_hash and case.get("_evidence_hash") == current_hash):
            continue
        doms, ips = _case_artifacts(case)
        seen = set()
        for typ, val in indicators:
            if typ == "domain":
                for host, field in doms:
                    m = _host_matches(host, val)
                    if m and (val, field, m) not in seen:
                        seen.add((val, field, m))
                        rows.append(_case_row(case, val, "domain", field, m, host))
            else:
                for ip, field in ips:
                    if _norm(ip) == val and (val, field) not in seen:
                        seen.add((val, field))
                        rows.append(_case_row(case, val, "ip", field, "exact", ip))
    rows.sort(key=lambda r: -float(r["Score"] or 0))
    return rows[:MAX_ROWS]


def _case_row(case, indicator, typ, field, match, found):
    p = case.get("parsed", {}) or {}
    return {"Source": "Earlier email", "Indicator": indicator, "Type": typ, "Match": match,
            "Where": f"{case.get('name', '-')} ({field}" + (f": {found}" if _norm(found) != indicator else "") + ")",
            "First seen": "-", "Last seen": "-", "Times": 1,
            "Verdict": str(case.get("level", "-")).upper(), "Score": round(float(case.get("score", 0) or 0), 1)}


def hunt_memory(indicators, conns, self_logged_ip=None):
    """Threat-memory hits. `conns` = iterable of open sqlite3 connections (private DB,
    plus the shared feed DB when the app runs multi-user). Read-only; failures on one
    connection are skipped, never raised."""
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
                        rows.append(_mem_row(ind, "domain", _host_matches(ind, val) or "exact", rep, cat, fs, ls, obs, src))
                    c.execute("SELECT indicator, reputation, category, first_seen, last_seen, observations, source FROM threat_intel "
                              "WHERE indicator_type='url' AND instr(indicator, ?) > 0 LIMIT 200", (val,))
                    for ind, rep, cat, fs, ls, obs, src in c.fetchall():
                        try:
                            host = urllib.parse.urlsplit(ind if "://" in ind else "//" + ind).hostname
                        except ValueError:
                            host = None
                        m = _host_matches(host or "", val)
                        if m:
                            rows.append(_mem_row(ind[:90], "url", m, rep, cat, fs, ls, obs, src))
                else:
                    c.execute("SELECT indicator, reputation, category, first_seen, last_seen, observations, source FROM threat_intel "
                              "WHERE indicator_type='ip' AND indicator=? LIMIT 5", (val,))
                    for ind, rep, cat, fs, ls, obs, src in c.fetchall():
                        rows.append(_mem_row(ind, "ip", "exact", rep, cat, fs, ls, obs, src))
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
    return rows[:MAX_ROWS]


def _mem_row(ind, typ, match, rep, cat, fs, ls, obs, src):
    return {"Source": "Threat memory", "Indicator": ind, "Type": typ, "Match": match,
            "Where": f"{cat or 'unknown'} via {src or '?'} (reputation {float(rep or 0):.2f})",
            "First seen": fs or "-", "Last seen": ls or "-", "Times": int(obs or 0), "Verdict": "-", "Score": "-"}


def hunt(indicators, cases, conns, current_name=None, current_hash=None, self_logged_ip=None):
    """All hits: earlier emails first, then threat memory. Never raises."""
    try:
        rows = hunt_cases(indicators, cases, current_name, current_hash) + hunt_memory(indicators, conns, self_logged_ip)
    except Exception:
        rows = []
    return rows[:MAX_ROWS]


def summary(rows, n_indicators):
    if not rows:
        return (f"Hunted {n_indicators} indicator(s) through earlier emails and threat memory: no earlier sighting found. "
                "That only means this app has not recorded them before.")
    emails = {r["Where"].split(" (")[0] for r in rows if r["Source"] == "Earlier email"}
    mem = sum(1 for r in rows if r["Source"] != "Earlier email")
    return (f"{len(rows)} earlier sighting(s) of {n_indicators} hunted indicator(s): {len(emails)} other email(s) this session and "
            f"{mem} threat-memory record(s). A sighting means 'seen before', not 'malicious'.")


def to_markdown(rows, n_indicators=0):
    def md(v):
        return re.sub(r"\s+", " ", str(v if v is not None else "-")).replace("|", "\\|").strip() or "-"
    out = [summary(rows, n_indicators), ""]
    if rows:
        cols = ("Source", "Indicator", "Match", "Where", "First seen", "Last seen", "Times", "Verdict", "Score")
        out += ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        out += ["| " + " | ".join(md(r[c]) for c in cols) + " |" for r in rows]
    return "\n".join(out)
