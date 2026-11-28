"""Phase 5 - Operator Intelligence: read-only, deterministic analyst assistance over a finished investigation.

Consumes the investigation dict produced by investigation_agent.investigate() (and, optionally, the scanner result). It
  * NEVER changes the scanner score/verdict, never runs a tool, never makes a network call, never persists raw IPs or email content;
  * derives every recommendation from evidence already in the investigation (evidence IDs are cited, nothing is fabricated);
  * keeps confirmed (tool-verified), probable (tool signals) and hypotheses (model-proposed) strictly separate;
  * scores PRIORITY (what to look at first) separately from CONFIDENCE (how complete the evidence is) and from the scanner verdict;
  * keeps analyst decisions per scan in session state only (no new persistence layer); decisions never cross scan IDs.
Missing or failed evidence raises review priority; it is never treated as proof of safety.
"""
import hashlib
import re
import time

import investigation_agent as ia

# Transparent priority weights (sum 100). Priority orders the analyst's work; it is NOT a threat verdict.
WEIGHTS = {"severity": 30, "cross_source_correlation": 20, "campaign": 15, "evidence_gaps": 15, "impact": 10, "urgency": 10}
MAX_RECS, MAX_QUESTIONS, MAX_DECISIONS, MAX_ITEMS = 12, 8, 50, 20
STATUSES = ("pending", "done", "dismissed")
_IMPACT_CUES = re.compile(r"\b(payment|invoice|wire|bank|credential|password|gift card|payroll|attachment|login)\b", re.I)
_BANDS = ((70, "P1 Urgent"), (50, "P2 High"), (25, "P3 Standard"), (0, "P4 Low"))
LIMITATIONS = (
    "Operator Intelligence is read-only analyst assistance. It does not change the scanner score or verdict and is not a threat verdict.",
    "Priority ranks what to review first; it is not a probability of malice. Confidence reflects evidence coverage, not severity.",
    "Missing, failed or skipped checks are unresolved questions, never evidence of safety.",
    "Hypotheses (model-proposed) are unverified and are never presented as findings. No attacker identity or geographic movement is inferred.",
    "Recommendations are derived only from evidence recorded in this investigation; evidence from other scans is never mixed in.",
)


def _c(v, n=200):
    return ia.clean(v, n)


def _evs(inv):
    return [e for e in (inv.get("evidence") or []) if isinstance(e, dict) and isinstance(e.get("id"), str)][:60]


def _ind(e):
    a = e.get("args")
    return _c(a.get("indicator"), 80) if isinstance(a, dict) and a.get("indicator") else ""


def _rid(*parts):
    return "R" + hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:8]


MAX_IDENT = 512                                   # identity-comparison safety limit; longer indicators are excluded from correlation, never truncated


def _raw_ind(e):
    a = e.get("args")
    v = a.get("indicator") if isinstance(a, dict) else None
    return v if isinstance(v, str) else ""


def _ident(e):
    """Full normalized indicator identity for correlation ('' = unusable: missing, non-string or over the safety limit)."""
    v = _raw_ind(e)
    return v.strip().lower().rstrip(".") if 0 < len(v) <= MAX_IDENT else ""


def _latest(evs):
    """Latest evidence per (tool, indicator) check: a failed attempt followed by a retry no longer counts, and repeats never multiply."""
    last = {}
    for e in evs:
        v = _raw_ind(e).strip().lower().rstrip(".")                   # same canonical form as _ident(), but full-length (no 512 limit, no display truncation)
        last[(e.get("tool"), v) if v else (e.get("tool"), None, e["id"])] = e   # no indicator: no reliable retry identity, so each check stays separate
    return list(last.values())


def _norm_ind(v):
    return _c(v, 80).strip().lower().rstrip(".")


def _records(evs):
    return [(e, r) for e in evs for r in (e.get("records") or []) if isinstance(r, dict)]


_ORIGIN_RANK = {"untrusted_claim": 1, "inference": 2, "historical": 3, "trusted_external": 4, "direct_machine": 5}
_ORIGIN_CAT = {"direct_machine": "confirmed", "trusted_external": "confirmed", "untrusted_claim": "claims", "unresolved": "claims",
               "historical": "historical", "inference": "inferred"}
FINDING_TITLES = (("confirmed", "Confirmed findings (tool-observed: machine or trusted-external evidence)"),
                  ("claims", "Unverified claims (sender-controlled, or evidence not found in the register - NOT independently confirmed)"),
                  ("historical", "Historical observations (seen before; not proof)"),
                  ("inferred", "Inferences (derived or approximate)"),
                  ("probable", "Probable findings (tool signals, not proof)"),
                  ("hypotheses", "Hypotheses (model-proposed, unverified - NOT findings)"))


def _weakest_origin(ids, org):
    """Weakest origin among the cited evidence; an ID that is not in the register (or no ID at all) is 'unresolved' and is never upgraded."""
    got = [org.get(i) for i in ids]
    if not ids or any(o not in _ORIGIN_RANK for o in got):
        return "unresolved"
    return min(got, key=_ORIGIN_RANK.get)


def _classify(inv, evs=None):
    """Provenance-aware: a 'verified' tool finding is confirmed only if ALL cited evidence is machine-observed or trusted-external.
    probable = tool signals; hypotheses = model-proposed (always unverified)."""
    org = {e["id"]: e.get("origin") for e in (evs if evs is not None else _evs(inv))}
    out = {k: [] for k, _ in FINDING_TITLES}
    for f in inv.get("findings") or []:
        if not isinstance(f, dict) or f.get("kind") not in ("verified", "suspicious"):
            continue
        ids = [_c(x, 12) for x in (f.get("evidence_ids") or [])][:6]
        o = _weakest_origin(ids, org)
        k = _ORIGIN_CAT[o] if f["kind"] == "verified" else "probable"
        out[k].append({"statement": _c(f.get("statement"), 300), "evidence_ids": ids, "origin": "tool", "evidence_origin": o,
                       "origin_label": ia.ORIGIN_LABEL.get(o, "evidence not found in the register"), "finding_id": _c(f.get("finding_id"), 12)})
    for f in inv.get("narrative_findings") or []:
        if isinstance(f, dict):
            out["hypotheses"].append({"statement": _c(f.get("statement"), 300), "evidence_ids": [_c(x, 12) for x in (f.get("evidence_ids") or [])][:6],
                                      "origin": "model", "supported_by_ids": bool(f.get("supported", True))})
    return {k: v[:MAX_ITEMS] for k, v in out.items()}


def _confidence(inv, evs):
    if not evs:
        return {"level": "None", "coverage": 0.0, "note": "No investigation evidence was collected."}
    cov = round(sum(1 for e in evs if e.get("status") == "ok") / len(evs), 2)
    complete = inv.get("status") == "complete"
    lvl = "High" if (cov >= 0.9 and complete) else "Moderate" if cov >= 0.6 else "Low"
    return {"level": lvl, "coverage": cov, "note": "Evidence coverage of this investigation (%d%% of checks completed cleanly%s); not a severity measure."
            % (round(cov * 100), "" if complete else ", investigation incomplete")}


def _priority(inv, result, evs, cls):
    live = {e["id"] for e in evs}                              # evs here is already the latest-per-check list
    sc = inv.get("score_snapshot") if isinstance(inv.get("score_snapshot"), dict) else {}
    score = sc.get("score") if isinstance(sc.get("score"), (int, float)) and not isinstance(sc.get("score"), bool) else None
    recs = _records(evs)
    conf_n = sum(1 for _, r in recs if r.get("tier") == "confirmed")
    susp_n = sum(1 for _, r in recs if r.get("tier") == "suspicious")
    # Correlation is measured per SHARED indicator only: evidence is grouped by the normalized indicator argument, and an indicator
    # counts as corroborated when 2+ distinct origin classes (e.g. historical memory vs external DNS/RDAP) raised signals or
    # suspicious/confirmed records about it. Several records or checks of one origin class count once. Checks with no indicator
    # argument (authentication, headers, URLs, origin, content) cannot be tied to an entity and are excluded.
    by_ind = {}
    for e in evs:
        i = _ident(e)
        if i and e.get("status") in ("ok", "partial") and (e.get("signals") or any(
                r.get("tier") in ("confirmed", "suspicious") for r in (e.get("records") or []) if isinstance(r, dict))):
            o = e.get("origin")
            if isinstance(o, str) and o in ia.ORIGIN_LABEL:               # only recognized origin classes; missing/unknown never corroborate
                by_ind.setdefault(i, set()).add(o)
    corr_n = max([len(v) for v in by_ind.values()] or [0])
    cm = (result or {}).get("campaign_matches") if isinstance(result, dict) else None
    camp_n = len(cm.get("matches") or []) if isinstance(cm, dict) and isinstance(cm.get("matches"), list) else 0
    bad = sum(1 for e in evs if e.get("status") != "ok") + sum(
        1 for f in (inv.get("findings") or []) if isinstance(f, dict) and f.get("kind") == "uncertain"
        and (not f.get("evidence_ids") or any(x in live for x in f.get("evidence_ids") or [])))
    gap_f = 1.0 if not evs else min(1.0, bad / 4.0)
    cues = sum(1 for f in cls["probable"] if _IMPACT_CUES.search(f["statement"]))
    auth_sig = any(e.get("tool") == "review_authentication" and e.get("signals") for e in evs)
    comp = {"severity": (min(max(score, 0), 100) / 100.0 if score is not None else 0.0),
            "cross_source_correlation": (min(corr_n, 4) - 1) / 3.0 if corr_n >= 2 else 0.0, "campaign": min(camp_n, 3) / 3.0, "evidence_gaps": gap_f,
            "impact": 1.0 if cues >= 2 else 0.5 if cues == 1 else 0.0,
            "urgency": 1.0 if conf_n else 0.5 if auth_sig else 0.0}
    why = {"severity": "scanner score %s/100" % (int(score) if score is not None else "unavailable"),
           "cross_source_correlation": "most distinct evidence origin class(es) raising signals/suspicious records about ONE shared indicator: %d (scores only at 2+; %d indicator(s) with signals; %d confirmed, %d suspicious stored record(s) seen)" % (corr_n, len(by_ind), conf_n, susp_n),
           "campaign": "%d campaign match(es) on the scan result" % camp_n,
           "evidence_gaps": "%d failed/skipped/uncertain item(s)%s (gaps raise priority; they are not proof of safety)" % (bad, "; no evidence collected" if not evs else ""),
           "impact": "%d suspicious finding(s) mention payment/credential/attachment cues (keyword heuristic)" % cues,
           "urgency": "confirmed stored evidence" if conf_n else "authentication anomaly" if auth_sig else "no urgency trigger"}
    parts = [{"factor": k, "weight": WEIGHTS[k], "points": round(WEIGHTS[k] * comp[k], 1), "basis": why[k]} for k in WEIGHTS]
    total = round(sum(p["points"] for p in parts))
    band = next(b for lo, b in _BANDS if total >= lo)
    floored = False
    if (inv.get("status") != "complete" or not evs) and total < 25:
        total, band, floored = max(total, 25), "P3 Standard", True      # incomplete evidence never ranks as low priority
    return {"score": total, "band": band, "components": parts, "floored_for_incomplete_evidence": floored,
            "note": "Priority orders analyst work only. It is separate from the scanner verdict and from evidence confidence."}


def _recommendations(inv, evs):
    evs = _latest(evs)                        # latest result per (tool, indicator) check; superseded attempts never drive recommendations
    out, seen = [], set()

    def add(cat, rank, key, title, reason, ids, source, conf, value, lim, approval=False):
        rid = _rid(cat, key)
        if rid in seen or len(out) >= MAX_RECS:
            return
        seen.add(rid)
        out.append({"id": rid, "category": cat, "rank": rank, "title": _c(title, 120), "reason": _c(reason, 300), "evidence_ids": ids[:8],
                    "source": _c(source, 120), "confidence": conf, "expected_value": value,
                    "limitations": _c(lim, 300) or "None recorded.", "requires_approval": approval})

    for tier, rank, title, conf, value in (("confirmed", 0, "Review confirmed stored evidence before releasing or acting on this message", "Confirmed (stored evidence)", "High"),
                                           ("suspicious", 1, "Review suspicious stored records", "Probable (indicator, not proof)", "Medium")):
        grp = [(e, r) for e, r in _records(evs) if r.get("tier") == tier]
        if grp:
            ids = list(dict.fromkeys(e["id"] for e, _ in grp))
            add(tier, rank, tier, title, "%d %s record(s) were found in local threat memory/history." % (len(grp), tier), ids,
                "; ".join(dict.fromkeys(_c(e.get("source"), 40) for e, _ in grp)), conf, value,
                "Stored records reflect earlier local observations only; review each record's reason field.")
    for e in evs:
        if e.get("signals") and e.get("status") in ("ok", "partial") and not any(r.get("tier") in ("confirmed", "suspicious") for r in (e.get("records") or [])):
            add("signal", 2, e["id"], "Review signals from %s%s" % (_c(e.get("tool"), 40), (" (%s)" % _ind(e)) if _ind(e) else ""),
                "%d heuristic signal(s) were raised by this check." % len(e["signals"]), [e["id"]], _c(e.get("source"), 60),
                "Probable (heuristic, not proof)", "Medium", "Heuristic signals can be false positives; verify against the message context.")
    for e in _latest(evs):
        if e.get("status") != "ok":
            miss = "; ".join(_c(m, 120) for m in (e.get("missing") or [])[:2]) or "No detail recorded."
            add("gap", 3, "%s|%s" % (e.get("tool"), _ident(e) or e["id"]), "Resolve incomplete check: %s%s" % (_c(e.get("tool"), 40), (" (%s)" % _ind(e)) if _ind(e) else ""),
                "This check ended '%s'; its conclusions are unavailable." % _c(e.get("status"), 20), [e["id"]], _c(e.get("source"), 60),
                "Unresolved (gap)", "Medium", miss)
    ran_dns = any(e.get("tool") == "lookup_domain_dns_rdap" for e in evs)
    doms = [e["id"] for e in evs if e.get("tool") in ("lookup_threat_memory", "retro_hunt_indicator") and "." in _ind(e) and "@" not in _ind(e)]
    if evs and doms and not ran_dns and not inv.get("network_allowed"):
        add("optional", 4, "dns", "Consider a public DNS/RDAP lookup for the indicator domain(s)",
            "No DNS/RDAP evidence exists because external lookups were not permitted for this run.", doms, "Not yet collected", "Unknown (not collected)",
            "Medium", "Makes an external network call; requires analyst approval and a new bounded run. Domain age/registration alone does not prove intent.", True)
    if inv.get("stop_reason") in ("iteration_limit", "tool_call_limit", "time_limit", "provider_failed", "internal_error"):
        add("gap", 3, "stop", "Continue the investigation manually", "The run stopped early (%s)." % _c(inv.get("stop_reason"), 30), [],
            "Investigation run status", "Unresolved (gap)", "Medium", "No supporting evidence ID: derived from the run's stop reason, not from a tool result.")
    if not evs:
        add("gap", 3, "none", "Run the investigation before drawing conclusions", "No investigation evidence is available for this scan.", [],
            "Investigation run status", "None", "High", "No supporting evidence exists; nothing can be concluded from this panel.")
    out.sort(key=lambda r: (r["rank"], r["id"]))
    return out


def _questions(inv, cls, recs, live=None):
    qs = []
    for f in inv.get("findings") or []:
        if isinstance(f, dict) and f.get("kind") == "uncertain" and (live is None or not f.get("evidence_ids") or any(x in live for x in f["evidence_ids"])):
            qs.append({"question": _c(f.get("statement"), 240), "evidence_ids": [_c(x, 12) for x in (f.get("evidence_ids") or [])][:4], "type": "evidence gap"})
    for i, h in enumerate(cls["hypotheses"], 1):
        qs.append({"question": "Verify unverified model hypothesis #%d (listed once, as unverified)" % i, "evidence_ids": h["evidence_ids"][:4], "type": "unverified hypothesis"})
    uniq, seen = [], set()
    for q in qs:
        if q["question"] not in seen:
            seen.add(q["question"]); uniq.append(q)
    return uniq[:MAX_QUESTIONS]


def build_operator_intel(inv, result=None, now=None):
    """Pure and deterministic for identical inputs (only generated_utc depends on the clock). Never raises."""
    try:
        if not isinstance(inv, dict):
            raise ValueError("no investigation")
        evs = _evs(inv)
        cls = _classify(inv, evs)
        recs = _recommendations(inv, evs)
        latest = _latest(evs)
        live = {e["id"] for e in latest}
        raw_sid = inv.get("scan_id")
        sid = raw_sid if isinstance(raw_sid, str) and ia.SCAN_ID_RE.fullmatch(raw_sid) else ""     # 'SC-' + 32 lowercase hex, else unbound
        done_checks = [{"n": s.get("n"), "tool": _c(s.get("tool"), 40), "status": _c(s.get("status"), 20), "evidence_id": _c(s.get("evidence_id"), 12)}
                       for s in (inv.get("steps") or []) if isinstance(s, dict)][:30]
        return {"available": True, "scan_id": sid, "bound": bool(sid), "investigation_status": _c(inv.get("status"), 20),
                "generated_utc": now or time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "scanner_snapshot": {"score": (inv.get("score_snapshot") or {}).get("score"), "level": _c((inv.get("score_snapshot") or {}).get("level"), 30),
                                     "note": "Scanner verdict, unchanged by Operator Intelligence."},
                "priority": _priority(inv, result, latest, cls), "confidence": _confidence(inv, latest), "findings": cls, "recommendations": recs,
                "unresolved_questions": _questions(inv, cls, recs, live), "completed_checks": done_checks, "limitations": list(LIMITATIONS)}
    except Exception as exc:                                # fail-soft: never break the panel or the report
        return {"available": False, "error": _c(type(exc).__name__, 40), "limitations": list(LIMITATIONS)}


# ---- analyst decisions: per scan, session-scoped, bounded ------------------------------------------------------------
def new_state(scan_id):
    return {"scan_id": _c(scan_id, 80), "created_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), "decisions": {}}


def record_decision(state, intel, rec_id, status, note="", now=None):
    """Raises ValueError for another scan's state, an unknown recommendation, a bad status or too many decisions."""
    if not isinstance(state, dict) or not intel.get("available") or not intel.get("bound") or not state.get("scan_id") or state.get("scan_id") != intel.get("scan_id"):
        raise ValueError("decision tracking requires a scan-bound investigation with a matching scan ID")
    if status not in STATUSES or rec_id not in {r["id"] for r in intel["recommendations"]}:
        raise ValueError("unknown recommendation or status")
    if rec_id not in state["decisions"] and len(state["decisions"]) >= MAX_DECISIONS:
        raise ValueError("decision limit reached")
    state["decisions"][rec_id] = {"status": status, "note": _c(note, 200), "utc": now or time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
    return state


def action_status(state, intel, rec_id):
    if isinstance(state, dict) and intel.get("available") and intel.get("bound") and state.get("scan_id") and state.get("scan_id") == intel.get("scan_id"):
        return (state.get("decisions") or {}).get(rec_id, {"status": "pending", "note": "", "utc": ""})
    return {"status": "pending", "note": "", "utc": ""}


# ---- report section (appended to the existing forensic report) -------------------------------------------------------
def _m(v):
    return _c(v, 300).replace("|", "\\|")


def render_section(intel, state=None, hypotheses_listed_elsewhere=False):
    if not isinstance(intel, dict) or not intel.get("available"):
        return ["", "## Operator Intelligence", "", "> Operator Intelligence was unavailable for this report; the sections above are unaffected."]
    p, cf = intel["priority"], intel["confidence"]
    L = ["", "## Operator Intelligence (operator-generated; read-only)", "",
         "_Analyst assistance derived from the investigation evidence above. It does not change the scanner score or verdict. "
         "Operator-generated hypotheses are not findings._", "",
         "| Field | Value |", "| --- | --- |",
         "| Investigation priority | **%s** (%s / 100) - ordering aid, not a verdict |" % (_m(p["band"]), p["score"]),
         "| Evidence confidence | %s (%s) |" % (_m(cf["level"]), _m(cf["note"])),
         "| Scan ID | %s |" % _m(intel.get("scan_id") or "not recorded"),
         "| Generated | %s |" % _m(intel["generated_utc"]), "",
         "### Priority breakdown", "", "| Factor | Weight | Points | Basis |", "| --- | --- | --- | --- |"]
    L += ["| %s | %s | %s | %s |" % (c["factor"], c["weight"], c["points"], _m(c["basis"])) for c in p["components"]]
    if p["floored_for_incomplete_evidence"]:
        L.append("\n_Priority was raised to the minimum because evidence is incomplete; this is not an all-clear._")
    for key, title in FINDING_TITLES:
        L += ["", "### " + title, ""]
        if key == "hypotheses" and hypotheses_listed_elsewhere and intel["findings"][key]:
            L.append("- %d model-proposed hypothesis(es) are listed once, as unverified, under 'AI-proposed findings' below; they are not repeated here." % len(intel["findings"][key]))
            continue
        L += ["- %s `[%s]`%s" % (_m(f["statement"]), ",".join(f["evidence_ids"]) or "no evidence ID", (" (%s)" % _m(f["origin_label"])) if "origin_label" in f else "")
              for f in intel["findings"][key]] or ["- None recorded."]
    L += ["", "### Recommended next actions", "", "| ID | Action | Why | Evidence | Source | Confidence | Value | Limitations | Approval | Status |",
          "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in intel["recommendations"]:
        L.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["id"], _m(r["title"]), _m(r["reason"]), ",".join(r["evidence_ids"]) or "none available", _m(r["source"]), _m(r["confidence"]),
            r["expected_value"], _m(r["limitations"]), "analyst approval required" if r["requires_approval"] else "read-only",
            action_status(state, intel, r["id"])["status"] if intel.get("bound") else "Not trackable (unbound)"))
    if not intel["recommendations"]:
        L.append("| - | None | - | - | - | - | - | - | - | - |")
    dec = [(r["title"], action_status(state, intel, r["id"])) for r in intel["recommendations"]]
    dec = [(t, d) for t, d in dec if d["status"] != "pending"]
    if dec:
        L += ["", "### Analyst decisions (this scan, recorded this session)", ""] + ["- %s: **%s** (%s)" % (_m(t), d["status"], _m(d["utc"])) for t, d in dec]
    L += ["", "### Unresolved questions", ""]
    L += ["- %s (%s) `[%s]`" % (_m(q["question"]), q["type"], ",".join(q["evidence_ids"]) or "no evidence ID") for q in intel["unresolved_questions"]] or ["- None recorded."]
    L += ["", "### Investigation limitations", ""] + ["- " + x for x in intel["limitations"]]
    return L


# ---- Streamlit panel (fail-soft; called from investigation_panel inside try/except) -----------------------------------
def render_streamlit(inv, result, key):
    import streamlit as st
    intel = build_operator_intel(inv, result)
    if not intel["available"]:
        st.caption("Operator Intelligence is unavailable for this investigation; the results in the other tabs are unaffected.")
        return intel
    store = st.session_state.setdefault("operator_intel_state", {})
    key = str(key)
    state = None
    if intel["bound"]:                                              # unbound investigations never create or persist decision state
        state = store.get(key)
        if not isinstance(state, dict) or state.get("scan_id") != intel["scan_id"]:
            state = store[key] = new_state(intel["scan_id"])       # a different scan never inherits decisions
    else:
        st.info("Decision tracking requires a scan-bound investigation. This investigation has no scan ID, so analyst decisions cannot be recorded.")
    p, cf = intel["priority"], intel["confidence"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Investigation priority", p["band"], "%d / 100" % p["score"], delta_color="off")
    c2.metric("Evidence confidence", cf["level"], "%d%% coverage" % round(cf["coverage"] * 100), delta_color="off")
    c3.metric("Investigation status", intel["investigation_status"] or "unknown")
    st.caption("Priority orders analyst work only. It is separate from the scanner verdict (%s, %s/100, unchanged) and from evidence confidence."
               % (intel["scanner_snapshot"]["level"] or "n/a", intel["scanner_snapshot"]["score"]))
    with st.expander("Priority breakdown (transparent weights)"):
        for c in p["components"]:
            st.markdown("**%s** - %s/%s pts: %s" % (c["factor"].replace("_", " "), c["points"], c["weight"], ia.clean(c["basis"], 200)))
    st.markdown("##### Facts vs hypotheses")
    for k, label in (("confirmed", ":green[Confirmed (tool-observed)]"), ("claims", ":orange[Unverified claims (not independently confirmed)]"),
                     ("historical", ":gray[Historical observations (not proof)]"), ("inferred", ":gray[Inferences (derived/approximate)]"),
                     ("probable", ":orange[Probable (signals, not proof)]"), ("hypotheses", ":gray[Hypothesis (unverified, not a finding)]")):
        items = intel["findings"][k]
        st.markdown("%s - %d" % (label, len(items)))
        for f in items[:8]:
            st.markdown("- %s `[%s]`%s" % (ia.clean(f["statement"], 240), ",".join(f["evidence_ids"]) or "no evidence ID",
                                           (" _(%s)_" % ia.clean(f["origin_label"], 120)) if f.get("origin_label") else ""))
    st.markdown("##### Recommended next actions")
    for r in intel["recommendations"]:
        cur = action_status(state, intel, r["id"])
        with st.container(border=True):
            st.markdown("**%s**" % ia.clean(r["title"], 140))
            st.caption("Why: %s | Evidence: %s | Source: %s | Confidence: %s | Value: %s%s" % (
                r["reason"], ",".join(r["evidence_ids"]) or "none available", r["source"], r["confidence"], r["expected_value"],
                " | Needs analyst approval (external call)" if r["requires_approval"] else ""))
            st.caption("Limitations: " + r["limitations"])
            if intel["bound"]:
                pick = st.selectbox("Analyst decision", STATUSES, index=STATUSES.index(cur["status"]), key="opi_%s_%s_%s" % (key, intel["scan_id"], r["id"]),
                                    label_visibility="collapsed")
                if pick != cur["status"]:
                    try:
                        record_decision(state, intel, r["id"], pick)
                    except ValueError as exc:
                        st.caption("Decision not saved: %s" % exc)
    if not intel["recommendations"]:
        st.caption("No recommendations: nothing in this investigation supports one.")
    _now = [action_status(state, intel, r["id"])["status"] for r in intel["recommendations"]]   # recomputed AFTER any decision recorded above
    pend, done = _now.count("pending"), len(_now) - _now.count("pending")
    if intel["bound"]:
        st.caption("Actions: %d pending, %d resolved by analyst. Decisions are kept for this session and this scan only; nothing is executed automatically." % (pend, done))
    else:
        st.caption("Actions: %d listed; none can be tracked without a scan-bound investigation. Nothing is executed automatically." % len(_now))
    if intel["unresolved_questions"]:
        st.markdown("##### Unresolved questions")
        for q in intel["unresolved_questions"]:
            st.markdown("- %s _(%s)_" % (ia.clean(q["question"], 240), q["type"]))
    with st.expander("Limitations"):
        for x in intel["limitations"]:
            st.markdown("- " + x)
    return intel
