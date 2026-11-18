"""campaign_intel.py -- Phase 3: Campaign Intelligence (pure).

Turns data Attack DNA (attack_dna.py) ALREADY computed -- this scan's fingerprint, its top matches and
the bounded history rows read by that same call -- into an analyst-facing summary: related retained
observations, per-relationship supporting feature families, tactic changes and category-level
infrastructure comparison.

Rules (enforced below, covered by test_campaign_intel.py):
  * PURE: no database, network, UI or mutation of inputs; deterministic for the same input.
  * No second similarity score or confidence formula: classification / score / confidence are Phase 2's
    compare_fingerprints() values passed through unchanged. Nothing here upgrades a relationship.
  * infra_class / structural families are "context only": reported, never counted as independent support.
  * Infrastructure comparison covers ONLY explicit class tags and ISO country tags. Missing on either side
    => "unavailable", never "changed". No IP/domain/ASN/hosting data exists here and none is inferred.
  * The timeline is DISTINCT RETAINED OBSERVATIONS ordered by storage time (created_at). It is not every
    scan, not email send times, not attack events: identical bytes share one scan_id and are stored once,
    and old rows are pruned/skipped by schema version.
  * Output holds only validated scan ids, storage timestamps and categorical tags -- never addresses,
    domains, IPs, subjects or body text. A similarity is never presented as the same attacker.
Nothing here is read by risk.py.
"""
from __future__ import annotations

import re

import attack_dna

SCHEMA_VERSION = 1
MAX_RELATIONSHIPS = attack_dna.MAX_RETURNED_MATCHES      # bounded by Phase 2's own top-N
MAX_TAGS = 10

_SCAN_ID_RE = re.compile(r"^SC-[0-9a-f]{32}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
_COUNTRY_RE = re.compile(r"^country:([A-Z]{2})$")
_CONTEXT_FAMILIES = frozenset({"infra_class", "structural"})
_TACTIC_FAMILIES = ("auth_anomalies", "url_tactics", "domain_alignment")
_CLASSIFICATIONS = ("strong", "weak")

TIMELINE_BASIS = ("Distinct retained observations ordered by storage time. Not every scan, not email send "
                  "dates and not confirmed attack events: identical emails share one record and older "
                  "records may have been pruned.")
LIMITATIONS = (
    "Similarity indicates shared tactics, not confirmed common authorship.",
    "Only the top Phase 2 matches are shown; other retained observations may exist.",
    "Infrastructure comparison is limited to coarse class and country tags; IP, domain and hosting changes are not observable.",
)
RELATIONSHIP_LIMITATIONS = {
    "strong": "Strong structural similarity from at least two independent specific feature families; still not attribution.",
    "weak": "Weak similarity: some specific overlap but not enough to suggest a shared campaign on its own.",
}


def _sid(v):
    return v if isinstance(v, str) and _SCAN_ID_RE.match(v) else None


def _ts(v):
    return v if isinstance(v, str) and _TS_RE.match(v) else None


# Stored JSON is not trusted: a tag is exposed only if it fits its family's known vocabulary / shape.
_URL_TAGS = frozenset(t for _p, t in attack_dna._URL_FLAG_TAGS)
_ALIGN_TAGS = frozenset({"freemail_sender", "reply_subdomain", "reply_org_mismatch",
                         "return_subdomain", "return_org_mismatch"})
_AUTH_RE = re.compile(r"^(high|medium|low|info):[A-Za-z0-9 .,()_\-]{1,60}$")   # "severity:Title"; known severities only; no @ / : //
_IPISH_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_STRUCT_RE = re.compile(r"^(len|urls|attach|html):[a-z]{2,8}$")


def _valid_tag(family, tag):
    if not isinstance(tag, str):
        return False
    if family == "url_tactics":
        return tag in _URL_TAGS
    if family == "domain_alignment":
        return tag in _ALIGN_TAGS
    if family == "auth_anomalies":
        return bool(_AUTH_RE.match(tag)) and not _IPISH_RE.search(tag)
    if family == "structural":
        return bool(_STRUCT_RE.match(tag))
    if family == "infra_class":
        return tag in attack_dna._VALID_INFRA_CLASSES or (
            bool(_COUNTRY_RE.match(tag)) and tag[8:] in attack_dna._ISO_3166_1_ALPHA2)
    return False


def _tags(fp, family):
    """Sorted VALIDATED tags of one family, or None when the family is missing/malformed/has no valid tag."""
    fam = fp.get("families") if isinstance(fp, dict) else None
    raw = fam.get(family) if isinstance(fam, dict) else None
    if not isinstance(raw, list):
        return None
    out = sorted({t for t in raw if _valid_tag(family, t)})
    return out or None


def _unit(v):
    """A finite number in [0, 1] (Phase 2 score/confidence range) or None."""
    return round(float(v), 4) if isinstance(v, (int, float)) and not isinstance(v, bool) and 0.0 <= v <= 1.0 else None


def _families(v):
    return sorted(f for f in v if isinstance(f, str) and f in attack_dna.FAMILY_WEIGHTS)


def tactic_summary(rel):
    """One-line analyst text for a relationship's tactic_changes: shows added (+) / removed (-) tags only for families
    where BOTH observations had data; otherwise says the data was insufficient. Used by the UI and the report."""
    tc = rel.get("tactic_changes") if isinstance(rel, dict) else None
    if not isinstance(tc, dict):
        return "insufficient data"
    parts, states = [], []
    for fam in _TACTIC_FAMILIES:
        e = tc.get(fam) if isinstance(tc.get(fam), dict) else {}
        states.append(e.get("status"))
        if e.get("status") == "changed":
            add = " ".join("+" + t for t in e.get("added") or [])
            rem = " ".join("-" + t for t in e.get("removed") or [])
            parts.append("%s: %s" % (fam, " ".join(x for x in (add, rem) if x)))
    if parts:
        return "; ".join(parts) + ("" if "unavailable" not in states else " (other families: insufficient data)")
    return "no change" if "unchanged" in states and "unavailable" not in states else (
        "no change in comparable families (others: insufficient data)" if "unchanged" in states else "insufficient data")


def _infra_parts(fp):
    tags = _tags(fp, "infra_class")
    if tags is None:
        return None, None
    classes = [t for t in tags if t in attack_dna._VALID_INFRA_CLASSES]
    countries = []
    for t in tags:
        m = _COUNTRY_RE.match(t)
        if m and m.group(1) in attack_dna._ISO_3166_1_ALPHA2:
            countries.append(m.group(1))
    return classes or None, countries or None


def _cmp_category(a, b):
    if a is None or b is None:
        return {"status": "unavailable"}
    if a == b:
        return {"status": "unchanged", "values": a}
    return {"status": "changed", "earlier": b, "current": a}


def compare_infrastructure(current_fp, other_fp):
    """Category-level comparison of explicit infra class / country tags (current vs an earlier
    observation). Each category is judged independently and only when BOTH sides carry explicit data;
    otherwise "unavailable" -- never a confirmed change."""
    ca, ka = _infra_parts(current_fp)
    cb, kb = _infra_parts(other_fp)
    return {"infra_class": _cmp_category(ca, cb), "country": _cmp_category(ka, kb)}


def tactic_changes(current_fp, other_fp):
    """Tags added/removed per tactic family, only where both sides have data for that family."""
    out = {}
    for fam in _TACTIC_FAMILIES:
        a, b = _tags(current_fp, fam), _tags(other_fp, fam)
        if a is None or b is None:
            out[fam] = {"status": "unavailable"}
            continue
        sa, sb = set(a), set(b)
        out[fam] = {"status": "unchanged" if sa == sb else "changed",
                    "added": sorted(sa - sb)[:MAX_TAGS], "removed": sorted(sb - sa)[:MAX_TAGS]}
    return out


def build_campaign_intel(features, match_report, history_rows):
    """Assemble the precomputed intelligence dict. `features` / `match_report` are attack_dna.find_matches()
    outputs; `history_rows` is the (already bounded) list that same call read. Never raises."""
    try:
        return _build(features, match_report, history_rows)
    except Exception:
        return _empty("error")


def _empty(status, history_checked=0):
    return {"schema": SCHEMA_VERSION, "status": status, "timeline_basis": TIMELINE_BASIS,
            "history_checked": history_checked, "observations": [], "relationships": [],
            "skipped_malformed": 0, "limitations": list(LIMITATIONS)}


def _build(features, match_report, history_rows):
    if not isinstance(features, dict) or not isinstance(match_report, dict):
        return _empty("unavailable")
    status = match_report.get("status")
    checked = match_report.get("history_checked")
    checked = checked if isinstance(checked, int) and not isinstance(checked, bool) and checked >= 0 else 0
    if status != "ok":
        return _empty("unavailable", checked)
    if checked == 0:
        return _empty("no_history")

    by_id = {}
    for row in history_rows if isinstance(history_rows, list) else []:
        if isinstance(row, dict) and _sid(row.get("scan_id")) and isinstance(row.get("features"), dict):
            by_id.setdefault(row["scan_id"], row)

    rels, skipped, seen = [], 0, set()
    matches = match_report.get("matches")
    for m in matches if isinstance(matches, list) else []:
        sid = _sid(m.get("scan_id")) if isinstance(m, dict) else None
        cls = m.get("classification") if isinstance(m, dict) else None
        if not sid or cls not in _CLASSIFICATIONS or sid in seen:
            skipped += 1
            continue
        seen.add(sid)
        fams = m.get("matched_families") if isinstance(m.get("matched_families"), dict) else {}
        qual = m.get("qualifying_families") if isinstance(m.get("qualifying_families"), list) else []
        row = by_id.get(sid)
        rel = {
            "relationship_type": "%s_structural_similarity" % cls,
            "classification": cls,                                   # Phase 2, unchanged
            "phase2_score": _unit(m.get("score")),                   # Phase 2 value, range-validated (no new formula)
            "phase2_confidence": _unit(m.get("confidence")),         # Phase 2 value, range-validated
            "observation_ref": sid,
            "observed_at": _ts(m.get("created_at")) or (_ts(row.get("created_at")) if row else None),
            "supporting_families": [f for f in _families(fams) if f not in _CONTEXT_FAMILIES],
            "context_only_families": [f for f in _families(fams) if f in _CONTEXT_FAMILIES],
            "qualifying_families": _families(qual),
            "limitations": [RELATIONSHIP_LIMITATIONS[cls]],
        }
        if row:
            rel["infrastructure"] = compare_infrastructure(features, row["features"])
            rel["tactic_changes"] = tactic_changes(features, row["features"])
        else:
            rel["infrastructure"] = {"infra_class": {"status": "unavailable"}, "country": {"status": "unavailable"}}
            rel["tactic_changes"] = {f: {"status": "unavailable"} for f in _TACTIC_FAMILIES}
            rel["limitations"].append("The matched observation's record was not available for comparison.")
        rels.append(rel)
    rels.sort(key=lambda r: (r["observed_at"] or "9999", r["observation_ref"]))   # chronological, deterministic
    rels = rels[:MAX_RELATIONSHIPS]

    observations = [{"scan_id": r["observation_ref"], "observed_at": r["observed_at"], "role": "related",
                     "classification": r["classification"]} for r in rels]
    return {"schema": SCHEMA_VERSION, "status": "ok" if rels else "no_related_observations",
            "timeline_basis": TIMELINE_BASIS, "history_checked": checked, "observations": observations,
            "relationships": rels, "skipped_malformed": skipped, "limitations": list(LIMITATIONS)}
