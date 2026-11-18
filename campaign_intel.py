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


def _tags(fp, family):
    """Sorted plain-string tags of one family, or None when the family is missing/malformed/empty."""
    fam = fp.get("families") if isinstance(fp, dict) else None
    raw = fam.get(family) if isinstance(fam, dict) else None
    if not isinstance(raw, list):
        return None
    out = sorted({t[:80] for t in raw if isinstance(t, str) and t})
    return out or None


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
            "phase2_score": m.get("score"),                          # Phase 2, unchanged (no new formula)
            "phase2_confidence": m.get("confidence"),                # Phase 2, unchanged
            "observation_ref": sid,
            "observed_at": _ts(m.get("created_at")) or (_ts(row.get("created_at")) if row else None),
            "supporting_families": sorted(f for f in fams if isinstance(f, str) and f not in _CONTEXT_FAMILIES),
            "context_only_families": sorted(f for f in fams if isinstance(f, str) and f in _CONTEXT_FAMILIES),
            "qualifying_families": sorted(f for f in qual if isinstance(f, str)),
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
