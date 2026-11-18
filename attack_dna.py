"""attack_dna.py -- Phase 2: Attack DNA / Campaign Fingerprinting.

Recognises potentially related campaigns even when an attacker rotates domains, IPs, or hosting,
by comparing the *structural/tactical shape* of an email (which auth checks it fails, which URL
tricks it uses, how its sender/reply-to/return-path disagree, coarse infra class, coarse size
buckets) rather than its literal indicators.

Deliberately separate from, and never a replacement for:
  - correlate.py:   links cases that share an IDENTICAL indicator (same domain/IP/wallet).
  - retro_hunt.py:  exact indicator lookups against stored threat memory.
  - nomic_embed.py: AI semantic similarity of *origin/routing* text via a local/cloud embedding
                     model (network/paid-service dependent -- explicitly NOT used here).
Attack DNA answers a different question: "does this email's tactics resemble a prior one", using
only pure, offline, deterministic comparisons of already-extracted signals.

Design rules (all enforced below, not just documented):
  * extract_features() and compare_fingerprints() are PURE: no I/O, no database access, no
    mutation of their input, deterministic for the same input.
  * Only categorical tags and size buckets are stored/compared -- never raw domains, addresses,
    IPs, subjects, or body text. (The one exception, `country`, is the same coarse field already
    surfaced throughout the app's existing geolocation evidence, e.g. origin_intel.py -- it is
    not email content.)
  * Shared hosting/ASN/infra-class or a single generic auth anomaly can NEVER alone produce a
    "strong" classification -- see SPECIFIC_FAMILIES / compare_fingerprints().
  * Missing information (no SPF/DKIM/DMARC result, no Received chain, unresolved geolocation) is
    never itself campaign-signature evidence: generic "absent"/"unverified"/"unknown" placeholders
    are excluded from every feature family rather than compared -- see
    _GENERIC_AUTH_ABSENCE_TITLES. Missing evidence stays missing; it is never transformed into a
    matching feature. infra/country are additionally restricted to strict allow-lists
    (_VALID_INFRA_CLASSES / _ISO_3166_1_ALPHA2) so no raw IP, hostname, email address or other
    arbitrary string can ever end up stored as an infra_class tag.
  * infra_class and structural overlap can add weight but can never, by themselves, produce even a
    "weak" classification -- a weak match requires at least one meaningful (non-generic) overlap in
    a specific feature family; see _is_specific_overlap() / compare_fingerprints().
  * A missing or malformed feature family lowers `confidence`; it is never treated as a match.
  * Persistence fails soft everywhere: a database problem degrades to "no history available",
    never an exception that could break a scan.
  * Never changes a threat score or verdict. Nothing here is read by risk.py.
"""
from __future__ import annotations

import datetime
import json

import config as C
import header_analysis
import tracker

# Bumped because extraction semantics changed (generic missing-auth-info / unknown-infra
# placeholders are now excluded rather than compared). Older stored fingerprints are not deleted or
# rewritten -- query_recent_fingerprints() already skips any row whose schema_version doesn't match
# the current one, so they simply stop being used for comparison. New fingerprints are stored and
# compared normally under the new version.
CURRENT_SCHEMA_VERSION = 2

# Bounded historical query: a single lookup never scans more than this many stored fingerprints.
MAX_HISTORY = 200
# Of those, only the best few are surfaced as evidence/findings.
MAX_RETURNED_MATCHES = 5
# Conservative cap on total stored fingerprint rows: the oldest excess rows are pruned on save, so
# the table can't grow without bound. Nothing else in threat_memory.db is ever touched by this.
MAX_STORED_FINGERPRINTS = 5000

# Each family's contribution to the weighted similarity score. Deliberately sums to 1.0 so `score`
# stays a 0..1 figure comparable to other confidence-style numbers already used in this codebase.
FAMILY_WEIGHTS = {
    "auth_anomalies": 0.30,
    "url_tactics": 0.30,
    "domain_alignment": 0.20,
    "infra_class": 0.10,
    "structural": 0.10,
}

# Families that may count toward the ">= 2 independent families" requirement for a STRONG match,
# and how much overlap within that family is needed to "qualify" (a single shared generic anomaly
# tag is common and must not count; two or more co-occurring tags is a much more specific signature).
# "infra_class" and "structural" are deliberately absent here: shared hosting/ASN/IP-prefix/size
# alone can add weight but can never by themselves satisfy the independent-families requirement.
SPECIFIC_FAMILIES = {
    "auth_anomalies": 2,
    "url_tactics": 1,
    "domain_alignment": 1,
}

# Within url_tactics/domain_alignment, tags that are, on their own, too common across vast numbers
# of unrelated senders to count as campaign-specific evidence toward a STRONG match -- the same
# concern that already makes auth_anomalies require >=2 co-occurring tags, applied per-tag instead
# of per-family so a genuinely distinctive single tag isn't penalised along with the generic ones.
#   url_tactics: "shortener" (any mass-market shortener service), "unencrypted_http" (plain http://
#     links are common even in legitimate mail) and "suspicious_tld" (cheap/low-reputation TLDs are
#     reused across huge numbers of unrelated spam/phishing senders) are commodity tactics. By
#     contrast "raw_ip_host", "punycode", "brand_lookalike", "credential_path" and "deep_subdomain"
#     are each a deliberate, specific construction choice and remain fine to qualify alone.
#   domain_alignment: every tag here (a reply/return domain that is a same-org subdomain, or
#     belongs to an entirely different org, or freemail use) is an extremely common phishing/BEC
#     tell on its own; none is distinctive enough alone, so the whole family's tags are listed.
#     Two or more of them occurring together is a materially more specific coincidence and is not
#     affected by this veto -- see _qualifies_for_strong().
_GENERIC_SINGLE_TAGS = {
    "url_tactics": frozenset({"shortener", "unencrypted_http", "suspicious_tld"}),
    "domain_alignment": frozenset({
        "freemail_sender", "reply_subdomain", "reply_org_mismatch",
        "return_subdomain", "return_org_mismatch",
    }),
}

STRONG_THRESHOLD = 0.55
WEAK_THRESHOLD = 0.15

# Exact header_analysis.py anomaly titles that mean "we don't know" rather than "we observed
# something suspicious": an absent SPF/DKIM/DMARC verdict, an unverified-provenance auth result, or
# no Received chain to examine. These are excluded from auth_anomalies entirely -- missing routing
# or authentication information is not evidence of a shared campaign signature, generic or otherwise.
_GENERIC_AUTH_ABSENCE_TITLES = frozenset({
    "SPF result absent", "DKIM result absent", "DMARC result absent",
    "Authentication results unverified", "No Received chain",
})

# infra_class is a strict allow-list, not a placeholder-exclusion list: these are the only infra
# categories geolocate.py's INFRA_RISK ever actually assigns (besides "unknown", which is excluded
# by simply not being in this set). Anything else -- a raw IP, a hostname, an email address, a typo,
# an unrecognised future category -- is rejected rather than stored, closing off any path by which
# an unvalidated string could end up in a stored fingerprint.
_VALID_INFRA_CLASSES = frozenset({"tor", "vpn", "proxy", "hosting", "residential", "corporate"})

# The full set of assigned ISO 3166-1 alpha-2 country codes. No external dependency: this is a fixed,
# self-contained list. Anything not an exact two-letter match here (an email address, a domain, an IP,
# a full country name, "Unknown", empty) is rejected rather than stored.
_ISO_3166_1_ALPHA2 = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DO DZ
EC EE EG EH ER ES ET
FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
HK HM HN HR HT HU
ID IE IL IM IN IO IQ IR IS IT
JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ
LA LB LC LI LK LR LS LT LU LV LY
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ
OM
PA PE PF PG PH PK PL PM PN PR PS PT PW PY
QA
RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
UA UG UM US UY UZ
VA VC VE VG VI VN VU
WF WS
YE YT
ZA ZM ZW
""".split())

# Prefixes of header_analysis.py's anomaly titles / ioc_extract.py's URL flag strings, mapped to a
# small set of stable category tags. Matching by prefix (not storing the flag text verbatim) keeps
# variable, potentially-identifying substrings (a specific brand name, a specific TLD) out of the
# stored fingerprint.
_URL_FLAG_TAGS = (
    ("URL shortener", "shortener"),
    ("Link points at a raw IP", "raw_ip_host"),
    ("Punycode host", "punycode"),
    ("Brand look-alike", "brand_lookalike"),
    ("Low-reputation", "suspicious_tld"),
    ("Path suggests a credential-entry page", "credential_path"),
    ("Deeply nested subdomains", "deep_subdomain"),
    ("Unencrypted HTTP link", "unencrypted_http"),
)


def _url_tag(flag_text):
    text = str(flag_text or "")
    for prefix, tag in _URL_FLAG_TAGS:
        if text.startswith(prefix):
            return tag
    return None


def _as_list(x):
    """Coerce a field that is supposed to be a list into one. Anything else (a scalar, a dict, a
    string, None) becomes an empty list rather than being iterated or sized -- a non-list value here
    is malformed input, not zero items, but treating it as "nothing to extract" is the only choice
    that can never raise."""
    return x if isinstance(x, list) else []


def _safe_tags(x):
    """Coerce a stored/extracted feature-family value into a set of comparable string tags. Only
    plain strings are kept: a dict, a nested list, a number, a bool or None inside the list is
    dropped rather than hashed, stringified or otherwise turned into something that could
    accidentally overlap with a genuine tag. Not a list at all -> empty set, never an exception."""
    if not isinstance(x, list):
        return set()
    return {t for t in x if isinstance(t, str)}


def _bucket(n, edges, labels):
    try:
        n = int(n)
    except (TypeError, ValueError):
        n = 0
    for edge, label in zip(edges, labels):
        if n <= edge:
            return label
    return labels[-1]


# --------------------------------------------------------------------------
# Pure feature extraction -- no I/O, no DB, does not mutate `result`.
# --------------------------------------------------------------------------
def extract_features(result):
    """Minimized, privacy-safe, JSON-serialisable feature dict built only from fields already
    computed elsewhere in the pipeline (parsed/headers/iocs/geo). Never reads the database. Never
    mutates `result`. Malformed/missing input degrades to an all-empty feature set rather than
    raising -- callers see "nothing extracted", never a crash.
    """
    result = result if isinstance(result, dict) else {}
    parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {}
    headers = result.get("headers") if isinstance(result.get("headers"), dict) else {}
    iocs = result.get("iocs") if isinstance(result.get("iocs"), dict) else {}
    geo = result.get("geo") if isinstance(result.get("geo"), dict) else {}

    auth_anomalies = sorted({
        "%s:%s" % (str(a.get("severity") or "")[:12], str(a.get("title") or "")[:60])
        for a in _as_list(headers.get("anomalies"))
        if isinstance(a, dict) and a.get("title") and a.get("title") not in _GENERIC_AUTH_ABSENCE_TITLES
    })

    url_tactics = sorted({
        tag
        for u in _as_list(iocs.get("urls")) if isinstance(u, dict)
        for tag in (_url_tag(f) for f in _as_list(u.get("flags")))
        if tag
    })

    from_domain = str(parsed.get("from_domain") or "").strip().lower()
    reply_domain = str(parsed.get("reply_to_domain") or "").strip().lower()
    return_domain = str(parsed.get("return_path_domain") or "").strip().lower()
    domain_alignment = set()
    try:
        if reply_domain and from_domain and reply_domain != from_domain:
            domain_alignment.add("reply_subdomain" if header_analysis.same_org(from_domain, reply_domain) else "reply_org_mismatch")
        if return_domain and from_domain and return_domain != from_domain:
            domain_alignment.add("return_subdomain" if header_analysis.same_org(from_domain, return_domain) else "return_org_mismatch")
    except Exception:
        pass    # same_org() is pure/stdlib and shouldn't raise, but a malformed domain must never break fingerprinting
    if from_domain and from_domain in getattr(C, "FREEMAIL_DOMAINS", ()):
        domain_alignment.add("freemail_sender")
    domain_alignment = sorted(domain_alignment)

    origin = geo.get("origin") if isinstance(geo.get("origin"), dict) else {}
    infra = str(origin.get("infra") or "").strip().lower()
    # The ISO alpha-2 code geolocate.py already resolved (never the full country name, and never
    # inferred here from an IP -- this module only validates/normalizes a value computed elsewhere).
    country_code = str(origin.get("country_code") or "").strip().upper()
    infra_tags = set()
    if infra in _VALID_INFRA_CLASSES:                      # strict allow-list: rejects IPs, hostnames,
        infra_tags.add(infra)                               # email addresses, typos and "unknown" alike
    if len(country_code) == 2 and country_code in _ISO_3166_1_ALPHA2:
        infra_tags.add("country:" + country_code)
    infra_class = sorted(infra_tags)

    body_len = len(str(parsed.get("body_text") or ""))
    structural = sorted({
        "len:" + _bucket(body_len, (200, 1000, 4000), ("short", "medium", "long", "verylong")),
        "urls:" + _bucket(len(_as_list(iocs.get("urls"))), (0, 3), ("none", "few", "many")),
        "attach:" + _bucket(len(_as_list(parsed.get("attachments"))), (0, 1), ("none", "one", "many")),
        "html:yes" if parsed.get("html_links") else "html:no",
    })

    return {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "families": {
            "auth_anomalies": auth_anomalies,
            "url_tactics": url_tactics,
            "domain_alignment": domain_alignment,
            "infra_class": infra_class,
            "structural": structural,
        },
    }


def _lacks_specific_evidence(family, overlap_tags):
    """True when `overlap_tags`, within `family`, contains no tag that counts as specific/
    non-generic evidence on its own -- i.e. the overlap is exactly one tag, and that family has a
    known-generic set (_GENERIC_SINGLE_TAGS) containing it. Shared by both _is_specific_overlap()
    (the WEAK gate) and _qualifies_for_strong() (the STRONG gate) so a tag this module has already
    classified as generic is treated consistently at *both* levels: it would be incoherent to call
    a lone "shortener" or "reply_org_mismatch" too common to prove a shared campaign for STRONG,
    while still accepting it as "meaningful, non-generic overlap" for WEAK.

    Families with no entry in _GENERIC_SINGLE_TAGS (currently only auth_anomalies) are unaffected
    here -- a single auth_anomalies tag has always been enough to raise WEAK (see
    test_weak_similarity_from_only_one_feature_family); SPECIFIC_FAMILIES["auth_anomalies"] = 2
    separately keeps a single tag from reaching STRONG, via the count check in
    _qualifies_for_strong(), not via this function.

    Two or more co-occurring tags in the same family are never vetoed here, generic or not -- that
    combination is a materially more specific coincidence than any one tag alone."""
    if len(overlap_tags) != 1:
        return False
    generic = _GENERIC_SINGLE_TAGS.get(family)
    return bool(generic) and overlap_tags[0] in generic


def _is_specific_overlap(family, overlap_tags):
    """Whether an overlap in this family counts toward the "at least one meaningful, specific
    overlap" requirement for a WEAK match. infra_class and structural never count -- shared
    hosting/ASN/country or shared size/shape alone is supporting context, never proof of a shared
    campaign. A lone tag from a family's known-generic set (_GENERIC_SINGLE_TAGS) -- which includes
    domain_alignment's "freemail_sender" -- is too common across unrelated senders to count as
    specific evidence on its own; see _lacks_specific_evidence()."""
    if family not in SPECIFIC_FAMILIES:
        return False
    if _lacks_specific_evidence(family, overlap_tags):
        return False
    return True


def _qualifies_for_strong(family, overlap_tags):
    """Whether this family's overlap can count toward the ">= 2 independent families" requirement
    for a STRONG classification. Uses the same generic-single-tag veto as _is_specific_overlap()
    (_lacks_specific_evidence()), plus the family's own SPECIFIC_FAMILIES count requirement -- for
    auth_anomalies that count (2) is what keeps a single tag from reaching STRONG, since
    auth_anomalies has no generic set of its own. A distinctive single tag (e.g. "punycode",
    "raw_ip_host") still qualifies alone, and two or more co-occurring tags in the same family
    qualify regardless of whether each is individually generic."""
    if family not in SPECIFIC_FAMILIES:
        return False
    if len(overlap_tags) < SPECIFIC_FAMILIES[family]:
        return False
    if _lacks_specific_evidence(family, overlap_tags):
        return False
    return True


def compare_fingerprints(fp_a, fp_b):
    """PURE similarity comparison of two extract_features() outputs. Never raises; malformed input
    on either side is treated as an empty feature set (lowers confidence, is never scored as a
    match). Returns:

        {"classification": "strong" | "weak" | "none",
         "score": 0..1 weighted overlap, "confidence": 0..1 (share of families that were
         actually comparable on both sides), "matched_families": {family: [shared tags]},
         "qualifying_families": [...], "families_compared": int, "families_total": int}

    A "weak" classification requires at least one specific (non-generic) overlap -- see
    _is_specific_overlap() / _lacks_specific_evidence(). infra_class/structural overlap alone, or a
    lone tag from a family's known-generic set (_GENERIC_SINGLE_TAGS -- e.g. domain_alignment's
    "freemail_sender", url_tactics' "shortener"), can add to `score` but can never by themselves
    reach "weak" or "strong". A "strong" classification additionally requires >= 2 of those
    families to independently clear _qualifies_for_strong(), which adds a per-family tag-count
    requirement (SPECIFIC_FAMILIES) on top of the same generic-tag veto -- so generic infra_class/
    structural weight can never turn two merely-generic single-tag overlaps into a "strong"
    classification, and generic single tags can no longer turn into a "weak" one either.
    """
    fam_a = (fp_a or {}).get("families") if isinstance(fp_a, dict) else {}
    fam_b = (fp_b or {}).get("families") if isinstance(fp_b, dict) else {}
    fam_a = fam_a if isinstance(fam_a, dict) else {}
    fam_b = fam_b if isinstance(fam_b, dict) else {}

    weighted_score = 0.0
    matched = {}
    qualifying = []
    specific_overlap_present = False
    compared = 0
    for family, weight in FAMILY_WEIGHTS.items():
        raw_a, raw_b = fam_a.get(family), fam_b.get(family)
        if not isinstance(raw_a, list) or not isinstance(raw_b, list):
            continue    # missing/malformed on either side: not comparable -> lowers confidence, never a match
        # Only plain strings inside each list are ever compared: a dict, a nested list, a number, a
        # bool or None is dropped here rather than hashed or stringified, so it can never raise
        # (set() on an unhashable item) and can never accidentally register as a shared tag.
        a, b = _safe_tags(raw_a), _safe_tags(raw_b)
        if not a or not b:
            continue
        compared += 1
        overlap = sorted(a & b)
        if not overlap:
            continue
        union = a | b
        score = len(overlap) / len(union) if union else 0.0
        weighted_score += weight * score
        matched[family] = overlap
        if _is_specific_overlap(family, overlap):
            specific_overlap_present = True
        if _qualifies_for_strong(family, overlap):
            qualifying.append(family)

    families_total = len(FAMILY_WEIGHTS)
    confidence = round(compared / families_total, 4) if families_total else 0.0

    # infra_class/structural overlap (and a bare "freemail_sender"-only domain_alignment overlap)
    # can still raise weighted_score, but can never by themselves clear either bar below: a weak
    # match requires at least one genuinely specific overlap, not just generic supporting context.
    if len(qualifying) >= 2 and weighted_score >= STRONG_THRESHOLD:
        classification = "strong"
    elif specific_overlap_present and weighted_score >= WEAK_THRESHOLD:
        classification = "weak"
    else:
        classification = "none"

    return {
        "classification": classification,
        "score": round(weighted_score, 4),
        "confidence": confidence,
        "matched_families": matched,
        "qualifying_families": sorted(qualifying),
        "families_compared": compared,
        "families_total": families_total,
    }


# --------------------------------------------------------------------------
# Persistence. Every function here fails soft: a storage problem degrades the
# result, it never raises out to the caller.
#
# Privacy scope: tracker.get_connection(shared=...) was read before use here (tracker.py,
# _db_path()). shared=True ALWAYS resolves to the single pooled, cross-session threat_memory.db
# file -- that's the explicit, intentional choice nomic_embed.py makes for its own origin-embedding
# table. shared=False (this module's default) instead resolves, in SIH26106_MULTIUSER mode, to a
# throwaway per-session database keyed to the visitor's Streamlit session id -- i.e. private,
# user-scoped storage -- and only falls back to the single shared file when MULTIUSER mode is off
# (a single-operator deployment with one user in the first place). So the default here is
# private/per-user; pooling fingerprints across visitors would require explicitly passing
# shared=True, which nothing in this module's own call path does.
# --------------------------------------------------------------------------
def _ensure_table(shared=False):
    """On success, returns the open connection exactly as before -- the caller remains responsible
    for closing it. On failure (CREATE TABLE, CREATE INDEX, or the commit below raises), this
    function closes the connection itself before propagating: a rollback and a close are each
    attempted in their own best-effort try/except so a secondary failure in either can never mask
    the original exception, which is always re-raised unchanged via a bare `raise`."""
    conn = tracker.get_connection(shared=shared)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS campaign_fingerprints (
                scan_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                features_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_campaign_fingerprints_created_at ON campaign_fingerprints(created_at)")
        conn.commit()
        return conn
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        raise


def save_fingerprint(scan_id, features, shared=False):
    """Safe upsert keyed by scan_id (the same content-derived id investigation_agent.scan_id_for()
    already assigns): re-scanning the same bytes overwrites the same row rather than creating a
    duplicate. The upsert and the retention prune below run as ONE transaction -- a single commit
    covers both, and any failure in either rolls the whole thing back, so a pruning problem can
    never leave a silently-"successful" save that didn't actually happen, and a failed save can
    never leave a stray partial prune behind. The connection is always closed in `finally`, on every
    path. Returns True/False; never raises."""
    if not scan_id or not isinstance(features, dict):
        return False
    conn = None
    try:
        conn = _ensure_table(shared=shared)
        c = conn.cursor()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
            INSERT INTO campaign_fingerprints (scan_id, schema_version, features_json, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                schema_version=excluded.schema_version,
                features_json=excluded.features_json,
                created_at=excluded.created_at
        """, (scan_id, CURRENT_SCHEMA_VERSION, json.dumps(features), now))

        # Conservative storage cap, pruned in the SAME transaction as the upsert above: only this
        # table's oldest excess rows (by created_at, scan_id as a deterministic tie-break) are ever
        # removed -- never any other threat-memory table.
        c.execute("SELECT COUNT(*) FROM campaign_fingerprints")
        total = c.fetchone()[0]
        if total > MAX_STORED_FINGERPRINTS:
            excess = total - MAX_STORED_FINGERPRINTS
            c.execute("""
                DELETE FROM campaign_fingerprints WHERE scan_id IN (
                    SELECT scan_id FROM campaign_fingerprints ORDER BY created_at ASC, scan_id ASC LIMIT ?
                )
            """, (excess,))

        conn.commit()
        return True
    except Exception:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _query_recent_fingerprints(exclude_scan_id="", limit=MAX_HISTORY, shared=False):
    """Internal. Returns a list on success (possibly empty, meaning a genuinely empty history), or
    None if the history read itself failed (connection/SELECT/fetchall error). This None/[]
    distinction is what lets find_matches() tell "checked and found nothing" apart from "could not
    check" -- the public query_recent_fingerprints() wrapper below collapses None to [] so its own
    existing return contract (always a list, never raises) is unchanged."""
    try:
        limit = max(1, min(int(limit), MAX_HISTORY))
    except (TypeError, ValueError):
        limit = MAX_HISTORY
    conn = None
    try:
        conn = _ensure_table(shared=shared)
        c = conn.cursor()
        c.execute("""
            SELECT scan_id, schema_version, features_json, created_at FROM campaign_fingerprints
            WHERE scan_id != ? ORDER BY created_at DESC, scan_id ASC LIMIT ?
        """, (exclude_scan_id or "", limit))
        rows = c.fetchall()
    except Exception:
        return None
    finally:
        # _ensure_table() already closes on its own failure (conn stays None here in that case, so
        # there is nothing to double-close); on every path where a connection WAS acquired -- the
        # successful SELECT above, or a failure in it -- it is closed exactly once, here.
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    out = []
    for scan_id, schema_version, features_json, created_at in rows:
        if schema_version != CURRENT_SCHEMA_VERSION:
            continue
        try:
            features = json.loads(features_json)
        except Exception:
            continue
        if not isinstance(features, dict):
            continue
        out.append({"scan_id": scan_id, "features": features, "created_at": created_at})
    return out


def query_recent_fingerprints(exclude_scan_id="", limit=MAX_HISTORY, shared=False):
    """Bounded (<= MAX_HISTORY rows), read-only. Rows stored under an incompatible schema_version
    are skipped -- never compared against, never deleted, never upgraded. A malformed stored row
    (bad JSON, wrong type) is skipped the same way. Returns [] on any storage error; never raises.
    """
    rows = _query_recent_fingerprints(exclude_scan_id=exclude_scan_id, limit=limit, shared=shared)
    return rows if rows is not None else []


def find_matches(result, shared=False, limit=MAX_HISTORY, top_n=MAX_RETURNED_MATCHES, history_sink=None):
    """Orchestration only: NOT called from build_scan_evidence() (which must stay pure/DB-free).
    Called once from analyzer.analyze_email(); its two return values are attached to `result`
    before build_scan_evidence() runs, so the evidence builder only ever reads precomputed data.

    Returns (features, match_report). `features` is always the pure extract_features() output --
    computed before any DB access, so storage trouble never prevents a scan from getting its own
    fingerprint. `match_report` is:
        {"status": "ok" | "no_identity" | "storage_unavailable",
         "matches": [... up to top_n compare_fingerprints() results, each with scan_id/created_at
                     of the matched prior case, sorted by score desc],
         "history_checked": int}
    """
    features = extract_features(result)
    scan_id = result.get("scan_id") if isinstance(result, dict) else ""
    if not scan_id:
        return features, {"status": "no_identity", "matches": [], "history_checked": 0}

    try:
        history = _query_recent_fingerprints(exclude_scan_id=scan_id, limit=limit, shared=shared)
        saved = save_fingerprint(scan_id, features, shared=shared)
    except Exception:
        return features, {"status": "storage_unavailable", "matches": [], "history_checked": 0}

    # history is None means the read itself failed (not "checked and found nothing") -- that must
    # never be reported as "ok" with history_checked: 0, even though saving may have still succeeded.
    if history is None or not saved:
        return features, {"status": "storage_unavailable", "matches": [], "history_checked": 0}

    if isinstance(history_sink, list):    # opt-in: hand the SAME bounded read to a caller (Phase 3) -- no 2nd query
        history_sink.extend(history)
    matches = []
    for row in history:
        cmp_ = compare_fingerprints(features, row["features"])
        if cmp_["classification"] == "none":
            continue
        matches.append(dict(cmp_, scan_id=row["scan_id"], created_at=row["created_at"]))
    # Deterministic ordering on tied scores: scan_id as a stable secondary sort key.
    matches.sort(key=lambda m: (-float(m["score"]), str(m["scan_id"])))
    return features, {"status": "ok", "matches": matches[:top_n], "history_checked": len(history)}
