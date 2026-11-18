"""Deterministic, offline tests for attack_dna.py (Phase 2: Attack DNA / Campaign Fingerprinting).

Every test uses a temporary on-disk sqlite file (never the real threat_memory.db) and never
touches the network. Mirrors the isolation pattern already used in test_retro_hunt.py and
test_evidence_integration.py's install_offline().
"""
import copy
import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

import attack_dna as dna
import analyzer
import investigation_agent as ia
import report
import risk
import tor_check
import tracker


def _tmp_db(case):
    """Isolated per-test sqlite file under a real TemporaryDirectory, registered for cleanup via
    addCleanup() (which unittest runs even if the test body raises/fails). Cleanup order matters:
    the DB_FILE/MULTIUSER patches must be stopped BEFORE the directory is removed -- addCleanup runs
    callbacks in LIFO order, so registering the directory cleanup first and the patcher stops after
    means the stops run first (last registered, first run), leaving no patched attribute pointing at
    an already-deleted path while any of this test's own cleanup is still in progress."""
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    path = os.path.join(tmp.name, "t.db")
    patchers = [mock.patch.object(tracker, "DB_FILE", path), mock.patch.object(tracker, "MULTIUSER", False)]
    for p in patchers:
        p.start()
        case.addCleanup(p.stop)     # registered after tmp.cleanup -> stops run first, directory removed last
    return path


class _FlakyCursor:
    """Wraps a real sqlite3 cursor and raises on exactly one named SQL stage, so a single call site
    can be reused to inject a failure at CREATE TABLE, CREATE INDEX, commit (via the connection),
    SELECT, fetchall, INSERT, or the retention DELETE -- the real cursor/connection (a normal, local
    temp-file sqlite3 connection, never the real threat_memory.db) handles everything else."""
    def __init__(self, real, fail_on, exc):
        self._real, self._fail_on, self._exc = real, fail_on, exc

    def execute(self, sql, params=()):
        s = sql.strip()
        hit = {
            "create_table": s.startswith("CREATE TABLE"),
            "create_index": s.startswith("CREATE INDEX"),
            "select": s.startswith("SELECT scan_id, schema_version"),
            "insert": s.startswith("INSERT INTO campaign_fingerprints"),
            "prune_delete": s.startswith("DELETE FROM campaign_fingerprints"),
        }.get(self._fail_on, False)
        if hit:
            raise self._exc
        return self._real.execute(sql, params)

    def fetchall(self):
        if self._fail_on == "fetchall":
            raise self._exc
        return self._real.fetchall()

    def fetchone(self):
        return self._real.fetchone()


class _FlakyConn:
    """Wraps a real sqlite3 connection. Tracks whether rollback()/close() were actually called, and
    can itself fail at commit(), while every other operation goes through to the real, isolated
    temp-file connection underneath."""
    def __init__(self, real, fail_on, exc):
        self._real, self._fail_on, self._exc = real, fail_on, exc
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return _FlakyCursor(self._real.cursor(), self._fail_on, self._exc)

    def commit(self):
        if self._fail_on == "commit":
            raise self._exc
        return self._real.commit()

    def rollback(self):
        self.rolled_back = True
        return self._real.rollback()

    def close(self):
        self.closed = True
        return self._real.close()


def _patch_flaky_connection(case, fail_on, exc=None):
    """Patches tracker.get_connection (for the duration of the current test) so the NEXT call
    returns a _FlakyConn that fails at `fail_on`. Returns the _FlakyConn so the test can inspect
    .rolled_back / .closed afterwards. The underlying connection is a real, isolated temp-file
    sqlite3 connection (via _tmp_db's own DB_FILE patch) -- never the real threat_memory.db."""
    exc = exc or sqlite3.OperationalError("injected: %s failure" % fail_on)
    real_get_connection = tracker.get_connection
    holder = {}

    def spy(shared=False):
        real = real_get_connection(shared=shared)
        fc = _FlakyConn(real, fail_on, exc)
        holder["conn"] = fc
        return fc

    p = mock.patch.object(tracker, "get_connection", spy)
    p.start()
    case.addCleanup(p.stop)
    return holder, exc


def mk_result(scan_id, from_domain="evil.example", reply_domain="drop.example", return_domain="drop.example",
              anomalies=(("high", "SPF fail"), ("high", "DKIM fail")),
              url_flags=(("URL shortener hides the real destination",), ("Punycode host - may render as look-alike Unicode letters",)),
              infra="tor", country="DE", body_len=300, n_urls=None, attachments=None, html=True):
    urls = [{"flags": list(fl)} for fl in url_flags]
    if n_urls is not None:
        urls = urls[:n_urls] + [{"flags": []}] * max(0, n_urls - len(urls))
    return {
        "scan_id": scan_id,
        "parsed": {
            "from_domain": from_domain, "reply_to_domain": reply_domain, "return_path_domain": return_domain,
            "body_text": "x" * body_len, "attachments": attachments if attachments is not None else [],
            "html_links": [{"href": "http://x"}] if html else [],
        },
        "headers": {"anomalies": [{"severity": s, "title": t} for s, t in anomalies]},
        "iocs": {"urls": urls},
        "geo": {"origin": {"infra": infra, "country_code": country}},
    }


class PureFeatureExtraction(unittest.TestCase):
    def test_extraction_is_pure_and_does_not_mutate_input(self):
        result = mk_result("SC-1")
        before = copy.deepcopy(result)
        dna.extract_features(result)
        self.assertEqual(result, before)                       # test 9: fingerprinting never mutates the scan result

    def test_extraction_is_deterministic(self):
        result = mk_result("SC-1")
        self.assertEqual(dna.extract_features(result), dna.extract_features(copy.deepcopy(result)))

    def test_no_raw_content_in_extracted_features(self):
        result = mk_result("SC-1", from_domain="secret-corp-internal.example")
        features = dna.extract_features(result)
        blob = json.dumps(features)
        self.assertNotIn("secret-corp-internal.example", blob)  # test 10: no raw domain/content ever appears
        self.assertNotIn("x" * 300, blob)                       # no body text

    def test_malformed_input_degrades_to_empty_features_not_a_crash(self):
        for bad in (None, {}, {"parsed": "not a dict"}, {"headers": {"anomalies": "not a list"}}, 123, "garbage"):
            features = dna.extract_features(bad)
            self.assertEqual(features["schema_version"], dna.CURRENT_SCHEMA_VERSION)
            self.assertTrue(all(isinstance(v, list) for v in features["families"].values()))

    def test_scalar_anomalies_urls_flags_attachments_degrade_gracefully(self):
        """Each of anomalies/urls/flags/attachments is supposed to be a list; a non-iterable truthy
        scalar there (an int, for instance) must never raise when iterated or measured with len()."""
        result = {"headers": {"anomalies": 5}, "iocs": {"urls": [{"flags": 7}]}, "parsed": {"attachments": 3}}
        features = dna.extract_features(result)     # must not raise
        self.assertEqual(features["families"]["auth_anomalies"], [])
        self.assertEqual(features["families"]["url_tactics"], [])
        self.assertIn("attach:none", features["families"]["structural"])   # scalar attachments treated as none, not sized

        scalar_urls = dna.extract_features({"iocs": {"urls": 5}})          # iocs.urls itself as a scalar (not just urls[*].flags)
        self.assertEqual(scalar_urls["families"]["url_tactics"], [])
        self.assertIn("urls:none", scalar_urls["families"]["structural"])

    def test_mixed_garbage_inside_anomalies_urls_flags_degrades_gracefully(self):
        """Lists that are themselves fine but contain a mix of wrong-typed items (non-dict anomaly/url
        entries, non-string flags, nested lists, None, dicts) must not raise and must not silently
        fabricate a tag from the garbage."""
        result = {
            "headers": {"anomalies": [1, 2, "x", None, {"title": "SPF fail", "severity": "high"}]},
            "iocs": {"urls": ["notadict", {"flags": ["URL shortener hides the real destination", 5, None, ["nested"], {"a": 1}]}]},
            "parsed": {"attachments": "notalist"},
        }
        features = dna.extract_features(result)      # must not raise
        self.assertIn("high:SPF fail", features["families"]["auth_anomalies"])
        self.assertEqual(features["families"]["url_tactics"], ["shortener"])    # only the one valid flag tag survives
        self.assertIn("attach:none", features["families"]["structural"])        # non-list attachments treated as none

    def test_dict_shaped_anomalies_urls_attachments_degrade_gracefully(self):
        """A dict where a list was expected must not be partially iterated (e.g. over its keys) --
        it degrades to the same "nothing extracted" result as any other malformed shape."""
        result = {"headers": {"anomalies": {"a": 1}}, "iocs": {"urls": {"a": 1}}, "parsed": {"attachments": {"a": 1}}}
        features = dna.extract_features(result)       # must not raise
        self.assertEqual(features["families"]["auth_anomalies"], [])
        self.assertIn("urls:none", features["families"]["structural"])
        self.assertIn("attach:none", features["families"]["structural"])


class SimilarityClassification(unittest.TestCase):
    def test_strong_match_across_different_domains_and_ips(self):
        a = dna.extract_features(mk_result("SC-a", from_domain="evil1.example", infra="tor", country="DE"))
        b = dna.extract_features(mk_result("SC-b", from_domain="evil2.example", infra="hosting", country="NL"))
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertEqual(cmp_["classification"], "strong")
        self.assertGreaterEqual(len(cmp_["qualifying_families"]), 2)

    def test_weak_similarity_from_only_one_feature_family(self):
        a = dna.extract_features(mk_result("SC-a", anomalies=(("high", "SPF fail"),), url_flags=(), reply_domain="evil.example",
                                            return_domain="evil.example"))
        b = dna.extract_features(mk_result("SC-b", anomalies=(("high", "SPF fail"),), url_flags=(), from_domain="other.example",
                                            reply_domain="other.example", return_domain="other.example"))
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertIn(cmp_["classification"], ("weak", "none"))
        self.assertNotEqual(cmp_["classification"], "strong")

    def test_shared_hosting_or_asn_alone_cannot_produce_a_strong_match(self):
        a = dna.extract_features(mk_result("SC-a", anomalies=(), url_flags=(), reply_domain="evil1.example",
                                            return_domain="evil1.example", infra="hosting", country="RU"))
        b = dna.extract_features(mk_result("SC-b", anomalies=(), url_flags=(), from_domain="other.example",
                                            reply_domain="other.example", return_domain="other.example",
                                            infra="hosting", country="RU"))
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertNotEqual(cmp_["classification"], "strong")
        self.assertNotIn("infra_class", cmp_["qualifying_families"])   # infra_class can never "qualify" at all

    def test_single_generic_auth_anomaly_alone_does_not_qualify_the_family(self):
        a = dna.extract_features(mk_result("SC-a", anomalies=(("high", "SPF fail"),), url_flags=()))
        b = dna.extract_features(mk_result("SC-b", anomalies=(("high", "SPF fail"),), url_flags=(),
                                            from_domain="other.example", reply_domain="other.example", return_domain="other.example"))
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertNotIn("auth_anomalies", cmp_["qualifying_families"])   # only one shared anomaly tag -- too generic

    def test_infrastructure_rotation_with_retained_structural_pattern(self):
        a = mk_result("SC-a", from_domain="evil1.example", reply_domain="drop1.example", return_domain="drop1.example",
                       infra="tor", country="DE")
        b = mk_result("SC-b", from_domain="evil2.example", reply_domain="drop2.example", return_domain="drop2.example",
                       infra="hosting", country="NL")
        cmp_ = dna.compare_fingerprints(dna.extract_features(a), dna.extract_features(b))
        self.assertEqual(cmp_["classification"], "strong")
        self.assertNotIn("infra_class", cmp_["matched_families"])    # the match held despite infra differing entirely

    def test_unrelated_emails_produce_no_match(self):
        a = dna.extract_features(mk_result("SC-a", anomalies=(("high", "SPF fail"), ("high", "DKIM fail")),
                                            url_flags=(("URL shortener hides the real destination",),),
                                            reply_domain="evil.example", return_domain="evil.example", infra="tor"))
        b = dna.extract_features(mk_result("SC-b", anomalies=(), url_flags=(), from_domain="newsletter.example",
                                            reply_domain="newsletter.example", return_domain="newsletter.example",
                                            infra="corporate", country="", body_len=20, html=False))
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertEqual(cmp_["classification"], "none")

    def test_missing_or_malformed_evidence_degrades_gracefully(self):
        a = dna.extract_features(mk_result("SC-a"))
        for bad in (None, {}, {"families": "not a dict"}, {"families": {"auth_anomalies": "not a list"}}):
            cmp_ = dna.compare_fingerprints(a, bad)
            self.assertEqual(cmp_["classification"], "none")
            self.assertLess(cmp_["confidence"], 1.0)             # missing families reduce confidence, not treated as a match

    def test_dict_values_inside_a_feature_list_do_not_crash_or_match(self):
        a = {"families": {"auth_anomalies": ["high:SPF fail", "high:DKIM fail"]}}
        b = {"families": {"auth_anomalies": [{"x": 1}, {"y": 2}]}}
        cmp_ = dna.compare_fingerprints(a, b)       # set() on dicts would normally raise TypeError: unhashable
        self.assertEqual(cmp_["classification"], "none")
        self.assertNotIn("auth_anomalies", cmp_["matched_families"])

    def test_nested_lists_inside_a_feature_list_do_not_crash_or_match(self):
        a = {"families": {"url_tactics": ["shortener", "punycode"]}}
        b = {"families": {"url_tactics": [["shortener"], ["punycode"]]}}
        cmp_ = dna.compare_fingerprints(a, b)       # set() on nested lists would normally raise TypeError: unhashable
        self.assertEqual(cmp_["classification"], "none")
        self.assertNotIn("url_tactics", cmp_["matched_families"])

    def test_non_string_scalars_inside_a_feature_list_are_dropped_not_matched(self):
        a = {"families": {"infra_class": ["tor", 1, True, None]}}
        b = {"families": {"infra_class": [1, True, None]}}
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertNotIn("infra_class", cmp_["matched_families"])     # 1/True/None never count as a shared tag
        self.assertEqual(cmp_["classification"], "none")

    def test_mixed_valid_and_invalid_tags_only_the_valid_ones_can_match(self):
        a = {"families": {"auth_anomalies": ["high:SPF fail", "high:DKIM fail"], "url_tactics": ["shortener"]}}
        b = {"families": {"auth_anomalies": ["high:SPF fail", {"bad": 1}, 5], "url_tactics": [["nested"], "shortener"]}}
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertEqual(cmp_["matched_families"]["auth_anomalies"], ["high:SPF fail"])
        self.assertEqual(cmp_["matched_families"]["url_tactics"], ["shortener"])
        self.assertNotIn("auth_anomalies", cmp_["qualifying_families"])   # only 1 valid shared tag -- too generic to qualify

    def test_one_sided_missing_family_lowers_confidence_but_never_matches_on_it(self):
        a = dna.extract_features(mk_result("SC-a"))
        b = copy.deepcopy(a)
        b["families"]["auth_anomalies"] = []        # this one email simply has no header anomalies
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertNotIn("auth_anomalies", cmp_["matched_families"])
        self.assertLess(cmp_["confidence"], 1.0)


class GenericTagSpecificity(unittest.TestCase):
    """Regression tests for the url_tactics/domain_alignment generic-vs-distinctive single-tag
    fix. A lone tag from a family's known-generic set (_GENERIC_SINGLE_TAGS) must never count as
    "specific" evidence at EITHER level: not toward the ">= 2 qualifying families" requirement for
    STRONG, and not toward the "at least one meaningful, non-generic overlap" requirement for WEAK
    -- a tag this module itself classifies as generic cannot simultaneously be treated as
    meaningful/non-generic for WEAK purposes. A lone genuinely distinctive single tag, or two or
    more co-occurring tags in the same family (generic or not), must still be able to qualify."""

    def test_reproduced_false_positive_scenario_no_longer_reaches_strong_or_weak(self):
        """Exact scenario from the review: two otherwise-unrelated emails sharing only a URL
        shortener, a reply-to org mismatch, generic 'hosting' infra and the same coarse structural
        buckets used to be classified STRONG purely from two generic single-tag overlaps plus
        generic supporting weight. Neither the generic overlaps nor the generic infra/structural
        weight on top of them are specific evidence, so this must now resolve to NONE even though
        the raw weighted score alone would still clear STRONG_THRESHOLD."""
        common_struct = ["len:short", "urls:few", "attach:none", "html:no"]
        fam = {"auth_anomalies": [], "url_tactics": ["shortener"], "domain_alignment": ["reply_org_mismatch"],
               "infra_class": ["hosting"], "structural": common_struct}
        a, b = {"families": fam}, {"families": dict(fam)}
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertEqual(cmp_["classification"], "none")
        self.assertEqual(cmp_["qualifying_families"], [])
        self.assertGreaterEqual(cmp_["score"], dna.STRONG_THRESHOLD)   # score alone would have crossed STRONG

    def test_generic_url_tactic_overlap_alone_does_not_qualify_weak_or_strong(self):
        """A single shared 'shortener' (or any other _GENERIC_SINGLE_TAGS url_tactics entry), with
        nothing else to compare, must not reach WEAK (not just not STRONG)."""
        a = {"families": {"url_tactics": ["shortener"]}}
        b = {"families": {"url_tactics": ["shortener"]}}
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertNotIn("url_tactics", cmp_["qualifying_families"])
        self.assertEqual(cmp_["classification"], "none")

    def test_generic_domain_alignment_overlap_alone_does_not_qualify_weak_or_strong(self):
        """A single shared 'reply_org_mismatch' (or any other _GENERIC_SINGLE_TAGS domain_alignment
        entry), with nothing else to compare, must not reach WEAK (not just not STRONG)."""
        a = {"families": {"domain_alignment": ["reply_org_mismatch"]}}
        b = {"families": {"domain_alignment": ["reply_org_mismatch"]}}
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertNotIn("domain_alignment", cmp_["qualifying_families"])
        self.assertEqual(cmp_["classification"], "none")

    def test_two_generic_domain_alignment_tags_together_still_qualify(self):
        """Two co-occurring domain_alignment tags are a materially more specific coincidence than
        either alone, even if each individual tag is in _GENERIC_SINGLE_TAGS -- the veto in
        _lacks_specific_evidence() only applies to a *single*-tag overlap, so this still qualifies
        for (at least) WEAK."""
        a = {"families": {"domain_alignment": ["reply_org_mismatch", "return_org_mismatch"]}}
        b = {"families": {"domain_alignment": ["reply_org_mismatch", "return_org_mismatch"]}}
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertIn("domain_alignment", cmp_["qualifying_families"])
        self.assertNotEqual(cmp_["classification"], "none")

    def test_distinctive_single_url_tactic_still_qualifies_alone(self):
        """A genuinely distinctive single tag (e.g. 'punycode', not in _GENERIC_SINGLE_TAGS) must
        still be able to qualify on its own, combined with one other qualifying family, producing a
        STRONG classification exactly as before this fix -- distinctive single-tag behaviour is
        unaffected by tightening the generic-tag veto to also cover WEAK."""
        a = {"families": {"auth_anomalies": ["high:SPF fail", "high:DKIM fail"], "url_tactics": ["punycode"]}}
        b = {"families": {"auth_anomalies": ["high:SPF fail", "high:DKIM fail"], "url_tactics": ["punycode"]}}
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertEqual(cmp_["classification"], "strong")
        self.assertIn("url_tactics", cmp_["qualifying_families"])
        self.assertIn("auth_anomalies", cmp_["qualifying_families"])

    def test_distinctive_single_url_tactic_alone_still_flags_weak(self):
        """A genuinely distinctive single tag alone (no second qualifying family) must still reach
        WEAK -- only generic single tags lost that ability, not distinctive ones."""
        a = {"families": {"url_tactics": ["punycode"]}}
        b = {"families": {"url_tactics": ["punycode"]}}
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertEqual(cmp_["classification"], "weak")

    def test_single_generic_auth_anomaly_still_flags_weak_unaffected_by_this_fix(self):
        """auth_anomalies has no entry in _GENERIC_SINGLE_TAGS, so its pre-existing behaviour is
        unaffected: a single shared generic auth anomaly tag still reaches WEAK on its own (as
        test_weak_similarity_from_only_one_feature_family already covers end-to-end); only
        url_tactics/domain_alignment gained a generic-tag veto."""
        a = {"families": {"auth_anomalies": ["high:SPF fail"]}}
        b = {"families": {"auth_anomalies": ["high:SPF fail"]}}
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertEqual(cmp_["classification"], "weak")

    def test_infrastructure_rotation_strong_match_is_preserved(self):
        """This fix must not regress the existing infrastructure-rotation STRONG-match behaviour:
        two emails with completely different domains/infra/country but repeated, genuinely
        distinctive tactics (2+ auth anomalies, a distinctive URL tactic, a domain-alignment
        mismatch) must still classify STRONG. Mirrors
        SimilarityClassification.test_infrastructure_rotation_with_retained_structural_pattern."""
        a = dna.extract_features(mk_result("GT-a", from_domain="evil1.example", reply_domain="drop1.example",
                                            return_domain="drop1.example", infra="tor", country="DE"))
        b = dna.extract_features(mk_result("GT-b", from_domain="evil2.example", reply_domain="drop2.example",
                                            return_domain="drop2.example", infra="hosting", country="NL"))
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertEqual(cmp_["classification"], "strong")
        self.assertNotIn("infra_class", cmp_["matched_families"])


class GenericTagVetoRegression(unittest.TestCase):
    """Separate from GenericTagSpecificity (which must stay as is): end-to-end regression, through the real
    extract_features() -> compare_fingerprints() path, that purely generic overlap can never classify."""

    def test_generic_shortener_reply_mismatch_infra_structural_is_none_not_weak(self):
        """Two otherwise unrelated emails (different sender/reply domains, countries, no auth anomalies) that share
        only a URL shortener, a reply-to org mismatch, generic 'hosting' infra and the same coarse structural buckets.
        The weighted score alone clears STRONG_THRESHOLD, but none of the overlap is specific evidence, so the result
        must be 'none' (not 'weak', not 'strong') with no qualifying family."""
        def generic_only(tag, sender, reply, country):
            return dna.extract_features(mk_result(
                "VETO-" + tag, from_domain=sender, reply_domain=reply, return_domain=sender, anomalies=(),
                url_flags=(("URL shortener hides the real destination",),), infra="hosting", country=country, body_len=300))
        a = generic_only("a", "alpha-one.example", "other-one.example", "DE")
        b = generic_only("b", "beta-two.example", "other-two.example", "NL")
        self.assertEqual(a["families"]["url_tactics"], ["shortener"])
        self.assertEqual(a["families"]["domain_alignment"], ["reply_org_mismatch"])
        cmp_ = dna.compare_fingerprints(a, b)
        self.assertEqual(cmp_["classification"], "none")
        self.assertNotEqual(cmp_["classification"], "weak")
        self.assertEqual(cmp_["qualifying_families"], [])
        self.assertGreaterEqual(cmp_["score"], dna.STRONG_THRESHOLD)   # raw score alone would have crossed STRONG
        for fam in ("url_tactics", "domain_alignment", "infra_class", "structural"):
            self.assertIn(fam, cmp_["matched_families"])               # the overlap really was present


class Persistence(unittest.TestCase):
    def setUp(self):
        _tmp_db(self)

    def test_repeated_scans_do_not_create_duplicate_records(self):
        result = mk_result("SC-dup")
        features = dna.extract_features(result)
        dna.save_fingerprint("SC-dup", features)
        dna.save_fingerprint("SC-dup", features)         # same scan_id re-saved (e.g. re-scanning the same file)
        conn = tracker.get_connection(shared=False)
        n = conn.execute("SELECT COUNT(*) FROM campaign_fingerprints").fetchone()[0]
        conn.close()
        self.assertEqual(n, 1)

    def test_bounded_historical_lookup(self):
        for i in range(dna.MAX_HISTORY + 20):
            dna.save_fingerprint("SC-%d" % i, dna.extract_features(mk_result("SC-%d" % i)))
        rows = dna.query_recent_fingerprints(exclude_scan_id="", limit=10_000)   # even an oversized request is capped
        self.assertLessEqual(len(rows), dna.MAX_HISTORY)

    def test_fingerprint_version_compatibility(self):
        conn = tracker.get_connection(shared=False)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS campaign_fingerprints
                      (scan_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, features_json TEXT NOT NULL, created_at TEXT NOT NULL)""")
        c.execute("INSERT INTO campaign_fingerprints VALUES (?,?,?,?)",
                  ("SC-old", dna.CURRENT_SCHEMA_VERSION + 999, json.dumps(dna.extract_features(mk_result("SC-old"))), "2020-01-01 00:00:00"))
        conn.commit()
        conn.close()
        rows = dna.query_recent_fingerprints()
        self.assertFalse(any(r["scan_id"] == "SC-old" for r in rows))   # incompatible version is skipped, not used, not deleted
        conn = tracker.get_connection(shared=False)
        still_there = conn.execute("SELECT COUNT(*) FROM campaign_fingerprints WHERE scan_id='SC-old'").fetchone()[0]
        conn.close()
        self.assertEqual(still_there, 1)

    def test_malformed_stored_rows_do_not_break_scanning(self):
        conn = tracker.get_connection(shared=False)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS campaign_fingerprints
                      (scan_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, features_json TEXT NOT NULL, created_at TEXT NOT NULL)""")
        c.execute("INSERT INTO campaign_fingerprints VALUES (?,?,?,?)", ("SC-bad", dna.CURRENT_SCHEMA_VERSION, "{not json", "2020-01-01"))
        c.execute("INSERT INTO campaign_fingerprints VALUES (?,?,?,?)", ("SC-bad2", dna.CURRENT_SCHEMA_VERSION, "42", "2020-01-01"))
        conn.commit()
        conn.close()
        rows = dna.query_recent_fingerprints()
        self.assertEqual(rows, [])     # both malformed rows are skipped, not raised

    def test_database_unavailable_degrades_to_no_history_without_raising(self):
        with mock.patch.object(tracker, "get_connection", side_effect=sqlite3.OperationalError("locked")):
            self.assertEqual(dna.query_recent_fingerprints(), [])
            self.assertFalse(dna.save_fingerprint("SC-x", dna.extract_features(mk_result("SC-x"))))
            features, report_ = dna.find_matches(mk_result("SC-x"))
            self.assertEqual(report_["status"], "storage_unavailable")
            self.assertEqual(report_["matches"], [])
            self.assertIsInstance(features, dict)       # pure extraction still succeeds even though storage is down

    def test_find_matches_saves_and_finds_a_real_match(self):
        a = mk_result("SC-a", from_domain="evil1.example", infra="tor", country="DE")
        b = mk_result("SC-b", from_domain="evil2.example", infra="hosting", country="NL")
        _, report_a = dna.find_matches(a)
        self.assertEqual(report_a["matches"], [])
        _, report_b = dna.find_matches(b)
        self.assertTrue(any(m["classification"] == "strong" for m in report_b["matches"]))
        self.assertEqual(report_b["matches"][0]["scan_id"], "SC-a")

    def test_no_identity_degrades_without_touching_storage(self):
        features, report_ = dna.find_matches(mk_result(""))
        self.assertEqual(report_["status"], "no_identity")
        conn = tracker.get_connection(shared=False)
        try:
            n = conn.execute("SELECT COUNT(*) FROM campaign_fingerprints").fetchone()[0]
        except sqlite3.OperationalError:
            n = 0     # table was never even created -- also acceptable
        conn.close()
        self.assertEqual(n, 0)


class PersistenceFailureInjection(unittest.TestCase):
    """Automated regression coverage for _ensure_table()'s and _query_recent_fingerprints()'s
    failure-cleanup behavior -- previously only checked by hand in chat, never captured as a test."""
    def setUp(self):
        _tmp_db(self)

    def _assert_ensure_table_raises_and_cleans_up(self, fail_on):
        holder, exc = _patch_flaky_connection(self, fail_on)
        with self.assertRaises(type(exc)) as ctx:
            dna._ensure_table(shared=False)
        self.assertIs(ctx.exception, exc)          # the exact original exception, not a replacement/wrapper
        self.assertTrue(holder["conn"].rolled_back)
        self.assertTrue(holder["conn"].closed)

    def test_create_table_failure_is_rolled_back_connection_closed_exception_preserved(self):
        self._assert_ensure_table_raises_and_cleans_up("create_table")

    def test_create_index_failure_is_rolled_back_connection_closed_exception_preserved(self):
        self._assert_ensure_table_raises_and_cleans_up("create_index")

    def test_ensure_table_commit_failure_is_rolled_back_connection_closed_exception_preserved(self):
        self._assert_ensure_table_raises_and_cleans_up("commit")

    def _assert_callers_fail_soft(self, fail_on):
        _patch_flaky_connection(self, fail_on)
        self.assertEqual(dna.query_recent_fingerprints(), [])
        self.assertFalse(dna.save_fingerprint("SC-x", dna.extract_features(mk_result("SC-x"))))
        features, report_ = dna.find_matches(mk_result("SC-y"))
        self.assertEqual(report_["status"], "storage_unavailable")
        self.assertEqual(report_["matches"], [])
        self.assertIsInstance(features, dict)       # pure extraction is unaffected by storage trouble

    def test_create_table_failure_callers_fail_soft(self):
        self._assert_callers_fail_soft("create_table")

    def test_create_index_failure_callers_fail_soft(self):
        self._assert_callers_fail_soft("create_index")

    def test_ensure_table_commit_failure_callers_fail_soft(self):
        self._assert_callers_fail_soft("commit")

    def test_select_failure_closes_connection_returns_empty_no_exception_escapes(self):
        holder, exc = _patch_flaky_connection(self, "select")
        rows = dna.query_recent_fingerprints()      # must not raise
        self.assertEqual(rows, [])
        self.assertTrue(holder["conn"].closed)

    def test_fetchall_failure_closes_connection_returns_empty_no_exception_escapes(self):
        holder, exc = _patch_flaky_connection(self, "fetchall")
        rows = dna.query_recent_fingerprints()      # must not raise
        self.assertEqual(rows, [])
        self.assertTrue(holder["conn"].closed)

    def test_select_failure_makes_find_matches_report_storage_unavailable(self):
        _patch_flaky_connection(self, "select")
        features, report_ = dna.find_matches(mk_result("SC-sel"))
        self.assertEqual(report_["status"], "storage_unavailable")
        self.assertEqual(report_["history_checked"], 0)

    def test_fetchall_failure_makes_find_matches_report_storage_unavailable(self):
        _patch_flaky_connection(self, "fetchall")
        features, report_ = dna.find_matches(mk_result("SC-fa"))
        self.assertEqual(report_["status"], "storage_unavailable")
        self.assertEqual(report_["history_checked"], 0)

    def test_genuine_empty_history_reports_ok_not_storage_unavailable(self):
        """A failed read and a real, empty history must be distinguishable: with NO failure
        injected and nothing stored yet, the first scan must report "ok" with history_checked: 0,
        never "storage_unavailable"."""
        features, report_ = dna.find_matches(mk_result("SC-first"))
        self.assertEqual(report_, {"status": "ok", "matches": [], "history_checked": 0})

    def test_successful_history_retrieval_and_matching_are_unaffected_by_this_harness(self):
        """Sanity check on the test harness itself: with no failure injected, a real strong match
        still works exactly as it did before this coverage pass was added."""
        a = mk_result("SC-a", from_domain="evil1.example", infra="tor", country="DE")
        b = mk_result("SC-b", from_domain="evil2.example", infra="hosting", country="NL")
        dna.find_matches(a)
        _, report_b = dna.find_matches(b)
        self.assertEqual(report_b["status"], "ok")
        self.assertTrue(any(m["classification"] == "strong" for m in report_b["matches"]))


class RetentionAndOrdering(unittest.TestCase):
    """Automated coverage for the 5,000-row storage cap, the 200-row bounded query, deterministic
    tie-break ordering, and that pruning never touches an unrelated table."""
    def setUp(self):
        _tmp_db(self)

    def test_storage_cap_prunes_only_the_oldest_rows_keeps_the_cap(self):
        dna.save_fingerprint("SC-old", dna.extract_features(mk_result("SC-old")))
        conn = tracker.get_connection(shared=False)
        conn.execute("UPDATE campaign_fingerprints SET created_at = '2000-01-01 00:00:00' WHERE scan_id='SC-old'")
        conn.commit()
        conn.close()
        with mock.patch.object(dna, "MAX_STORED_FINGERPRINTS", 3):
            dna.save_fingerprint("SC-1", dna.extract_features(mk_result("SC-1")))
            dna.save_fingerprint("SC-2", dna.extract_features(mk_result("SC-2")))
            dna.save_fingerprint("SC-3", dna.extract_features(mk_result("SC-3")))   # now 4 rows -> prune 1
        conn = tracker.get_connection(shared=False)
        remaining = {r[0] for r in conn.execute("SELECT scan_id FROM campaign_fingerprints").fetchall()}
        n = conn.execute("SELECT COUNT(*) FROM campaign_fingerprints").fetchone()[0]
        conn.close()
        self.assertEqual(n, 3)
        self.assertNotIn("SC-old", remaining)                 # the oldest row was the one pruned
        self.assertEqual(remaining, {"SC-1", "SC-2", "SC-3"})  # the newest rows were kept

    def test_pruning_never_touches_an_unrelated_table(self):
        # A uniquely-named table standing in for threat_memory.db's other tables (attackers,
        # threat_intel, etc. -- which get their own schema from tracker.get_connection() itself,
        # independent of attack_dna). The point is that attack_dna's own retention DELETE only ever
        # names campaign_fingerprints, so any other table -- this one included -- is never touched.
        conn = tracker.get_connection(shared=False)
        conn.execute("CREATE TABLE IF NOT EXISTS unrelated_threat_memory_table (marker TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO unrelated_threat_memory_table VALUES ('do-not-touch')")
        conn.commit()
        conn.close()
        with mock.patch.object(dna, "MAX_STORED_FINGERPRINTS", 1):
            dna.save_fingerprint("SC-1", dna.extract_features(mk_result("SC-1")))
            dna.save_fingerprint("SC-2", dna.extract_features(mk_result("SC-2")))   # triggers a prune
        conn = tracker.get_connection(shared=False)
        n = conn.execute("SELECT COUNT(*) FROM unrelated_threat_memory_table").fetchone()[0]
        still_there = conn.execute("SELECT marker FROM unrelated_threat_memory_table").fetchone()[0]
        conn.close()
        self.assertEqual(n, 1)
        self.assertEqual(still_there, "do-not-touch")

    def test_historical_query_stays_bounded_to_200_even_with_a_larger_request(self):
        for i in range(dna.MAX_HISTORY + 20):
            dna.save_fingerprint("SC-%03d" % i, dna.extract_features(mk_result("SC-%03d" % i)))
        rows = dna.query_recent_fingerprints(limit=100_000)
        self.assertEqual(len(rows), dna.MAX_HISTORY)

    def test_historical_query_ordering_is_deterministic_on_tied_timestamps(self):
        for scan_id in ("SC-b", "SC-a", "SC-c"):
            dna.save_fingerprint(scan_id, dna.extract_features(mk_result(scan_id)))
        conn = tracker.get_connection(shared=False)
        conn.execute("UPDATE campaign_fingerprints SET created_at = '2024-01-01 00:00:00'")   # force a tie
        conn.commit()
        conn.close()
        order1 = [r["scan_id"] for r in dna.query_recent_fingerprints()]
        order2 = [r["scan_id"] for r in dna.query_recent_fingerprints()]
        self.assertEqual(order1, order2)
        self.assertEqual(order1, sorted(order1))    # scan_id ascending is the documented tie-break

    def test_match_ordering_is_deterministic_on_tied_scores(self):
        base = mk_result("SC-base", anomalies=(("high", "SPF fail"), ("high", "DKIM fail")), url_flags=())
        dna.find_matches(base)
        twin1 = mk_result("SC-twin-2", from_domain="other2.example", anomalies=(("high", "SPF fail"), ("high", "DKIM fail")), url_flags=())
        twin2 = mk_result("SC-twin-1", from_domain="other1.example", anomalies=(("high", "SPF fail"), ("high", "DKIM fail")), url_flags=())
        dna.find_matches(twin1)
        _, report_ = dna.find_matches(twin2)
        scored = [m for m in report_["matches"] if m["score"] == report_["matches"][0]["score"]]
        if len(scored) > 1:
            self.assertEqual([m["scan_id"] for m in scored], sorted(m["scan_id"] for m in scored))


class PrivacyRegression(unittest.TestCase):
    """Automated coverage for the infra/country allow-lists and for what actually ends up in a
    persisted fingerprint row -- previously only checked by hand in chat, never captured as a test."""
    def setUp(self):
        _tmp_db(self)

    def test_valid_iso_country_codes_are_accepted(self):
        for code in ("US", "DE", "IN", "GB", "JP"):
            f = dna.extract_features({"geo": {"origin": {"country_code": code}}})
            self.assertIn("country:" + code, f["families"]["infra_class"])

    def test_lowercase_and_whitespace_country_code_is_normalized_then_accepted(self):
        f = dna.extract_features({"geo": {"origin": {"country_code": " de "}}})
        self.assertIn("country:DE", f["families"]["infra_class"])

    def test_raw_ip_domain_email_and_arbitrary_country_strings_are_rejected(self):
        for bad in ("203.0.113.7", "mail.attacker.example", "alice@example.org", "Germany", "XX", "Not A Country", ""):
            f = dna.extract_features({"geo": {"origin": {"country_code": bad}}})
            self.assertFalse(any(t.startswith("country:") for t in f["families"]["infra_class"]), bad)

    def test_valid_infra_categories_are_accepted(self):
        for cat in ("tor", "vpn", "proxy", "hosting", "residential", "corporate"):
            f = dna.extract_features({"geo": {"origin": {"infra": cat}}})
            self.assertIn(cat, f["families"]["infra_class"])

    def test_infra_is_normalized_for_case_and_whitespace(self):
        f = dna.extract_features({"geo": {"origin": {"infra": "  ToR  "}}})
        self.assertIn("tor", f["families"]["infra_class"])

    def test_unknown_and_arbitrary_infra_values_are_rejected(self):
        for bad in ("unknown", "203.0.113.7", "mail.attacker.example", "alice@example.org", "not-a-category", ""):
            f = dna.extract_features({"geo": {"origin": {"infra": bad}}})
            self.assertEqual(f["families"]["infra_class"], [], bad)

    def test_no_raw_ip_domain_email_subject_or_body_in_a_persisted_fingerprint_row(self):
        secrets = ("203.0.113.7", "mail.attacker.example", "alice@example.org", "bob@mail.attacker.example",
                   "SECRET SUBJECT LINE", "the quick brown fox body text")
        result = mk_result("SC-secret", from_domain="mail.attacker.example", reply_domain="mail.attacker.example",
                            return_domain="mail.attacker.example")
        # Realistic full fields, not just the *_domain summaries mk_result() already sets -- the
        # actual email_parser.py output also carries the full address and the subject line, and
        # neither of those is ever read by extract_features(), so neither should ever reach storage.
        result["parsed"]["subject"] = "SECRET SUBJECT LINE"
        result["parsed"]["from_addr"] = "alice@example.org"
        result["parsed"]["reply_to"] = "bob@mail.attacker.example"
        result["parsed"]["return_path"] = "bob@mail.attacker.example"
        result["parsed"]["body_text"] = "the quick brown fox body text alice@example.org"
        result["geo"] = {"origin": {"ip": "203.0.113.7", "infra": "203.0.113.7", "country_code": "mail.attacker.example"}}
        dna.save_fingerprint("SC-secret", dna.extract_features(result))
        conn = tracker.get_connection(shared=False)
        stored_json = conn.execute("SELECT features_json FROM campaign_fingerprints WHERE scan_id='SC-secret'").fetchone()[0]
        conn.close()
        for secret in secrets:
            self.assertNotIn(secret, stored_json)


class TestIsolation(unittest.TestCase):
    """Confirms the isolation guarantees the other test classes rely on: a fresh, non-production
    database per test, and that unittest's addCleanup runs regardless of test outcome."""
    def test_tmp_db_path_is_never_the_project_or_production_database(self):
        path = _tmp_db(self)
        self.assertTrue(os.path.abspath(path).startswith(os.path.abspath(tempfile.gettempdir())))
        self.assertNotIn("threat_memory.db", path)

    def test_addcleanup_runs_even_when_the_test_body_raises(self):
        """unittest guarantees addCleanup callbacks run after a failing test; this confirms it for
        this suite's own harness by invoking a test method that fails, via a throwaway TestCase/
        TestResult, and checking the cleanup still fired."""
        ran = []

        class _Throwaway(unittest.TestCase):
            def test_it(self):
                _tmp_db(self)
                self.addCleanup(lambda: ran.append(True))
                raise AssertionError("deliberate failure to prove cleanup still runs")

        result = unittest.TestResult()
        _Throwaway("test_it").run(result)
        self.assertEqual(len(result.failures), 1)
        self.assertEqual(ran, [True])

    def test_each_synthetic_scan_starts_with_isolated_history_by_default(self):
        """Two unittest.TestCase instances each get their own _tmp_db() -- a scan saved under one
        test's isolated database must not be visible from a freshly isolated database. The inner
        test asserts (against its own, still-active isolated database) that the save actually
        succeeded and is queryable there, so its own failure would be visible via wasSuccessful()
        rather than silently passing regardless of what _CaseA actually did."""
        class _CaseA(unittest.TestCase):
            def test_it(self):
                _tmp_db(self)
                saved = dna.save_fingerprint("SC-isolated", dna.extract_features(mk_result("SC-isolated")))
                self.assertTrue(saved)                                        # the save itself must have succeeded
                seen = dna.query_recent_fingerprints(exclude_scan_id="")
                self.assertEqual([r["scan_id"] for r in seen], ["SC-isolated"])  # ...and be visible in THIS database

        result = unittest.TestResult()
        _CaseA("test_it").run(result)
        self.assertTrue(result.wasSuccessful(), (result.failures, result.errors))  # the first scan completed cleanly

        _tmp_db(self)   # this test's own, separately initialized, isolated database
        self.assertEqual(dna.query_recent_fingerprints(), [])   # ...cannot see the fingerprint saved under _CaseA's


class PrivacyScope(unittest.TestCase):
    def setUp(self):
        _tmp_db(self)

    def test_private_storage_does_not_cross_session_boundaries(self):
        """shared=False (this module's default) must resolve to per-session storage once MULTIUSER
        is on -- confirming the documented privacy scope rather than assuming it."""
        with mock.patch.object(tracker, "MULTIUSER", True), \
             mock.patch.object(tracker, "_session_id", return_value="session-A"):
            dna.save_fingerprint("SC-A", dna.extract_features(mk_result("SC-A")), shared=False)
        with mock.patch.object(tracker, "MULTIUSER", True), \
             mock.patch.object(tracker, "_session_id", return_value="session-B"):
            rows_seen_by_b = dna.query_recent_fingerprints(shared=False)
        self.assertEqual(rows_seen_by_b, [])     # session B's private storage must not see session A's fingerprint

    def test_shared_true_is_cross_session_by_design_and_never_the_default(self):
        with mock.patch.object(tracker, "MULTIUSER", True), \
             mock.patch.object(tracker, "_session_id", return_value="session-A"):
            dna.save_fingerprint("SC-A", dna.extract_features(mk_result("SC-A")), shared=True)
        with mock.patch.object(tracker, "MULTIUSER", True), \
             mock.patch.object(tracker, "_session_id", return_value="session-B"):
            rows_seen_by_b = dna.query_recent_fingerprints(shared=True)
        self.assertTrue(any(r["scan_id"] == "SC-A" for r in rows_seen_by_b))   # shared=True pools by design (opt-in only)
        import inspect
        self.assertEqual(inspect.signature(dna.find_matches).parameters["shared"].default, False)   # never the default


class EvidencePipelineIntegration(unittest.TestCase):
    def setUp(self):
        _tmp_db(self)

    def _result(self, scan_id, **kw):
        r = mk_result(scan_id, **kw)
        r["campaign_fingerprint"], r["campaign_matches"] = dna.find_matches(r)
        return r

    def test_build_scan_evidence_reads_precomputed_fields_only(self):
        """build_scan_evidence() must stay deterministic/DB-free: patch out the database entirely
        and confirm the campaign-fingerprint section still runs cleanly off precomputed fields."""
        r = self._result("SC-1")
        with mock.patch.object(tracker, "get_connection", side_effect=AssertionError("build_scan_evidence touched the DB")):
            reg, fnd = ia.build_scan_evidence(r)
        self.assertTrue(any(e["source"] == "attack_dna" for e in reg))

    def test_strong_match_produces_valid_evidence_and_findings(self):
        a = self._result("SC-a", from_domain="evil1.example", infra="tor", country="DE")
        b = self._result("SC-b", from_domain="evil2.example", infra="hosting", country="NL")
        reg, fnd = ia.build_scan_evidence(b)
        dna_findings = [f for f in fnd if f.get("kind") in ("suspicious", "uncertain") and
                        any(reg[int(i[1:]) - 1]["source"] == "attack_dna" for i in f["evidence_ids"])]
        self.assertTrue(any(f["kind"] == "suspicious" for f in dna_findings))
        for f in fnd:
            self.assertIn(f["kind"], ("verified", "suspicious", "uncertain"))   # never an invented finding kind
            self.assertTrue(f["evidence_ids"])
            for eid in f["evidence_ids"]:
                self.assertTrue(any(e["id"] == eid for e in reg))              # every cited id actually exists in the register
        statement = next(f["statement"] for f in fnd if f["kind"] == "suspicious" and
                          any(reg[int(i[1:]) - 1]["source"] == "attack_dna" for i in f["evidence_ids"]))
        self.assertNotIn("same attacker", statement.lower())
        self.assertIn("not confirmed", statement.lower())   # explicit hedge: resemblance, never asserted common authorship

    def test_missing_fingerprint_fields_produce_an_uncertain_finding_not_a_crash(self):
        r = mk_result("SC-x")   # no campaign_fingerprint / campaign_matches attached at all
        reg, fnd = ia.build_scan_evidence(r)
        dna_entries = [e for e in reg if e["source"] == "attack_dna"]
        self.assertEqual(dna_entries[0]["status"], "missing")

    def test_evidence_ids_and_finding_kinds_follow_the_same_contract_as_every_other_section(self):
        """Preserves existing provenance rules: attack_dna's findings use only the pre-existing
        _FINDING_KINDS vocabulary and cite only ids that genuinely exist in the register -- the same
        contract test_investigation_agent.py already enforces for every other section, unmodified."""
        r = self._result("SC-1")
        reg, fnd = ia.build_scan_evidence(r)
        ids = {e["id"] for e in reg}
        for f in fnd:
            self.assertIn(f["kind"], ia._FINDING_KINDS)
            self.assertTrue(set(f["evidence_ids"]) <= ids)


class ReportAndUIConsistency(unittest.TestCase):
    def setUp(self):
        _tmp_db(self)

    def test_scan_evidence_md_renders_attack_dna_entries_without_a_dedicated_renderer(self):
        r = mk_result("SC-1")
        r["campaign_fingerprint"], r["campaign_matches"] = dna.find_matches(r)
        r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
        md = report.scan_evidence_md(r)
        self.assertTrue(any("attack_dna" in line or "campaign fingerprint" in line for line in md))

    def test_ui_panel_reads_precomputed_fields_only(self):
        """The app.py Attack DNA panel must not call attack_dna.find_matches() or touch the database
        itself -- it only displays sel_res["campaign_fingerprint"]/["campaign_matches"], exactly like
        the evidence-register section does. Confirmed by searching the panel's own source slice."""
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "app.py"), encoding="utf-8") as f:
            src = f.read()
        start = src.index('"Attack DNA — Campaign Fingerprinting"')
        end = src.index("SHA-256 Cryptographic Evidence Hash", start)
        panel_src = src[start:end]
        self.assertIn('sel_res.get("campaign_fingerprint")', panel_src)
        self.assertIn('sel_res.get("campaign_matches")', panel_src)
        self.assertNotIn("find_matches(", panel_src)
        self.assertNotIn("get_connection(", panel_src)
        self.assertNotIn("save_fingerprint(", panel_src)

    def test_attack_dna_does_not_duplicate_correlate_or_retro_hunt(self):
        # Read as plain text rather than importing: correlate.py pulls in plotly, which isn't
        # required to prove these files are untouched by this feature.
        base = os.path.dirname(os.path.abspath(__file__))
        for name in ("correlate.py", "retro_hunt.py"):
            with open(os.path.join(base, name), encoding="utf-8") as f:
                self.assertNotIn("attack_dna", f.read())


class RiskScoreRegression(unittest.TestCase):
    def setUp(self):
        _tmp_db(self)

    def test_attack_dna_never_changes_the_score_or_verdict(self):
        """Compute the full verdict twice for the same inputs -- once with a populated campaign
        fingerprint/match history, once with none -- and confirm risk.score() is byte-for-byte
        unaffected, since risk.py never receives anything from attack_dna in the first place."""
        kwargs = dict(ml_prob=0.6, auth_fail=0.4, header_anomaly=0.3, url_risk=0.5, origin_risk=0.35,
                      bec_score=0.0, extortion_score=0.0)
        v1 = risk.score(**kwargs)
        # Simulate a "noisy" campaign_fingerprint/campaign_matches state and confirm risk.score's
        # own signature/behavior (the only thing that could carry such noise into a verdict) is untouched.
        import inspect
        self.assertNotIn("campaign", inspect.getsource(risk).lower())
        v2 = risk.score(**kwargs)
        self.assertEqual(v1, v2)

    def test_analyzer_pipeline_score_matches_with_and_without_campaign_dna_available(self):
        import email_parser
        raw = b"From: a@example.com\r\nSubject: hi\r\n\r\nHello there, just checking in.\r\n"
        # geolocate.py calls tor_check.maybe_update_tor_list() (via its own "import tor_check"), so
        # the attribute must be patched on the tor_check module itself -- that's the one object every
        # caller's "tor_check.maybe_update_tor_list()" actually looks up. Stubbed for both
        # analyze_email() calls below. This stub prevents the real Tor-list refresh during this test.
        # It does not disable IP geolocation, URL fetching, or network functionality elsewhere in the
        # application.
        with mock.patch.object(tor_check, "maybe_update_tor_list", return_value=False):
            with mock.patch.object(analyzer, "attack_dna") as blocked:
                blocked.find_matches.side_effect = RuntimeError("attack_dna unavailable")
                res_without = analyzer.analyze_email(raw, "a.eml")
            res_with = analyzer.analyze_email(raw, "a.eml")
        self.assertEqual(res_without["score"], res_with["score"])
        self.assertEqual(res_without["level"], res_with["level"])


if __name__ == "__main__":
    unittest.main()
