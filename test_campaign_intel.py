"""Phase 3 tests: campaign_intel.py (pure) + analyzer/agent/report integration. Offline, isolated temp DBs."""
import copy
import inspect
import re
import unittest
from unittest import mock

import analyzer
import attack_dna as dna
import campaign_intel as ci
import investigation_agent as ia
import report
import tracker
from test_attack_dna import mk_result, _tmp_db


def sid(n):
    return "SC-%032x" % n


def fp(auth=(("high", "SPF fail"), ("high", "DKIM fail")), url=(("URL shortener hides the real destination",),),
       infra="tor", country="DE", **kw):
    return dna.extract_features(mk_result("x", anomalies=auth, url_flags=url, infra=infra, country=country, **kw))


def row(n, features, ts="2026-01-0%d 10:00:00"):
    return {"scan_id": sid(n), "features": features, "created_at": ts % n}


def intel(cur, rows):
    """Run the real Phase 2 comparison over rows exactly as find_matches() would, then Phase 3."""
    matches = []
    for r in rows:
        c = dna.compare_fingerprints(cur, r["features"])
        if c["classification"] != "none":
            matches.append(dict(c, scan_id=r["scan_id"], created_at=r["created_at"]))
    matches.sort(key=lambda m: (-m["score"], m["scan_id"]))
    rep = {"status": "ok", "matches": matches[:5], "history_checked": len(rows)}
    return ci.build_campaign_intel(cur, rep, rows)


SPECIFIC = dict(auth=(("high", "SPF fail"), ("high", "DKIM fail"), ("high", "DMARC fail")),
                url=(("URL shortener hides the real destination",), ("Punycode host - may render as look-alike Unicode letters",)))


class Timeline(unittest.TestCase):
    def test_ordered_by_storage_time_then_id_and_labelled_honestly(self):
        cur = fp(**SPECIFIC)
        rows = [row(3, fp(**SPECIFIC)), row(1, fp(**SPECIFIC)), row(2, fp(**SPECIFIC))]
        out = intel(cur, rows)
        self.assertEqual([o["scan_id"] for o in out["observations"]], [sid(1), sid(2), sid(3)])
        self.assertIn("storage time", out["timeline_basis"])
        self.assertIn("Not every scan", out["timeline_basis"])

    def test_tied_timestamps_are_deterministic(self):
        cur = fp(**SPECIFIC)
        rows = [dict(row(n, fp(**SPECIFIC)), created_at="2026-01-01 00:00:00") for n in (5, 4, 6)]
        a, b = intel(cur, rows), intel(cur, list(reversed(rows)))
        self.assertEqual(a["observations"], b["observations"])

    def test_missing_timestamp_never_invented(self):
        cur = fp(**SPECIFIC)
        r = dict(row(1, fp(**SPECIFIC)), created_at="garbage")
        out = intel(cur, [r])
        self.assertIsNone(out["relationships"][0]["observed_at"])


class Infrastructure(unittest.TestCase):
    def test_unchanged(self):
        d = ci.compare_infrastructure(fp(), fp())
        self.assertEqual(d["infra_class"]["status"], "unchanged")
        self.assertEqual(d["country"]["status"], "unchanged")

    def test_rotation_is_confirmed_only_when_both_sides_explicit(self):
        d = ci.compare_infrastructure(fp(infra="tor", country="DE"), fp(infra="hosting", country="US"))
        self.assertEqual(d["infra_class"], {"status": "changed", "earlier": ["hosting"], "current": ["tor"]})
        self.assertEqual(d["country"]["status"], "changed")

    def test_missing_side_is_unavailable_never_changed(self):
        for other in (fp(infra="", country=""), {}, {"families": {"infra_class": "bad"}}, None):
            d = ci.compare_infrastructure(fp(), other)
            self.assertEqual(d["infra_class"]["status"], "unavailable")
            self.assertEqual(d["country"]["status"], "unavailable")

    def test_categories_judged_independently(self):
        d = ci.compare_infrastructure(fp(infra="tor", country="DE"), fp(infra="tor", country=""))
        self.assertEqual(d["infra_class"]["status"], "unchanged")
        self.assertEqual(d["country"]["status"], "unavailable")

    def test_hostile_tags_rejected(self):
        evil = {"families": {"infra_class": ["203.0.113.9", "user@evil.example", "country:ZZ", "country:de"]}}
        d = ci.compare_infrastructure(fp(), evil)
        self.assertEqual(d["infra_class"]["status"], "unavailable")
        self.assertNotIn("203.0.113.9", repr(d))

    def test_similar_campaign_different_infrastructure_still_related(self):
        cur = fp(infra="tor", country="DE", **SPECIFIC)
        out = intel(cur, [row(1, fp(infra="hosting", country="US", **SPECIFIC))])
        r = out["relationships"][0]
        self.assertEqual(r["infrastructure"]["infra_class"]["status"], "changed")
        self.assertIn(r["classification"], ("strong", "weak"))
        self.assertNotIn("infra_class", r["supporting_families"])

    def test_infrastructure_overlap_alone_is_not_a_relationship(self):
        same = dict(from_domain="evil.example", reply_domain="evil.example", return_domain="evil.example")
        cur = fp(auth=(), url=(), infra="tor", country="DE", **same)
        other = fp(auth=(("high", "SPF fail"),), url=(("Punycode host - may render as look-alike Unicode letters",),), infra="tor", country="DE", **same)
        out = intel(cur, [row(1, other)])
        self.assertEqual(out["relationships"], [])
        self.assertEqual(out["status"], "no_related_observations")


class Relationships(unittest.TestCase):
    def test_phase2_values_passed_through_unchanged_no_second_score(self):
        cur = fp(**SPECIFIC)
        r0 = row(1, fp(**SPECIFIC))
        c = dna.compare_fingerprints(cur, r0["features"])
        r = intel(cur, [r0])["relationships"][0]
        self.assertEqual((r["classification"], r["phase2_score"], r["phase2_confidence"]),
                         (c["classification"], c["score"], c["confidence"]))
        self.assertFalse([k for k in r if "confidence_score" in k or k == "score"])

    def test_context_families_are_not_counted_as_support(self):
        cur = fp(**SPECIFIC)
        r = intel(cur, [row(1, fp(**SPECIFIC))])["relationships"][0]
        self.assertTrue({"infra_class", "structural"} & set(r["context_only_families"]))
        self.assertFalse({"infra_class", "structural"} & set(r["supporting_families"]))

    def test_generic_feature_false_positive_not_promoted(self):
        generic = dict(auth=(), url=(("URL shortener hides the real destination",),))
        cur, other = fp(**generic), fp(**generic)
        out = intel(cur, [row(1, other)])
        self.assertTrue(all(x["classification"] != "strong" for x in out["relationships"]))

    def test_evidence_provenance_and_limitations(self):
        cur = fp(**SPECIFIC)
        out = intel(cur, [row(7, fp(**SPECIFIC))])
        r = out["relationships"][0]
        self.assertEqual(r["observation_ref"], sid(7))
        self.assertTrue(r["limitations"])
        self.assertTrue(any("not confirmed common authorship" in s for s in out["limitations"]))
        self.assertNotIn("same attacker", repr(out).lower().replace("not the same attacker", ""))

    def test_missing_matched_record_marks_infra_unavailable(self):
        cur = fp(**SPECIFIC)
        c = dna.compare_fingerprints(cur, fp(**SPECIFIC))
        rep = {"status": "ok", "history_checked": 1, "matches": [dict(c, scan_id=sid(1), created_at="2026-01-01 00:00:00")]}
        r = ci.build_campaign_intel(cur, rep, [])["relationships"][0]       # history rows missing
        self.assertEqual(r["infrastructure"]["infra_class"]["status"], "unavailable")
        self.assertTrue(any("not available" in s for s in r["limitations"]))

    def test_tactic_changes_only_when_both_sides_have_data(self):
        t = ci.tactic_changes(fp(**SPECIFIC), fp(auth=(), url=SPECIFIC["url"]))
        self.assertEqual(t["auth_anomalies"]["status"], "unavailable")
        self.assertEqual(t["url_tactics"]["status"], "unchanged")


class Robustness(unittest.TestCase):
    def test_empty_history(self):
        out = ci.build_campaign_intel(fp(), {"status": "ok", "matches": [], "history_checked": 0}, [])
        self.assertEqual((out["status"], out["relationships"]), ("no_history", []))

    def test_storage_unavailable_not_reported_as_empty(self):
        out = ci.build_campaign_intel(fp(), {"status": "storage_unavailable", "matches": [], "history_checked": 0}, [])
        self.assertEqual(out["status"], "unavailable")

    def test_malformed_inputs_never_raise(self):
        for a, b, c in ((None, None, None), ({}, [], 5), (fp(), {"status": "ok", "history_checked": "x", "matches": 3}, "z"),
                        (fp(), {"status": "ok", "history_checked": 2, "matches": [None, 5, {"scan_id": "bad", "classification": "strong"},
                                                                                {"scan_id": sid(1), "classification": "none"}]}, [None, {"scan_id": 3}])):
            out = ci.build_campaign_intel(a, b, c)
            self.assertIn("status", out)
            self.assertEqual(out["relationships"], [])

    def test_malformed_matches_counted_and_skipped(self):
        rep = {"status": "ok", "history_checked": 3, "matches": [{"scan_id": "bad", "classification": "strong"}, "x"]}
        self.assertEqual(ci.build_campaign_intel(fp(), rep, [])["skipped_malformed"], 2)

    def test_bounded_and_deduplicated(self):
        cur = fp(**SPECIFIC)
        rows = [row(n % 9 + 1, fp(**SPECIFIC)) for n in range(40)]
        out = intel(cur, rows)
        self.assertLessEqual(len(out["relationships"]), ci.MAX_RELATIONSHIPS)
        ids = [r["observation_ref"] for r in out["relationships"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_pure_no_mutation_and_no_io_imports(self):
        cur, rows = fp(**SPECIFIC), [row(1, fp(**SPECIFIC))]
        before = copy.deepcopy((cur, rows))
        intel(cur, rows)
        self.assertEqual((cur, rows), before)
        src = inspect.getsource(ci)
        for banned in ("tracker", "sqlite3", "requests", "streamlit", "import socket"):
            self.assertNotIn(banned, src.replace("never touches", ""))

    def test_privacy_output_contains_only_ids_timestamps_and_tags(self):
        cur = fp(from_domain="secret-bank.example", reply_domain="drop.example", **SPECIFIC)
        out = repr(intel(cur, [row(1, fp(**SPECIFIC))]))
        for leak in ("secret-bank", "drop.example", "@", "http", "Subject"):
            self.assertNotIn(leak, out)
        self.assertTrue(set(re.findall(r"SC-\w+", out)) <= {sid(1)})


class Persistence(unittest.TestCase):
    def setUp(self):
        _tmp_db(self)

    def test_history_sink_reuses_single_bounded_read_and_is_optional(self):
        for n in range(3):
            r = mk_result(sid(n + 1))
            dna.save_fingerprint(sid(n + 1), dna.extract_features(r))
        sink = []
        calls = []
        orig = dna._query_recent_fingerprints
        with mock.patch.object(dna, "_query_recent_fingerprints", side_effect=lambda **k: calls.append(k) or orig(**k)):
            _, rep = dna.find_matches(mk_result(sid(9)), history_sink=sink)
        self.assertEqual(len(calls), 1)                      # no second query
        self.assertEqual(len(sink), rep["history_checked"])
        self.assertLessEqual(len(sink), dna.MAX_HISTORY)
        _, rep2 = dna.find_matches(mk_result(sid(10)))        # default call shape unchanged
        self.assertEqual(rep2["status"], "ok")
        self.assertIsNone(inspect.signature(dna.find_matches).parameters["history_sink"].default)

    def test_database_unavailable_degrades(self):
        sink = []
        with mock.patch.object(tracker, "get_connection", side_effect=RuntimeError("down")):
            f, rep = dna.find_matches(mk_result(sid(1)), history_sink=sink)
        self.assertEqual(sink, [])
        self.assertEqual(ci.build_campaign_intel(f, rep, sink)["status"], "unavailable")

    def test_multi_user_isolation(self):
        with mock.patch.object(tracker, "MULTIUSER", True), mock.patch.object(tracker, "_session_id", return_value="A"):
            dna.save_fingerprint(sid(1), fp(**SPECIFIC))
        sink = []
        with mock.patch.object(tracker, "MULTIUSER", True), mock.patch.object(tracker, "_session_id", return_value="B"):
            f, rep = dna.find_matches(mk_result(sid(2), anomalies=SPECIFIC["auth"], url_flags=SPECIFIC["url"]), history_sink=sink)
        self.assertEqual(sink, [])
        self.assertEqual(ci.build_campaign_intel(f, rep, sink)["status"], "no_history")


def _scan_result(n, **kw):
    r = mk_result(sid(n), anomalies=SPECIFIC["auth"], url_flags=SPECIFIC["url"], **kw)
    r["campaign_fingerprint"], rep = None, None
    sink = []
    r["campaign_fingerprint"], rep = dna.find_matches(r, history_sink=sink)
    r["campaign_matches"] = rep
    r["campaign_intel"] = ci.build_campaign_intel(r["campaign_fingerprint"], rep, sink)
    return r


class Integration(unittest.TestCase):
    def setUp(self):
        _tmp_db(self)
        _scan_result(1, infra="hosting", country="US")
        self.res = _scan_result(2, infra="tor", country="DE")

    def test_agent_section_cites_real_evidence_and_appends_without_renumbering(self):
        reg, fnd = ia.build_scan_evidence(self.res)
        base = copy.deepcopy(self.res)
        base["campaign_intel"] = None
        reg0, _ = ia.build_scan_evidence(base)
        self.assertEqual(reg[:len(reg0)], reg0)               # existing evidence IDs untouched
        new = [e for e in reg if e["source"] == "campaign_intel"]
        self.assertTrue(new)
        ids = {e["id"] for e in reg}
        self.assertTrue(all(set(f["evidence_ids"]) <= ids for f in fnd))
        mine = [f for f in fnd if set(f["evidence_ids"]) & {e["id"] for e in new}]
        self.assertTrue(mine and all(f["kind"] == "uncertain" for f in mine))   # never escalates to suspicious/verified
        txt = " ".join(f["statement"] for f in mine).lower()
        self.assertIn("not confirmed common authorship", txt)
        self.res["evidence_register"], self.res["scan_findings"] = reg, fnd
        self.assertEqual(ia.validate_scan_register(self.res), [])

    def test_infra_change_finding_does_not_claim_continuity(self):
        _, fnd = ia.build_scan_evidence(self.res)
        s = " ".join(f["statement"] for f in fnd if "infrastructure" in f["statement"])
        self.assertIn("neither establishes nor rules out", s)

    def test_report_section_and_backward_compat(self):
        self.res["evidence_register"], self.res["scan_findings"] = ia.build_scan_evidence(self.res)
        md = "\n".join(report.scan_evidence_md(self.res))
        self.assertIn("Campaign intelligence (Phase 3)", md)
        self.assertIn(sid(1), md)
        legacy = {k: v for k, v in self.res.items() if k != "campaign_intel"}
        md2 = "\n".join(report.scan_evidence_md(legacy))
        self.assertNotIn("Campaign intelligence (Phase 3)", md2)
        self.assertEqual(report.campaign_intel_md({"campaign_intel": "junk"}), [])
        self.assertEqual(report.campaign_intel_md(None), [])

    def test_risk_untouched_by_phase3(self):
        import risk
        src = inspect.getsource(risk)
        self.assertNotIn("campaign_intel", src)
        self.assertNotIn("campaign_matches", src)

    def test_analyzer_wiring_failsoft(self):
        src = inspect.getsource(analyzer)
        self.assertIn("campaign_intel.build_campaign_intel", src)
        self.assertIn("history_sink=_hist", src)


if __name__ == "__main__":
    unittest.main()
