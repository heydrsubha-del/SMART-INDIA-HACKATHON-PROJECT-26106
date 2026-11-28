"""Phase 5 tests for the implemented architecture: operator_intel.py is an investigation-scoped, read-only, deterministic analyst-assistance
layer over the output of investigation_agent.investigate(). It is surfaced by investigation_panel.py (Operator tab) and
investigation_agent.render_report() (report section). Decisions are session-only and bound to one scan ID.
The previous version of this file tested a different, never-implemented design (cross-scan impossible-journey / common-operator tracking with
tracker persistence); that design conflicts with the documented privacy model and is intentionally not part of this architecture.
Offline: no network, no database, no Streamlit runtime (a stub is used)."""
import copy
import os
import sys
import unittest
from unittest import mock

import investigation_agent as ia
import operator_intel as op

SID = "SC-" + "a" * 32
OTHER = "SC-" + "b" * 32
HERE = os.path.dirname(os.path.abspath(__file__))


def ev(i, tool="lookup_threat_memory", ind=None, status="ok", origin="historical", signals=None, records=None, missing=None):
    return {"id": "E%d" % i, "tool": tool, "args": {"indicator": ind} if ind is not None else {}, "status": status, "origin": origin,
            "signals": signals or [], "records": records or [], "missing": missing or [], "source": "test"}


def inv(evs=(), findings=None, status="complete", scan_id=SID, score=40, narrative=None, **kw):
    d = {"evidence": list(evs), "findings": findings or [], "status": status, "steps": [], "narrative_findings": narrative or [],
         "score_snapshot": {"score": score, "level": "Medium"} if score is not None else None}
    if scan_id is not None:
        d["scan_id"] = scan_id
    d.update(kw)
    return d


def comp(intel, name):
    return next(c for c in intel["priority"]["components"] if c["factor"] == name)


def src(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()


class Identity(unittest.TestCase):
    def test_ident_normalises_and_respects_max_ident(self):
        self.assertEqual(op._ident(ev(1, ind="  Evil.COM. ")), "evil.com")
        self.assertEqual(op._ident(ev(1, ind="x" * op.MAX_IDENT)), "x" * op.MAX_IDENT)
        self.assertEqual(op._ident(ev(1, ind="x" * (op.MAX_IDENT + 1))), "")
        for bad in ({"id": "E1"}, {"id": "E1", "args": "s"}, {"id": "E1", "args": {"indicator": 5}}, ev(1)):
            self.assertEqual(op._ident(bad), "")

    def test_display_prefix_is_not_identity(self):
        a, b = ev(1, ind="a" * 90 + "1.com"), ev(2, ind="a" * 90 + "2.com")
        self.assertEqual(op._ind(a), op._ind(b))                  # display values collide
        self.assertNotEqual(op._ident(a), op._ident(b))           # identities do not

    def test_latest_keeps_last_attempt_per_tool_and_indicator(self):
        evs = [ev(1, ind="Evil.com", status="failed"), ev(2, ind="evil.com."), ev(3, ind="evil.com", tool="other"), ev(4), ev(5)]
        self.assertEqual({e["id"] for e in op._latest(evs)}, {"E2", "E3", "E4", "E5"})   # no indicator: checks stay separate

    def test_retry_is_not_a_gap(self):
        i = inv([ev(1, ind="evil.com", status="failed"), ev(2, ind="evil.com")])
        recs = op._recommendations(i, op._evs(i))
        self.assertFalse([r for r in recs if r["category"] == "gap"])
        self.assertEqual(op.build_operator_intel(i)["confidence"]["coverage"], 1.0)

    def test_gap_keys_do_not_collide_on_display_prefix(self):
        i = inv([ev(1, ind="a" * 90 + "1.com", status="failed"), ev(2, ind="a" * 90 + "2.com", status="failed")])
        gaps = [r for r in op._recommendations(i, op._evs(i)) if r["category"] == "gap"]
        self.assertEqual(len(gaps), 2)

    def test_oversized_indicators_fall_back_to_evidence_id_and_are_not_truncated(self):
        big = "a" * 600
        i = inv([ev(1, ind=big + "1", status="failed"), ev(2, ind=big + "2", status="failed")])
        self.assertEqual(len([r for r in op._recommendations(i, op._evs(i)) if r["category"] == "gap"]), 2)
        same = inv([ev(1, ind=big, status="failed"), ev(2, ind=big, status="failed")])         # identical oversized check repeated: latest only
        self.assertEqual(len([r for r in op._recommendations(same, op._evs(same)) if r["category"] == "gap"]), 1)

    def test_prefix_sharing_indicators_never_corroborate_each_other(self):
        a = ev(1, ind="a" * 90 + "1.com", origin="historical", signals=["s"])
        b = ev(2, ind="a" * 90 + "2.com", origin="trusted_external", signals=["s"])
        self.assertEqual(comp(op.build_operator_intel(inv([a, b])), "cross_source_correlation")["points"], 0)
        b2 = ev(2, tool="other", ind="A" * 90 + "1.com.", origin="trusted_external", signals=["s"])         # same identity after normalisation
        self.assertAlmostEqual(comp(op.build_operator_intel(inv([a, b2])), "cross_source_correlation")["points"], 6.7, places=1)

    def test_same_origin_class_counts_once_and_unknown_origin_never_corroborates(self):
        a, b = ev(1, ind="x.com", signals=["s"]), ev(2, tool="t2", ind="x.com", signals=["s"])
        self.assertEqual(comp(op.build_operator_intel(inv([a, b])), "cross_source_correlation")["points"], 0)
        c = ev(3, tool="t3", ind="x.com", signals=["s"], origin="made_up")
        self.assertEqual(comp(op.build_operator_intel(inv([a, c])), "cross_source_correlation")["points"], 0)


class Classification(unittest.TestCase):
    def cls(self, findings, evs, narrative=None):
        i = inv(evs, findings=findings, narrative=narrative)
        return op._classify(i, op._evs(i))

    def f(self, kind, ids, text="stmt"):
        return {"kind": kind, "statement": text, "evidence_ids": ids, "finding_id": "F1"}

    def test_verified_is_confirmed_only_when_all_evidence_is_machine_or_trusted(self):
        evs = [ev(1, origin="direct_machine"), ev(2, origin="trusted_external"), ev(3, origin="untrusted_claim"), ev(4, origin="historical")]
        c = self.cls([self.f("verified", ["E1", "E2"]), self.f("verified", ["E1", "E3"]), self.f("verified", ["E4"]), self.f("verified", ["E1", "E9"]),
                      self.f("verified", [])], evs)
        self.assertEqual(len(c["confirmed"]), 1)
        self.assertEqual(len(c["claims"]), 3)                      # sender claim, unknown ID and no ID are never upgraded
        self.assertEqual(len(c["historical"]), 1)

    def test_suspicious_is_probable_and_hypotheses_are_never_confirmed(self):
        c = self.cls([self.f("suspicious", ["E1"])], [ev(1, origin="direct_machine")],
                     narrative=[{"statement": "Attacker is X", "evidence_ids": ["E1"], "supported": True}])
        self.assertEqual((len(c["probable"]), len(c["confirmed"]), len(c["hypotheses"])), (1, 0, 1))
        self.assertEqual(c["hypotheses"][0]["origin"], "model")

    def test_malformed_findings_are_ignored(self):
        c = self.cls(["x", None, {"kind": "other"}, {"kind": "uncertain", "statement": "u"}], [])
        self.assertTrue(all(not v for v in c.values()))


class ConfidenceAndPriority(unittest.TestCase):
    def test_confidence_levels(self):
        self.assertEqual(op._confidence(inv(), [])["level"], "None")
        ok = [ev(i, tool="t%d" % i) for i in range(10)]
        self.assertEqual(op._confidence(inv(ok), ok)["level"], "High")
        self.assertEqual(op._confidence(inv(ok, status="running"), ok)["level"], "Moderate")     # incomplete run is never High
        mix = [ev(1), ev(2, tool="b"), ev(3, tool="c", status="failed")]
        self.assertEqual(op._confidence(inv(mix), mix)["level"], "Moderate")
        low = [ev(1, status="failed"), ev(2, tool="b")]
        self.assertEqual(op._confidence(inv(low), low)["level"], "Low")

    def test_no_evidence_is_floored_not_low_priority(self):
        p = op.build_operator_intel(inv(score=None))["priority"]
        self.assertTrue(p["floored_for_incomplete_evidence"])
        self.assertEqual((p["band"], p["score"]), ("P3 Standard", 25))

    def test_missing_score_and_weights(self):
        i = op.build_operator_intel(inv([ev(1)], score=None))
        self.assertEqual(comp(i, "severity")["points"], 0)
        self.assertIn("unavailable", comp(i, "severity")["basis"])
        self.assertEqual(sum(op.WEIGHTS.values()), 100)
        self.assertEqual(comp(op.build_operator_intel(inv([ev(1)], score=80)), "severity")["points"], 24.0)

    def test_skipped_and_failed_checks_raise_priority_and_are_gaps(self):
        i = inv([ev(1, status="skipped", missing=["feed off"]), ev(2, tool="b", status="failed")])
        intel = op.build_operator_intel(i)
        self.assertGreater(comp(intel, "evidence_gaps")["points"], 0)
        self.assertEqual(len([r for r in intel["recommendations"] if r["category"] == "gap"]), 2)

    def test_scanner_score_and_verdict_are_unchanged(self):
        i = inv([ev(1, signals=["s"], records=[{"tier": "confirmed"}])], score=77)
        res = {"score": 77, "level": "High", "campaign_matches": {"matches": [1, 2]}}
        i0, r0 = copy.deepcopy(i), copy.deepcopy(res)
        intel = op.build_operator_intel(i, res)
        self.assertEqual((i, res), (i0, r0))                       # inputs not mutated
        self.assertEqual(intel["scanner_snapshot"]["score"], 77)
        self.assertEqual(comp(intel, "campaign")["points"], 10.0)

    def test_deterministic(self):
        i = inv([ev(1, signals=["s"]), ev(2, tool="b", status="failed")])
        self.assertEqual(op.build_operator_intel(i, now="T"), op.build_operator_intel(copy.deepcopy(i), now="T"))


class Recommendations(unittest.TestCase):
    def test_recommendations_cite_only_real_evidence(self):
        i = inv([ev(1, records=[{"tier": "confirmed"}], ind="evil.com"), ev(2, tool="b", signals=["s"]), ev(3, tool="c", status="failed")])
        recs = op._recommendations(i, op._evs(i))
        self.assertEqual(recs[0]["category"], "confirmed")
        ids = {e["id"] for e in i["evidence"]}
        self.assertTrue(all(set(r["evidence_ids"]) <= ids for r in recs))

    def test_no_evidence_recommends_running_the_investigation_without_citations(self):
        r = op.build_operator_intel(inv())["recommendations"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["evidence_ids"], [])
        self.assertIn("Run the investigation", r[0]["title"])

    def test_external_lookup_is_optional_and_needs_approval(self):
        recs = op._recommendations(inv([ev(1, ind="evil.com")]), op._evs(inv([ev(1, ind="evil.com")])))
        opt = [r for r in recs if r["category"] == "optional"]
        self.assertEqual(len(opt), 1)
        self.assertTrue(opt[0]["requires_approval"])
        i = inv([ev(1, ind="evil.com")], network_allowed=True)
        self.assertFalse([r for r in op._recommendations(i, op._evs(i)) if r["category"] == "optional"])

    def test_early_stop_adds_a_gap_without_evidence_id(self):
        i = inv([ev(1)], stop_reason="time_limit")
        self.assertTrue([r for r in op._recommendations(i, op._evs(i)) if r["evidence_ids"] == [] and r["category"] == "gap"])

    def test_hypotheses_become_unverified_questions_only(self):
        intel = op.build_operator_intel(inv([ev(1)], narrative=[{"statement": "Attacker is X", "evidence_ids": ["E1"]}]))
        self.assertEqual(len(intel["findings"]["hypotheses"]), 1)
        self.assertFalse(intel["findings"]["confirmed"])
        self.assertIn("unverified hypothesis", [q["type"] for q in intel["unresolved_questions"]])
        self.assertNotIn("Attacker is X", str(intel["unresolved_questions"]))


class EdgeCasesAndFailSoft(unittest.TestCase):
    def test_missing_investigation_is_unavailable(self):
        for bad in (None, "x", 5, []):
            intel = op.build_operator_intel(bad)
            self.assertFalse(intel["available"])
            self.assertTrue(intel["limitations"])

    def test_malformed_evidence_does_not_raise(self):
        i = inv([None, 5, "x", {"id": 3}, {"id": "E1", "tool": "t", "args": "bad", "status": "ok", "records": ["x", None]}])
        intel = op.build_operator_intel(i)
        self.assertTrue(intel["available"])
        self.assertTrue(op.build_operator_intel(inv(evidence="not a list"))["available"])

    def test_internal_failure_is_fail_soft(self):
        intel = op.build_operator_intel(inv(findings=5))
        self.assertFalse(intel["available"])
        self.assertIn("unavailable", "\n".join(op.render_section(intel)))
        with mock.patch.object(op, "_classify", side_effect=RuntimeError("boom")):
            self.assertFalse(op.build_operator_intel(inv([ev(1)]))["available"])

    def test_scan_id_binding(self):
        for bad in (None, 5, "SC-ABC", "sc-" + "a" * 32, "SC-" + "A" * 32, "SC-" + "a" * 31, "SC-" + "a" * 33):
            intel = op.build_operator_intel(inv([ev(1)], scan_id=bad))
            self.assertEqual((intel["bound"], intel["scan_id"]), (False, ""), bad)
        self.assertEqual(op.build_operator_intel(inv([ev(1)]))["scan_id"], SID)

    def test_evidence_list_is_bounded(self):
        self.assertEqual(len(op._evs(inv([ev(i, tool="t%d" % i) for i in range(200)]))), 60)


class Decisions(unittest.TestCase):
    def setUp(self):
        self.intel = op.build_operator_intel(inv([ev(1, status="failed"), ev(2, tool="b", status="failed")]))
        self.ids = [r["id"] for r in self.intel["recommendations"]]

    def test_record_and_read_back(self):
        st = op.new_state(SID)
        op.record_decision(st, self.intel, self.ids[0], "done", "n" * 500)
        a = op.action_status(st, self.intel, self.ids[0])
        self.assertEqual(a["status"], "done")
        self.assertLessEqual(len(a["note"]), 200)
        self.assertEqual(op.action_status(st, self.intel, self.ids[1])["status"], "pending")

    def test_invalid_inputs_are_rejected(self):
        st = op.new_state(SID)
        for args in ((st, self.intel, "Rnope", "done"), (st, self.intel, self.ids[0], "bogus"), (op.new_state(OTHER), self.intel, self.ids[0], "done"),
                     (None, self.intel, self.ids[0], "done"), (st, {"available": False}, self.ids[0], "done"),
                     (st, op.build_operator_intel(inv([ev(1, status="failed")], scan_id=None)), self.ids[0], "done")):
            with self.assertRaises(ValueError):
                op.record_decision(*args)
        self.assertEqual(st["decisions"], {})

    def test_decisions_never_cross_scans(self):
        st = op.new_state(SID)
        op.record_decision(st, self.intel, self.ids[0], "dismissed")
        other = op.build_operator_intel(inv([ev(1, status="failed"), ev(2, tool="b", status="failed")], scan_id=OTHER))
        self.assertEqual(op.action_status(st, other, self.ids[0])["status"], "pending")
        unbound = op.build_operator_intel(inv([ev(1, status="failed")], scan_id=None))
        self.assertEqual(op.action_status(st, unbound, self.ids[0])["status"], "pending")

    def test_decision_limit(self):
        st = op.new_state(SID)
        with mock.patch.object(op, "MAX_DECISIONS", 1):
            op.record_decision(st, self.intel, self.ids[0], "done")
            with self.assertRaises(ValueError):
                op.record_decision(st, self.intel, self.ids[1], "done")
            op.record_decision(st, self.intel, self.ids[0], "dismissed")          # updating an existing decision is still allowed
        self.assertEqual(len(st["decisions"]), 1)


class ReportSection(unittest.TestCase):
    def md(self, i, **kw):
        return "\n".join(op.render_section(op.build_operator_intel(i), **kw))

    @staticmethod
    def part(md, title):
        s = md.index("### " + title)
        e = md.find("\n### ", s + 1)
        return md[s:e if e > 0 else len(md)]

    def test_section_separates_confirmed_from_hypotheses(self):
        i = inv([ev(1, origin="direct_machine")], findings=[{"kind": "verified", "statement": "SPF failed", "evidence_ids": ["E1"]}],
                narrative=[{"statement": "Attacker is X", "evidence_ids": ["E1"]}])
        md = self.md(i)
        self.assertIn("## Operator Intelligence", md)
        self.assertIn("SPF failed", self.part(md, "Confirmed findings"))
        self.assertNotIn("Attacker is X", self.part(md, "Confirmed findings"))
        self.assertIn("Attacker is X", self.part(md, "Hypotheses"))
        self.assertIn("not a verdict", md)

    def test_hypotheses_listed_elsewhere_are_not_repeated(self):
        md = self.md(inv([ev(1)], narrative=[{"statement": "Attacker is X", "evidence_ids": []}]), hypotheses_listed_elsewhere=True)
        self.assertNotIn("Attacker is X", md)
        self.assertIn("listed once", md)

    def test_pipes_are_escaped_and_unbound_is_not_trackable(self):
        i = inv([ev(1, origin="direct_machine", status="failed")], findings=[{"kind": "verified", "statement": "a|b", "evidence_ids": ["E1"]}], scan_id=None)
        md = self.md(i)
        self.assertIn("a\\|b", md)
        self.assertIn("Not trackable (unbound)", md)

    def test_unavailable_and_decisions(self):
        for bad in (None, {"available": False}):
            self.assertIn("unavailable", "\n".join(op.render_section(bad)))
        i = inv([ev(1, status="failed")])
        intel = op.build_operator_intel(i)
        st = op.new_state(SID)
        op.record_decision(st, intel, intel["recommendations"][0]["id"], "done")
        self.assertIn("Analyst decisions (this scan", "\n".join(op.render_section(intel, st)))
        self.assertNotIn("Analyst decisions", "\n".join(op.render_section(intel, op.new_state(OTHER))))



def fake_streamlit(choice=None):
    st = mock.MagicMock()
    st.session_state = {}
    st.columns.return_value = [mock.MagicMock(), mock.MagicMock(), mock.MagicMock()]
    st.selectbox.side_effect = lambda label, opts, index=0, **kw: choice or opts[index]
    return st


class StreamlitPanel(unittest.TestCase):
    def run_panel(self, i, key="k", st=None):
        st = st or fake_streamlit()
        with mock.patch.dict(sys.modules, {"streamlit": st}):
            return op.render_streamlit(i, {"score": 1}, key), st

    def test_bound_investigation_creates_scan_bound_state_only(self):
        intel, st = self.run_panel(inv([ev(1, status="failed")]))
        self.assertTrue(intel["available"])
        s = st.session_state["operator_intel_state"]["k"]
        self.assertEqual((s["scan_id"], s["decisions"]), (SID, {}))

    def test_unbound_investigation_creates_no_state(self):
        _, st = self.run_panel(inv([ev(1, status="failed")], scan_id=None))
        self.assertEqual(st.session_state["operator_intel_state"], {})
        st.info.assert_called()

    def test_another_scan_never_inherits_decisions(self):
        st = fake_streamlit()
        st.session_state["operator_intel_state"] = {"k": {"scan_id": OTHER, "decisions": {"R1": {"status": "done"}}}}
        self.run_panel(inv([ev(1, status="failed")]), st=st)
        s = st.session_state["operator_intel_state"]["k"]
        self.assertEqual((s["scan_id"], s["decisions"]), (SID, {}))

    def test_selection_is_recorded_for_this_scan_only(self):
        i = inv([ev(1, status="failed")])
        intel, st = self.run_panel(i, st=fake_streamlit("done"))
        s = st.session_state["operator_intel_state"]["k"]
        self.assertEqual({r["id"] for r in intel["recommendations"]}, set(s["decisions"]))
        self.assertEqual(s["scan_id"], SID)

    def test_unavailable_is_fail_soft(self):
        intel, st = self.run_panel(None)
        self.assertFalse(intel["available"])
        st.caption.assert_called()


class IntegrationBoundaries(unittest.TestCase):
    def test_report_integration_is_fail_soft(self):
        s = src("investigation_agent.py")
        a = s.index("import operator_intel")
        self.assertIn("try:", s[a - 400:a])
        self.assertIn("operator_intel.render_section(operator_intel.build_operator_intel(inv, result), decisions", s)
        self.assertIn("Operator Intelligence was unavailable for this report", s[a:a + 900])

    def test_panel_has_operator_tab_and_is_fail_soft(self):
        s = src("investigation_panel.py")
        self.assertIn('"Operator"', s)
        a = s.index("operator_intel.render_streamlit(inv, result, key)")
        self.assertIn("try:", s[a - 300:a])
        self.assertIn("except Exception:", s[a:a + 200])
        self.assertIn("decisions=_st", s)

    def test_module_is_read_only_and_makes_no_network_or_storage_calls(self):
        s = src("operator_intel.py")
        for banned in ("import requests", "urllib.request", "urlopen", "import socket", "http.client", "httpx", "supabase", "sqlite3", "tracker",
                       "get_connection", "shared=True", "contribution", "classifier", "nomic_embed", "geolocate", "os.environ", "subprocess"):
            self.assertNotIn(banned, s, banned)

    def test_no_second_operator_api_and_protected_modules_do_not_reference_it(self):
        for name in ("analyzer.py", "report.py", "risk.py", "attack_dna.py", "correlate.py", "retro_hunt.py", "classifier.py", "tracker.py",
                     "entity_graph.py", "origin_intel.py", "geolocate.py", "campaign_intel.py", "contribution_client.py", "nomic_embed.py", "config.py"):
            self.assertNotIn("operator_intel", src(name), name)
        for gone in ("assess_journey", "extract_event", "evaluate_pair"):
            self.assertFalse(hasattr(op, gone), gone)            # cross-scan journey tracking is intentionally not implemented


if __name__ == "__main__":
    unittest.main()
