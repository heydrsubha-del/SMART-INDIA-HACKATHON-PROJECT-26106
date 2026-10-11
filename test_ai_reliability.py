"""URL prompt-cap truthfulness, completion metadata, and report-completeness checks (no live model calls)."""
import json, sys, types, unittest
from unittest import mock

try:
    import cloud_backend  # noqa: F401
except Exception:
    stub = types.ModuleType("cloud_backend")
    stub.BackendError = Exception
    stub.resolve_backend = lambda *a, **k: None
    sys.modules["cloud_backend"] = stub

import ioc_extract
import ollama_threat as O
import test_ai_evidence as T


def _urls_body(n=12, bad_at=11):
    urls = ["https://example.org/page%d" % i for i in range(n)]
    urls[bad_at] = "https://paypa1-secure-login.example.net/verify/password"
    return "Links:\n" + "\n".join(urls)


class UrlCap(unittest.TestCase):
    def setUp(self):
        self.iocs = ioc_extract.extract({"subject": "s", "body_text": _urls_body()})

    def test_machine_pipeline_sees_all_urls_and_the_late_suspicious_one(self):
        self.assertEqual(len(self.iocs["urls"]), 12)
        self.assertEqual(self.iocs["counts"]["urls"], 12)
        self.assertTrue(any("paypa1" in u["url"] for u in self.iocs["suspicious_urls"]))
        self.assertGreaterEqual(self.iocs["url_score"], 0.5)

    def test_prompt_prioritises_suspicious_and_reports_omitted_count(self):
        res = T.result_for(T.raw_mail()); res["iocs"] = self.iocs
        ma = O.build_evidence(res)["machine_analysis"]
        self.assertEqual(len(ma["urls"]), 10)
        self.assertIn("paypa1", ma["urls"][0]["url"])
        self.assertEqual(ma["prompt_limits"]["urls"], {"total": 12, "shown_to_you": 10, "omitted_from_prompt": 2})
        self.assertIn("heuristic", ma["prompt_limits"]["note"])
        self.assertIn("not proof", ma["prompt_limits"]["note"])

    def test_source_data_not_mutated_or_deduplicated(self):
        res = T.result_for(T.raw_mail()); res["iocs"] = self.iocs
        before = json.dumps(self.iocs, sort_keys=True)
        O.build_evidence(res)
        self.assertEqual(json.dumps(self.iocs, sort_keys=True), before)
        self.assertEqual(len(self.iocs["urls"]), 12)

    def test_no_omission_when_under_limit(self):
        ma = O.build_evidence(T.result_for(T.raw_mail()))["machine_analysis"]
        self.assertEqual(ma["prompt_limits"]["urls"]["omitted_from_prompt"], 0)


class Sections(unittest.TestCase):
    FULL = "\n".join("## %s:\ntext" % s for s in O.REQUIRED_SECTIONS)

    def test_full_report_complete(self):
        self.assertEqual(O._missing_sections(self.FULL), [])

    def test_verdict_only_is_incomplete(self):
        m = O._missing_sections("THREAT VERDICT:\nLow risk.")
        self.assertIn("VPN / TOR / ANONYMIZATION", m); self.assertIn("ANALYST NOTE", m)

    def test_heading_format_variants_accepted(self):
        self.assertNotIn("VPN / TOR / ANONYMIZATION", O._missing_sections("**VPN/TOR/ANONYMIZATION**"))


class Meta(unittest.TestCase):
    def test_unavailable_is_none_not_zero(self):
        d = O._completion_diagnostics(O._new_meta("local"), self_full())
        self.assertIsNone(d["prompt_tokens"]); self.assertIsNone(d["completion_tokens"])
        self.assertIsNone(d["output_truncated"]); self.assertIsNone(d["prompt_may_exceed_context"])
        self.assertTrue(d["complete"])

    def test_length_stop_is_confirmed_truncation(self):
        m = O._new_meta("local"); m["finish_reason"] = "length"
        d = O._completion_diagnostics(m, self_full())
        self.assertTrue(d["output_truncated"]); self.assertFalse(d["complete"])

    def test_stop_reason_not_truncated(self):
        m = O._new_meta("local"); m["finish_reason"] = "stop"
        self.assertFalse(O._completion_diagnostics(m, self_full())["output_truncated"])

    def test_prompt_at_context_limit_flagged_as_possible_only(self):
        m = O._new_meta("local"); m.update(prompt_tokens=16384, context_limit=16384, finish_reason="stop")
        d = O._completion_diagnostics(m, self_full())
        self.assertTrue(d["prompt_may_exceed_context"]); self.assertFalse(d["output_truncated"])

    def test_diagnostics_hold_no_prompt_or_body(self):
        d = O._completion_diagnostics(O._new_meta("cloud"), self_full())
        self.assertEqual(set(d), {"backend", "model", "finish_reason", "prompt_tokens", "completion_tokens", "output_limit",
                                  "context_limit", "output_truncated", "prompt_may_exceed_context",
                                  "missing_sections", "complete"})


def self_full():
    return Sections.FULL


class _Resp:
    def __init__(self, lines, status=200): self.lines, self.status_code = lines, status
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def raise_for_status(self): pass
    def iter_lines(self): return iter(self.lines)


class StreamCapture(unittest.TestCase):
    def test_ollama_captures_done_reason_and_counts(self):
        lines = [json.dumps({"message": {"content": "THREAT VERDICT: x"}, "done": False}).encode(),
                 json.dumps({"done": True, "done_reason": "length", "eval_count": 2500, "prompt_eval_count": 4000}).encode()]
        meta = {}
        with mock.patch.object(O.requests, "post", return_value=_Resp(lines)):
            O._stream_ollama({"options": {}}, 5, 10, None, meta=meta)
        self.assertEqual((meta["finish_reason"], meta["completion_tokens"], meta["prompt_tokens"]), ("length", 2500, 4000))

    def test_groq_captures_finish_reason_and_usage_when_present(self):
        lines = [b'data: ' + json.dumps({"choices": [{"delta": {"content": "hi"}}]}).encode(),
                 b'data: ' + json.dumps({"choices": [{"delta": {}, "finish_reason": "length"}],
                                         "x_groq": {"usage": {"prompt_tokens": 900, "completion_tokens": 1024}}}).encode()]
        meta = {}
        with mock.patch.object(O.requests, "post", return_value=_Resp(lines)):
            O._stream_groq({"options": {}}, "k", 5, 10, None, meta=meta)
        self.assertEqual((meta["finish_reason"], meta["prompt_tokens"], meta["completion_tokens"]), ("length", 900, 1024))

    def test_groq_without_usage_stays_none(self):
        lines = [b'data: ' + json.dumps({"choices": [{"delta": {}, "finish_reason": "stop"}]}).encode()]
        meta = O._new_meta("cloud")
        with mock.patch.object(O.requests, "post", return_value=_Resp(lines)):
            O._stream_groq({"options": {}}, "k", 5, 10, None, meta=meta)
        self.assertIsNone(meta["prompt_tokens"]); self.assertIsNone(meta["completion_tokens"])


class EndToEnd(unittest.TestCase):
    def _run(self, answer, reason):
        def fake_request(payload, meta=None, **k):
            meta.update(O._new_meta("local")); meta["finish_reason"] = reason
            return answer
        with mock.patch.object(O, "_request", side_effect=fake_request):
            return O.analyze_with_ollama(T.result_for(T.raw_mail()))

    def test_truncated_report_flagged_in_text_and_diagnostics(self):
        r = self._run("THREAT VERDICT:\nLow.", "length")
        self.assertTrue(r["ok"]); self.assertFalse(r["diagnostics"]["complete"])
        self.assertIn("output-token limit", r["analysis"])

    def test_complete_report_has_no_incomplete_note(self):
        r = self._run(Sections.FULL, "stop")
        self.assertTrue(r["diagnostics"]["complete"]); self.assertNotIn("may be incomplete", r["analysis"])


class BackendIdentity(unittest.TestCase):
    def _run(self, backend, lines):
        with mock.patch.object(O, "resolve_backend", return_value=(backend, "k" if backend == "cloud" else None)), \
             mock.patch.object(O, "_ollama_available", return_value=backend == "local"), \
             mock.patch.object(O.requests, "post", return_value=_Resp(lines)):
            return O.analyze_with_ollama(T.result_for(T.raw_mail()))

    def test_local_reports_ollama_and_qwen_model(self):
        lines = [json.dumps({"message": {"content": Sections.FULL}, "done": False}).encode(),
                 json.dumps({"done": True, "done_reason": "stop", "eval_count": 700, "prompt_eval_count": 3000}).encode()]
        r = self._run("local", lines)
        self.assertEqual((r["backend"], r["model"]), ("local", O.OLLAMA_MODEL))
        self.assertEqual(r["diagnostics"]["prompt_tokens"], 3000)
        self.assertIn("Ollama (local)", O.generation_summary(r)); self.assertIn("complete", O.generation_summary(r))

    def test_cloud_reports_groq_model_not_qwen(self):
        lines = [b"data: " + json.dumps({"choices": [{"delta": {"content": Sections.FULL}}]}).encode(),
                 b"data: " + json.dumps({"choices": [{"delta": {}, "finish_reason": "stop"}]}).encode(),
                 b"data: " + json.dumps({"choices": [], "x_groq": {"usage": {"prompt_tokens": 1500, "completion_tokens": 640}}}).encode(),
                 b"data: [DONE]"]
        r = self._run("cloud", lines)
        self.assertEqual((r["backend"], r["model"]), ("cloud", O.GROQ_MODEL))
        self.assertNotEqual(r["model"], O.OLLAMA_MODEL)
        self.assertEqual((r["diagnostics"]["prompt_tokens"], r["diagnostics"]["completion_tokens"]), (1500, 640))
        self.assertIn("Groq (cloud)", O.generation_summary(r))

    def test_groq_usage_in_separate_final_chunk_after_finish(self):
        lines = [b"data: " + json.dumps({"choices": [{"delta": {"content": "x"}, "finish_reason": "length"}]}).encode(),
                 b"data: " + json.dumps({"choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 22}}).encode(),
                 b"data: [DONE]"]
        meta = {}
        with mock.patch.object(O.requests, "post", return_value=_Resp(lines)):
            O._stream_groq({"options": {}}, "k", 5, 10, None, meta=meta)
        self.assertEqual((meta["finish_reason"], meta["prompt_tokens"], meta["completion_tokens"]), ("length", 11, 22))

    def test_summary_marks_unavailable_not_zero_and_has_no_content(self):
        r = {"diagnostics": O._completion_diagnostics(dict(O._new_meta("cloud"), model="m"), "THREAT VERDICT: SECRETBODY")}
        t = O.generation_summary(r)
        self.assertIn("prompt tokens: unavailable", t); self.assertNotIn("tokens: 0", t)
        self.assertNotIn("SECRETBODY", t); self.assertIn("possibly incomplete", t)

    def test_summary_empty_without_diagnostics(self):
        self.assertEqual(O.generation_summary({"ok": True}), "")


class Groq413(unittest.TestCase):
    def _resp413(self):
        r = _Resp([], 413)
        err = O.requests.exceptions.HTTPError("413 Payload Too Large")
        err.response = r
        r.raise_for_status = mock.Mock(side_effect=err)
        return r

    def _run(self, responses, res=None):
        bodies = []
        def post(url, **kw):
            bodies.append(len(json.dumps(kw.get("json"))))
            return responses.pop(0)
        ok = [b"data: " + json.dumps({"choices": [{"delta": {"content": Sections.FULL}, "finish_reason": "stop"}]}).encode(),
              b"data: [DONE]"]
        responses = [self._resp413() if r == "413" else _Resp(ok) for r in responses]
        res = res or T.result_for(T.raw_mail())
        with mock.patch.object(O, "resolve_backend", return_value=("cloud", "k")), \
             mock.patch.object(O, "_ollama_available", return_value=False), \
             mock.patch.object(O.requests, "post", side_effect=post):
            return O.analyze_with_ollama(res), bodies

    def _big(self):
        res = T.result_for(T.raw_mail())
        res["parsed"]["body_text"] = "word " * 4000
        return res

    def test_413_retries_once_with_smaller_prompt_and_succeeds(self):
        r, bodies = self._run(["413", "ok"], self._big())
        self.assertTrue(r["ok"]); self.assertEqual(len(bodies), 2); self.assertLess(bodies[1], bodies[0])
        self.assertEqual(r["backend"], "cloud")

    def test_compact_prompt_labels_reduction_and_keeps_counts(self):
        res = self._big(); res["iocs"] = ioc_extract.extract({"subject": "s", "body_text": _urls_body()})
        ma = O.build_evidence(res, compact=True)["machine_analysis"]
        self.assertIn("Reduced evidence", ma["compact_mode"])
        self.assertEqual(ma["prompt_limits"]["urls"], {"total": 12, "shown_to_you": 5, "omitted_from_prompt": 7})
        self.assertIs(O.build_evidence(res)["machine_analysis"]["compact_mode"], False)

    def test_persistent_413_gives_clear_backend_neutral_error(self):
        r, bodies = self._run(["413", "413"])
        self.assertFalse(r["ok"]); self.assertEqual(len(bodies), 2)
        self.assertIn("413", r["error"]); self.assertNotIn("Ollama", r["error"])


class RetroHuntDiscrepancy(unittest.TestCase):
    """Machine: 11 earlier local sightings, 0 feed matches. Mocked Groq answer claims zero."""
    BAD = Sections.FULL + "\nFORENSIC EVIDENCE: Local memory matches: 0; URLhaus matches: 0. There are no earlier local sightings."

    def _groq(self, res, answer):
        sent = []
        def post(url, **kw):
            sent.append(json.dumps(kw["json"]["messages"]))
            return _Resp([b"data: " + json.dumps({"choices": [{"delta": {"content": answer}, "finish_reason": "stop"}]}).encode(),
                          b"data: [DONE]"])
        with mock.patch.object(O, "resolve_backend", return_value=("cloud", "k")), \
             mock.patch.object(O, "_ollama_available", return_value=False), \
             mock.patch.object(O.requests, "post", side_effect=post):
            return O.analyze_with_ollama(res), sent[0]

    def _res(self, retro=True):
        res = T.result_for(T.raw_mail())
        res["intelligence"] = {}          # as the real pipeline: the key is never populated
        if retro:
            res["retro_hunt"] = {"emails": 0, "email_rows": 0, "intel": 11, "intel_feed": 0, "log": 0}
        return res

    def test_prompt_carries_machine_counts_not_a_fabricated_zero(self):
        ma = O.build_evidence(self._res())["machine_analysis"]
        self.assertEqual(ma["local_memory_matches"], 11)
        self.assertEqual(ma["threat_memory"]["earlier_local_sightings"], 11)
        self.assertEqual(ma["threat_memory"]["external_feed_matches"], 0)

    def test_groq_prompt_sent_contains_11_and_local_vs_feed_distinction(self):
        r, prompt = self._groq(self._res(), Sections.FULL)
        self.assertIn('\\"local_memory_matches\\": 11', prompt)
        self.assertIn("NOT evidence of malice", prompt)
        self.assertEqual(r["backend"], "cloud")

    def test_groq_zero_claim_is_corrected_with_machine_counts(self):
        r, _ = self._groq(self._res(), self.BAD)
        self.assertIn("recorded 11 earlier local sighting(s) and 0 external-feed", r["analysis"])
        self.assertIn("not confirmed malicious", r["analysis"])

    def test_consistent_answer_gets_no_note(self):
        good = Sections.FULL + "\nThe app recorded 11 earlier local sightings and 0 external feed matches."
        r, _ = self._groq(self._res(), good)
        self.assertNotIn("Retro-Hunt recorded", r["analysis"])

    def test_without_retro_result_counts_are_not_evaluated_not_zero(self):
        ma = O.build_evidence(self._res(retro=False))["machine_analysis"]
        self.assertEqual(ma["local_memory_matches"], "not evaluated")
        self.assertEqual(ma["urlhaus_matches"], "not evaluated")
        r, _ = self._groq(self._res(retro=False), self.BAD)
        self.assertNotIn("Retro-Hunt recorded", r["analysis"])

    def test_explicit_pipeline_values_still_win(self):
        res = self._res(); res["intelligence"] = {"urlhaus_matches": 2, "local_memory_matches": 5}
        ma = O.build_evidence(res)["machine_analysis"]
        self.assertEqual((ma["urlhaus_matches"], ma["local_memory_matches"]), (2, 5))

    def test_local_qwen_path_same_counts(self):
        lines = [json.dumps({"message": {"content": Sections.FULL}, "done": False}).encode(),
                 json.dumps({"done": True, "done_reason": "stop"}).encode()]
        with mock.patch.object(O, "resolve_backend", return_value=("local", None)), \
             mock.patch.object(O, "_ollama_available", return_value=True), \
             mock.patch.object(O.requests, "post", return_value=_Resp(lines)) as post:
            r = O.analyze_with_ollama(self._res())
        self.assertEqual(r["backend"], "local")
        self.assertIn('\\"local_memory_matches\\": 11', json.dumps(post.call_args.kwargs["json"]["messages"]))


class RetroSourceClassesInAI(unittest.TestCase):
    def _res(self, **rh):
        res = T.result_for(T.raw_mail()); res["retro_hunt"] = dict({"intel": 0, "intel_feed": 0}, **rh); return res

    def test_community_and_unknown_are_not_local_sightings_or_feed_matches(self):
        tm = O.build_evidence(self._res(intel=9, intel_local=4, intel_feed=1, intel_community=3, intel_unknown=1))["machine_analysis"]["threat_memory"]
        self.assertEqual((tm["earlier_local_sightings"], tm["external_feed_matches"]), (4, 1))
        self.assertEqual((tm["community_reported_unverified"], tm["unrecognised_source_records"]), (3, 1))
        self.assertIn("NOT confirmed", tm["note"])

    def test_old_count_shape_still_works(self):
        tm = O.build_evidence(self._res(intel=11, intel_feed=0))["machine_analysis"]["threat_memory"]
        self.assertEqual((tm["earlier_local_sightings"], tm["external_feed_matches"]), (11, 0))


if __name__ == "__main__":
    unittest.main()