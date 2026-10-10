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
        self.assertEqual(set(d), {"backend", "finish_reason", "prompt_tokens", "completion_tokens", "output_limit",
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
        meta = {}
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


if __name__ == "__main__":
    unittest.main()
