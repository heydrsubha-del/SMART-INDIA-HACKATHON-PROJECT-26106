"""Community intelligence (Phase 2): flag OFF by default, contextual only, fail-soft, no scan data leaves the machine."""
import os
import unittest
from unittest import mock

import analyzer
import community_intel as CI
import requests
import shared_intel_client as SC

FEED = [
    {"indicator": "evil.example.net", "type": "domain", "verdict": "malicious", "confidence": 0.9, "source": "community"},
    {"indicator": "8.8.4.4", "type": "ip", "verdict": "suspicious", "confidence": 0.6, "source": "community"},
    {"indicator": "http://other.example.org/login", "type": "url", "verdict": "malicious", "confidence": 0.7, "source": "community"},
]
RAW = (b"Return-Path: <a@evil.example.net>\nFrom: Bob <bob@mail.evil.example.net>\nTo: victim@corp-example.org\n"
       b"Subject: Hello\nDate: Mon, 5 Oct 2026 10:00:00 +0000\nMessage-ID: <1@x>\n\n"
       b"Please see http://other.example.org/login?token=SECRET123 and http://unknown.example.com/page\n")
GEO = {"origin_risk": 0.0, "origin": {"ip": "8.8.4.4"}, "hops": []}


def ok(rows=None):
    return {"ok": True, "rows": FEED if rows is None else rows, "rejected": 0, "error": ""}


class Base(unittest.TestCase):
    def setUp(self):
        CI.reset_cache(); self.addCleanup(CI.reset_cache)
        env = mock.patch.dict(os.environ, {}, clear=False); env.start(); self.addCleanup(env.stop)
        os.environ.pop(CI.FLAG_ENV, None)

    def on(self):
        os.environ[CI.FLAG_ENV] = "1"


class Flag(Base):
    def test_off_by_default_does_nothing(self):
        with mock.patch.object(SC, "fetch_verified") as fetch:
            self.assertIsNone(CI.lookup({}, {}, {}))
        fetch.assert_not_called()

    def test_falsey_values_keep_it_off(self):
        for v in ("", "0", "false", "no", "off", "maybe"):
            os.environ[CI.FLAG_ENV] = v
            self.assertFalse(CI.enabled(), v)

    def test_truthy_values_turn_it_on(self):
        for v in ("1", "true", "YES", " On "):
            os.environ[CI.FLAG_ENV] = v
            self.assertTrue(CI.enabled(), v)


class Matching(Base):
    def lookup(self, parsed=None, iocs=None, geo=None, feed=None):
        self.on()
        with mock.patch.object(SC, "fetch_verified", return_value=ok(feed)):
            return CI.lookup(parsed or {}, iocs or {}, geo or {})

    def test_domain_exact_and_subdomain_match(self):
        r = self.lookup(parsed={"from_domain": "mail.evil.example.net", "reply_to_domain": "evil.example.net"})
        self.assertEqual(r["status"], "ok")
        hits = {(m["indicator"], m["match"]) for m in r["matches"]}
        self.assertEqual(hits, {("evil.example.net", "subdomain"), ("evil.example.net", "exact")})
        self.assertTrue(all(m["source"] == "community" for m in r["matches"]))

    def test_ip_and_url_match_and_query_ignored(self):
        r = self.lookup(iocs={"urls": [{"url": "http://other.example.org/login?token=SECRET123"}]}, geo=GEO)
        kinds = {m["type"] for m in r["matches"]}
        self.assertEqual(kinds, {"ip", "url"})
        self.assertNotIn("SECRET123", repr(r))

    def test_unknown_indicators_give_ok_with_no_matches(self):
        r = self.lookup(iocs={"urls": [{"url": "http://unknown.example.com/page"}]}, parsed={"from_domain": "fine.example.org"})
        self.assertEqual((r["status"], r["matches"]), ("ok", []))
        self.assertGreater(r["checked"], 0)

    def test_private_and_malformed_indicators_are_not_checked(self):
        r = self.lookup(geo={"origin": {"ip": "10.0.0.5"}, "hops": [{"ip": "999.1.1.1"}]}, parsed={"from_domain": "localhost"})
        self.assertEqual((r["status"], r["matches"], r["checked"]), ("ok", [], 0))

    def test_note_says_contextual_not_malicious_confirmation(self):
        r = self.lookup(parsed={"from_domain": "evil.example.net"})
        self.assertIn("not a confirmed malicious match", r["note"]); self.assertIn("did not change the threat score", r["note"])


class FailSoft(Base):
    def run_lookup(self, **fetch_kw):
        self.on()
        with mock.patch.object(SC, "fetch_verified", **fetch_kw):
            return CI.lookup({"from_domain": "evil.example.net"}, {}, {})

    def test_unavailable_service(self):
        r = self.run_lookup(return_value={"ok": False, "rows": [], "rejected": 0, "error": "down"})
        self.assertEqual((r["status"], r["matches"]), ("unavailable", []))

    def test_timeout_never_raises(self):
        r = self.run_lookup(side_effect=requests.Timeout("slow"))
        self.assertEqual(r["status"], "unavailable")

    def test_invalid_data_never_raises(self):
        for bad in ({"ok": True, "rows": [{"junk": 1}]}, {"ok": True, "rows": "nope"}, {"ok": True}, None, "text"):
            CI.reset_cache()
            self.assertEqual(self.run_lookup(return_value=bad)["status"], "unavailable", repr(bad))

    def test_failure_is_cached_briefly_so_scans_are_not_slowed(self):
        self.on()
        with mock.patch.object(SC, "fetch_verified", return_value={"ok": False, "rows": [], "error": "x"}) as fetch:
            CI.lookup({}, {}, {}); CI.lookup({}, {}, {}); CI.lookup({}, {}, {})
        self.assertEqual(fetch.call_count, 1)

    def test_success_is_cached(self):
        self.on()
        with mock.patch.object(SC, "fetch_verified", return_value=ok()) as fetch:
            CI.lookup({}, {}, {}); CI.lookup({}, {}, {})
        self.assertEqual(fetch.call_count, 1)


class Privacy(Base):
    def test_nothing_from_the_scan_is_sent(self):
        self.on()
        calls = []
        def fake_get(url, headers=None, params=None, timeout=None):
            calls.append((url, dict(headers or {}), dict(params or {})))
            class R:
                def raise_for_status(self): pass
                def json(self): return []
            return R()
        env = {SC.URL_ENV: "https://proj.supabase.co", SC.KEY_ENV: "sb_publishable_test"}
        with mock.patch.dict(os.environ, env), mock.patch.object(SC.requests, "get", side_effect=fake_get), \
             mock.patch.object(SC.requests, "post") as post:
            CI.lookup({"from_addr": "bob@secret-sender.example", "from_domain": "secret-sender.example"},
                      {"urls": [{"url": "http://unique-scan-marker.example/x?t=TOKEN"}]}, {"origin": {"ip": "8.8.8.8"}})
        post.assert_not_called()
        sent = repr(calls)
        for private in ("secret-sender", "bob@", "unique-scan-marker", "TOKEN", "8.8.8.8"):
            self.assertNotIn(private, sent)


class Pipeline(Base):
    """analyze_email with every external dependency stubbed."""
    def run_scan(self, enabled, feed=None, verdict=None):
        CI.reset_cache()
        if enabled:
            self.on()
        else:
            os.environ.pop(CI.FLAG_ENV, None)
        verdict = verdict or {"score": 12.5, "level": "low", "color": "green"}
        order = []
        real_lookup = CI.lookup
        def spy(*a, **k):
            order.append("lookup"); return real_lookup(*a, **k)
        def score(**k):
            order.append("score"); return dict(verdict)
        with mock.patch.object(analyzer, "predict", return_value=(0.1, "legit", [])), \
             mock.patch.object(analyzer.geolocate, "trace", return_value=dict(GEO)), \
             mock.patch.object(analyzer, "remember_indicator", return_value=False), \
             mock.patch.object(analyzer, "lookup_indicator", return_value=None), \
             mock.patch.object(analyzer, "refresh_stale_url_scores"), \
             mock.patch.object(analyzer, "origin_intel", None), \
             mock.patch.object(analyzer.risk, "score", side_effect=score), \
             mock.patch.object(analyzer.community_intel, "lookup", side_effect=spy), \
             mock.patch.object(SC, "fetch_verified", return_value=ok(feed)):
            return analyzer.analyze_email(RAW, "t.eml", pipe=object()), order

    def test_flag_off_result_has_no_community_key(self):
        res, order = self.run_scan(False)
        self.assertNotIn("community_intel", res)

    def test_flag_on_adds_separate_key_and_score_is_unchanged(self):
        off, _ = self.run_scan(False)
        on, order = self.run_scan(True)
        self.assertEqual(on["community_intel"]["status"], "ok")
        self.assertGreater(len(on["community_intel"]["matches"]), 0)
        for key in ("score", "level", "color", "verdict", "ml", "headers", "iocs", "geo"):
            self.assertEqual(on[key], off[key], key)
        self.assertEqual({k for k in on} - {k for k in off}, {"community_intel"})
        self.assertLess(order.index("score"), order.index("lookup"))     # looked up only after scoring

    def test_strong_community_match_never_raises_score_or_marks_malicious(self):
        on, _ = self.run_scan(True, verdict={"score": 3.0, "level": "low", "color": "green"})
        self.assertEqual((on["score"], on["level"]), (3.0, "low"))
        self.assertTrue(all(m["source"] == "community" for m in on["community_intel"]["matches"]))

    def test_outage_still_returns_normal_result(self):
        CI.reset_cache(); self.on()
        with mock.patch.object(SC, "fetch_verified", side_effect=requests.Timeout("t")):
            res, _ = self.run_scan(True)
        self.assertIn(res["community_intel"]["status"], ("ok", "unavailable"))
        self.assertEqual(res["score"], 12.5)


class Downstream(unittest.TestCase):
    def test_retro_hunt_never_counts_community_as_feed(self):
        import retro_hunt as R
        self.assertEqual(R.classify_source("community"), "community")
        row = {"Source": "Threat memory", "Where": "x via community (reputation 0.9)"}
        self.assertEqual((R.counts([row])["intel_feed"], R.counts([row])["intel_community"]), (0, 1))

    def test_ai_evidence_marks_community_as_contextual(self):
        import ollama_threat as O, test_ai_evidence as T
        res = T.result_for(T.raw_mail())
        self.assertEqual(O.build_evidence(res)["machine_analysis"]["community_intelligence"], "not enabled")
        res["community_intel"] = {"status": "ok", "checked": 3, "note": "n", "matches": [dict(FEED[0], found_in=["From"], match="exact")]}
        blk = O.build_evidence(res)["machine_analysis"]["community_intelligence"]
        self.assertEqual(blk["community_reports"][0]["indicator"], "evil.example.net")
        self.assertEqual(blk["indicators_checked"], 3)


if __name__ == "__main__":
    unittest.main()
