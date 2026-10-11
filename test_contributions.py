"""Phase 3 contributions: off by default, consent-gated, sanitized, quarantine-only, reviewer tool, scoring untouched."""
import base64
import json
import os
import unittest
from unittest import mock

import analyzer
import community_intel as CI
import contribution_client as CC
import requests
import review_tool as RT
import shared_intel_client as SC


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def jwt(role):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return "%s.%s.sig" % (b({"alg": "HS256"}), b({"role": role}))


class Resp:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data if data is not None else {}, status
    def json(self):
        return self.data
    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError("http %s" % self.status_code)


GOOD = [{"indicator_type": "domain", "value_norm": "evil.example.net"}, {"indicator_type": "url", "value_norm": "http://evil.example.net/login"}]
OK_BODY = {"accepted": 2, "duplicates": 0, "rejected": 0}


class Base(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {SC.URL_ENV: "https://proj.supabase.co", SC.KEY_ENV: jwt("anon")})
        patcher.start(); self.addCleanup(patcher.stop)
        os.environ.pop(CC.FLAG_ENV, None)
        CC._last_submit.clear()

    def on(self):
        os.environ[CC.FLAG_ENV] = "1"

    def post(self, rpc_resp=None, signup=None):
        calls = []
        def fake(url, **kw):
            calls.append((url, kw))
            if url.endswith("/auth/v1/signup"):
                return signup or Resp({"access_token": "user-session-token"})
            return rpc_resp or Resp(OK_BODY)
        return mock.patch.object(CC.requests, "post", side_effect=fake), calls


class OffAndConsent(Base):
    def test_off_by_default_no_network(self):
        p, calls = self.post()
        with p:
            self.assertEqual(CC.submit(GOOD, "suspicious", True)["error"], "disabled")
        self.assertEqual(calls, [])
        self.assertFalse(CC.enabled())

    def test_flag_values(self):
        for v, want in (("1", True), ("true", True), ("YES", True), ("0", False), ("", False), ("maybe", False)):
            os.environ[CC.FLAG_ENV] = v
            self.assertEqual(CC.enabled(), want, v)

    def test_explicit_consent_required(self):
        self.on()
        for consent in (False, None, "yes", 1, "true"):
            p, calls = self.post()
            with p:
                self.assertEqual(CC.submit(GOOD, "suspicious", consent)["error"], "consent_required", repr(consent))
            self.assertEqual(calls, [])

    def test_unknown_verdict_refused(self):
        self.on()
        self.assertEqual(CC.submit(GOOD, "benign", True)["error"], "invalid_verdict")


class Sanitization(Base):
    def test_prepare_sanitizes_dedupes_and_drops_unsafe(self):
        r = CC.prepare([("url", "https://u:p@Evil.Example.net/login?token=SECRET#f"), ("url", "http://evil.example.net/login"),
                        ("domain", "someone@example.com"), ("ip", "10.0.0.5"), ("url", "http://x.example.org/aB3xK9pQ2mZ7vL1nR8tY4wC6/z"),
                        ("domain", "evil.example.net")])
        values = [i["value_norm"] for i in r["items"]]
        self.assertEqual(values, ["https://evil.example.net/login", "http://evil.example.net/login", "http://x.example.org/", "evil.example.net"])
        self.assertEqual(len(values), len(set(values)))
        self.assertNotIn("SECRET", repr(r)); self.assertNotIn("@", repr(r)); self.assertNotIn("10.0.0.5", repr(r))

    def test_prepare_caps_items(self):
        r = CC.prepare([("domain", "d%d.example.org" % i) for i in range(30)])
        self.assertEqual(len(r["items"]), CC.MAX_ITEMS); self.assertTrue(r["truncated"])

    def test_payload_has_only_allowed_fields_and_sanitized_values(self):
        self.on()
        dirty = GOOD + [{"indicator_type": "url", "value_norm": "http://x.example.org/a?t=1"}, {"indicator_type": "domain", "value_norm": "a@b.example.org"},
                        {"indicator_type": "ip", "value_norm": "192.168.1.1"}, "junk", None]
        p, calls = self.post()
        with p:
            r = CC.submit(dirty, "malicious", True)
        self.assertTrue(r["ok"])
        sent = calls[-1][1]["json"]["p_items"]
        self.assertEqual([i["value_norm"] for i in sent], ["evil.example.net", "http://evil.example.net/login"])
        for i in sent:
            self.assertEqual(set(i), {"indicator_type", "value_norm", "claimed_verdict"})
        self.assertNotIn("status", repr(calls)); self.assertNotIn("contributor", repr(calls))

    def test_only_unsafe_items_means_nothing_sent(self):
        self.on()
        p, calls = self.post()
        with p:
            r = CC.submit([{"indicator_type": "domain", "value_norm": "a@b.example.org"}], "suspicious", True)
        self.assertEqual((r["error"], calls), ("nothing_to_submit", []))

    def test_candidates_from_result_use_only_flagged_urls_and_hosts(self):
        res = {"iocs": {"suspicious_urls": [{"url": "http://evil.example.net/login?x=1"}], "urls": [{"url": "http://fine.example.org/"}],
                        "emails": ["me@example.com"]}, "parsed": {"from_addr": "me@example.com", "full_text": "SECRET BODY"}}
        c = CC.candidates_from_result(res)
        self.assertEqual({k for k, _ in c}, {"url", "domain"})
        self.assertNotIn("fine.example.org", repr(c)); self.assertNotIn("SECRET", repr(c)); self.assertNotIn("me@", repr(c))
        self.assertEqual(CC.candidates_from_result({}), [])


class Transport(Base):
    def setUp(self):
        super().setUp(); self.on()

    def test_anonymous_signin_then_rpc_with_user_token(self):
        p, calls = self.post()
        with p:
            r = CC.submit(GOOD, "suspicious", True)
        self.assertEqual((r["ok"], r["accepted"], r["token"]), (True, 2, "user-session-token"))
        signup, rpc = calls
        self.assertTrue(signup[0].endswith("/auth/v1/signup")); self.assertEqual(signup[1]["json"], {})
        self.assertTrue(rpc[0].endswith("/rest/v1/rpc/submit_indicators"))
        self.assertEqual(rpc[1]["headers"]["Authorization"], "Bearer user-session-token")

    def test_existing_token_reused(self):
        p, calls = self.post()
        with p:
            CC.submit(GOOD, "suspicious", True, token="cached")
        self.assertEqual(len(calls), 1); self.assertEqual(calls[0][1]["headers"]["Authorization"], "Bearer cached")

    def test_expired_token_retried_once(self):
        seq = [Resp({}, 401), Resp(OK_BODY)]
        def fake(url, **kw):
            return Resp({"access_token": "new"}) if url.endswith("/signup") else seq.pop(0)
        with mock.patch.object(CC.requests, "post", side_effect=fake):
            self.assertTrue(CC.submit(GOOD, "suspicious", True, token="old")["ok"])

    def test_secret_keys_and_insecure_urls_refused_without_requests(self):
        for env in ({SC.KEY_ENV: jwt("service_role")}, {SC.KEY_ENV: "sb_secret_x"}, {SC.URL_ENV: "http://example.org"}, {SC.URL_ENV: ""}):
            CC._last_submit.clear()
            with mock.patch.dict(os.environ, env):
                p, calls = self.post()
                with p:
                    self.assertEqual(CC.submit(GOOD, "suspicious", True)["error"], "not_configured")
                self.assertEqual(calls, [])

    def test_local_rate_limit(self):
        p, calls = self.post()
        with p:
            self.assertTrue(CC.submit(GOOD, "suspicious", True, token="s1")["ok"])
            self.assertEqual(CC.submit(GOOD, "suspicious", True, token="s1")["error"], "rate_limited_locally")
            self.assertTrue(CC.submit(GOOD, "suspicious", True, token="s2")["ok"])        # another session is not throttled by s1

    def test_server_side_limits_map_to_codes(self):
        for msg in ("rate_limited", "blocked", "too_many_items"):
            CC._last_submit.clear()
            p, _ = self.post(rpc_resp=Resp({"code": "P0001", "message": msg}, 400))
            with p:
                self.assertEqual(CC.submit(GOOD, "suspicious", True, token="t")["error"], msg)

    def test_unknown_server_error_text_not_echoed(self):
        p, _ = self.post(rpc_resp=Resp({"message": "secret internal detail"}, 500))
        with p:
            self.assertEqual(CC.submit(GOOD, "suspicious", True, token="t")["error"], "server_error")

    def test_timeouts_and_garbage_fail_soft(self):
        key = os.environ[SC.KEY_ENV]
        for effect in (requests.Timeout("slow " + key), ConnectionError("x")):
            CC._last_submit.clear()
            with mock.patch.object(CC.requests, "post", side_effect=effect):
                r = CC.submit(GOOD, "suspicious", True)
            self.assertEqual((r["ok"], r["error"]), (False, "unavailable")); self.assertNotIn(key, repr(r))
        for bad in (Resp("text"), Resp({"accepted": "2", "duplicates": 0, "rejected": 0}), Resp({"accepted": -1, "duplicates": 0, "rejected": 0}), Resp([])):
            CC._last_submit.clear()
            p, _ = self.post(rpc_resp=bad)
            with p:
                self.assertEqual(CC.submit(GOOD, "suspicious", True, token="t")["error"], "unavailable")

    def test_signin_failure_fails_soft(self):
        p, _ = self.post(signup=Resp({}, 500))
        with p:
            self.assertEqual(CC.submit(GOOD, "suspicious", True)["error"], "unavailable")


class ReviewTool(Base):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ, {RT.JWT_ENV: jwt("authenticated")}); patcher.start(); self.addCleanup(patcher.stop)

    def test_list_and_decide_use_reviewer_token_and_only_needed_fields(self):
        with mock.patch.object(RT.requests, "post", return_value=Resp([{"id": "1", "indicator_type": "domain"}])) as post:
            self.assertTrue(RT.list_pending(10)["ok"])
        self.assertTrue(post.call_args[0][0].endswith("/rpc/review_queue"))
        self.assertEqual(post.call_args[1]["headers"]["Authorization"], "Bearer " + os.environ[RT.JWT_ENV])
        with mock.patch.object(RT.requests, "post", return_value=Resp({"status": "approved"})) as post:
            self.assertTrue(RT.decide("abc", "approve", "ok")["ok"])
        self.assertEqual(post.call_args[1]["json"], {"p_id": "abc", "p_decision": "approve", "p_note": "ok"})

    def test_invalid_decision_and_missing_config(self):
        self.assertEqual(RT.decide("abc", "promote")["error"], "invalid_decision")
        with mock.patch.dict(os.environ, {RT.JWT_ENV: ""}):
            self.assertEqual(RT.list_pending()["error"], "not_configured")

    def test_service_role_credentials_refused(self):
        for env in ({SC.KEY_ENV: jwt("service_role")}, {RT.JWT_ENV: jwt("service_role")}, {SC.KEY_ENV: "sb_secret_x"}):
            with mock.patch.dict(os.environ, env), mock.patch.object(RT.requests, "post") as post:
                self.assertEqual(RT.list_pending()["error"], "unsafe_credentials")
            post.assert_not_called()

    def test_non_reviewer_gets_forbidden_without_details(self):
        with mock.patch.object(RT.requests, "post", return_value=Resp({"message": "forbidden"}, 403)):
            self.assertEqual(RT.decide("abc", "approve")["error"], "forbidden")

    def test_network_failure_fail_soft(self):
        with mock.patch.object(RT.requests, "post", side_effect=requests.Timeout("t")):
            self.assertEqual(RT.list_pending()["error"], "unavailable")


class ScoringAndVerifiedOnly(Base):
    def run_scan(self):
        geo = {"origin_risk": 0.0, "origin": {"ip": "8.8.4.4"}, "hops": []}
        raw = b"From: a@evil.example.net\nTo: v@corp-example.org\nSubject: Hi\nDate: Mon, 5 Oct 2026 10:00:00 +0000\nMessage-ID: <1@x>\n\nsee http://evil.example.net/login\n"
        with mock.patch.object(analyzer, "predict", return_value=(0.1, "legit", [])), \
             mock.patch.object(analyzer.geolocate, "trace", return_value=geo), \
             mock.patch.object(analyzer, "remember_indicator", return_value=False), \
             mock.patch.object(analyzer, "lookup_indicator", return_value=None), \
             mock.patch.object(analyzer, "refresh_stale_url_scores"), mock.patch.object(analyzer, "origin_intel", None), \
             mock.patch.object(analyzer.risk, "score", return_value={"score": 12.5, "level": "low", "color": "g"}):
            return analyzer.analyze_email(raw, "t.eml", pipe=object())

    def test_enabling_contributions_changes_nothing_in_scans(self):
        off = self.run_scan()
        self.on()
        with mock.patch.object(CC.requests, "post") as post:
            on = self.run_scan()
        post.assert_not_called()                                    # scanning never submits anything
        self.assertEqual(on, off)

    def test_scoring_modules_do_not_depend_on_contributions(self):
        for mod in ("analyzer.py", "risk.py", "community_intel.py", "ioc_extract.py"):
            self.assertNotIn("contribution_client", _read(mod), mod)

    def test_community_lookup_requests_only_verified_rows(self):
        CI.reset_cache(); os.environ[CI.FLAG_ENV] = "1"; self.addCleanup(CI.reset_cache)
        with mock.patch.object(SC.requests, "get", return_value=Resp([])) as get:
            CI.lookup({"from_domain": "evil.example.net"}, {}, {})
        self.assertEqual(get.call_args[1]["params"]["status"], "eq.verified")
        os.environ.pop(CI.FLAG_ENV, None)

    def test_pending_or_rejected_rows_in_a_feed_are_dropped(self):
        rows = [{"indicator_type": "domain", "value_norm": "evil.example.net", "verdict": "pending", "confidence": 1},
                {"indicator_type": "domain", "value_norm": "b.example.net", "verdict": "rejected", "confidence": 1},
                {"indicator_type": "domain", "value_norm": "ok.example.net", "verdict": "suspicious", "confidence": 1}]
        with mock.patch.object(SC.requests, "get", return_value=Resp(rows)):
            out = SC.fetch_verified()
        self.assertEqual([r["indicator"] for r in out["rows"]], ["ok.example.net"])


if __name__ == "__main__":
    unittest.main()
