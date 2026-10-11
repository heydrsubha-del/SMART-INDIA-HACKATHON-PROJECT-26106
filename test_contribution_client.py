"""contribution_client: no redirects for authenticated requests, and no needless anonymous users. Offline (loopback only)."""
import http.server
import importlib
import os
import sys
import threading
import types
import unittest
from unittest import mock

try:                                        # real modules in the project; minimal stand-ins only if they are not importable
    import indicator_sanitizer, shared_intel_client  # noqa: F401
except ImportError:
    ok = lambda v: types.SimpleNamespace(ok=True, indicator_type="domain", value=v, status="accepted")
    san = types.ModuleType("indicator_sanitizer"); san.sanitize_indicator = lambda v, k: ok(v) if v and k == "domain" and "@" not in v else types.SimpleNamespace(ok=False)
    sic = types.ModuleType("shared_intel_client"); sic.URL_ENV, sic.KEY_ENV = "SHARED_INTEL_URL", "SHARED_INTEL_KEY"
    sic._base_url = lambda u: u.rstrip("/"); sic._key_problem = lambda k: None
    sys.modules.update(indicator_sanitizer=san, shared_intel_client=sic)

import contribution_client as CC
import shared_intel_client as SIC

ITEMS = [{"indicator_type": "domain", "value_norm": "synthetic-abcdefgh-x.example.org"}]


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._b = status, body
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http")
    def json(self):
        return self._b


OK = {"accepted": 1, "duplicates": 0, "rejected": 0}


class Base(unittest.TestCase):
    def setUp(self):
        env = {CC.FLAG_ENV: "1", SIC.URL_ENV: "https://abcdtestref.supabase.co", SIC.KEY_ENV: "sb_publishable_x"}
        p = mock.patch.dict(os.environ, env); p.start(); self.addCleanup(p.stop)
        CC._last_submit.clear()

    def fake(self, rpc, signups=None):
        self.signups = 0
        def post(url, **kw):
            if url.endswith("/auth/v1/signup"):
                self.signups += 1
                return (signups or (lambda n: Resp(200, {"access_token": "anon%d" % n})))(self.signups)
            return rpc(url, **kw)
        return mock.patch.object(CC.requests, "post", side_effect=post)


class Redirects(Base):
    def test_every_authenticated_request_disables_redirects(self):
        with self.fake(lambda u, **k: Resp(200, OK)) as post:
            CC.submit(ITEMS, "malicious", True)
        self.assertEqual(len(post.call_args_list), 2)
        for c in post.call_args_list:
            self.assertIs(c[1]["allow_redirects"], False)

    def test_redirect_from_rpc_is_a_soft_failure_that_keeps_the_session(self):
        with self.fake(lambda u, **k: Resp(307)):
            r = CC.submit(ITEMS, "malicious", True, token="t1")
        self.assertEqual((r["ok"], r["error"], r["token"]), (False, "unavailable", "t1"))

    def test_redirect_from_signup_is_a_soft_failure(self):
        with self.fake(lambda u, **k: Resp(200, OK), signups=lambda n: Resp(302)):
            r = CC.submit(ITEMS, "malicious", True)
        self.assertEqual((r["ok"], r["error"], r["token"]), (False, "unavailable", None))

    def test_real_redirect_to_another_host_is_not_followed(self):
        hits = {"b": []}
        class B(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits["b"].append(dict(self.headers)); self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
            log_message = lambda *a: None
        b = http.server.HTTPServer(("127.0.0.1", 0), B)
        class A(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(307); self.send_header("Location", "http://127.0.0.1:%d/leak" % b.server_port)
                self.send_header("Content-Length", "0"); self.end_headers()
            log_message = lambda *a: None
        a = http.server.HTTPServer(("127.0.0.1", 0), A)
        for s in (a, b):
            threading.Thread(target=s.serve_forever, daemon=True).start(); self.addCleanup(s.server_close); self.addCleanup(s.shutdown)
        with mock.patch.dict(os.environ, {SIC.URL_ENV: "http://127.0.0.1:%d" % a.server_port}):
            r1 = CC.submit(ITEMS, "malicious", True, token="secret-session-token")
            CC._last_submit.clear()
            r2 = CC.submit(ITEMS, "malicious", True)                       # sign-in path
        self.assertEqual((r1["error"], r2["error"]), ("unavailable", "unavailable"))
        self.assertEqual(hits["b"], [])                                    # the other host never saw a request or a token


class AnonymousSessions(Base):
    def test_returned_token_is_reused_so_only_one_user_is_created(self):
        with self.fake(lambda u, **k: Resp(200, OK)):
            r1 = CC.submit(ITEMS, "malicious", True)
            CC._last_submit.clear()
            r2 = CC.submit(ITEMS, "suspicious", True, token=r1["token"])
        self.assertEqual((self.signups, r1["token"], r2["token"]), (1, "anon1", "anon1"))

    def test_failure_after_signup_returns_the_session_for_reuse(self):
        with self.fake(lambda u, **k: Resp(500, {"message": "boom"})):
            r = CC.submit(ITEMS, "malicious", True)
        self.assertEqual((r["ok"], r["error"], r["token"]), (False, "server_error", "anon1"))
        with self.fake(lambda u, **k: Resp(200, OK)):
            CC._last_submit.clear()
            r2 = CC.submit(ITEMS, "malicious", True, token=r["token"])
        self.assertEqual((self.signups, r2["ok"]), (0, True))

    def test_exception_after_signup_keeps_the_session(self):
        def boom(u, **k): raise RuntimeError("net")
        with self.fake(boom):
            r = CC.submit(ITEMS, "malicious", True)
        self.assertEqual((r["error"], r["token"]), ("unavailable", "anon1"))

    def test_expired_session_signs_in_exactly_once_more(self):
        calls = {"n": 0}
        def rpc(u, **k):
            calls["n"] += 1
            return Resp(401, {"message": "JWT expired"}) if calls["n"] == 1 else Resp(200, OK)
        with self.fake(rpc):
            r = CC.submit(ITEMS, "malicious", True, token="old")
        self.assertEqual((r["ok"], r["token"], self.signups), (True, "anon1", 1))

    def test_auth_refused_fresh_session_is_not_returned_and_not_retried(self):
        with self.fake(lambda u, **k: Resp(403, {"message": "x"})):
            r = CC.submit(ITEMS, "malicious", True)
        self.assertEqual((r["token"], self.signups), (None, 1))

    def test_nothing_that_fails_early_creates_a_user(self):
        cases = [dict(items=ITEMS, verdict="malicious", consent=False), dict(items=ITEMS, verdict="bad", consent=True),
                 dict(items=[], verdict="malicious", consent=True), dict(items=[{"indicator_type": "domain", "value_norm": "A@b.c"}], verdict="malicious", consent=True)]
        with self.fake(lambda u, **k: Resp(200, OK)) as post:
            for c in cases:
                self.assertFalse(CC.submit(c["items"], c["verdict"], c["consent"])["ok"])
            with mock.patch.dict(os.environ, {SIC.KEY_ENV: ""}):
                self.assertEqual(CC.submit(ITEMS, "malicious", True)["error"], "not_configured")
            with mock.patch.dict(os.environ, {CC.FLAG_ENV: "0"}):
                self.assertEqual(CC.submit(ITEMS, "malicious", True)["error"], "disabled")
        post.assert_not_called()

    def test_non_string_token_is_treated_as_no_session(self):
        with self.fake(lambda u, **k: Resp(200, OK)):
            r = CC.submit(ITEMS, "malicious", True, token=12345)
        self.assertEqual((r["ok"], self.signups), (True, 1))


if __name__ == "__main__":
    unittest.main()
