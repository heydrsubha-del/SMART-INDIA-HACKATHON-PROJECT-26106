"""Redirect-safety tests for contribution_client (authenticated flow). Offline: mocked HTTP + a local loopback server."""
import base64, hashlib, http.server, json, os, threading, time, unittest
from unittest import mock

import contribution_client as CC

ITEMS = [{"indicator_type": "domain", "value_norm": "bad-login.example.net"}]


def jwt(**claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return enc({"alg": "none"}) + "." + enc(claims) + ".sig"


def session():
    return {"access_token": jwt(sub="u", is_anonymous=False), "refresh_token": "rt"}


def id_store():
    return {CC.ID_TOKEN_KEY: jwt(nonce=hashlib.sha256(b"n").hexdigest(), exp=int(time.time()) + 600), CC.ID_NONCE_KEY: "n"}


class Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._d = status, data or {}
    def json(self):
        return self._d


class Redirects(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ, {"SIH26106_CONTRIBUTIONS": "1", "SIH26106_SUPABASE_URL": "https://proj.supabase.co",
                                         "SIH26106_SUPABASE_ANON_KEY": "sb_publishable_synthetic"})
        p.start(); self.addCleanup(p.stop)

    def test_every_request_disables_redirects(self):
        calls = []
        def fake(url, **kw):
            calls.append(kw)
            if url.endswith("/auth/v1/token"):
                return Resp(200, session())
            return Resp(200, {"accepted": 1, "duplicates": 0, "rejected": 0})
        with mock.patch("contribution_client.requests.post", fake):
            self.assertTrue(CC.submit(ITEMS, "malicious", True, store=id_store())["ok"])
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(kw["allow_redirects"] is False for kw in calls))

    def test_redirect_from_id_token_exchange_is_soft_failure_and_keeps_id_token(self):
        st = id_store()
        with mock.patch("contribution_client.requests.post", return_value=Resp(302)):
            self.assertEqual(CC.submit(ITEMS, "malicious", True, store=st)["error"], "unavailable")
        self.assertIn(CC.ID_TOKEN_KEY, st); self.assertNotIn(CC.SESSION_KEY, st)

    def test_redirect_from_rpc_is_soft_failure_and_keeps_session(self):
        st = {CC.SESSION_KEY: session()}
        with mock.patch("contribution_client.requests.post", return_value=Resp(307)):
            self.assertEqual(CC.submit(ITEMS, "malicious", True, store=st)["error"], "unavailable")
        self.assertIn(CC.SESSION_KEY, st)

    def test_redirect_from_refresh_is_soft_failure_and_keeps_session(self):
        st = {CC.SESSION_KEY: session()}
        def fake(url, **kw):
            return Resp(401) if url.endswith("/rpc/submit_indicators") else Resp(302)
        with mock.patch("contribution_client.requests.post", fake):
            self.assertEqual(CC.submit(ITEMS, "malicious", True, store=st)["error"], "unavailable")
        self.assertIn(CC.SESSION_KEY, st)

    def test_real_redirect_to_another_host_is_not_followed(self):
        hits = {"target": 0}
        class Target(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits["target"] += 1; self.send_response(200); self.end_headers()
            do_GET = do_POST
            def log_message(self, *a): pass
        target = http.server.HTTPServer(("127.0.0.1", 0), Target)
        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(307); self.send_header("Location", "http://127.0.0.1:%d/x" % target.server_port)
                self.send_header("Content-Length", "0"); self.end_headers()
            def log_message(self, *a): pass
        redir = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
        for s in (target, redir):
            threading.Thread(target=s.serve_forever, daemon=True).start()
            self.addCleanup(s.server_close); self.addCleanup(s.shutdown)
        with mock.patch.dict(os.environ, {"SIH26106_SUPABASE_URL": "http://127.0.0.1:%d" % redir.server_port}):
            st = {CC.SESSION_KEY: session()}
            self.assertEqual(CC.submit(ITEMS, "malicious", True, store=st, timeout=3)["error"], "unavailable")
        self.assertEqual(hits["target"], 0)         # the bearer token never reached the other host
        self.assertIn(CC.SESSION_KEY, st)


if __name__ == "__main__":
    unittest.main()
