"""Offline tests for the stage-aware diagnostics in contribution_client (stderr only; no network, tokens or secrets)."""
import io, unittest
from contextlib import redirect_stderr
from unittest import mock

import requests

import contribution_client as cc
from test_contribution_auth import Base, Net, Resp, ITEMS, store_with_id, sess, jwt

SECRETS = ("rt-", "eyJ", "sb_publishable_synthetic", "proj.supabase.co", "a@b.c")


class Diag(Base):
    def run_diag(self, net, store):
        buf = io.StringIO()
        with redirect_stderr(buf):
            r = self.run_submit(net, store)
        return r, buf.getvalue()

    def assertClean(self, out):
        for s in SECRETS:
            self.assertNotIn(s, out)

    def test_auth_exchange_5xx(self):
        r, out = self.run_diag(Net(id_token=[Resp(502, {"msg": "bad gateway https://proj.supabase.co/x a@b.c"})]), store_with_id())
        self.assertEqual(r["error"], "unavailable")
        self.assertIn("stage=auth_exchange", out); self.assertIn("status=502", out); self.assertClean(out)

    def test_session_validation_malformed_token_response(self):
        r, out = self.run_diag(Net(id_token=[Resp(200, {"access_token": "x", "refresh_token": "y"})]), store_with_id())
        self.assertEqual(r["error"], "unavailable")
        self.assertIn("stage=session_validation", out); self.assertIn("status=200", out)

    def test_rpc_redirect(self):
        r, out = self.run_diag(Net(rpc=[Resp(302)]), {cc.SESSION_KEY: sess()})
        self.assertEqual(r["error"], "unavailable")
        self.assertIn("stage=rpc_request", out); self.assertIn("status=302", out)

    def test_rpc_http_error_keeps_mapped_code(self):
        r, out = self.run_diag(Net(rpc=[Resp(404, {"message": "Could not find the function public.submit_indicators", "code": "PGRST202"})]), {cc.SESSION_KEY: sess()})
        self.assertEqual(r["error"], "server_error")
        self.assertIn("stage=rpc_request", out); self.assertIn("status=404", out)

    def test_response_validation(self):
        r, out = self.run_diag(Net(rpc=[Resp(200, {"accepted": "1"})]), {cc.SESSION_KEY: sess()})
        self.assertEqual(r["error"], "unavailable")
        self.assertIn("stage=response_validation", out)

    def test_network_exception_per_stage(self):
        def boom(*a, **k):
            raise requests.exceptions.ConnectTimeout("timeout talking to https://proj.supabase.co with Bearer " + jwt(sub="u"))
        r, out = self.run_diag(boom, store_with_id())
        self.assertEqual(r["error"], "unavailable")
        self.assertIn("stage=auth_exchange", out); self.assertIn("exc=ConnectTimeout", out); self.assertClean(out)
        r, out = self.run_diag(boom, {cc.SESSION_KEY: sess()})
        self.assertIn("stage=rpc_request", out); self.assertIn("exc=ConnectTimeout", out); self.assertClean(out)

    def test_exception_before_request_is_session_validation(self):
        with mock.patch("contribution_client._valid_session", side_effect=KeyError("boom")):
            r, out = self.run_diag(Net(), {cc.SESSION_KEY: sess()})
        self.assertEqual(r["error"], "unavailable")
        self.assertIn("stage=session_validation", out); self.assertIn("exc=KeyError", out)

    def test_success_and_gates_log_nothing(self):
        r, out = self.run_diag(Net(), store_with_id())
        self.assertTrue(r["ok"]); self.assertEqual(out, "")
        r, out = self.run_diag(Net(), None)
        self.assertEqual(r["error"], "auth_required"); self.assertEqual(out, "")

    def test_scrub_redacts_and_truncates(self):
        t = cc._scrub("Bearer abc https://x.y/z " + jwt(a=1) + " sb_secret_zzz a@b.c " + "A" * 40 + " " + "w" * 500)
        self.assertNotIn("abc", t); self.assertNotIn("sb_secret_zzz", t); self.assertNotIn("a@b.c", t); self.assertLessEqual(len(t), 120)

    def test_diag_never_raises(self):
        class Bad:
            status_code = 500
            def json(self): raise ValueError("x")
        cc._diag("auth_exchange", Bad(), exc=None)


if __name__ == "__main__":
    unittest.main()
