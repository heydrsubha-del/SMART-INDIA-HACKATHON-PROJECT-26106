"""queue_full handling in contribution_client (offline, authenticated flow). Mocks only; no live DB needed."""
import os, unittest
from unittest import mock
import test_contribution_client as T

CC, Resp = T.CC, T.Resp
OK = Resp(200, {"accepted": 1, "duplicates": 0, "rejected": 0})


class QueueFull(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ, {"SIH26106_CONTRIBUTIONS": "1", "SIH26106_SUPABASE_URL": "https://proj.supabase.co",
                                         "SIH26106_SUPABASE_ANON_KEY": "sb_publishable_synthetic"})
        p.start(); self.addCleanup(p.stop)
        self.calls = []

    def fake(self, rpc, token_resp=None):
        def f(url, **kw):
            self.calls.append((url, kw))
            if url.endswith("/auth/v1/token"):
                return token_resp or Resp(200, T.session())
            return rpc(url, **kw)
        return mock.patch("contribution_client.requests.post", f)

    def test_queue_full_is_surfaced_and_session_kept(self):
        st = {CC.SESSION_KEY: T.session()}
        with self.fake(lambda u, **k: Resp(400, {"message": "queue_full"})):
            r = CC.submit(T.ITEMS, "malicious", True, store=st)
        self.assertEqual((r["ok"], r["error"]), (False, "queue_full")); self.assertIn(CC.SESSION_KEY, st)
        self.assertNotIn("token", r)

    def test_unknown_message_still_generic(self):
        with self.fake(lambda u, **k: Resp(400, {"message": "boom"})):
            self.assertEqual(CC.submit(T.ITEMS, "malicious", True, store={CC.SESSION_KEY: T.session()})["error"], "server_error")

    def test_anonymous_rejection_drops_session_no_retry_storm(self):
        st = T.id_store()
        with self.fake(lambda u, **k: Resp(403, {"message": "auth_required"})):
            r = CC.submit(T.ITEMS, "malicious", True, store=st)
        self.assertEqual(r["error"], "auth_required"); self.assertNotIn(CC.SESSION_KEY, st)
        self.assertEqual(len([c for c in self.calls if (c[1].get("params") or {}).get("grant_type") == "id_token"]), 1)
        self.assertFalse(any((c[1].get("params") or {}).get("grant_type") == "refresh_token" for c in self.calls))
        self.assertFalse(any("signup" in c[0] for c in self.calls))


if __name__ == "__main__":
    unittest.main()
