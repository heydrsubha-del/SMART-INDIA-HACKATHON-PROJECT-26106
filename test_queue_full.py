"""queue_full handling in contribution_client (offline). Needs the migration only for the live DB, not for these mocks."""
import os, unittest
from unittest import mock
import test_contribution_client as T
CC, Resp, OK = T.CC, T.Resp, T.OK

class QueueFull(T.Base):
    def test_queue_full_is_surfaced_and_session_kept(self):
        with self.fake(lambda u, **k: Resp(400, {"message": "queue_full"})):
            r = CC.submit(T.ITEMS, "malicious", True, token="t1")
        self.assertEqual((r["ok"], r["error"], r["token"]), (False, "queue_full", "t1"))
    def test_unknown_message_still_generic(self):
        with self.fake(lambda u, **k: Resp(400, {"message": "boom"})):
            self.assertEqual(CC.submit(T.ITEMS, "malicious", True, token="t1")["error"], "server_error")
    def test_anonymous_rejection_drops_session_no_retry_storm(self):
        with self.fake(lambda u, **k: Resp(403, {"message": "auth_required"})):
            r = CC.submit(T.ITEMS, "malicious", True)
        self.assertEqual((r["error"], r["token"], self.signups), ("auth_required", None, 1))
if __name__ == "__main__": unittest.main()
