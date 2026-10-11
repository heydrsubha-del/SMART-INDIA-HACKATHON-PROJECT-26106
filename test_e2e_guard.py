"""The Phase 4 script must refuse to touch anything that is not provably the test project. No network is used."""
import contextlib
import io
import os
import string
import secrets
import unittest
from unittest import mock

import e2e_phase4 as E
import indicator_sanitizer as IS
import shared_intel_client as SIC

REF = "abcdtestref"


def env(**kw):
    base = {E.CONFIRM_ENV: "TEST-PROJECT-ONLY:" + REF, E.REF_ENV: REF, E.PROD_REFS_ENV: "",
            SIC.URL_ENV: "https://%s.supabase.co" % REF, SIC.KEY_ENV: "sb_publishable_x"}
    base.update(kw)
    return mock.patch.dict(os.environ, base, clear=False)


class R:
    def __init__(self, status=200, body=None, text=None):
        self.status_code, self._b, self.text = status, body, str(body) if text is None else text

    def json(self):
        if isinstance(self._b, Exception):
            raise self._b
        return self._b


class Guard(unittest.TestCase):
    def setUp(self):
        E._state["marker_ok"] = None

    def refused(self, **kw):
        with env(**kw), mock.patch.object(E.requests, "request") as req, mock.patch.object(E.requests, "post") as post:
            with self.assertRaises(E.Abort):
                E.call("GET", "/rest/v1/shared_indicators")
        req.assert_not_called(); post.assert_not_called()

    def test_missing_confirmation(self):
        self.refused(**{E.CONFIRM_ENV: "yes"})

    def test_confirmation_must_be_bound_to_the_ref(self):
        self.refused(**{E.CONFIRM_ENV: "TEST-PROJECT-ONLY"})
        self.refused(**{E.CONFIRM_ENV: "TEST-PROJECT-ONLY:someotherref"})

    def test_wrong_project_ref(self):
        self.refused(**{SIC.URL_ENV: "https://prodprojectref.supabase.co"})

    def test_missing_or_malformed_ref(self):
        self.refused(**{E.REF_ENV: ""})
        self.refused(**{E.REF_ENV: "ABC/../x"})

    def test_production_denylist(self):
        self.refused(**{E.PROD_REFS_ENV: "other, %s" % REF})

    def test_service_role_key_refused(self):
        self.refused(**{SIC.KEY_ENV: "sb_secret_abc"})

    def test_non_https_and_localhost_refused(self):
        self.refused(**{SIC.URL_ENV: "http://%s.supabase.co" % REF})
        self.refused(**{SIC.URL_ENV: "http://localhost:54321"})
        self.refused(**{SIC.URL_ENV: "http://127.0.0.1:54321"})

    def test_project_without_test_marker_is_refused_before_the_real_request(self):
        for bad in (R(404, {}), R(200, False), R(200, ValueError("not json"))):
            E._state["marker_ok"] = None
            with env(), mock.patch.object(E.requests, "post", return_value=bad), mock.patch.object(E.requests, "request") as req:
                with self.assertRaises(E.Abort):
                    E.call("GET", "/rest/v1/shared_indicators")
            req.assert_not_called()

    def test_marker_true_allows_request_is_checked_once_and_redirects_are_off(self):
        with env(), mock.patch.object(E.requests, "post", return_value=R(200, True)) as post, \
             mock.patch.object(E.requests, "request", return_value="ok") as req:
            E.call("GET", "/a"); E.call("GET", "/b")
        self.assertEqual((post.call_count, req.call_count), (1, 2))
        self.assertEqual(req.call_args[1]["headers"]["apikey"], "sb_publishable_x")
        self.assertNotIn("Authorization", req.call_args[1]["headers"])        # publishable keys are apikey-only
        self.assertIs(req.call_args[1]["allow_redirects"], False)
        self.assertIs(post.call_args[1]["allow_redirects"], False)

    def test_main_aborts_with_code_3_and_no_network(self):
        with env(**{E.CONFIRM_ENV: ""}), mock.patch.object(E.requests, "request") as req:
            self.assertEqual(E.main(["run"]), 3)
        req.assert_not_called()


class Denied(unittest.TestCase):
    def test_only_authorization_refusals_count(self):
        self.assertTrue(E.denied(R(403, {"code": "42501", "message": "permission denied"})))
        self.assertTrue(E.denied(R(401, {"code": "42501"})))                       # PostgREST: anon role + 42501 => 401
        self.assertTrue(E.denied(R(403, {"message": "not_authorized"})))
        self.assertFalse(E.denied(R(401, {"code": "PGRST301", "message": "JWT expired"})))
        self.assertFalse(E.denied(R(403, {"code": "PGRST999"})))
        self.assertFalse(E.denied(R(404, {"code": "PGRST202", "message": "function not found"})))
        self.assertFalse(E.denied(R(204, None, "")))                               # RLS-silent no-op is not proof
        self.assertFalse(E.denied(R(200, [])))


class Results(unittest.TestCase):
    def setUp(self):
        E.RESULTS.clear(); E.PENDING.clear(); E.CONTROLS.clear()

    def finish(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return E.finish()

    def test_exit_code_is_zero_only_when_nothing_failed_or_skipped(self):
        with contextlib.redirect_stdout(io.StringIO()):
            E.check("a", True)
        self.assertEqual(self.finish(), 0)
        E.RESULTS.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            E.check("a", True); E.skip("b", "why")
        self.assertEqual(self.finish(), 1)
        E.RESULTS.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            E.check("a", True); E.check("b", False)
        self.assertEqual(self.finish(), 1)
        self.assertEqual(self.finish(), 1)                                          # nothing ran => failure, not success

    def test_negative_check_is_inconclusive_without_its_positive_control(self):
        E.negative("X cannot do Y", True, control="reviewer")
        self.assertEqual(self.finish(), 1)
        self.assertEqual(E.RESULTS, [("skip", "X cannot do Y")])

    def test_negative_check_counts_once_the_control_passed(self):
        E.CONTROLS["reviewer"] = True
        E.negative("X cannot do Y", True); E.negative("X cannot do Z", False)
        self.finish()
        self.assertEqual(E.RESULTS, [("pass", "X cannot do Y"), ("fail", "X cannot do Z")])

    def test_failure_details_never_show_tokens(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            E.check("t", False, "eyJhbGciOi.eyJyb2xlIjoiYW5vbiJ9.sig HTTP 403")
        self.assertNotIn("eyJ", buf.getvalue())


class SyntheticData(unittest.TestCase):
    def test_generated_domains_pass_the_projects_own_sanitizer(self):
        for _ in range(300):
            tag = "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))
            for s in "xyz":
                d = "synthetic-%s-%s.example.org" % (tag, s)
                self.assertEqual(IS.sanitize_indicator(d, "domain").status, "accepted", d)

    def test_the_old_hex_format_was_rejected_by_the_sanitizer(self):
        rejected = sum(not IS.sanitize_indicator("e2e%sx.example.org" % secrets.token_hex(4), "domain").ok for _ in range(100))
        self.assertGreater(rejected, 50)


class Totp(unittest.TestCase):
    def test_rfc6238_vector(self):
        self.assertEqual(E.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", now=59, digits=8), "94287082")
        self.assertEqual(E.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", now=1111111109, digits=8), "07081804")


if __name__ == "__main__":
    unittest.main()
