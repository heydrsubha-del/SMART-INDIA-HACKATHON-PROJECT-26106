"""Drives the real e2e_phase4.run() against an in-memory FAKE Supabase (no network). Proves the happy path passes and that
deliberately broken security properties make the run FAIL (no false-positive success). This tests the SCRIPT, not Supabase."""
import contextlib
import io
import os
import sys
import types
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import e2e_phase4 as E
import indicator_sanitizer as IS
import shared_intel_client as SIC

REF, SECRET = "abcdtestref", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class Resp:
    def __init__(self, status=200, body=None, text=None):
        self.status_code, self._b, self.text = status, body, str(body) if text is None else text

    def json(self):
        return self._b


DENY = lambda: Resp(403, {"code": "42501", "message": "permission denied"})


class FakeSupabase:
    def __init__(self, bug=None):
        self.bug, self.n = bug, 0
        self.users = {}                       # token -> {"uid", "anon", "admin", "aal2"}
        self.subs = {}                        # value -> {"id","status","owner"}
        self.scans = {}
        self.verified = set()

    def tok(self, **info):
        self.n += 1
        t = "tok%d" % self.n
        self.users[t] = {**dict(uid="u%d" % self.n, anon=False, admin=False, aal2=False), **info}
        return t

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def request(self, method, url, **kw):
        u = urlsplit(url); path, q = u.path, parse_qs(u.query)
        if u.hostname in ("127.0.0.1", "localhost"):
            raise E.requests.ConnectionError("connection refused (simulated closed local port)")
        auth = (kw.get("headers") or {}).get("Authorization", "")
        me = self.users.get(auth.replace("Bearer ", ""))
        body = kw.get("json")
        if path.endswith("/rpc/is_test_project"):
            return Resp(200, True)
        if path == "/auth/v1/signup":
            if body == {}:
                return Resp(200, {"access_token": self.tok(anon=True)})
            t = self.tok(email=body["email"]); return Resp(200, {"access_token": t})
        if path == "/auth/v1/token":
            if body["email"] == os.environ[E.EMAIL_ENV]:
                return Resp(200, {"access_token": self.tok(admin=True)})
            return Resp(200, {"access_token": self.tok(email=body["email"])})
        if path == "/auth/v1/user" and method == "GET":
            return Resp(200, {"factors": [{"id": "f1", "factor_type": "totp", "status": "verified"}]})
        if path == "/auth/v1/user" and method == "PUT":
            return Resp(200, {})
        if path.endswith("/challenge"):
            return Resp(200, {"id": "ch1"})
        if path.endswith("/verify"):
            if body["code"] != E.totp(SECRET):
                return Resp(400, {"code": "bad"})
            t = self.tok(admin=True); self.users[t]["aal2"] = True
            return Resp(200, {"access_token": t})
        if "/rpc/" in path:
            return self.rpc(path.rsplit("/", 1)[1], body, me)
        if path == "/rest/v1/shared_indicators":
            if method != "GET":
                return DENY()
            val = (q.get("value_norm") or [""])[0].replace("eq.", "")
            if "status" in q:
                return Resp(200, [])
            pub = self.verified | ({val} if self.bug == "pending_public" else set())
            return Resp(200, [{"value_norm": val, "verdict": "malicious", "status": "verified"}] if val in pub else [])
        if path == "/rest/v1/indicator_submissions":
            if method != "GET":
                return DENY()
            val = (q.get("value_norm") or [""])[0].replace("eq.", "")
            row = self.subs.get(val)
            return Resp(200, [{"status": row["status"]}] if me and row and row["owner"] == me["uid"] else [])
        if path == "/rest/v1/scans":
            return self.scans_api(method, q, body, me, kw)
        return Resp(404, {"code": "PGRST202"})

    def rpc(self, fn, body, me):
        if fn == "submit_indicators":
    if not me:
        return DENY()
    if me.get("anon"):
        return Resp(403, {
            "code": "42501",
            "message": "auth_required"
        })
            out = {"accepted": 0, "duplicates": 0, "rejected": 0}
            for it in body["p_items"]:
                s = IS.sanitize_indicator(it["value_norm"], it["indicator_type"])
                if not s.ok or s.value != it["value_norm"]:
                    out["rejected"] += 1
                elif it["value_norm"] in self.subs:
                    out["duplicates"] += 1
                else:
                    self.subs[it["value_norm"]] = {"id": "s%d" % len(self.subs), "status": "pending", "owner": me["uid"]}
                    out["accepted"] += 1
            return Resp(200, out)
        is_rev = bool(me and me["admin"] and (me["aal2"] or self.bug == "no_mfa_needed")) or (self.bug == "anyone_approves" and me)
        if not is_rev:
            return DENY()
        if fn == "review_queue":
            return Resp(200, [{"id": v["id"], "value_norm": k} for k, v in self.subs.items() if v["status"] == "pending"])
        if fn == "review_submission":
            val, row = next(((k, v) for k, v in self.subs.items() if v["id"] == body["p_id"]), (None, None))
            if row is None:
                return Resp(400, {"message": "not_found"})
            if row["status"] != "pending":
                return Resp(400, {"message": "already_reviewed"})
            if row["owner"] == me["uid"]:
                return Resp(400, {"message": "self_review"})
            row["status"] = "approved" if body["p_decision"] == "approve" else "rejected"
            if row["status"] == "approved":
                self.verified.add(val)
            return Resp(200, {"status": row["status"]})
        return Resp(404, {})

    def scans_api(self, method, q, body, me, kw):
        if method == "POST":
            if not me or me["anon"] or ("user_id" in body and body["user_id"] != me["uid"]):
                return DENY()
            if "body" in body["summary"]:
                return Resp(400, {"code": "23514"})
            sid = "scan%d" % len(self.scans)
            self.scans[sid] = {"owner": me["uid"], "summary": body["summary"]}
            return Resp(201, [{"id": sid}])
        sid = q["id"][0].replace("eq.", "")
        row = self.scans.get(sid)
        mine = bool(row and me and (row["owner"] == me["uid"] or self.bug == "cross_read"))
        if method == "GET":
            cols = q.get("select", ["id,summary"])[0].split(",")
            full = {"id": sid, "summary": row["summary"]} if row else {}
            return Resp(200, [{c: full[c] for c in cols}] if mine else [])
        if mine and row["owner"] == me["uid"]:
            if method == "DELETE":
                self.scans.pop(sid)
            else:
                row["summary"] = body["summary"]
        return Resp(204, None, "")


class Run(unittest.TestCase):
    def play(self, bug=None, with_cc=True):
        fake = FakeSupabase(bug)
        env = {E.CONFIRM_ENV: "TEST-PROJECT-ONLY:" + REF, E.REF_ENV: REF, E.PROD_REFS_ENV: "", SIC.URL_ENV: "https://%s.supabase.co" % REF,
               SIC.KEY_ENV: "sb_publishable_x", E.EMAIL_ENV: "reviewer@example.test", E.PASS_ENV: "pw", E.TOTP_ENV: SECRET}
        cc = types.SimpleNamespace(FLAG_ENV="SIH26106_CONTRIBUTIONS", _last_submit={}, submit=lambda *a, **k: {"ok": False, "error": "unavailable"})

        def scan(dom, flag, base_env=None):
            r = {"score": 5.0, "level": "Low"}
            if flag:
                r["community_intel"] = {"status": "unavailable" if base_env else "ok"}
            return r

        community = lambda d: {"status": "ok", "matches": [{"indicator": d, "source": "community"}] if d in fake.verified else []}
        E._state["marker_ok"] = None
        E.RESULTS.clear(); E.PENDING.clear(); E.CONTROLS.clear()
        mods = {"contribution_client": cc} if with_cc is True else ({"contribution_client": None} if with_cc is False else {})
        with mock.patch.dict(os.environ, env), mock.patch.object(E.requests, "request", fake.request), \
             mock.patch.object(E.requests, "post", fake.post), mock.patch.object(E, "scan", scan), \
             mock.patch.object(E, "community", community), mock.patch.dict(sys.modules, mods), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = E.run()
        return rc, list(E.RESULTS)

    def failed(self, results):
        return [n for st, n in results if st == "fail"]

    def test_happy_path_passes_everything_with_no_skips(self):
        rc, res = self.play()
        self.assertEqual(self.failed(res), []); self.assertEqual([n for st, n in res if st == "skip"], [])
        self.assertEqual(rc, 0); self.assertGreaterEqual(sum(st == "pass" for st, _ in res), 30)

    def test_ordinary_user_who_can_approve_is_caught(self):
        rc, res = self.play("anyone_approves")
        self.assertEqual(rc, 1); self.assertIn("ordinary user cannot approve", self.failed(res))

    def test_review_without_mfa_is_caught(self):
        rc, res = self.play("no_mfa_needed")
        self.assertEqual(rc, 1); self.assertIn("reviewer WITHOUT MFA (aal1) is refused", self.failed(res))

    def test_cross_user_scan_read_is_caught(self):
        rc, res = self.play("cross_read")
        self.assertEqual(rc, 1); self.assertIn("user B cannot read A's scan", self.failed(res))

    def test_pending_indicator_leaking_to_the_public_is_caught(self):
        rc, res = self.play("pending_public")
        self.assertEqual(rc, 1); self.assertIn("pending indicator is NOT in the public verified set", self.failed(res))

    def test_happy_path_with_the_real_contribution_client(self):
        try:
            import contribution_client  # noqa: F401
        except ImportError:
            self.skipTest("contribution_client.py is not importable here")
        rc, res = self.play(with_cc="real")
        self.assertEqual(self.failed(res), []); self.assertEqual([n for st, n in res if st == "skip"], [])
        self.assertIn(("pass", "contribution fails softly when the database is down"), res)
        self.assertEqual(rc, 0)

    def test_missing_contribution_client_is_a_skip_not_a_pass(self):
        rc, res = self.play(with_cc=False)
        self.assertEqual(rc, 1); self.assertIn(("skip", "contribution fails softly when the database is down"), res)

    def test_a_server_that_denies_everything_never_yields_success(self):
        fake = FakeSupabase()
        fake.request = lambda m, u, **k: Resp(200, True) if "is_test_project" in u else (
            Resp(200, {"access_token": "t"}) if u.endswith("/auth/v1/signup") else DENY())
        env = {E.CONFIRM_ENV: "TEST-PROJECT-ONLY:" + REF, E.REF_ENV: REF, E.PROD_REFS_ENV: "", SIC.URL_ENV: "https://%s.supabase.co" % REF, SIC.KEY_ENV: "sb_publishable_x"}
        E._state["marker_ok"] = None; E.RESULTS.clear(); E.PENDING.clear(); E.CONTROLS.clear()
        with mock.patch.dict(os.environ, env), mock.patch.object(E.requests, "request", fake.request), \
             mock.patch.object(E.requests, "post", lambda u, **k: fake.request("POST", u, **k)), \
             mock.patch.object(E, "community", lambda d: {"status": "ok", "matches": []}), \
             mock.patch.object(E, "scan", lambda d, f, b=None: {"score": 1, "level": "Low", "community_intel": {"status": "unavailable"}}), \
             mock.patch.dict(sys.modules, {"contribution_client": None}), contextlib.redirect_stdout(io.StringIO()):
            rc = E.run()
        self.assertEqual(rc, 1)
        self.assertEqual([n for st, n in E.RESULTS if st == "pass" and ("cannot" in n or "refused" in n)], [])


if __name__ == "__main__":
    unittest.main()
