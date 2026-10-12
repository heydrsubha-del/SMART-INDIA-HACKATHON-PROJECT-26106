"""Offline tests for the authenticated contribution flow. Synthetic tokens, mocked HTTP, no network/accounts/secrets."""
import base64, hashlib, json, os, tempfile, time, unittest
from unittest import mock

import contribution_client as cc
import google_Oauth as go

BASE, KEY = "https://proj.supabase.co", "sb_publishable_synthetic"
ITEMS = [{"indicator_type": "domain", "value_norm": "bad-login.example.net"}]


def jwt(**claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return enc({"alg": "none"}) + "." + enc(claims) + ".sig"


class Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._d = status, data if data is not None else {}
    def json(self):
        return self._d


def sess(anon=False, tag="a"):
    return {"access_token": jwt(sub="u", is_anonymous=anon, tag=tag), "refresh_token": "rt-" + tag}


OK_RPC = Resp(200, {"accepted": 1, "duplicates": 0, "rejected": 0})


class Net:
    """Routes mocked requests.post by URL/grant; records calls."""
    def __init__(self, id_token=None, refresh=None, rpc=None):
        self.calls, self.id_token, self.refresh, self.rpc = [], id_token or [sess()], refresh or [], list(rpc or [OK_RPC])
    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        grant = (kw.get("params") or {}).get("grant_type")
        if url.endswith("/auth/v1/token") and grant == "id_token":
            r = self.id_token
        elif url.endswith("/auth/v1/token") and grant == "refresh_token":
            r = self.refresh
        elif url.endswith("/rpc/submit_indicators"):
            r = self.rpc
        else:
            raise AssertionError("unexpected request " + url)
        x = r.pop(0) if isinstance(r, list) else r
        return x if isinstance(x, Resp) else Resp(200, x)
    def urls(self):
        return [u for u, _ in self.calls]


def store_with_id(nonce="raw-nonce", exp_delta=3600):
    return {cc.ID_TOKEN_KEY: jwt(nonce=hashlib.sha256(nonce.encode()).hexdigest(), exp=int(time.time()) + exp_delta),
            cc.ID_NONCE_KEY: nonce}


class Base(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ, {"SIH26106_CONTRIBUTIONS": "1", "SIH26106_SUPABASE_URL": BASE, "SIH26106_SUPABASE_ANON_KEY": KEY})
        p.start(); self.addCleanup(p.stop)

    def run_submit(self, net, store, **kw):
        with mock.patch("contribution_client.requests.post", net):
            return cc.submit(kw.pop("items", ITEMS), kw.pop("verdict", "malicious"), kw.pop("consent", True), store=store)


class SignIn(Base):
    def test_id_token_exchange_sends_provider_token_raw_nonce(self):
        st = store_with_id(); tok = st[cc.ID_TOKEN_KEY]; net = Net()
        r = self.run_submit(net, st)
        self.assertTrue(r["ok"]); self.assertEqual(r["accepted"], 1)
        url, kw = net.calls[0]
        self.assertEqual(kw["params"], {"grant_type": "id_token"})
        self.assertEqual(kw["json"], {"provider": "google", "id_token": tok, "nonce": "raw-nonce"})
        self.assertNotEqual(kw["json"]["nonce"], hashlib.sha256(b"raw-nonce").hexdigest())   # raw, not the hash
        self.assertIn(cc.SESSION_KEY, st); self.assertNotIn(cc.ID_TOKEN_KEY, st); self.assertNotIn(cc.ID_NONCE_KEY, st)

    def test_no_anonymous_signup_ever(self):
        for st in ({}, store_with_id(), store_with_id(exp_delta=-5)):
            net = Net()
            self.run_submit(net, st)
            self.assertFalse(any("/auth/v1/signup" in u for u in net.urls()))
        net = Net(); r = self.run_submit(net, {})
        self.assertEqual((r["error"], net.calls), ("auth_required", []))

    def test_missing_invalid_expired_id_token(self):
        for st in ({}, {cc.ID_TOKEN_KEY: "garbage", cc.ID_NONCE_KEY: "n"}, {cc.ID_TOKEN_KEY: jwt(exp=1)}, store_with_id(exp_delta=-10),
                   {cc.ID_TOKEN_KEY: store_with_id()[cc.ID_TOKEN_KEY]}):
            net = Net(); r = self.run_submit(net, st)
            self.assertEqual((r["ok"], r["error"], net.calls), (False, "auth_required", []))

    def test_access_token_is_never_a_substitute(self):
        st = {"google_oauth_token": "ya29.synthetic"}; net = Net()
        self.assertEqual(self.run_submit(net, st)["error"], "auth_required"); self.assertEqual(net.calls, [])

    def test_anonymous_session_from_server_rejected(self):
        st = store_with_id(); net = Net(id_token=[sess(anon=True)]); r = self.run_submit(net, st)
        self.assertEqual(r["error"], "auth_required"); self.assertNotIn(cc.SESSION_KEY, st)
        self.assertFalse(any(u.endswith("/rpc/submit_indicators") for u in net.urls()))

    def test_stored_anonymous_session_not_used(self):
        st = {cc.SESSION_KEY: sess(anon=True)}; net = Net(); r = self.run_submit(net, st)
        self.assertEqual(r["error"], "auth_required"); self.assertEqual(net.calls, [])
        self.assertTrue(cc._is_anonymous(jwt(is_anonymous=True))); self.assertFalse(cc._is_anonymous(jwt(is_anonymous=False)))

    def test_id_token_rejected_by_supabase_is_dropped(self):
        st = store_with_id(); r = self.run_submit(Net(id_token=[Resp(400, {"msg": "bad"})]), st)
        self.assertEqual(r["error"], "auth_required"); self.assertNotIn(cc.ID_TOKEN_KEY, st)

    def test_transient_signin_failure_keeps_id_token(self):
        for resp, code in ((Resp(503), "unavailable"), (Resp(429), "rate_limited"), (Resp(302), "unavailable")):
            st = store_with_id(); r = self.run_submit(Net(id_token=[resp]), st)
            self.assertEqual(r["error"], code); self.assertIn(cc.ID_TOKEN_KEY, st)

    def test_malformed_session_response(self):
        st = store_with_id(); r = self.run_submit(Net(id_token=[{"access_token": "x"}]), st)
        self.assertEqual(r["error"], "unavailable"); self.assertNotIn(cc.SESSION_KEY, st)

    def test_auth_state(self):
        self.assertIsNone(cc.auth_state({})); self.assertIsNone(cc.auth_state(None))
        self.assertEqual(cc.auth_state(store_with_id()), "id_token"); self.assertEqual(cc.auth_state({cc.SESSION_KEY: sess()}), "session")
        self.assertIsNone(cc.auth_state({cc.SESSION_KEY: sess(anon=True)}))


class SessionLifecycle(Base):
    def test_valid_session_reused_without_new_auth(self):
        st = {cc.SESSION_KEY: sess()}; net = Net(); r = self.run_submit(net, st)
        self.assertTrue(r["ok"]); self.assertEqual(len(net.calls), 1); self.assertTrue(net.urls()[0].endswith("/rpc/submit_indicators"))

    def test_expired_session_refreshes_once_then_retries(self):
        old, new = sess(tag="old"), sess(tag="new"); st = {cc.SESSION_KEY: old}
        net = Net(refresh=[new], rpc=[Resp(401, {}), OK_RPC]); r = self.run_submit(net, st)
        self.assertTrue(r["ok"]); self.assertEqual(st[cc.SESSION_KEY], new)
        self.assertEqual(net.calls[1][1]["params"], {"grant_type": "refresh_token"})
        self.assertEqual(net.calls[1][1]["json"], {"refresh_token": old["refresh_token"]})
        self.assertEqual(net.calls[2][1]["headers"]["Authorization"], "Bearer " + new["access_token"])

    def test_at_most_one_retry(self):
        st = {cc.SESSION_KEY: sess(tag="old")}; net = Net(refresh=[sess(tag="new")], rpc=[Resp(401), Resp(401), Resp(401)])
        r = self.run_submit(net, st)
        self.assertEqual(r["error"], "session_expired"); self.assertEqual(len(net.calls), 3); self.assertNotIn(cc.SESSION_KEY, st)

    def test_failed_refresh_is_session_expired(self):
        st = {cc.SESSION_KEY: sess()}; net = Net(refresh=[Resp(400)], rpc=[Resp(401)]); r = self.run_submit(net, st)
        self.assertEqual(r["error"], "session_expired"); self.assertNotIn(cc.SESSION_KEY, st); self.assertEqual(len(net.calls), 2)
        self.assertFalse(any("signup" in u or "grant_type" in str(kw.get("params")) and kw["params"]["grant_type"] == "id_token" for u, kw in net.calls))

    def test_transient_refresh_failure_keeps_session(self):
        st = {cc.SESSION_KEY: sess()}; r = self.run_submit(Net(refresh=[Resp(503)], rpc=[Resp(401)]), st)
        self.assertEqual(r["error"], "unavailable"); self.assertIn(cc.SESSION_KEY, st)

    def test_refresh_returning_anonymous_session_rejected(self):
        st = {cc.SESSION_KEY: sess()}; r = self.run_submit(Net(refresh=[sess(anon=True)], rpc=[Resp(401)]), st)
        self.assertEqual(r["error"], "session_expired"); self.assertNotIn(cc.SESSION_KEY, st)

    def test_fresh_session_refused_does_not_loop(self):
        st = store_with_id(); net = Net(rpc=[Resp(403, {"message": "auth_required"})]); r = self.run_submit(net, st)
        self.assertEqual(r["error"], "auth_required"); self.assertEqual(len(net.calls), 2)
        self.assertFalse(any((kw.get("params") or {}).get("grant_type") == "refresh_token" for _, kw in net.calls))


class Errors(Base):
    def test_server_error_mapping(self):
        for resp, code in ((Resp(400, {"message": "rate_limited"}), "rate_limited"), (Resp(400, {"message": "queue_full"}), "queue_full"),
                           (Resp(400, {"message": "invalid_payload"}), "invalid_payload"), (Resp(429, {}), "rate_limited"),
                           (Resp(500, {"message": "secret internal detail"}), "server_error"), (Resp(302), "unavailable"),
                           (Resp(200, {"accepted": "x"}), "unavailable")):
            r = self.run_submit(Net(rpc=[resp]), {cc.SESSION_KEY: sess()})
            self.assertEqual(r["error"], code, resp.status_code); self.assertNotIn("secret", json.dumps(r))

    def test_network_exception_is_unavailable_without_details(self):
        st = {cc.SESSION_KEY: sess()}
        with mock.patch("contribution_client.requests.post", side_effect=RuntimeError("boom " + BASE + " " + KEY)):
            r = cc.submit(ITEMS, "malicious", True, store=st)
        self.assertEqual(r, cc._fail("unavailable")); self.assertNotIn(BASE, json.dumps(r)); self.assertIn(cc.SESSION_KEY, st)

    def test_errors_never_contain_tokens_or_keys(self):
        st = store_with_id(); blob = []
        for net in (Net(id_token=[Resp(400)]), Net(id_token=[Resp(503)]), Net(rpc=[Resp(500)])):
            blob.append(json.dumps(self.run_submit(net, dict(st))))
        s = "".join(blob)
        for secret in (st[cc.ID_TOKEN_KEY], KEY, BASE, "raw-nonce"):
            self.assertNotIn(secret, s)

    def test_local_throttle(self):
        st = {cc.SESSION_KEY: sess()}; net = Net(rpc=[OK_RPC, OK_RPC])
        self.assertTrue(self.run_submit(net, st)["ok"]); self.assertEqual(self.run_submit(net, st)["error"], "rate_limited_locally")


class Gates(Base):
    def test_flag_and_consent_and_verdict(self):
        net = Net(); st = {cc.SESSION_KEY: sess()}
        with mock.patch.dict(os.environ, {"SIH26106_CONTRIBUTIONS": "0"}):
            self.assertEqual(self.run_submit(net, st)["error"], "disabled")
        for c in (False, None, "yes", 1):
            self.assertEqual(self.run_submit(net, st, consent=c)["error"], "consent_required")
        self.assertEqual(self.run_submit(net, st, verdict="benign")["error"], "invalid_verdict")
        self.assertEqual(net.calls, [])

    def test_service_role_and_secret_keys_rejected(self):
        pl = base64.urlsafe_b64encode(b'{"role":"service_role"}').rstrip(b"=").decode()
        for bad in ("sb_secret_abc", "h." + pl + ".s"):
            with mock.patch.dict(os.environ, {"SIH26106_SUPABASE_ANON_KEY": bad}):
                net = Net(); self.assertEqual(self.run_submit(net, {cc.SESSION_KEY: sess()})["error"], "not_configured"); self.assertEqual(net.calls, [])

    def test_bad_url_not_configured(self):
        with mock.patch.dict(os.environ, {"SIH26106_SUPABASE_URL": "http://evil.example.com"}):
            self.assertEqual(self.run_submit(Net(), {})["error"], "not_configured")

    def test_no_store_means_auth_required(self):
        with mock.patch("contribution_client.requests.post", Net()) as p:
            self.assertEqual(cc.submit(ITEMS, "malicious", True)["error"], "auth_required")

    def test_payload_only_approved_fields_and_unsanitized_dropped(self):
        net = Net(); items = ITEMS + [{"indicator_type": "domain", "value_norm": "Mixed.Case.com", "email": "a@b.c", "body": "x"}, {"indicator_type": "url", "value_norm": "http://x.test/?q=1"}, "junk"]
        self.run_submit(net, {cc.SESSION_KEY: sess()}, items=items)
        sent = net.calls[0][1]["json"]
        self.assertEqual(list(sent), ["p_items"])
        self.assertEqual(sent["p_items"], [{"indicator_type": "domain", "value_norm": "bad-login.example.net", "claimed_verdict": "malicious"}])

    def test_no_redirects_and_timeout_on_every_request(self):
        net = Net(); self.run_submit(net, store_with_id())
        self.assertEqual(len(net.calls), 2)
        for url, kw in net.calls:
            self.assertIs(kw["allow_redirects"], False); self.assertTrue(kw["timeout"]); self.assertTrue(url.startswith(BASE + "/"))
            self.assertEqual(kw["headers"]["apikey"], KEY)
        self.assertNotIn("Authorization", net.calls[0][1]["headers"])      # token endpoint: apikey only


class NoDisk(Base):
    def test_tokens_never_written_to_disk(self):
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                st = store_with_id(); s = sess(tag="persist"); self.run_submit(Net(id_token=[s]), st)
                self.run_submit(Net(refresh=[sess(tag="r2")], rpc=[Resp(401), OK_RPC]), {cc.SESSION_KEY: s, cc.LAST_KEY: -1000.0})
            finally:
                os.chdir(old)
            self.assertEqual(os.listdir(d), [])
        with open(cc.__file__, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("/auth/v1/signup", src.replace("There is NO anonymous sign-up", ""))
        self.assertNotIn("open(", src)


class FakeCreds:
    def __init__(self, id_token, token="ya29.synthetic"):
        self.token, self.id_token = token, id_token
    def to_json(self):
        return json.dumps({"token": self.token, "refresh_token": "1//rt", "client_id": "cid", "scopes": ["openid"], "id_token": self.id_token})


class FakeFlow:
    def __init__(self, creds=None):
        self.kw, self.credentials = None, creds
    def authorization_url(self, **kw):
        self.kw = kw
        return "https://accounts.example/auth", "state"
    def fetch_token(self, **kw):
        self.fetched = kw


def make_state(nonce):
    return go._pack_state("v" * 43, "me.user@x.com", nonce)


class GoogleNonce(unittest.TestCase):
    def test_nonce_generation_and_hash(self):
        a, b = go._generate_nonce(), go._generate_nonce()
        self.assertNotEqual(a, b); self.assertGreaterEqual(len(a), 40); self.assertNotIn(".", a)
        self.assertEqual(go._nonce_hash("abc"), hashlib.sha256(b"abc").hexdigest()); self.assertEqual(len(go._nonce_hash(a)), 64)

    def test_authorization_request_carries_hash_and_state_carries_raw(self):
        flows = []
        def build(**kw):
            flows.append(FakeFlow()); return flows[-1]
        with mock.patch.object(go, "_build_flow", side_effect=build):
            go.get_authorization_url("me@x.com"); _, st = go.get_authorization_url("me@x.com")
        k = flows[0].kw
        self.assertEqual(k["code_challenge_method"], "S256"); self.assertIn("code_challenge", k)
        self.assertEqual(len(k["nonce"]), 64)
        self.assertNotEqual(flows[0].kw["nonce"], flows[1].kw["nonce"])

    def test_state_roundtrip_and_compat(self):
        s = make_state("N0nce_-x")
        self.assertEqual(go._unpack_state(s), ("v" * 43, "me.user@x.com")); self.assertEqual(go._unpack_nonce(s), "N0nce_-x")
        self.assertIsNone(go._unpack_nonce("%%%")); self.assertIsInstance(go._pack_state("v" * 43), str)

    def test_nonce_in_state_matches_hash_sent_to_google(self):
        seen = {}
        def build(state=None, code_verifier=None):
            seen["state"] = state; f = FakeFlow(); seen["flow"] = f; return f
        with mock.patch.object(go, "_build_flow", side_effect=build):
            go.get_authorization_url("")
        self.assertEqual(seen["flow"].kw["nonce"], go._nonce_hash(go._unpack_nonce(seen["state"])))

    def _exchange(self, id_token, nonce, multiuser=True, tmp=None):
        creds = FakeCreds(id_token); flow = FakeFlow(creds); ss = {}
        with mock.patch.object(go, "_build_flow", return_value=flow), mock.patch.object(go, "MULTIUSER", multiuser), \
             mock.patch.object(go, "_session_state", return_value=ss), \
             mock.patch.object(go, "_token_path", return_value=tmp):
            out = go.exchange_code_for_token("code", state=make_state(nonce))
        return out, ss

    def test_exchange_keeps_signature_and_stores_matching_id_token(self):
        idt = jwt(nonce=go._nonce_hash("RAW"), exp=int(time.time()) + 600)
        out, ss = self._exchange(idt, "RAW")
        self.assertEqual(out, ("ya29.synthetic", "me.user@x.com"))
        self.assertEqual((ss[go.ID_TOKEN_KEY], ss[go.ID_NONCE_KEY]), (idt, "RAW"))
        self.assertEqual((go.ID_TOKEN_KEY, go.ID_NONCE_KEY), (cc.ID_TOKEN_KEY, cc.ID_NONCE_KEY))

    def test_mismatched_or_missing_id_token_not_stored_but_gmail_works(self):
        for idt in (jwt(nonce=go._nonce_hash("OTHER")), jwt(sub="no-nonce"), None, "garbage"):
            out, ss = self._exchange(idt, "RAW")
            self.assertEqual(out[0], "ya29.synthetic"); self.assertNotIn(go.ID_TOKEN_KEY, ss); self.assertNotIn(go.ID_NONCE_KEY, ss)

    def test_saved_gmail_credentials_exclude_id_token_but_keep_fields(self):
        idt = jwt(nonce=go._nonce_hash("RAW"))
        out, ss = self._exchange(idt, "RAW")
        saved = json.loads(ss[go.SESSION_TOKEN_KEY])
        self.assertNotIn("id_token", saved); self.assertNotIn(idt, ss[go.SESSION_TOKEN_KEY])
        self.assertEqual((saved["token"], saved["refresh_token"], saved["client_id"], saved["scopes"]), ("ya29.synthetic", "1//rt", "cid", ["openid"]))

    def test_id_token_not_written_to_token_file(self):
        from pathlib import Path
        idt = jwt(nonce=go._nonce_hash("RAW"))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "tok.json"; self._exchange(idt, "RAW", multiuser=False, tmp=p)
            text = p.read_text(); self.assertNotIn(idt, text); self.assertIn("refresh_token", text)

    def test_session_failure_never_breaks_gmail_login(self):
        creds = FakeCreds(jwt(nonce=go._nonce_hash("RAW"))); flow = FakeFlow(creds); calls = {"n": 0}
        def ss():
            calls["n"] += 1
            if calls["n"] > 1: raise RuntimeError("no session")
            return {}
        with mock.patch.object(go, "_build_flow", return_value=flow), mock.patch.object(go, "MULTIUSER", True), mock.patch.object(go, "_session_state", side_effect=ss):
            self.assertEqual(go.exchange_code_for_token("c", state=make_state("RAW"))[0], "ya29.synthetic")

    def test_sign_out_clears_id_token_and_contribution_session(self):
        ss = {go.ID_TOKEN_KEY: "t", go.ID_NONCE_KEY: "n", cc.SESSION_KEY: sess(), go.SESSION_TOKEN_KEY: "{}"}
        with mock.patch.object(go, "MULTIUSER", True), mock.patch.object(go, "_session_state", return_value=ss):
            go.clear_saved_token()
        self.assertEqual(ss, {})


# --------------------------------------------------------------------------------------------------------------------
# Supabase id_token grant: access_token is required ONLY when the ID token carries an at_hash claim (Supabase reference for
# SignInWithIdTokenCredentials: "Some ID tokens contain an at_hash which require that you provide an access_token value").
# --------------------------------------------------------------------------------------------------------------------
GOOGLE_ACCESS = "ya29.google-access-synthetic"


def id_with_at_hash(nonce="raw-nonce"):
    return jwt(nonce=hashlib.sha256(nonce.encode()).hexdigest(), at_hash="synthetic-at-hash", exp=int(time.time()) + 3600)


class AccessTokenWhenRequired(Base):
    def _store(self, access=GOOGLE_ACCESS):
        st = {cc.ID_TOKEN_KEY: id_with_at_hash(), cc.ID_NONCE_KEY: "raw-nonce"}
        if access:
            st[cc.ID_ACCESS_KEY] = access
        return st

    def test_access_token_sent_to_token_endpoint_only_when_id_token_has_at_hash(self):
        st = self._store(); tok = st[cc.ID_TOKEN_KEY]; net = Net()
        self.assertTrue(self.run_submit(net, st)["ok"])
        self.assertEqual(net.calls[0][1]["json"], {"provider": "google", "id_token": tok, "nonce": "raw-nonce", "access_token": GOOGLE_ACCESS})
        self.assertNotIn(GOOGLE_ACCESS, json.dumps(net.calls[1][1]))             # never to the RPC
        for k in (cc.ID_TOKEN_KEY, cc.ID_NONCE_KEY, cc.ID_ACCESS_KEY):           # consumed after the exchange
            self.assertNotIn(k, st)

    def test_at_hash_without_access_token_is_auth_required_and_sends_nothing(self):
        st = self._store(access=None); net = Net()
        self.assertEqual(self.run_submit(net, st)["error"], "auth_required")
        self.assertEqual(net.calls, [])

    def test_no_at_hash_means_no_access_token_in_request(self):
        st = store_with_id(); st[cc.ID_ACCESS_KEY] = "stray-access"; net = Net()
        self.run_submit(net, st)
        self.assertNotIn("access_token", net.calls[0][1]["json"])
        self.assertNotIn(cc.ID_ACCESS_KEY, st)

    def test_rejected_id_token_drops_access_token_and_does_not_retry(self):
        st = self._store(); net = Net(id_token=[Resp(400)])
        self.assertEqual(self.run_submit(net, st)["error"], "auth_required")
        self.assertNotIn(cc.ID_ACCESS_KEY, st); self.assertEqual(len(net.calls), 1)

    def test_transient_failure_keeps_access_token_for_a_later_retry(self):
        st = self._store(); net = Net(id_token=[Resp(503)])
        self.assertEqual(self.run_submit(net, st)["error"], "unavailable")
        self.assertEqual(st[cc.ID_ACCESS_KEY], GOOGLE_ACCESS)

    def test_auth_state_and_clear_session(self):
        self.assertEqual(cc.auth_state(self._store()), "id_token")
        self.assertIsNone(cc.auth_state(self._store(access=None)))
        st = self._store(); st[cc.SESSION_KEY] = sess(); cc.clear_session(st); self.assertEqual(st, {})


class GoogleAtHash(unittest.TestCase):
    _exchange = GoogleNonce._exchange

    def test_at_hash_token_keeps_access_token_in_session_only(self):
        out, ss = self._exchange(id_with_at_hash("RAW"), "RAW")
        self.assertEqual(ss[go.ID_ACCESS_KEY], "ya29.synthetic"); self.assertEqual(go.ID_ACCESS_KEY, cc.ID_ACCESS_KEY)
        self.assertNotIn(id_with_at_hash("RAW"), ss[go.SESSION_TOKEN_KEY])

    def test_without_at_hash_the_access_token_is_not_kept_as_contribution_credential(self):
        out, ss = self._exchange(jwt(nonce=go._nonce_hash("RAW")), "RAW")
        self.assertIn(go.ID_TOKEN_KEY, ss); self.assertNotIn(go.ID_ACCESS_KEY, ss)

    def test_at_hash_without_access_token_fails_closed(self):
        ss = {go.ID_ACCESS_KEY: "stale"}
        with mock.patch.object(go, "_session_state", return_value=ss):
            go._remember_id_token(id_with_at_hash("RAW"), "RAW", None)
        self.assertEqual(ss, {})

    def test_sign_out_clears_access_token(self):
        ss = {go.ID_TOKEN_KEY: "t", go.ID_NONCE_KEY: "n", go.ID_ACCESS_KEY: "a", cc.SESSION_KEY: sess(), go.SESSION_TOKEN_KEY: "{}"}
        with mock.patch.object(go, "MULTIUSER", True), mock.patch.object(go, "_session_state", return_value=ss):
            go.clear_saved_token()
        self.assertEqual(ss, {})


# --------------------------------------------------------------------------------------------------------------------
# Static checks (app.py cannot be imported without Streamlit; SQL is never executed here).
# --------------------------------------------------------------------------------------------------------------------
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
MIG = os.path.join("supabase", "migrations", "20261014000001_harden_submit_indicators.sql")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read().replace("\r\n", "\n")


class GenericGoogleOAuthErrors(unittest.TestCase):
    def test_google_callback_shows_only_fixed_messages(self):
        src = _read("app.py")
        block = src[src.index("elif GOOGLE_OAUTH_READY and _oauth_error:"):src.index("# PROFESSIONAL SOC / FORENSICS UI")]
        cleaned = re.sub(r"as _oauth_exc|type\(_oauth_exc\)\.__name__", "", block)
        self.assertIsNone(re.search(r"(?<![A-Za-z0-9_])_oauth_exc(?![A-Za-z0-9_])", cleaned))   # only the class name is ever used
        self.assertNotIn("str(_oauth_exc)", block); self.assertNotIn("{_oauth_exc}", block)      # exception text never used
        self.assertNotRegex(block, r'\["_google_oauth_error"\]\s*=\s*_oauth_error\b')           # raw ?error= value never shown
        self.assertEqual(block.count('"something went wrong. Please try again."'), 2)
        self.assertNotIn("sign-in failed while completing sign-in: {", block.split("elif GOOGLE_OAUTH_READY")[1])


class MigrationFiles(unittest.TestCase):
    def _fn(self):
        sql = _read(MIG); i = sql.index("public.submit_indicators(p_items jsonb)")
        return sql[i:sql.index("end $function$;", i)]

    def test_anonymous_and_missing_sessions_rejected_before_any_lock_or_write(self):
        fn = self._fn()
        guard = "if v_uid is null or private.is_anonymous() then raise exception 'auth_required' using errcode = '42501'; end if;"
        self.assertIn("auth.uid()", fn); self.assertIn(guard, fn)
        for later in ("pg_advisory_xact_lock", "from public.indicator_submissions", "insert into public.contribution_log"):
            self.assertLess(fn.index(guard), fn.index(later))

    def test_existing_hardening_is_carried_forward(self):
        fn, sql = self._fn(), _read(MIG)
        for needle in ("pg_advisory_xact_lock(hashtext(v_uid::text))", "pg_advisory_xact_lock(7301, 1)", "c_per_request constant int := 20",
                       "c_per_hour constant int := 50", "c_per_day constant int := 200", "c_global_hour constant int := 2000",
                       "c_reject_block constant int := 10", "c_pending_user constant int := 100", "c_pending_global constant int := 1000",
                       "'queue_full'", "'rate_limited'", "'blocked'", "'too_many_items'", "'invalid_payload'", "private.valid_indicator(v_type, v_value)"):
            self.assertIn(needle, fn)
        self.assertIn("function private.valid_host_labels", sql); self.assertIn("private.valid_host_labels(p_value)", sql)
        self.assertIn("revoke all on function public.submit_indicators(jsonb) from public, anon;", sql)

    def test_migration_does_not_touch_tables_reviewer_functions_or_rls(self):
        sql = _read(MIG).lower()
        for banned in ("create table", "alter table", "drop function", "drop table", "function public.review", "disable row level security", " to anon"):
            self.assertNotIn(banned, sql)

    def test_pgtap_003_has_matching_plan_and_covers_anonymous_rejection(self):
        t = _read("supabase", "tests", "003_contributions.sql")
        self.assertEqual(int(re.search(r"select plan\((\d+)\);", t).group(1)), len(re.findall(r"^select (?:is|throws_ok|ok)\(", t, re.M)))
        self.assertIn("'auth_required'", t); self.assertIn('"is_anonymous":false', t)
        anon = re.findall(r'"sub":"([0-9a-f-]+)"[^\n]*"is_anonymous":true', t)
        self.assertTrue(anon and all(u.endswith("00e") for u in anon))                           # only the dedicated anonymous user


if __name__ == "__main__":
    unittest.main()
