"""Google OAuth2 helper for Gmail IMAP/XOAUTH2 in SIH26106.

This uses a standard "web app" OAuth2 flow: the user clicks a sign-in link
that sends their browser to Google, and Google redirects the browser back
to this app's own URL with a ``?code=...`` parameter, which is exchanged
for tokens server-side.

This is deliberately NOT the "installed app" flow (``InstalledAppFlow.
run_local_server``). That flow starts a throwaway local web server on the
*machine running the Streamlit process* and waits for a browser on that
same machine to hit it. That only works when a developer runs the app on
their own laptop; it cannot work for anyone testing a deployed instance
over the network (there is no way for their browser to reach a random
localhost port on the server), and it also fails outright if the OAuth
client was created as a "Web application" client instead of "Desktop app",
since Google then requires an exact, pre-registered redirect URI rather
than an arbitrary port. The flow below works the same way whether the app
is running locally or deployed, and works with either client type, as
long as the redirect URI below is registered on the OAuth client (Desktop
clients also accept it automatically for any http://localhost/127.0.0.1
address).

The user's Google password is never collected by the application.

Public hosting: set SIH26106_MULTIUSER=1 so tokens live only in each visitor's
own session, and supply the OAuth client through SIH26106_GOOGLE_CLIENT_CONFIG
instead of a file.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

GMAIL_IMAP_SCOPE = "https://mail.google.com/"
# Requested alongside the IMAP scope purely so the access token can also be
# used to ask Google "which account is this?" (see
# app.py:_fetch_google_email_from_token). Without this, Google's userinfo
# endpoint has no permission to hand back an email address for the token,
# so the app had no way to know which account the user actually signed in
# with -- it could only reuse whatever address the user happened to type
# into the Email address field *before* clicking "Sign in with Google",
# which left the field blank after sign-in for anyone who didn't.
GOOGLE_EMAIL_SCOPE = "https://www.googleapis.com/auth/userinfo.email"
OAUTH_SCOPES = [GMAIL_IMAP_SCOPE, GOOGLE_EMAIL_SCOPE, "openid"]
DEFAULT_CLIENT_SECRETS = "client_secret.json"
DEFAULT_TOKEN_FILE = ".sih26106_google_token.json"
# Streamlit's default local port. Override with SIH26106_GOOGLE_REDIRECT_URI
# (e.g. to your deployed https://... URL) when the app isn't served here.
DEFAULT_REDIRECT_URI = "http://localhost:8501"

# Public-hosting mode (set SIH26106_MULTIUSER=1). In this mode a visitor's
# Google token is kept ONLY in that visitor's own session (server memory) --
# never written to a file, so it can never be picked up by another visitor,
# and it disappears when the session ends. Locally (the default) the token is
# still cached in a file so you don't have to sign in every restart.
MULTIUSER = os.environ.get("SIH26106_MULTIUSER", "").strip().lower() in (
    "1", "true", "yes", "on"
)
SESSION_TOKEN_KEY = "_google_creds_json"
# Contribution-only credentials (see get_authorization_url / _remember_id_token). They live in the visitor's
# Streamlit session state ONLY: never written to disk, never part of the saved Gmail credential JSON.
# Keep these two names identical to contribution_client.ID_TOKEN_KEY / ID_NONCE_KEY.
ID_TOKEN_KEY = "_google_id_token"
ID_NONCE_KEY = "_google_id_nonce"
# Google access token, kept ONLY when the ID token carries an at_hash claim: Supabase then requires the matching access token
# (see contribution_client). Session state only; popped with the ID token. Must equal contribution_client.ID_ACCESS_KEY.
ID_ACCESS_KEY = "_google_id_access_token"

# On a host where you can't upload a client_secret.json file (e.g. Streamlit
# Community Cloud), put the whole JSON in this environment variable / secret.
CLIENT_CONFIG_ENV = "SIH26106_GOOGLE_CLIENT_CONFIG"


def _client_secret_path() -> Path:
    return Path(os.getenv("SIH26106_GOOGLE_CLIENT_SECRETS", DEFAULT_CLIENT_SECRETS))


def _token_path() -> Path:
    return Path(os.getenv("SIH26106_GOOGLE_TOKEN_FILE", DEFAULT_TOKEN_FILE))


def redirect_uri() -> str:
    """The URL Google should send the browser back to after sign-in.

    Must exactly match (scheme, host, port, no trailing slash) a redirect
    URI registered on the OAuth client, and must be the URL this app is
    actually reachable at for whoever is testing it.
    """
    return os.getenv("SIH26106_GOOGLE_REDIRECT_URI", DEFAULT_REDIRECT_URI).strip().rstrip("/")


def _client_config_source() -> tuple[str | None, str]:
    """Return (raw_json_text, where_it_came_from). raw_json_text is None when
    no client configuration exists at all."""
    raw = os.getenv(CLIENT_CONFIG_ENV, "").strip()
    if raw:
        return raw, f"the {CLIENT_CONFIG_ENV} setting"
    path = _client_secret_path()
    if path.is_file():
        try:
            return path.read_text(encoding="utf-8"), str(path)
        except Exception:
            return None, str(path)
    return None, str(path)


def _client_config() -> dict | None:
    raw, _where = _client_config_source()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def oauth_available() -> bool:
    """Return True when the Google OAuth dependency and client config exist."""
    try:
        import google_auth_oauthlib  # noqa: F401
    except Exception:
        return False
    return _client_config() is not None


def client_secret_issue() -> str | None:
    """Return a human-readable problem with the Google client config, or None if it looks fine."""
    raw, where = _client_config_source()
    if not raw:
        return (
            f"Google client settings not found. Add a client_secret.json ({where}) "
            f"or set {CLIENT_CONFIG_ENV}."
        )
    try:
        data = json.loads(raw)
    except Exception as e:
        return f"Google client settings from {where} aren't valid JSON: {e}"
    key = "web" if "web" in data else ("installed" if "installed" in data else None)
    if key is None:
        return "Google client settings don't look like an OAuth client (missing 'web'/'installed' key)."
    cfg = data[key]
    if not cfg.get("client_id") or not cfg.get("client_secret"):
        return "Google client settings are missing client_id / client_secret."
    if "YOUR_CLIENT" in str(cfg.get("client_id")) or "YOUR_CLIENT" in str(cfg.get("client_secret")):
        return "Google client settings still contain the placeholder values from client_secret.example.json."
    return None


def _session_state():
    import streamlit as st
    return st.session_state


def _credentials_json(creds) -> str:
    """creds.to_json() with any ID token removed. The ID token is only used for the optional contribution
    sign-in and must never be saved with the Gmail credentials (all other fields, incl. refresh_token, stay)."""
    raw = creds.to_json()
    try:
        data = json.loads(raw)
    except Exception:
        return raw
    if isinstance(data, dict) and "id_token" in data:
        data.pop("id_token", None)
        return json.dumps(data)
    return raw


def _save_credentials(creds) -> None:
    if MULTIUSER:
        _session_state()[SESSION_TOKEN_KEY] = _credentials_json(creds)
        return
    path = _token_path()
    path.write_text(_credentials_json(creds), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_credentials():
    try:
        from google.oauth2.credentials import Credentials
    except Exception:
        return None

    try:
        if MULTIUSER:
            raw = _session_state().get(SESSION_TOKEN_KEY)
            if not raw:
                return None
            data = json.loads(raw)
        else:
            path = _token_path()
            if not path.is_file():
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
        return Credentials.from_authorized_user_info(data, OAUTH_SCOPES)
    except Exception:
        return None


def get_cached_access_token():
    """Return a token from a previous sign-in without ever opening a browser.

    Refreshes silently if the saved token is expired but still has a refresh
    token. Returns None if the user has never signed in, or the saved token
    can no longer be refreshed -- callers should fall back to showing the
    'Sign in with Google' link in that case.
    """
    try:
        from google.auth.transport.requests import Request
    except Exception:
        return None

    creds = _load_credentials()
    if not creds:
        return None
    if creds.valid:
        return creds.token
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            _save_credentials(creds)
            return creds.token
        except Exception:
            return None
    return None


def _generate_code_verifier() -> str:
    """A fresh RFC 7636 PKCE code_verifier (43-128 chars of unreserved
    characters). 96 random bytes -> 128 base64url chars with no padding,
    right at the top of that range."""
    return base64.urlsafe_b64encode(secrets.token_bytes(96)).rstrip(b"=").decode("ascii")


def _code_challenge_for(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _generate_nonce() -> str:
    """Unpredictable RAW nonce (43 url-safe chars, never contains '.'). Only its SHA-256 hex digest is sent to
    Google; the raw value is what Supabase's ID-token grant needs."""
    return secrets.token_urlsafe(32)


def _nonce_hash(raw_nonce: str) -> str:
    return hashlib.sha256(raw_nonce.encode("ascii")).hexdigest()


def _unpack_nonce(state: str) -> str | None:
    """Recover the raw nonce packed by _pack_state, or None if `state` is not one of ours."""
    try:
        padded = state + "=" * (-len(state) % 4)
        nonce = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8").split(".", 2)[0]
        return nonce or None
    except Exception:
        return None


def _jwt_claims(token) -> dict | None:
    """UNVERIFIED decode of a JWT payload (consistency checks only; Supabase verifies the token)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        data = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def clear_google_id_token() -> None:
    try:
        st_state = _session_state()
        st_state.pop(ID_TOKEN_KEY, None)
        st_state.pop(ID_NONCE_KEY, None)
        st_state.pop(ID_ACCESS_KEY, None)
    except Exception:
        pass


def _remember_id_token(id_token, raw_nonce, access_token=None) -> None:
    """Keep the ID token (+ raw nonce) in session state ONLY if it belongs to this OAuth transaction: its
    `nonce` claim must equal SHA-256(raw nonce) that we sent to Google. Never raises; never touches Gmail tokens."""
    try:
        clear_google_id_token()
        if not (isinstance(id_token, str) and id_token and isinstance(raw_nonce, str) and raw_nonce):
            return
        claims = _jwt_claims(id_token)
        if not claims or not secrets.compare_digest(str(claims.get("nonce", "")), _nonce_hash(raw_nonce)):
            return
        needs_access = claims.get("at_hash") is not None     # Supabase docs: an ID token with at_hash must be accompanied by its access_token
        if needs_access and not (isinstance(access_token, str) and access_token):
            return                                           # fail closed: contributing needs a fresh sign-in; Gmail is unaffected
        st_state = _session_state()
        st_state[ID_TOKEN_KEY] = id_token
        st_state[ID_NONCE_KEY] = raw_nonce
        if needs_access:
            st_state[ID_ACCESS_KEY] = access_token
    except Exception:
        pass


def _pack_state(code_verifier: str, email_hint: str = "", nonce: str | None = None) -> str:
    """Combine a fresh CSRF nonce, the PKCE code_verifier, and (optionally)
    whatever email address the user had already typed into `state`.

    `state` is the only piece of data Google guarantees to hand back
    unchanged on the redirect. Streamlit treats the post-redirect page load
    as a brand-new session -- nothing kept in memory or st.session_state
    from before the browser left for Google's sign-in page still exists by
    the time the callback runs, which is why a partially-filled "Email
    address" box would otherwise come back empty. Packing both values into
    `state` (instead of trying to keep them in memory, a session, or a file
    on disk) lets the callback rebuild the same Flow *and* restore the
    typed email, with nothing to persist server-side. `email_hint` is
    appended last and un-split, so an address containing "." is safe.
    """
    nonce = nonce or _generate_nonce()
    payload = f"{nonce}.{code_verifier}.{email_hint}".encode("utf-8")
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _unpack_state(state: str) -> tuple[str, str] | None:
    """Recover (code_verifier, email_hint) packed by _pack_state, or None
    if `state` doesn't look like one of ours (e.g. it's missing, or a stale
    link from before this packing scheme existed)."""
    try:
        padded = state + "=" * (-len(state) % 4)
        _nonce, code_verifier, email_hint = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8").split(".", 2)
        return code_verifier, email_hint
    except Exception:
        return None


def _build_flow(state: str | None = None, code_verifier: str | None = None):
    """Build a fresh Flow object. Stateless by design: Streamlit gives the
    callback request a brand-new session, so we never rely on an earlier
    Flow instance surviving the round trip to Google and back -- we just
    rebuild it from client_secret.json + the fixed redirect_uri (+ the
    code_verifier recovered from `state`, see _pack_state) each time.
    """
    from google_auth_oauthlib.flow import Flow

    issue = client_secret_issue()
    if issue:
        raise ValueError(issue)

    flow = Flow.from_client_config(
        _client_config(),
        scopes=OAUTH_SCOPES,
        state=state,
        code_verifier=code_verifier,
        # We always supply our own code_verifier explicitly (or none at all
        # for the no-PKCE fallback below) rather than letting the library
        # generate one internally -- current google-auth-oauthlib versions
        # default this to True, which is exactly what silently broke this
        # flow before: the Flow object built to *start* sign-in would
        # auto-generate a verifier that lived only in that one in-memory
        # object, then the unrelated Flow object rebuilt to *finish*
        # sign-in had no way to know it, so Google's token endpoint ended
        # up expecting a verifier that was never sent -- "(invalid_grant)
        # Missing code verifier".
        autogenerate_code_verifier=False,
    )
    flow.redirect_uri = redirect_uri()
    return flow


def get_authorization_url(email_hint: str = "") -> tuple[str, str]:
    """Return (authorization_url, state). Send the user's browser to
    authorization_url (e.g. via a link/st.link_button) to sign in.

    `email_hint`, if given (e.g. whatever the user already typed into an
    "Email address" box), rides along inside `state` and comes back out of
    exchange_code_for_token() -- see _pack_state.
    """
    code_verifier = _generate_code_verifier()
    raw_nonce = _generate_nonce()
    flow = _build_flow(state=_pack_state(code_verifier, email_hint, raw_nonce), code_verifier=code_verifier)
    auth_url, state = flow.authorization_url(
        nonce=_nonce_hash(raw_nonce),         # Google embeds this in the ID token; Supabase gets the raw value
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        code_challenge=_code_challenge_for(code_verifier),
        code_challenge_method="S256",
    )
    return auth_url, state


def exchange_code_for_token(code: str, state: str | None = None) -> tuple[str, str]:
    """Complete sign-in after Google redirects back with ?code=...&state=...

    Returns (access_token, email_hint) -- email_hint is whatever was passed
    to get_authorization_url(), or "" if none was given / recoverable.

    Call this once, on the run where the ?code param is present, then clear
    the query params so a page refresh doesn't try to reuse a spent code.
    """
    unpacked = _unpack_state(state) if state else None
    code_verifier, email_hint = unpacked if unpacked else (None, "")
    flow = _build_flow(state=state, code_verifier=code_verifier)
    if code_verifier:
        flow.fetch_token(code=code, code_verifier=code_verifier)
    else:
        flow.fetch_token(code=code)
    creds = flow.credentials
    if not creds or not creds.token:
        raise RuntimeError("Google OAuth completed but no access token was returned.")
    _save_credentials(creds)
    _remember_id_token(getattr(creds, "id_token", None), _unpack_nonce(state) if state else None, creds.token)
    return creds.token, email_hint


def clear_saved_token() -> None:
    clear_google_id_token()
    try:
        _session_state().pop("_contrib_session", None)      # contribution_client.SESSION_KEY: sign-out ends it too
    except Exception:
        pass
    if MULTIUSER:
        try:
            _session_state().pop(SESSION_TOKEN_KEY, None)
        except Exception:
            pass
        return
    try:
        _token_path().unlink(missing_ok=True)
    except Exception:
        pass