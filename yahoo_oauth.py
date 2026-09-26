"""Yahoo Mail OAuth2 for IMAP sign-in.

Same call interface as google_Oauth.py / microsoft_oauth.py, so app.py can
wire up a "Sign in with Yahoo" button identically:

    oauth_available() -> bool
    client_secret_issue() -> str | None
    redirect_uri() -> str
    get_authorization_url(email_hint=None) -> (url, state)
    exchange_code_for_token(code, state=None) -> (access_token, email_or_None)
    get_cached_access_token() -> str | None
    clear_saved_token() -> None

Setup (one-time, per environment):
  1. Register an app at https://developer.yahoo.com/apps -> Create an App.
     Redirect URI: this app's URL (see redirect_uri()).
     API permissions: "Mail" (Read/Write) and "OpenID Connect Permissions"
     (email, profile) so IMAP access + the sign-in email are both granted.
  2. Put {"client_id": "...", "client_secret": "..."} in
     client_secret_yahoo.json next to this file.

Yahoo's token endpoint authenticates the client with HTTP Basic Auth
(client_id:client_secret) rather than form fields, unlike Google/Microsoft
-- handled below.
"""
import base64
import json
import os
import secrets
import time
import urllib.request
import urllib.parse
import urllib.error

_CLIENT_SECRET_PATH = "client_secret_yahoo.json"
_TOKEN_CACHE_PATH = ".yahoo_oauth_token_cache.json"

_AUTH_ENDPOINT = "https://api.login.yahoo.com/oauth2/request_auth"
_TOKEN_ENDPOINT = "https://api.login.yahoo.com/oauth2/get_token"
_USERINFO_ENDPOINT = "https://api.login.yahoo.com/openid/v1/userinfo"
_SCOPES = "openid email mail-r"

# Same idea as microsoft_oauth.STATE_PREFIX: lets a shared callback handler
# tell Yahoo's redirect apart from Google's/Microsoft's on the same URL.
STATE_PREFIX = "yhoauth:"


def _load_client_secret():
    try:
        with open(_CLIENT_SECRET_PATH, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except Exception:
        return None
    if not data.get("client_id") or not data.get("client_secret"):
        return None
    return data


def client_secret_issue():
    data = _load_client_secret()
    if data is None:
        return (
            f"No `{_CLIENT_SECRET_PATH}` found (or it's missing `client_id`/"
            "`client_secret`). Register an app at developer.yahoo.com/apps "
            "and save its credentials there."
        )
    return None


def oauth_available():
    return client_secret_issue() is None


def redirect_uri():
    return (
        os.environ.get("SIH26106_YAHOO_REDIRECT_URI")
        or os.environ.get("SIH26106_REDIRECT_URI")
        or os.environ.get("SIH26106_GOOGLE_REDIRECT_URI")
        or "http://localhost:8501"
    ).rstrip("/")


def get_authorization_url(email_hint=None):
    data = _load_client_secret()
    if not data:
        raise RuntimeError(client_secret_issue() or "Yahoo OAuth is not configured.")
    state = STATE_PREFIX + secrets.token_urlsafe(24)
    params = {
        "client_id": data["client_id"],
        "redirect_uri": redirect_uri(),
        "response_type": "code",
        "scope": _SCOPES,
        "state": state,
        "language": "en-us",
    }
    if email_hint:
        params["login_hint"] = email_hint
    url = f"{_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    return url, state


def _basic_auth_header(data):
    raw = f"{data['client_id']}:{data['client_secret']}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _post_form(url, fields, data):
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": _basic_auth_header(data),
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_email(access_token):
    try:
        req = urllib.request.Request(
            _USERINFO_ENDPOINT,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            profile = json.loads(resp.read().decode("utf-8"))
        return profile.get("email") or None
    except Exception:
        return None


def exchange_code_for_token(code, state=None):
    data = _load_client_secret()
    if not data:
        raise RuntimeError(client_secret_issue() or "Yahoo OAuth is not configured.")
    token_resp = _post_form(
        _TOKEN_ENDPOINT,
        {
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri(),
            "code": code,
        },
        data,
    )
    access_token = token_resp.get("access_token")
    if not access_token:
        raise RuntimeError(f"Yahoo token exchange did not return an access token: {token_resp}")
    _save_token_cache(token_resp)
    email = fetch_email(access_token)
    return access_token, email


def _save_token_cache(token_resp):
    try:
        cache = {
            "access_token": token_resp.get("access_token"),
            "refresh_token": token_resp.get("refresh_token"),
            "expires_at": time.time() + float(token_resp.get("expires_in", 3600)) - 60,
        }
        with open(_TOKEN_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception:
        pass


def _refresh(cache):
    data = _load_client_secret()
    if not data or not cache.get("refresh_token"):
        return None
    try:
        token_resp = _post_form(
            _TOKEN_ENDPOINT,
            {
                "grant_type": "refresh_token",
                "redirect_uri": redirect_uri(),
                "refresh_token": cache["refresh_token"],
            },
            data,
        )
        if not token_resp.get("access_token"):
            return None
        token_resp.setdefault("refresh_token", cache.get("refresh_token"))
        _save_token_cache(token_resp)
        return token_resp.get("access_token")
    except Exception:
        return None


def get_cached_access_token():
    try:
        with open(_TOKEN_CACHE_PATH, "r", encoding="utf-8") as f:
            cache = json.load(f) or {}
    except Exception:
        return None
    if not cache.get("access_token"):
        return None
    if time.time() < cache.get("expires_at", 0):
        return cache["access_token"]
    return _refresh(cache)


def clear_saved_token():
    try:
        os.remove(_TOKEN_CACHE_PATH)
    except OSError:
        pass
