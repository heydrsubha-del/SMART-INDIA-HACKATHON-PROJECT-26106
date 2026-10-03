"""Yandex Mail OAuth2 for IMAP sign-in.

Same call interface as google_Oauth.py / microsoft_oauth.py / the retired
yahoo_oauth.py, so app.py can wire up a "Sign in with Yandex" button
identically:

    oauth_available() -> bool
    client_secret_issue() -> str | None
    redirect_uri() -> str
    get_authorization_url(email_hint=None) -> (url, state)
    exchange_code_for_token(code, state=None) -> (access_token, email_or_None)
    get_cached_access_token() -> str | None
    clear_saved_token() -> None

Setup (one-time, per environment):
  1. Register an app at https://oauth.yandex.com/client/new (Yandex ID ->
     "My Apps" -> "Create app"). Redirect URI: this app's URL (see
     redirect_uri()). Under "Mail API" permissions, grant:
       - "Read access to user mail via IMAP/SMTP protocols" (imap:ro)
       - "Access to user email address" (login:email) and login:info, if
         you also want the account email returned at sign-in.
  2. Put {"client_id": "...", "client_secret": "..."} in
     client_secret_yandex.json next to this file.

Unlike Yahoo, Yandex's self-serve app console still grants IMAP mail
access to ordinary third-party apps as of this writing -- there's no
deprecated-API dead end here the way there was with mail-r on Yahoo.

Yandex's token endpoint authenticates the client via form fields
(client_id/client_secret in the POST body), not HTTP Basic Auth like
Yahoo's does -- handled below.
"""
import json
import os
import secrets
import time
import urllib.request
import urllib.parse
import urllib.error

_CLIENT_SECRET_PATH = "client_secret_yandex.json"
_TOKEN_CACHE_PATH = ".yandex_oauth_token_cache.json"

# On a host where you can't/shouldn't commit a client_secret_yandex.json
# file (e.g. Streamlit Community Cloud), put
# {"client_id": "...", "client_secret": "..."} as JSON text in this
# environment variable / Streamlit secret instead. Mirrors
# google_Oauth.py's SIH26106_GOOGLE_CLIENT_CONFIG. Checked first; the local
# file below is still supported as a fallback for local dev.
_CLIENT_CONFIG_ENV = "SIH26106_YANDEX_CLIENT_CONFIG"

_AUTH_ENDPOINT = "https://oauth.yandex.com/authorize"
_TOKEN_ENDPOINT = "https://oauth.yandex.com/token"
_USERINFO_ENDPOINT = "https://login.yandex.ru/info?format=json"
_SCOPES = "login:email login:info mail:imap_ro"

# Same idea as microsoft_oauth.STATE_PREFIX / the retired
# yahoo_oauth.STATE_PREFIX: lets a shared callback handler tell Yandex's
# redirect apart from Google's/Microsoft's on the same URL.
STATE_PREFIX = "yaoauth:"


def _load_client_secret():
    raw = os.environ.get(_CLIENT_CONFIG_ENV, "").strip()
    if raw:
        try:
            data = json.loads(raw) or {}
        except Exception:
            return None
        if not data.get("client_id") or not data.get("client_secret"):
            return None
        return data
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
            f"No Yandex client config found. Set `{_CLIENT_CONFIG_ENV}` (a Streamlit "
            f"secret / env var holding `{{\"client_id\": ..., \"client_secret\": ...}}` "
            f"as JSON text) or add a `{_CLIENT_SECRET_PATH}` file locally. Register an "
            "app at oauth.yandex.com/client/new to get these values, with the "
            "\"Mail API\" IMAP/SMTP read permission granted."
        )
    if "PASTE_YOUR_YANDEX" in str(data.get("client_id", "")) or "PASTE_YOUR_YANDEX" in str(data.get("client_secret", "")):
        return (
            "Yandex client config still contains the placeholder values from the "
            "template. Register an app at oauth.yandex.com/client/new and put its "
            f"real client_id/client_secret in `{_CLIENT_CONFIG_ENV}`."
        )
    return None


def oauth_available():
    return client_secret_issue() is None


def redirect_uri():
    return (
        os.environ.get("SIH26106_YANDEX_REDIRECT_URI")
        or os.environ.get("SIH26106_REDIRECT_URI")
        or os.environ.get("SIH26106_GOOGLE_REDIRECT_URI")
        or "http://localhost:8501"
    ).rstrip("/")


def get_authorization_url(email_hint=None):
    data = _load_client_secret()
    if not data:
        raise RuntimeError(client_secret_issue() or "Yandex OAuth is not configured.")
    state = STATE_PREFIX + secrets.token_urlsafe(24)
    params = {
        "client_id": data["client_id"],
        "redirect_uri": redirect_uri(),
        "response_type": "code",
        "scope": _SCOPES,
        "state": state,
        "force_confirm": "yes",
    }
    if email_hint:
        params["login_hint"] = email_hint
    url = f"{_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    return url, state


def _post_form(url, fields):
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Surface Yandex's actual JSON error body (e.g.
        # {"error":"invalid_grant","error_description":"..."}) instead of
        # the generic "HTTP Error 400: Bad Request" -- same reasoning as
        # the fix applied to the retired yahoo_oauth.py.
        try:
            detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            detail = ""
        raise RuntimeError(f"Yandex token endpoint returned HTTP {e.code}: {detail or e.reason}") from e


def fetch_email(access_token):
    try:
        req = urllib.request.Request(
            _USERINFO_ENDPOINT,
            headers={"Authorization": f"OAuth {access_token}"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            profile = json.loads(resp.read().decode("utf-8"))
        return profile.get("default_email") or profile.get("login") or None
    except Exception:
        return None


def exchange_code_for_token(code, state=None):
    data = _load_client_secret()
    if not data:
        raise RuntimeError(client_secret_issue() or "Yandex OAuth is not configured.")
    token_resp = _post_form(
        _TOKEN_ENDPOINT,
        {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": data["client_id"],
            "client_secret": data["client_secret"],
            "redirect_uri": redirect_uri(),
        },
    )
    access_token = token_resp.get("access_token")
    if not access_token:
        raise RuntimeError(f"Yandex token exchange did not return an access token: {token_resp}")
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
                "refresh_token": cache["refresh_token"],
                "client_id": data["client_id"],
                "client_secret": data["client_secret"],
            },
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