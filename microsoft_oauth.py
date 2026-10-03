"""Microsoft (Outlook / Microsoft 365) OAuth2 for IMAP sign-in.

Same call interface as before, plus two small additions:

    oauth_available() -> bool
    client_secret_issue() -> str | None
    redirect_uri() -> str
    get_authorization_url(email_hint=None) -> (url, state)
    exchange_code_for_token(code, state=None) -> (access_token, email_or_None)
    get_cached_access_token() -> str | None      # refreshes automatically
    clear_saved_token() -> None
    last_error() -> str | None                   # NEW: why the last refresh failed

Config (checked in this order):
  1. Env var / Streamlit secret SIH26106_MS_CLIENT_CONFIG holding JSON text:
       {"client_id": "...", "client_secret": "...", "tenant": "common"}
  2. client_secret_microsoft.json next to this file (local dev).

Azure app registration: delegated permissions offline_access, openid, email,
https://outlook.office.com/IMAP.AccessAsUser.All. NOTE: client secrets in Azure
expire (max 24 months) -- when one does, sign-in AND token refresh both start
failing, so last_error() will say invalid_client.
"""
import json
import os
import secrets
import time
import urllib.request
import urllib.parse
import urllib.error

_CLIENT_SECRET_PATH = "client_secret_microsoft.json"
_TOKEN_CACHE_PATH = ".microsoft_oauth_token_cache.json"
_CLIENT_CONFIG_ENV = "SIH26106_MS_CLIENT_CONFIG"

_AUTHORITY = "https://login.microsoftonline.com/{tenant}"
_SCOPES = (
    "offline_access openid email "
    "https://outlook.office.com/IMAP.AccessAsUser.All"
)

STATE_PREFIX = "msoauth:"

_LAST_ERROR = None


def last_error():
    """Human-readable reason the most recent token refresh/exchange failed."""
    return _LAST_ERROR


def _load_client_secret():
    raw = os.environ.get(_CLIENT_CONFIG_ENV, "").strip()
    if raw:
        try:
            data = json.loads(raw) or {}
        except Exception:
            return None
    else:
        try:
            with open(_CLIENT_SECRET_PATH, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except Exception:
            return None
    if not data.get("client_id"):
        return None
    data.setdefault("tenant", "common")
    return data


def client_secret_issue():
    data = _load_client_secret()
    if data is None:
        return (
            f"No Microsoft client config found. Set `{_CLIENT_CONFIG_ENV}` (Streamlit "
            f"secret / env var with JSON `{{\"client_id\": ..., \"client_secret\": ...}}`) "
            f"or add `{_CLIENT_SECRET_PATH}` locally."
        )
    if not data.get("client_secret"):
        return "Microsoft client config is missing `client_secret`."
    return None


def oauth_available():
    return client_secret_issue() is None


def redirect_uri():
    return (
        os.environ.get("SIH26106_MS_REDIRECT_URI")
        or os.environ.get("SIH26106_REDIRECT_URI")
        or os.environ.get("SIH26106_GOOGLE_REDIRECT_URI")
        or "http://localhost:8501"
    ).rstrip("/")


def _authority():
    data = _load_client_secret() or {}
    return _AUTHORITY.format(tenant=data.get("tenant", "common"))


def get_authorization_url(email_hint=None):
    data = _load_client_secret()
    if not data:
        raise RuntimeError(client_secret_issue() or "Microsoft OAuth is not configured.")
    state = STATE_PREFIX + secrets.token_urlsafe(24)
    params = {
        "client_id": data["client_id"],
        "response_type": "code",
        "redirect_uri": redirect_uri(),
        "response_mode": "query",
        "scope": _SCOPES,
        "state": state,
        "prompt": "select_account",
    }
    if email_hint:
        params["login_hint"] = email_hint
    url = f"{_authority()}/oauth2/v2.0/authorize?{urllib.parse.urlencode(params)}"
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
        # Surface Microsoft's real error (invalid_grant, invalid_client, AADSTS...)
        try:
            detail = json.loads(e.read().decode("utf-8", errors="replace"))
            detail = f"{detail.get('error')}: {detail.get('error_description', '')}".strip()
        except Exception:
            detail = str(e.reason)
        raise RuntimeError(f"Microsoft token endpoint returned HTTP {e.code}: {detail}") from e


def fetch_email(access_token):
    try:
        req = urllib.request.Request(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            profile = json.loads(resp.read().decode("utf-8"))
        return profile.get("mail") or profile.get("userPrincipalName") or None
    except Exception:
        return None


def exchange_code_for_token(code, state=None):
    global _LAST_ERROR
    data = _load_client_secret()
    if not data:
        raise RuntimeError(client_secret_issue() or "Microsoft OAuth is not configured.")
    token_resp = _post_form(
        f"{_authority()}/oauth2/v2.0/token",
        {
            "client_id": data["client_id"],
            "client_secret": data["client_secret"],
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri(),
            "scope": _SCOPES,
        },
    )
    access_token = token_resp.get("access_token")
    if not access_token:
        raise RuntimeError(f"Microsoft token exchange did not return an access token: {token_resp}")
    if not token_resp.get("refresh_token"):
        _LAST_ERROR = "No refresh token was issued (is offline_access granted?). Sign-in will expire in ~1 hour."
    else:
        _LAST_ERROR = None
    _save_token_cache(token_resp)
    email = fetch_email(access_token)
    return access_token, email


def _save_token_cache(token_resp):
    try:
        cache = {
            "access_token": token_resp.get("access_token"),
            "refresh_token": token_resp.get("refresh_token"),
            "expires_at": time.time() + float(token_resp.get("expires_in", 3600)) - 120,
        }
        with open(_TOKEN_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception:
        pass


def _refresh(cache):
    global _LAST_ERROR
    data = _load_client_secret()
    if not data:
        _LAST_ERROR = client_secret_issue()
        return None
    if not cache.get("refresh_token"):
        _LAST_ERROR = "No refresh token saved - please sign in with Outlook again."
        return None
    try:
        token_resp = _post_form(
            f"{_authority()}/oauth2/v2.0/token",
            {
                "client_id": data["client_id"],
                "client_secret": data["client_secret"],
                "grant_type": "refresh_token",
                "refresh_token": cache["refresh_token"],
                "scope": _SCOPES,
            },
        )
        if not token_resp.get("access_token"):
            _LAST_ERROR = f"Refresh returned no access token: {token_resp}"
            return None
        token_resp.setdefault("refresh_token", cache.get("refresh_token"))
        _save_token_cache(token_resp)
        _LAST_ERROR = None
        return token_resp.get("access_token")
    except Exception as exc:
        _LAST_ERROR = str(exc)
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