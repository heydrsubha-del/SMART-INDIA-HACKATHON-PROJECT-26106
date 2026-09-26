"""Microsoft (Outlook / Microsoft 365) OAuth2 for IMAP sign-in.

Mirrors the call interface of google_Oauth.py so app.py can wire up a
"Sign in with Microsoft" button the same way it wires up Google's:

    oauth_available() -> bool
    client_secret_issue() -> str | None
    redirect_uri() -> str
    get_authorization_url(email_hint=None) -> (url, state)
    exchange_code_for_token(code, state=None) -> (access_token, email_or_None)
    get_cached_access_token() -> str | None
    clear_saved_token() -> None

Setup (one-time, per environment):
  1. Register an app at https://portal.azure.com -> App registrations.
     Platform: "Web". Redirect URI: this app's URL (see redirect_uri()).
  2. API permissions (delegated, Microsoft Graph + IMAP):
     offline_access, openid, email, https://outlook.office.com/IMAP.AccessAsUser.All
  3. Create a client secret under "Certificates & secrets".
  4. Put {"client_id": "...", "client_secret": "...", "tenant": "common"}
     in client_secret_microsoft.json next to this file (tenant is optional,
     defaults to "common" so both personal and work/school accounts work).

The IMAP.AccessAsUser.All scope is what lets the resulting access token be
used directly as the XOAUTH2 credential against outlook.office365.com,
exactly like a Gmail OAuth2 access token is used against imap.gmail.com.
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

_AUTHORITY = "https://login.microsoftonline.com/{tenant}"
_SCOPES = (
    "offline_access openid email "
    "https://outlook.office.com/IMAP.AccessAsUser.All"
)

# Distinguishes this provider's redirects from Google's/Yahoo's when all
# three share one redirect URI on the same running app -- the state value
# always starts with this prefix so app.py's shared callback handler knows
# which exchange_code_for_token() to call.
STATE_PREFIX = "msoauth:"


def _load_client_secret():
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
    """Returns a human-readable reason sign-in can't start yet, or None."""
    data = _load_client_secret()
    if data is None:
        return (
            f"No `{_CLIENT_SECRET_PATH}` found (or it's missing `client_id`). "
            "Register an app at portal.azure.com and save its credentials there."
        )
    if not data.get("client_secret"):
        return f"`{_CLIENT_SECRET_PATH}` is missing `client_secret`."
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
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


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
            return None
        # Microsoft doesn't always return a new refresh_token; keep the old
        # one if a fresh one wasn't issued.
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
