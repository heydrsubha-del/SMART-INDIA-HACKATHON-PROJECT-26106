"""Opt-in community contributions (Phase 3). Quarantine only: nothing here can make an indicator trusted.

* OFF unless SIH26106_CONTRIBUTIONS is truthy. Submitting also needs explicit consent (consent is True).
* Sends ONLY sanitized url/domain/ip/hash indicators (no query strings, addresses, email text, reports, attachments)
  plus a verdict word. Items are re-sanitized here and again by the database; status and identity are never sent.
* Authentication: a REAL (non-anonymous) Supabase session obtained from the user's Google ID token via
  POST /auth/v1/token?grant_type=id_token (provider=google, raw nonce). There is NO anonymous sign-up. The Google
  ID token, raw nonce and the Supabase access/refresh tokens live only in the caller-supplied `store` (Streamlit
  session state): never on disk, never logged, never in an error. A Google *access* token is never a substitute for the ID token; it is sent alongside it only when Supabase requires it (at_hash).
* Uses the public anon/publishable key only. Service-role/secret keys are refused. Supabase and the database
  remain the authoritative auth enforcement; the local is_anonymous JWT check is a defensive early reject only.
* Fail-soft: every problem returns {"ok": False, "error": <code>}; normal scanning is never affected.
"""
import base64
import json
import os
import time
from collections.abc import MutableMapping
from urllib.parse import urlsplit

import requests

import shared_intel_client as _sic
from indicator_sanitizer import sanitize_indicator

FLAG_ENV = "SIH26106_CONTRIBUTIONS"
MAX_ITEMS, MIN_INTERVAL, TIMEOUT = 20, 30.0, 8
VERDICTS = ("suspicious", "malicious")
# Session-state keys. ID_* must match google_Oauth.ID_TOKEN_KEY / ID_NONCE_KEY / ID_ACCESS_KEY.
ID_TOKEN_KEY, ID_NONCE_KEY, ID_ACCESS_KEY = "_google_id_token", "_google_id_nonce", "_google_id_access_token"
_ID_KEYS = (ID_TOKEN_KEY, ID_NONCE_KEY, ID_ACCESS_KEY)
SESSION_KEY, LAST_KEY = "_contrib_session", "_contrib_last_submit"
_KNOWN_ERRORS = {"rate_limited", "blocked", "too_many_items", "invalid_payload", "auth_required", "queue_full"}


def enabled():
    return os.environ.get(FLAG_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def candidates_from_result(result):
    """Heuristically flagged URLs (and their hosts) from a scan result. Raw values; run through prepare()."""
    out = []
    iocs = (result or {}).get("iocs") or {}
    for u in iocs.get("suspicious_urls") or []:
        raw = u.get("url") if isinstance(u, dict) else u
        if not isinstance(raw, str) or not raw:
            continue
        out.append(("url", raw))
        try:
            host = urlsplit(raw).hostname
        except ValueError:
            host = None
        if host:
            out.append(("domain", host))
    return out


def prepare(candidates):
    """Sanitize + dedupe + cap. Returns {"items": [{"indicator_type","value_norm"}], "rejected": n, "truncated": bool}.
    This is exactly what would be shared (plus the verdict the user picks)."""
    items, seen, rejected = [], set(), 0
    for kind, raw in candidates or []:
        res = sanitize_indicator(raw, kind)
        if not res.ok:
            rejected += 1
            continue
        key = (res.indicator_type, res.value)
        if key not in seen:
            seen.add(key)
            items.append({"indicator_type": res.indicator_type, "value_norm": res.value})
    return {"items": items[:MAX_ITEMS], "rejected": rejected, "truncated": len(items) > MAX_ITEMS}


def _fail(code):
    return {"ok": False, "accepted": 0, "duplicates": 0, "rejected": 0, "error": code}


def _jwt_claims(token):
    """UNVERIFIED decode of a JWT payload. Local sanity checks only, never authentication."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        data = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _is_anonymous(token):
    claims = _jwt_claims(token)
    return claims is not None and claims.get("is_anonymous") not in (None, False)


def _pop(store, *keys):
    for k in keys:
        store.pop(k, None)


def _valid_session(sess):
    return (isinstance(sess, dict) and all(isinstance(sess.get(k), str) and sess[k] for k in ("access_token", "refresh_token"))
            and _jwt_claims(sess["access_token"]) is not None and not _is_anonymous(sess["access_token"]))


def _id_token_usable(store):
    tok, nonce = store.get(ID_TOKEN_KEY), store.get(ID_NONCE_KEY)
    if not (isinstance(tok, str) and tok and isinstance(nonce, str) and nonce):
        return False
    claims = _jwt_claims(tok)
    if claims is None:
        return False
    if claims.get("at_hash") is not None:      # Supabase: an ID token with at_hash is only accepted together with its access_token
        acc = store.get(ID_ACCESS_KEY)
        if not (isinstance(acc, str) and acc):
            return False
    exp = claims.get("exp")
    return not (isinstance(exp, (int, float)) and exp <= time.time())


def auth_state(store):
    """'session' (reusable Supabase session), 'id_token' (fresh Google ID token, can sign in) or None (Google sign-in needed)."""
    if not isinstance(store, MutableMapping):
        return None
    if _valid_session(store.get(SESSION_KEY)):
        return "session"
    return "id_token" if _id_token_usable(store) else None


def clear_session(store):
    if isinstance(store, MutableMapping):
        _pop(store, SESSION_KEY, LAST_KEY, *_ID_KEYS)


def _token_request(base, key, grant, body, timeout):
    return requests.post(base + "/auth/v1/token", params={"grant_type": grant}, json=body, timeout=timeout,
                         allow_redirects=False,          # never follow a redirect: it could leave the project host
                         headers={"apikey": key, "Content-Type": "application/json"})


def _post_rpc(base, key, token, payload, timeout):
    return requests.post(base + "/rest/v1/rpc/submit_indicators", timeout=timeout, json={"p_items": payload},
                         allow_redirects=False,                         # the Bearer token must only ever go to the configured host
                         headers={"apikey": key, "Authorization": "Bearer " + token, "Content-Type": "application/json"})


def _auth_http_error(resp, refreshing):
    """Safe code for a non-2xx/3xx response from /auth/v1/token, or None when it succeeded."""
    sc = resp.status_code
    if 300 <= sc < 400 or sc >= 500:
        return "unavailable"
    if sc == 429:
        return "rate_limited"
    if sc >= 400:
        return "session_expired" if refreshing else "auth_required"
    return None


def _read_session(resp):
    """(session, None) or (None, code). Anonymous or malformed sessions are never accepted."""
    try:
        data = resp.json()
        sess = {"access_token": data.get("access_token"), "refresh_token": data.get("refresh_token")}
    except Exception:
        return None, "unavailable"
    if not all(isinstance(v, str) and v for v in sess.values()) or _jwt_claims(sess["access_token"]) is None:
        return None, "unavailable"
    if _is_anonymous(sess["access_token"]):
        return None, "auth_required"
    return sess, None


def _sign_in_google(store, base, key, timeout):
    if not _id_token_usable(store):
        _pop(store, *_ID_KEYS)
        return None, "auth_required"                 # no fresh ID token: the user must sign in with Google again
    body = {"provider": "google", "id_token": store[ID_TOKEN_KEY], "nonce": store[ID_NONCE_KEY]}
    if (_jwt_claims(store[ID_TOKEN_KEY]) or {}).get("at_hash") is not None:
        body["access_token"] = store[ID_ACCESS_KEY]      # only when required (Supabase docs); never otherwise
    resp = _token_request(base, key, "id_token", body, timeout)
    err = _auth_http_error(resp, refreshing=False)
    if err in ("auth_required",):
        _pop(store, *_ID_KEYS)      # rejected: do not keep retrying a bad token
        return None, err
    if err:
        return None, err                              # transient: keep the ID token for a later retry
    sess, err = _read_session(resp)
    if err:
        _pop(store, *_ID_KEYS)
        return None, err
    store[SESSION_KEY] = sess
    _pop(store, *_ID_KEYS)          # exchanged: no longer needed
    return sess, None


def _refresh(store, base, key, sess, timeout):
    resp = _token_request(base, key, "refresh_token", {"refresh_token": sess["refresh_token"]}, timeout)
    err = _auth_http_error(resp, refreshing=True)
    if err == "session_expired":
        _pop(store, SESSION_KEY)
        return None, err
    if err:
        return None, err                              # transient: keep the session
    new, err = _read_session(resp)
    if err:
        _pop(store, SESSION_KEY)
        return None, "session_expired" if err == "auth_required" else err
    store[SESSION_KEY] = new
    return new, None


def _rpc_error(resp, default):
    try:
        msg = str(resp.json().get("message", ""))
    except Exception:
        msg = ""
    if msg in _KNOWN_ERRORS:
        return msg
    return "rate_limited" if resp.status_code == 429 else default


def submit(items, verdict, consent, store=None, timeout=TIMEOUT):
    """Submit prepared items to quarantine. `store` is the caller's session-state mapping (st.session_state).
    Never raises, never falls back to anonymous access."""
    if not enabled():
        return _fail("disabled")
    if consent is not True:
        return _fail("consent_required")
    if verdict not in VERDICTS:
        return _fail("invalid_verdict")
    payload = []
    for it in (items or [])[:MAX_ITEMS]:
        if not isinstance(it, dict):
            continue
        res = sanitize_indicator(it.get("value_norm"), it.get("indicator_type"))
        if res.ok and res.value == it.get("value_norm"):          # callers are not trusted: unsanitized items are dropped
            payload.append({"indicator_type": res.indicator_type, "value_norm": res.value, "claimed_verdict": verdict})
    if not payload:
        return _fail("nothing_to_submit")
    url, key = os.environ.get(_sic.URL_ENV, "").strip(), os.environ.get(_sic.KEY_ENV, "").strip()
    base = _sic._base_url(url) if url else None
    if not base or not key or _sic._key_problem(key):
        return _fail("not_configured")
    if not isinstance(store, MutableMapping):
        return _fail("auth_required")
    now = time.monotonic()
    last = store.get(LAST_KEY)
    if isinstance(last, (int, float)) and 0 <= now - last < MIN_INTERVAL:      # courtesy throttle; the database enforces the real limits
        return _fail("rate_limited_locally")
    try:
        sess, fresh = store.get(SESSION_KEY), False
        if not _valid_session(sess):
            _pop(store, SESSION_KEY)
            sess, err = _sign_in_google(store, base, key, timeout)
            if err:
                return _fail(err)
            fresh = True
        store[LAST_KEY] = now
        resp = _post_rpc(base, key, sess["access_token"], payload, timeout)
        if resp.status_code in (401, 403):
            if fresh:                                              # a brand-new session was refused: do not loop
                _pop(store, SESSION_KEY)
                return _fail(_rpc_error(resp, "auth_required"))
            sess, err = _refresh(store, base, key, sess, timeout)    # at most ONE refresh + ONE retry
            if err:
                return _fail(err)
            resp = _post_rpc(base, key, sess["access_token"], payload, timeout)
            if resp.status_code in (401, 403):
                _pop(store, SESSION_KEY)
                return _fail(_rpc_error(resp, "session_expired"))
        if 300 <= resp.status_code < 400:
            return _fail("unavailable")                           # redirects are never followed
        if resp.status_code >= 400:
            return _fail(_rpc_error(resp, "server_error"))
        data = resp.json()
        counts = [data.get(k) for k in ("accepted", "duplicates", "rejected")] if isinstance(data, dict) else [None]
        if any(type(c) is not int or c < 0 for c in counts):
            return _fail("unavailable")
        return {"ok": True, "accepted": counts[0], "duplicates": counts[1], "rejected": counts[2], "error": ""}
    except Exception:
        return _fail("unavailable")    # never echo URLs, keys, tokens or exception text
