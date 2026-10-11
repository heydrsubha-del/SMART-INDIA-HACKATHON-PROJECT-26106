"""Opt-in community contributions (Phase 3). Quarantine only: nothing here can make an indicator trusted.

* OFF unless SIH26106_CONTRIBUTIONS is truthy. Submitting also needs explicit consent (consent is True).
* Sends ONLY sanitized url/domain/ip/hash indicators (no query strings, addresses, email text, reports, attachments)
  plus a verdict word. Items are re-sanitized here and again by the database; status and identity are never sent.
* Uses the public anon key and a per-session Supabase anonymous sign-in token. Service-role/secret keys are refused.
* Fail-soft: every problem returns {"ok": False, "error": <code>}; normal scanning is never affected.
"""
import os
import time
from urllib.parse import urlsplit

import requests

import shared_intel_client as _sic
from indicator_sanitizer import sanitize_indicator

FLAG_ENV = "SIH26106_CONTRIBUTIONS"
MAX_ITEMS, MIN_INTERVAL, TIMEOUT = 20, 30.0, 8
VERDICTS = ("suspicious", "malicious")
_KNOWN_ERRORS = {"rate_limited", "blocked", "too_many_items", "invalid_payload", "auth_required"}
_last_submit = {}          # session token -> last submit time (courtesy throttle; the database enforces the real limits)


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


def _fail(code, **kw):
    """Failure result. `token` (when given) is a still-valid anonymous session the caller should REUSE, so a
    transient failure after sign-in does not make the next attempt create another anonymous user."""
    return dict({"ok": False, "accepted": 0, "duplicates": 0, "rejected": 0, "error": code, "token": None}, **kw)


def _sign_in(base, key, timeout):
    resp = requests.post(base + "/auth/v1/signup", headers={"apikey": key, "Content-Type": "application/json"}, json={},
                         timeout=timeout, allow_redirects=False)       # never follow a redirect: it could leave the project host
    if 300 <= resp.status_code < 400:
        return None
    resp.raise_for_status()
    token = resp.json().get("access_token")
    return token if isinstance(token, str) and token else None


def _post_rpc(base, key, token, payload, timeout):
    return requests.post(base + "/rest/v1/rpc/submit_indicators", timeout=timeout, json={"p_items": payload},
                         allow_redirects=False,                         # the Bearer token must only ever go to the configured host
                         headers={"apikey": key, "Authorization": "Bearer " + token, "Content-Type": "application/json"})


def submit(items, verdict, consent, token=None, timeout=TIMEOUT):
    """Submit prepared items to quarantine. Never raises."""
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
    token = token if isinstance(token, str) and token else None      # anything else: treat as "no session"
    now = time.monotonic()
    if token:
        last = _last_submit.get(token)
        if last is not None and now - last < MIN_INTERVAL:
            return _fail("rate_limited_locally")
        if len(_last_submit) > 1000:
            _last_submit.clear()
        _last_submit[token] = now
    try:
        for attempt in (1, 2):
            fresh = token is None
            if fresh:
                token = _sign_in(base, key, timeout)
                if not token:
                    return _fail("unavailable")
            resp = _post_rpc(base, key, token, payload, timeout)
            if resp.status_code in (401, 403) and not fresh and attempt == 1:
                token = None                                       # expired session: sign in once more
                continue
            break
        if 300 <= resp.status_code < 400:
            return _fail("unavailable", token=token)             # redirects are never followed
        if resp.status_code >= 400:
            try:
                msg = str(resp.json().get("message", ""))
            except Exception:
                msg = ""
            keep = None if resp.status_code in (401, 403) else token     # an auth-refused session is not reusable
            return _fail(msg if msg in _KNOWN_ERRORS else "server_error", token=keep)
        data = resp.json()
        counts = [data.get(k) for k in ("accepted", "duplicates", "rejected")]
        if not isinstance(data, dict) or any(type(c) is not int or c < 0 for c in counts):
            return _fail("unavailable", token=token)
        return {"ok": True, "accepted": counts[0], "duplicates": counts[1], "rejected": counts[2], "error": "", "token": token}
    except Exception:
        return _fail("unavailable", token=token)    # never echo URLs, keys or exception text; keep any session already made
