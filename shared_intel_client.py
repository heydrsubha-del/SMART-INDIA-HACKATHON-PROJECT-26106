"""Read-only client for VERIFIED shared threat intelligence (Supabase REST, anon key only).

Not wired into scans yet. Never sends email data, never writes, never uses a service-role key (such keys are refused).
Every row is re-sanitized locally; rows that fail or change are dropped. Fail-soft: errors return ok=False.

Env: SIH26106_SUPABASE_URL, SIH26106_SUPABASE_ANON_KEY
"""
import base64
import json
import os
from urllib.parse import urlsplit

import requests

from indicator_sanitizer import sanitize_indicator

URL_ENV, KEY_ENV = "SIH26106_SUPABASE_URL", "SIH26106_SUPABASE_ANON_KEY"
_PAGE, _MAX_ROWS = 1000, 50000
_COLUMNS = "indicator_type,value_norm,verdict,confidence"
_VERDICTS = {"malicious", "suspicious"}


def _key_problem(key):
    """Reason the key must not be used, or None. Refuses secret / service-role keys outright."""
    if key.startswith("sb_secret_"):
        return "a secret key was supplied; only the public anon/publishable key is allowed"
    parts = key.split(".")
    if len(parts) == 3:
        try:
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            if str(payload.get("role", "")).lower() == "service_role":
                return "a service-role key was supplied; only the public anon key is allowed"
        except Exception:
            return "the key is not a valid anon key"
    return None


def _base_url(url):
    p = urlsplit(url.strip())
    local = p.hostname in ("localhost", "127.0.0.1")
    if p.scheme != "https" and not (p.scheme == "http" and local):
        return None
    return "%s://%s" % (p.scheme, p.netloc) if p.netloc else None


def is_configured():
    return bool(os.environ.get(URL_ENV, "").strip() and os.environ.get(KEY_ENV, "").strip())


def _fail(msg):
    return {"ok": False, "rows": [], "rejected": 0, "error": msg}


def fetch_verified(max_rows=_MAX_ROWS, timeout=15, session=None):
    """Return {"ok", "rows": [{"indicator","type","verdict","confidence","source":"community"}], "rejected", "error"}."""
    url, key = os.environ.get(URL_ENV, "").strip(), os.environ.get(KEY_ENV, "").strip()
    if not url or not key:
        return _fail("Supabase is not configured.")
    base = _base_url(url)
    if not base:
        return _fail("Supabase URL must be https (or http on localhost).")
    problem = _key_problem(key)
    if problem:
        return _fail(problem)

    http = session or requests
    headers = {"apikey": key, "Accept": "application/json"}
    if not key.startswith("sb_"):                 # new-style publishable keys are not JWTs: apikey header only
        headers["Authorization"] = "Bearer " + key
    rows, rejected, offset = [], 0, 0
    try:
        while offset < max_rows:
            resp = http.get(base + "/rest/v1/shared_indicators", headers=headers, timeout=timeout, allow_redirects=False,
                            params={"select": _COLUMNS, "status": "eq.verified", "order": "updated_at.asc",
                                    "limit": str(_PAGE), "offset": str(offset)})
            resp.raise_for_status()
            page = resp.json()
            if not isinstance(page, list):
                return _fail("Unexpected response from the shared-intelligence service.")
            for item in page:
                row = _clean_row(item)
                if row:
                    rows.append(row)
                else:
                    rejected += 1
            if len(page) < _PAGE:
                break
            offset += _PAGE
    except Exception:
        return _fail("Could not read shared intelligence (network or service error).")   # never echo the key or URL
    return {"ok": True, "rows": rows, "rejected": rejected, "error": ""}


def _clean_row(item):
    if not isinstance(item, dict):
        return None
    kind, value, verdict = item.get("indicator_type"), item.get("value_norm"), item.get("verdict")
    if verdict not in _VERDICTS or kind not in ("url", "domain", "ip", "hash"):
        return None
    res = sanitize_indicator(value, kind)
    if not res.ok or res.value != value:          # server data must already be in sanitized form
        return None
    try:
        conf = min(max(float(item.get("confidence", 0.5)), 0.0), 1.0)
    except (TypeError, ValueError):
        conf = 0.5
    return {"indicator": res.value, "type": kind, "verdict": verdict, "confidence": conf, "source": "community"}
