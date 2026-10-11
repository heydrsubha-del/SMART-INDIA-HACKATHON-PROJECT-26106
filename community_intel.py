"""Community threat intelligence lookup (Phase 2). Contextual evidence only.

* OFF unless SIH26106_COMMUNITY_INTEL is truthy; when off, lookup() returns None and nothing happens.
* Privacy: the only network call is the read-only fetch of the VERIFIED feed (shared_intel_client). No scan data,
  email, address, report or indicator from the scan is ever sent; matching happens locally.
* Never changes the score and never counts as an external-feed match or confirmed malicious indicator.
* Fail-soft: any problem yields status 'unavailable'; scanning continues normally.
"""
import os
import threading
import time

import shared_intel_client
from indicator_sanitizer import sanitize_indicator

FLAG_ENV = "SIH26106_COMMUNITY_INTEL"
_TTL_OK, _TTL_FAIL, _FETCH_TIMEOUT, MAX_MATCHES = 6 * 3600, 300, 5, 50
_NOTE = ("Community-reported and verified by reviewers, but contextual only: it is not a confirmed malicious match for "
         "this email, it did not change the threat score, and no match does not mean an indicator is safe.")
_cache = {"at": 0.0, "ttl": 0, "feed": None}
_lock = threading.Lock()


def enabled():
    return os.environ.get(FLAG_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _feed():
    """Cached verified feed as {'rows': [...]} or None when unavailable. Failures are cached briefly (no scan slowdown)."""
    with _lock:
        now = time.time()
        if now - _cache["at"] < _cache["ttl"]:
            return _cache["feed"]
        try:
            res = shared_intel_client.fetch_verified(timeout=_FETCH_TIMEOUT)
            feed = res["rows"] if res.get("ok") and isinstance(res.get("rows"), list) else None
        except Exception:
            feed = None
        _cache.update(at=now, ttl=_TTL_OK if feed is not None else _TTL_FAIL, feed=feed)
        return feed


def reset_cache():
    with _lock:
        _cache.update(at=0.0, ttl=0, feed=None)


def _artifacts(parsed, iocs, geo):
    """(domains, ips, urls) = lists of (value, field). Reuses Retro-Hunt's extraction; email addresses are reduced to domains."""
    import retro_hunt
    doms, ips = retro_hunt._case_artifacts({"parsed": parsed or {}, "iocs": iocs or {}, "geo": geo or {}})
    urls = []
    for u in (iocs or {}).get("urls") or []:
        raw = u.get("url") if isinstance(u, dict) else u
        if raw:
            urls.append((raw, "Link"))
    return doms, ips, urls


def lookup(parsed, iocs, geo):
    """None when disabled. Otherwise {'enabled', 'status', 'matches', 'checked', 'feed_size', 'note'}. Never raises."""
    if not enabled():
        return None
    base = {"enabled": True, "status": "unavailable", "matches": [], "checked": 0, "feed_size": 0, "note": _NOTE}
    try:
        feed = _feed()
        if feed is None:
            return base
        import retro_hunt
        doms, ips, urls = _artifacts(parsed, iocs, geo)
        by_type = {}
        for r in feed:
            by_type.setdefault(r["type"], []).append(r)
        found, checked = {}, set()

        def add(row, value, match, field):
            key = (row["type"], row["indicator"], value)
            hit = found.setdefault(key, {"indicator": row["indicator"], "type": row["type"], "match": match,
                                         "verdict": row["verdict"], "confidence": row["confidence"],
                                         "found_in": [], "source": "community"})
            if field not in hit["found_in"]:
                hit["found_in"].append(field)

        for value, field in doms:
            s = sanitize_indicator(value, "domain")
            if not s.ok:
                continue
            checked.add(("domain", s.value))
            for row in by_type.get("domain", []):
                m = retro_hunt._host_matches(s.value, row["indicator"])
                if m:
                    add(row, s.value, m, field)
        for value, field in ips:
            s = sanitize_indicator(value, "ip")
            if not s.ok:
                continue
            checked.add(("ip", s.value))
            for row in by_type.get("ip", []):
                if row["indicator"] == s.value:
                    add(row, s.value, "exact", field)
        for value, field in urls:
            s = sanitize_indicator(value, "url")
            if not s.ok:
                continue
            checked.add(("url", s.value))
            for row in by_type.get("url", []):
                if row["indicator"] == s.value:
                    add(row, s.value, "exact", field)
        matches = sorted(found.values(), key=lambda h: (-h["confidence"], h["indicator"]))[:MAX_MATCHES]
        return dict(base, status="ok", matches=matches, checked=len(checked), feed_size=len(feed))
    except Exception:
        return base
