"""ALGORITHMISTIC - AI-Powered Email Threat Detection, GeoLocation & Forensic
Intelligence Platform.

Run:   streamlit run app.py
"""
import traceback
import hashlib
import csv
import io
import os
import json
import random
import urllib.request
import urllib.error
import time
import threading
import html
import re
import textwrap

import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st
import streamlit.components.v1 as components

# Keep all Plotly visuals consistent with the dark SOC interface: extend the
# built-in dark template with our own palette/typography instead of leaving
# every chart on generic Plotly defaults.
pio.templates["sih26106_dark"] = go.layout.Template(
    layout=go.Layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, Segoe UI, Arial, sans-serif", color="#c9d8e7", size=12),
        title=dict(font=dict(family="Inter, Segoe UI, Arial, sans-serif", color="#edf5ff", size=15)),
        colorway=["#2fd8ff", "#35d399", "#ff9f43", "#ff4757", "#a389f4", "#f47ab0", "#f4c95d", "#5c6bc0"],
        xaxis=dict(gridcolor="#16324a", zerolinecolor="#1e3853", linecolor="#1e3853", tickfont=dict(color="#8fa5bd")),
        yaxis=dict(gridcolor="#16324a", zerolinecolor="#1e3853", linecolor="#1e3853", tickfont=dict(color="#8fa5bd")),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#c9d8e7")),
        hoverlabel=dict(bgcolor="#0d1a2b", bordercolor="#2c5877", font=dict(color="#edf5ff", family="Inter, Segoe UI, Arial, sans-serif")),
        margin=dict(t=40, l=10, r=10, b=10),
    )
)
pio.templates.default = "plotly_dark+sih26106_dark"
from ollama_threat import analyze_with_ollama, analyze_batch_with_ollama
from nomic_embed import nomic_available, embeddings_usable, embeddings_backend, describe_origin, embed_text, save_origin_embedding, find_similar_origins
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

try:
    from docx import Document
    from docx.shared import Inches, Pt
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    from google_Oauth import (
        oauth_available,
        clear_saved_token,
        get_cached_access_token,
        get_authorization_url,
        exchange_code_for_token,
        client_secret_issue,
        redirect_uri as google_redirect_uri,
    )
    GOOGLE_OAUTH_READY = True
except ImportError:
    GOOGLE_OAUTH_READY = False

try:
    import microsoft_oauth
    MICROSOFT_OAUTH_READY = True
except ImportError:
    MICROSOFT_OAUTH_READY = False

try:
    try:
        import yandex_oauth
    except ModuleNotFoundError:
        import yandex_Oauth as yandex_oauth
    YANDEX_OAUTH_READY = True
except Exception as _yandex_import_exc:
    # TEMPORARY: widened from `except ImportError` to `except Exception` and
    # keeping the actual exception, so the "Not available" caption in the
    # Yandex sign-in box can show the real reason instead of a generic
    # "failed to import" message that hides what's actually wrong --
    # ImportError only covers "file not found"; anything that goes wrong
    # *inside* yandex_oauth.py while it's loading (e.g. a typo, a bad
    # import) is a different exception type and was being silently caught
    # as if the file were simply missing. Once this is working, this can
    # be narrowed back to `except ImportError` if you don't want import
    # errors elsewhere masked this broadly.
    YANDEX_OAUTH_READY = False
    YANDEX_IMPORT_ERROR = repr(_yandex_import_exc)
else:
    YANDEX_IMPORT_ERROR = None

def _fresh_token(session_key, cached_getter, keep_session_fallback=False):
    """Return a valid OAuth access token, refreshing it if it has expired.

    The cached getter checks expiry and uses the refresh token; the session
    copy is only a convenience and goes stale after ~1 hour, so it must not
    take priority over it.
    """
    tok = None
    try:
        tok = cached_getter()
    except Exception:
        tok = None
    if tok:
        st.session_state[session_key] = tok
        return tok
    if keep_session_fallback:
        return st.session_state.get(session_key)
    st.session_state.pop(session_key, None)
    return None


# google_Oauth.py caches the OAuth *token* across restarts, but not the
# account email that goes with it -- so a restored session knew it was
# "signed in" without knowing which address that meant, and the Email
# address field came up blank even though sign-in had already happened.
# This small cache + lookup closes that gap: once we've resolved an email
# for a token (from the fresh sign-in redirect, or by asking Google), we
# remember it on disk so future restarts don't need the field retyped or
# even a network call.
_GOOGLE_EMAIL_CACHE_PATH = ".google_email_cache.json"


def _load_cached_google_email():
    """Best-effort read of the last-known signed-in Google email. Returns
    None (never raises) if no cache file exists yet or it's unreadable.
    On a public host (MULTIUSER) it lives only in this visitor's session."""
    if MULTIUSER:
        return st.session_state.get("_google_email_cache") or None
    try:
        with open(_GOOGLE_EMAIL_CACHE_PATH, "r", encoding="utf-8") as f:
            return (json.load(f) or {}).get("email") or None
    except Exception:
        return None


def _save_cached_google_email(email: str):
    """Best-effort write; failing to persist just means we'll re-resolve
    the email next time instead of breaking anything."""
    if MULTIUSER:
        st.session_state["_google_email_cache"] = email
        return
    try:
        with open(_GOOGLE_EMAIL_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump({"email": email}, f)
    except Exception:
        pass


def _fetch_google_email_from_token(access_token: str):
    """Ask Google which account an access token belongs to. Returns the
    email, or None (never raises) if the token has expired, lacks the
    email/profile scope, or the request fails for any other reason --
    callers fall back to manual entry in that case, so this can't break
    the sign-in flow, only skip the auto-fill."""
    try:
        req = urllib.request.Request(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("email") or None
    except Exception:
        return None


# Same email-cache idea as Google's, generalized so Microsoft and Yandex
# sign-in get the same "don't make me retype my address after a restart"
# behavior without three near-identical copies of the Google helpers above.
_PROVIDER_EMAIL_CACHE_PATHS = {
    "microsoft": ".microsoft_email_cache.json",
    "yandex": ".yandex_email_cache.json",
}


def _load_cached_provider_email(provider_key: str):
    if MULTIUSER:
        return st.session_state.get(f"_{provider_key}_email_cache") or None
    try:
        with open(_PROVIDER_EMAIL_CACHE_PATHS[provider_key], "r", encoding="utf-8") as f:
            return (json.load(f) or {}).get("email") or None
    except Exception:
        return None


def _save_cached_provider_email(provider_key: str, email: str):
    if MULTIUSER:
        st.session_state[f"_{provider_key}_email_cache"] = email
        return
    try:
        with open(_PROVIDER_EMAIL_CACHE_PATHS[provider_key], "w", encoding="utf-8") as f:
            json.dump({"email": email}, f)
    except Exception:
        pass

from tracker import (
    init_db,
    log_threat,
    check_history,
    add_feedback,
    get_feedback_history_count,
    get_connection,
    MULTIUSER,
    delete_my_data,
)

import folium
from streamlit_folium import st_folium

import config as C
import correlate
import threat_feed
import inspect

def _build_correlation_graph(cases, max_cases=None, seed=None):
    """Wrapper around correlate.build_graph() that stays compatible even if
    an older correlate.py (without the max_cases/seed sampling params) is on
    disk -- falls back to the full, unsampled graph instead of crashing the
    whole panel with a TypeError. If you're seeing this fall back, update
    correlate.py to the latest version to get the sampling/shuffle controls."""
    try:
        params = inspect.signature(correlate.build_graph).parameters
    except (TypeError, ValueError):
        params = {}
    kwargs = {}
    if "max_cases" in params:
        kwargs["max_cases"] = max_cases
    if "seed" in params:
        kwargs["seed"] = seed
    try:
        return correlate.build_graph(cases, **kwargs)
    except TypeError:
        return correlate.build_graph(cases)


def _render_correlation_figure(G, height=520, highlight_node=None):
    """Same idea as _build_correlation_graph() but for graph_figure() and
    its highlight_node param."""
    try:
        params = inspect.signature(correlate.graph_figure).parameters
    except (TypeError, ValueError):
        params = {}
    kwargs = {"height": height}
    if "highlight_node" in params:
        kwargs["highlight_node"] = highlight_node
    try:
        return correlate.graph_figure(G, **kwargs)
    except TypeError:
        return correlate.graph_figure(G, height=height)


@st.cache_data(show_spinner=False)
def _cached_correlation_view(graph_scope, _cases, cases_to_show, seed, use_semantic, highlight_node):
    """Build the sampled correlation graph and its rendered figure once per
    unique (case set, sample size, seed, semantic toggle, highlighted node)
    combination, instead of on every rerun.

    graph_figure() runs a force-directed (Kamada-Kawai) layout per cluster,
    which is by far the most expensive thing the Correlation panel does --
    and because Streamlit reruns the whole script top to bottom on *any*
    widget interaction, without this cache it was being recomputed every
    time you touched anything on this panel (the slider, a checkbox, even
    just clicking a node), not only when the underlying cases actually
    changed. ``_cases`` is prefixed with an underscore so Streamlit passes
    it through without spending time hashing it -- ``graph_scope`` (already
    a hash of the case set, computed by the caller) plus the remaining
    scalar args are what actually identify a unique result.
    """
    G_view = _build_correlation_graph(_cases, max_cases=cases_to_show, seed=seed)
    semantic_failed = False
    if use_semantic:
        try:
            correlate.add_semantic_edges(G_view, _cases, find_similar_origins)
        except Exception:
            semantic_failed = True
    fig = _render_correlation_figure(G_view, height=560, highlight_node=highlight_node)
    # G_view itself is returned too (not just the figure) because the
    # caller still needs the graph object for click-to-highlight and the
    # "connects to" neighbor summary below the chart. networkx graphs of
    # plain node/edge attributes like these pickle cleanly, so caching
    # them alongside the figure is safe.
    return (
        fig,
        G_view,
        semantic_failed,
        G_view.graph.get("sampled"),
        G_view.graph.get("case_count"),
        G_view.graph.get("total_case_count"),
    )

from analyzer import analyze_all_samples, analyze_email, list_samples
from classifier import (
    cached_metrics,
    load_or_train,
    maybe_retrain_from_feedback,
    get_adaptive_status,
    get_feedback_count,
)
from geolocate import INFRA_LABEL
from network_trust import assess_network_trust, load_vpn_ranges, scan_cases_for_vpn
import tor_check
try:
    from fetch_vpn_ranges import fetch_category as _fetch_vpn_category
    FETCH_VPN_RANGES_AVAILABLE = True
except ImportError:
    FETCH_VPN_RANGES_AVAILABLE = False
from report import build_report, evidence_hash
from live_scanner import PROVIDERS, fetch_mailbox_messages, fetch_message_by_uid, fetch_messages_by_uids


# --- Instant message opening ---------------------------------------------
# Opening a message used to mean: new TLS connection + login + SELECT + FETCH
# on every click. We now (a) prefetch the newest message bodies in ONE IMAP
# session in a background thread as soon as the mailbox loads, and (b) keep
# every body we fetch in a small per-session cache. A click on a cached
# message is then just a dict lookup. (analyze_bytes is already cached on the
# raw bytes, so re-opening a scanned message is instant too.)
_PREFETCH_COUNT = 15
_PREFETCH_MAX_BYTES = 4_000_000
_RAW_CACHE_LIMIT = 40


def _raw_cache():
    return st.session_state.setdefault("_imap_raw_cache", {})


def _raw_cache_key(cfg, uid):
    return (str(cfg.get("user")), str(cfg.get("folder")), str(uid))


def _store_raw(cfg, uid, raw):
    cache = _raw_cache()
    cache[_raw_cache_key(cfg, uid)] = bytes(raw)
    try:
        while len(cache) > _RAW_CACHE_LIMIT:
            cache.pop(next(iter(cache)))
    except Exception:
        pass


@st.cache_data(show_spinner=False, max_entries=60)
def _message_body_text(raw_bytes):
    """Readable text of a message body (plain part preferred, HTML stripped)."""
    try:
        from email import policy as _policy
        from email.parser import BytesParser as _BP
        msg = _BP(policy=_policy.default).parsebytes(raw_bytes)
        part = msg.get_body(preferencelist=("plain",))
        if part is not None:
            text = part.get_content()
        else:
            part = msg.get_body(preferencelist=("html",))
            text = part.get_content() if part is not None else ""
            text = re.sub(r"(?is)<(script|style).*?</\1>", "", text)
            text = re.sub(r"(?i)<br\s*/?>|</(p|div|tr|li|h[1-6])>", "\n", text)
            text = html.unescape(re.sub(r"<[^>]+>", "", text))
        text = re.sub(r"\n{3,}", "\n\n", str(text or "")).strip()
        if not text:
            return "(This message has no readable text body.)"
        return text[:200000]
    except Exception as exc:
        return f"(Could not read the message body: {exc})"


def _start_prefetch(cfg, uids):
    """Fetch the newest message bodies in the background over one session."""
    try:
        cache = _raw_cache()
        cfg = dict(cfg)
        todo = [str(u) for u in uids if _raw_cache_key(cfg, u) not in cache][:_PREFETCH_COUNT]
        if not todo:
            return

        def _work():
            try:
                got = fetch_messages_by_uids(
                    cfg["host"], cfg["user"], cfg["credential"], todo,
                    folder=cfg["folder"], port=cfg["port"], auth_mode=cfg["auth_mode"],
                ) or {}
                for uid, raw in got.items():
                    if isinstance(raw, (bytes, bytearray)) and raw and len(raw) <= _PREFETCH_MAX_BYTES:
                        cache[_raw_cache_key(cfg, uid)] = bytes(raw)
            except Exception:
                pass

        threading.Thread(target=_work, daemon=True).start()
    except Exception:
        pass


def _ensure_live_cases_from_prefetch(max_new=10):
    """Lazily turn already-prefetched Live IMAP messages into _corr_cases
    entries, so the Origin & Route map/picker and the Correlation graph
    have ALL browsed messages to show -- not just whichever single one
    the person happened to open -- without requiring a separate click on
    "Synapse Copilot - Full Report" first.

    Deliberately does MACHINE analysis only (analyze_bytes -- fast, local,
    no network calls beyond the geolocation lookups analyze_bytes already
    does), not the AI/Ollama campaign analysis or semantic-origin
    indexing _run_batch_pipeline also does. Those stay behind the
    explicit "Full Report" button because they're meaningfully slower
    (LLM calls per email) -- auto-running them on every mailbox load
    would make Origin & Route noticeably slow to open. If someone wants
    the AI analysis and semantic correlation too, "Full Report" is still
    the way to get that on top of this.

    Only touches messages _start_prefetch has already fetched into
    _raw_cache() (background thread, so this is instant/free when it's
    caught up); any not yet prefetched are silently skipped this run and
    picked up automatically on a later rerun once prefetch catches up --
    never blocks waiting on IMAP itself.
    """
    cfg = st.session_state.get("live_mailbox_config")
    headers = st.session_state.get("live_mailbox_messages") or []
    if not cfg or not headers:
        return
    cache = _raw_cache()
    added = 0
    for h in headers:
        if added >= max_new:
            break
        uid = h.get("uid")
        if uid is None:
            continue
        raw = cache.get(_raw_cache_key(cfg, uid))
        if not raw:
            continue
        ehash = hashlib.sha256(raw).hexdigest()
        if ehash in _corr_cases:
            continue
        try:
            res = analyze_bytes(raw, f"Live IMAP #{uid}")
        except Exception:
            continue
        res["_evidence_hash"] = ehash
        _corr_cases[ehash] = res
        added += 1
    if added:
        while len(_corr_cases) > 60:
            _corr_cases.pop(next(iter(_corr_cases)))


from antivirus_scan import clamd_available, clamd_version, scan_bytes, antivirus_usable, antivirus_backend

# ALGORITHMISTIC brand mark, embedded as a base64 PNG so the app stays a
# single self-contained file (no separate asset to lose track of). Resized
# down from the original 1254x1254 source to 160x160 -- plenty of
# resolution for the ~20-40px it's actually displayed at in the sidebar
# and top bar, at a fraction of the file size the full-resolution source
# would add here.
_ALGORITHMISTIC_LOGO_B64 = "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"
_ALGORITHMISTIC_LOGO_SRC = f"data:image/png;base64,{_ALGORITHMISTIC_LOGO_B64}"

# Stylized network/globe graphic for the banner background (matches the
# reference picture's glowing globe/network look). This is a generated
# abstract dot-and-line mesh in the app's own brand colors, not an actual
# world map image -- far lighter-weight than a real map asset and avoids
# any licensing question over map data, while still reading as "global
# network" the way the reference did.
_TOPBAR_MAP_B64 = "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA5MDAgMjYwIj4KPGNpcmNsZSBjeD0iODEwIiBjeT0iMTMwIiByPSIxNTAiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzIyYzdhYyIgc3Ryb2tlLW9wYWNpdHk9IjAuMTgiIHN0cm9rZS13aWR0aD0iMSIvPgo8Y2lyY2xlIGN4PSI4MTAiIGN5PSIxMzAiIHI9IjEwNSIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utb3BhY2l0eT0iMC4xNiIgc3Ryb2tlLXdpZHRoPSIxIi8+CjxsaW5lIHgxPSI1MDQiIHkxPSI0NiIgeDI9IjU4MCIgeTI9IjgyIiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI1MDQiIHkxPSI0NiIgeDI9IjQ5OSIgeTI9IjE1MSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNjk2IiB5MT0iMjciIHgyPSI2MzUiIHkyPSIyNSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNjk2IiB5MT0iMjciIHgyPSI3NDIiIHkyPSI3OSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNjI4IiB5MT0iOTgiIHgyPSI2NTMiIHkyPSIxMDUiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjYyOCIgeTE9Ijk4IiB4Mj0iNjU0IiB5Mj0iMTE5IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSIzNDkiIHkxPSIxMzIiIHgyPSIzMzciIHkyPSIxMTQiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjM0OSIgeTE9IjEzMiIgeDI9IjMzOCIgeTI9IjE3MCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iMzM3IiB5MT0iMTE0IiB4Mj0iMzQ5IiB5Mj0iMTMyIiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSIzMzciIHkxPSIxMTQiIHgyPSIzNTAiIHkyPSI1OSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iMzU2IiB5MT0iMzIiIHgyPSIzNTAiIHkyPSI1OSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iMzU2IiB5MT0iMzIiIHgyPSIzOTkiIHkyPSIzOCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNTYzIiB5MT0iMjA4IiB4Mj0iNTYwIiB5Mj0iMTkyIiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI1NjMiIHkxPSIyMDgiIHgyPSI2MjIiIHkyPSIyMjAiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjM4NyIgeTE9IjY0IiB4Mj0iMzk5IiB5Mj0iMzgiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjM4NyIgeTE9IjY0IiB4Mj0iMzUwIiB5Mj0iNTkiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjY4MiIgeTE9IjIzNyIgeDI9IjYyMiIgeTI9IjIyMCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNjgyIiB5MT0iMjM3IiB4Mj0iNzIyIiB5Mj0iMTUzIiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI2NTMiIHkxPSIxMDUiIHgyPSI2NTQiIHkyPSIxMTkiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjY1MyIgeTE9IjEwNSIgeDI9IjYyOCIgeTI9Ijk4IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI4ODYiIHkxPSIyMSIgeDI9Ijg4OCIgeTI9IjM4IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI4ODYiIHkxPSIyMSIgeDI9IjgyNyIgeTI9Ijg1IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI4MTciIHkxPSI4MCIgeDI9IjgyNyIgeTI9Ijg1IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI4MTciIHkxPSI4MCIgeDI9Ijc0MiIgeTI9Ijc5IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSIzOTkiIHkxPSIzOCIgeDI9IjM4NyIgeTI9IjY0IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSIzOTkiIHkxPSIzOCIgeDI9IjM1NiIgeTI9IjMyIiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI0OTUiIHkxPSIyMDYiIHgyPSI0OTkiIHkyPSIxNTEiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjQ5NSIgeTE9IjIwNiIgeDI9IjU2MCIgeTI9IjE5MiIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNDIxIiB5MT0iMTUwIiB4Mj0iNDA0IiB5Mj0iMTI3IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI0MjEiIHkxPSIxNTAiIHgyPSI0NTgiIHkyPSIxNDgiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjY4OSIgeTE9Ijk5IiB4Mj0iNzEzIiB5Mj0iMTEzIiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI2ODkiIHkxPSI5OSIgeDI9IjY1MyIgeTI9IjEwNSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNjM1IiB5MT0iMjUiIHgyPSI2OTYiIHkyPSIyNyIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNjM1IiB5MT0iMjUiIHgyPSI2MjgiIHkyPSI5OCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iMzUwIiB5MT0iNTkiIHgyPSIzNTYiIHkyPSIzMiIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iMzUwIiB5MT0iNTkiIHgyPSIzODciIHkyPSI2NCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNzEzIiB5MT0iMTEzIiB4Mj0iNjg5IiB5Mj0iOTkiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjcxMyIgeTE9IjExMyIgeDI9IjcyMiIgeTI9IjE1MyIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNDk5IiB5MT0iMTUxIiB4Mj0iNDU4IiB5Mj0iMTQ4IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI0OTkiIHkxPSIxNTEiIHgyPSI0OTUiIHkyPSIyMDYiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjU4MCIgeTE9IjgyIiB4Mj0iNjI4IiB5Mj0iOTgiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjU4MCIgeTE9IjgyIiB4Mj0iNjUzIiB5Mj0iMTA1IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI3ODAiIHkxPSIxNzgiIHgyPSI3NjIiIHkyPSIxNDgiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9Ijc4MCIgeTE9IjE3OCIgeDI9IjcyMiIgeTI9IjE1MyIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNDU4IiB5MT0iMTQ4IiB4Mj0iNDIxIiB5Mj0iMTUwIiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI0NTgiIHkxPSIxNDgiIHgyPSI0OTkiIHkyPSIxNTEiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjYyMiIgeTE9IjIyMCIgeDI9IjU2MyIgeTI9IjIwOCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNjIyIiB5MT0iMjIwIiB4Mj0iNjgyIiB5Mj0iMjM3IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI3NDIiIHkxPSI3OSIgeDI9IjcxMyIgeTI9IjExMyIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNzQyIiB5MT0iNzkiIHgyPSI2ODkiIHkyPSI5OSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iODg4IiB5MT0iMzgiIHgyPSI4ODYiIHkyPSIyMSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iODg4IiB5MT0iMzgiIHgyPSI4MjciIHkyPSI4NSIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNTYwIiB5MT0iMTkyIiB4Mj0iNTYzIiB5Mj0iMjA4IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI1NjAiIHkxPSIxOTIiIHgyPSI0OTUiIHkyPSIyMDYiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjQwNCIgeTE9IjEyNyIgeDI9IjQyMSIgeTI9IjE1MCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNDA0IiB5MT0iMTI3IiB4Mj0iMzQ5IiB5Mj0iMTMyIiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSIzMzgiIHkxPSIxNzAiIHgyPSIzNDkiIHkyPSIxMzIiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjMzOCIgeTE9IjE3MCIgeDI9IjMzNyIgeTI9IjExNCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNzYyIiB5MT0iMTQ4IiB4Mj0iNzgwIiB5Mj0iMTc4IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI3NjIiIHkxPSIxNDgiIHgyPSI3MjIiIHkyPSIxNTMiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjgyNyIgeTE9Ijg1IiB4Mj0iODE3IiB5Mj0iODAiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjgyNyIgeTE9Ijg1IiB4Mj0iODg4IiB5Mj0iMzgiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjcyMiIgeTE9IjE1MyIgeDI9Ijc2MiIgeTI9IjE0OCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz48bGluZSB4MT0iNzIyIiB5MT0iMTUzIiB4Mj0iNzEzIiB5Mj0iMTEzIiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI2NTQiIHkxPSIxMTkiIHgyPSI2NTMiIHkyPSIxMDUiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjY1NCIgeTE9IjExOSIgeDI9IjYyOCIgeTI9Ijk4IiBzdHJva2U9IiM1NDcwZmYiIHN0cm9rZS13aWR0aD0iMC42IiBzdHJva2Utb3BhY2l0eT0iMC4zNSIvPjxsaW5lIHgxPSI4MDYiIHkxPSIyMzciIHgyPSI3ODAiIHkyPSIxNzgiIHN0cm9rZT0iIzU0NzBmZiIgc3Ryb2tlLXdpZHRoPSIwLjYiIHN0cm9rZS1vcGFjaXR5PSIwLjM1Ii8+PGxpbmUgeDE9IjgwNiIgeTE9IjIzNyIgeDI9Ijc2MiIgeTI9IjE0OCIgc3Ryb2tlPSIjNTQ3MGZmIiBzdHJva2Utd2lkdGg9IjAuNiIgc3Ryb2tlLW9wYWNpdHk9IjAuMzUiLz4KPGNpcmNsZSBjeD0iNTA0IiBjeT0iNDYiIHI9IjEuNyIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iNjk2IiBjeT0iMjciIHI9IjIuMCIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iNjI4IiBjeT0iOTgiIHI9IjEuMiIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iMzQ5IiBjeT0iMTMyIiByPSIyLjAiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjMzNyIgY3k9IjExNCIgcj0iMS45IiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSIzNTYiIGN5PSIzMiIgcj0iMi40IiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSI1NjMiIGN5PSIyMDgiIHI9IjIuMiIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iMzg3IiBjeT0iNjQiIHI9IjEuNSIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iNjgyIiBjeT0iMjM3IiByPSIxLjYiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjY1MyIgY3k9IjEwNSIgcj0iMi4wIiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSI4ODYiIGN5PSIyMSIgcj0iMS4xIiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSI4MTciIGN5PSI4MCIgcj0iMS43IiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSIzOTkiIGN5PSIzOCIgcj0iMS4zIiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSI0OTUiIGN5PSIyMDYiIHI9IjEuMyIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iNDIxIiBjeT0iMTUwIiByPSIxLjIiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjY4OSIgY3k9Ijk5IiByPSIyLjEiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjYzNSIgY3k9IjI1IiByPSIxLjMiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjM1MCIgY3k9IjU5IiByPSIxLjQiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjcxMyIgY3k9IjExMyIgcj0iMS42IiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSI0OTkiIGN5PSIxNTEiIHI9IjIuMiIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iNTgwIiBjeT0iODIiIHI9IjEuMiIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iNzgwIiBjeT0iMTc4IiByPSIxLjciIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjQ1OCIgY3k9IjE0OCIgcj0iMS44IiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSI2MjIiIGN5PSIyMjAiIHI9IjIuMiIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iNzQyIiBjeT0iNzkiIHI9IjIuMiIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iODg4IiBjeT0iMzgiIHI9IjIuMiIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iNTYwIiBjeT0iMTkyIiByPSIxLjUiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjQwNCIgY3k9IjEyNyIgcj0iMS42IiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSIzMzgiIGN5PSIxNzAiIHI9IjEuNiIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iNzYyIiBjeT0iMTQ4IiByPSIyLjIiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjgyNyIgY3k9Ijg1IiByPSIyLjMiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPjxjaXJjbGUgY3g9IjcyMiIgY3k9IjE1MyIgcj0iMS4zIiBmaWxsPSIjN2ZkOGZmIiBmaWxsLW9wYWNpdHk9IjAuNTUiLz48Y2lyY2xlIGN4PSI2NTQiIGN5PSIxMTkiIHI9IjEuMyIgZmlsbD0iIzdmZDhmZiIgZmlsbC1vcGFjaXR5PSIwLjU1Ii8+PGNpcmNsZSBjeD0iODA2IiBjeT0iMjM3IiByPSIxLjQiIGZpbGw9IiM3ZmQ4ZmYiIGZpbGwtb3BhY2l0eT0iMC41NSIvPgo8L3N2Zz4="
_TOPBAR_MAP_SRC = f"data:image/svg+xml;base64,{_TOPBAR_MAP_B64}"

@st.cache_data(ttl=20, show_spinner=False)
def _clamd_up_cached():
    """antivirus_usable() opens a real TCP socket to check clamd (and may
    check for a cloud API key too) -- st.tabs renders every tab's body on
    every rerun (only visibility is toggled client-side), so without this
    the antivirus tab would re-probe on every single interaction anywhere
    in the app, even the map tab. A 20s cache keeps the same live check
    without hammering the daemon. Despite the name, this now reflects
    whether scan_bytes() can actually scan at all -- local clamd or the
    cloud fallback -- not just local clamd; see antivirus_backend() for
    which one it'll actually use."""
    return antivirus_usable()

@st.cache_data(ttl=20, show_spinner=False)
def _antivirus_backend_cached():
    """Which backend scan_bytes() will actually use right now ('local',
    'cloud', or None) -- same caching rationale as _clamd_up_cached."""
    return antivirus_backend()

@st.cache_data(ttl=300, show_spinner=False)
def _scan_bytes_cached(data):
    """scan_bytes() opens a socket to clamd and scans the file for every
    call -- same 'st.tabs renders every tab body on every rerun' issue as
    _clamd_up_cached above, except here it means every attachment already
    scanned gets rescanned on every click anywhere else on this panel.
    Keyed on the attachment's own bytes, so identical content is never
    rescanned twice; the 5-minute ttl still picks up a freshly updated
    signature database without needing a restart."""
    return scan_bytes(data)

# --------------------------------------------------------------------------
# SEMANTIC ORIGIN CORRELATION (nomic-embed-text) -- shared helpers
#
# One place for how an origin is described, embedded, indexed, searched and
# labelled, so the Origin & Route panel, the batch pipeline, the copilot and
# the Forensic Report (per-email dossier + joint report) all produce the same
# findings instead of each doing its own slightly different thing.
#
#   * Richer profile text  -- describe_origin() plus the relay path, the
#     origin's network operator and Tor-exit status, so origins that "behave
#     the same way" embed closer together.
#   * Hybrid ranking       -- raw embedding similarity plus a small bonus for
#     verifiable shared traits (same IP / same /24 / same infrastructure
#     class / same country), so a match can always explain itself.
#   * De-duplication       -- one row per origin IP (with an "emails from this
#     origin" count) instead of the same relay repeated once per email.
#   * Confidence bands     -- Strong / Related / Weak, and a noise floor, in
#     place of one fixed "below 40% is unrelated" rule.
# --------------------------------------------------------------------------
_SEM_MIN_SIMILARITY = 0.55   # noise floor: below this a match is not reported
_SEM_STRONG = 0.85
_SEM_RELATED = 0.70
_SEM_UNKNOWN = {"", "unknown", "unattributed", "unclassified", "-", "none"}
_SEM_METHOD_NOTE = (
    "Method: each origin's routing/infrastructure profile is embedded locally with nomic-embed-text "
    "(Ollama) and compared by cosine similarity. Match score = embedding similarity plus a small bonus "
    "(up to +16 points) for verifiable shared traits: same origin IP, same /24 network block, same "
    "infrastructure class, same country. Bands: Strong >= 85%, Related >= 70%, Weak >= 55%; anything "
    "below 55% is not reported. A semantic match is an investigative lead, not proof of a common operator."
)


def _sem_known(value):
    return str(value or "").strip().lower() not in _SEM_UNKNOWN


def _sem_band(score):
    if score >= _SEM_STRONG:
        return "Strong"
    if score >= _SEM_RELATED:
        return "Related"
    return "Weak"


def _sem_net(ip):
    """/24 (IPv4) or /48 (IPv6) network block of an IP, or '' if not an IP."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(str(ip).strip())
        prefix = 24 if addr.version == 4 else 48
        return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
    except Exception:
        return ""


def _sem_describe_origin(geo):
    """describe_origin() plus route facts it may not carry. Every embedding
    path uses this, so all stored profiles are described the same way."""
    base = describe_origin(geo)
    try:
        geo = geo or {}
        origin = geo.get("origin", {}) or {}
        hops = geo.get("hops", []) or []
        extra = []
        if _sem_known(origin.get("isp")):
            extra.append(f"Origin network operator: {origin.get('isp')}.")
        if hops:
            path = []
            for h in hops[:8]:
                step = f"{h.get('country') or 'Unknown'} ({h.get('infra_label') or 'unclassified'})"
                if not path or path[-1] != step:
                    path.append(step)
            extra.append(f"Relay path across {len(hops)} hop(s): " + " -> ".join(path) + ".")
        if origin.get("tor_exit_confirmed"):
            extra.append("The origin IP is a confirmed Tor exit node.")
        return (base + "\n" + "\n".join(extra)) if extra else base
    except Exception:
        return base


def _nomic_ready():
    """embeddings_usable() may ping Ollama (and check a cloud API key), so
    cache the answer briefly -- the Forensic Report reruns on every widget
    click. Despite the name, this now reflects whether embed_text() can
    actually embed at all -- local Ollama or the Cohere cloud fallback --
    not just local Ollama; see embeddings_backend() for which one it'll
    actually use."""
    now = time.time()
    cached = st.session_state.get("_nomic_ready_cache")
    if cached and now - cached[0] < 30:
        return cached[1]
    try:
        ok = bool(embeddings_usable())
    except Exception:
        ok = False
    st.session_state["_nomic_ready_cache"] = (now, ok)
    return ok


def _sem_digest(geo):
    return hashlib.sha256(_sem_describe_origin(geo).encode("utf-8")).hexdigest()[:16]


def _sem_index(ehash, geo, force=False):
    """Embed and store one email's origin profile. Returns (ok, error)."""
    done = st.session_state.setdefault("_sem_indexed", {})
    geo = geo or {}
    description = _sem_describe_origin(geo)
    digest = hashlib.sha256(description.encode("utf-8")).hexdigest()[:16]
    if not force and done.get(ehash) == digest:
        return True, ""
    emb = embed_text(description)
    if not emb.get("ok"):
        return False, emb.get("error", "Embedding failed.")
    origin = geo.get("origin", {}) or {}
    save_origin_embedding(
        ehash, description, emb["embedding"],
        origin.get("ip", ""), origin.get("country", ""), origin.get("infra_label", ""),
    )
    done[ehash] = digest
    return True, ""


def _sem_index_many(pairs, label="Indexing origin profiles for semantic comparison..."):
    """Index (evidence_hash, geo) pairs not indexed yet this session. Silent
    and instant when everything is already indexed. Returns how many were new."""
    done = st.session_state.setdefault("_sem_indexed", {})
    pending = [(h, g) for h, g in pairs if done.get(h) != _sem_digest(g)]
    if not pending:
        return 0
    added = 0
    with st.spinner(label):
        for ehash, geo in pending:
            try:
                ok, _err = _sem_index(ehash, geo)
                added += 1 if ok else 0
            except Exception:
                continue
    return added


def _sem_find(ehash, origin=None, top_k=5, min_score=_SEM_MIN_SIMILARITY):
    """Similar origins for one email: over-fetch, add shared-trait bonuses,
    collapse to one row per origin IP, drop noise, rank, label."""
    origin = origin or {}
    try:
        raw = find_similar_origins(ehash, top_k=max(top_k * 6, 30)) or []
    except Exception:
        return []
    cur_ip = str(origin.get("ip") or "")
    cur_net = _sem_net(cur_ip) if cur_ip else ""
    groups = {}
    for m in raw:
        if ehash and ehash in {str(m.get(k)) for k in ("evidence_hash", "hash", "id")}:
            continue  # never report an email as similar to itself
        sim = float(m.get("similarity") or 0.0)
        ip = str(m.get("ip") or "")
        reasons, bonus = [], 0.0
        if ip and cur_ip and ip == cur_ip:
            reasons.append("same origin IP")
            bonus += 0.10
        elif ip and cur_net and _sem_net(ip) == cur_net:
            reasons.append("same /24 network block")
            bonus += 0.05
        if _sem_known(m.get("infra_label")) and m.get("infra_label") == origin.get("infra_label"):
            reasons.append("same infrastructure class")
            bonus += 0.04
        if _sem_known(m.get("country")) and m.get("country") == origin.get("country"):
            reasons.append("same country")
            bonus += 0.02
        score = min(1.0, sim + bonus)
        key = ip or f"{m.get('country')}|{m.get('infra_label')}"
        entry = groups.get(key)
        if entry is None:
            groups[key] = dict(m, similarity=sim, score=score, reasons=reasons, seen_in=1)
        else:
            seen = entry["seen_in"] + 1
            if score > entry["score"]:
                entry.update(dict(m, similarity=sim, score=score, reasons=reasons))
            entry["seen_in"] = seen
    found = [e for e in groups.values() if e["score"] >= min_score]
    for e in found:
        e["band"] = _sem_band(e["score"])
    found.sort(key=lambda e: (e["score"], e["seen_in"]), reverse=True)
    return found[:top_k]


def _sem_norm(m):
    """Fill defaults so matches saved by older code still render."""
    m = dict(m)
    m.setdefault("similarity", 0.0)
    m.setdefault("score", m["similarity"])
    m.setdefault("band", _sem_band(m["score"]))
    m.setdefault("reasons", [])
    m.setdefault("seen_in", 1)
    return m


def _sem_reason_text(m):
    return "; ".join(_sem_norm(m)["reasons"]) or "embedding similarity only"


def _sem_rows(matches):
    rows = []
    for m in map(_sem_norm, matches):
        rows.append({
            "Confidence": m["band"],
            "Match score": f"{m['score']:.0%}",
            "Embedding similarity": f"{m['similarity']:.0%}",
            "Origin IP": m.get("ip") or "Unknown",
            "Country": m.get("country") or "Unknown",
            "Infrastructure": m.get("infra_label") or "Unknown",
            "Emails from this origin": m["seen_in"],
            "Shared traits": _sem_reason_text(m),
        })
    return rows


def _sem_md_table(matches):
    lines = [
        "| Confidence | Match score | Embedding similarity | Origin IP | Country | Infrastructure | Emails from this origin | Shared traits |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in _sem_rows(matches):
        lines.append(
            f"| {r['Confidence']} | {r['Match score']} | {r['Embedding similarity']} | `{r['Origin IP']}` | "
            f"{r['Country']} | {r['Infrastructure']} | {r['Emails from this origin']} | {r['Shared traits']} |"
        )
    return "\n".join(lines)


def _sem_headline(matches):
    if not matches:
        return ""
    m = _sem_norm(matches[0])
    where = ", ".join(str(p) for p in (m.get("country"), m.get("infra_label")) if _sem_known(p))
    seen = f", seen in {m['seen_in']} indexed emails" if m["seen_in"] > 1 else ""
    return (
        f"Closest related origin: **{m['band']}** match ({m['score']:.0%}) - `{m.get('ip') or 'unknown IP'}`"
        + (f" ({where})" if where else "") + seen + f". Shared traits: {_sem_reason_text(m)}."
    )


def _sem_none_text(min_score=_SEM_MIN_SIMILARITY):
    return f"No related origin scored above {min_score:.0%} against the origin profiles indexed so far."


st.set_page_config(
    page_title="AI-Powered Email Threat Detection, GeoLocation & Forensic | ALGORITHMISTIC",
    page_icon="\U0001F6E1",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --------------------------------------------------------------------------
# Browser-autofill / saved-password fix for st.text_input widgets.
#
# When a browser or password manager autofills a field (e.g. the sign-in
# form's Email address / Password fields), it sets the underlying <input>
# element's .value directly via the DOM, bypassing the synthetic "input"
# event React relies on to notice the change. Streamlit's Python side never
# hears about it, so session_state["imap_user"] / ["imap_manual_password"]
# stay empty even though the field looks filled on screen -- which is why
# clicking "Log in" right after autofill used to fail with "Enter both your
# email address and password/app password first", but worked fine the
# moment you typed anything by hand (a real keystroke DOES fire the event).
#
# Fix: poll every input/textarea in the parent document for value changes,
# and for anything that changed WITHOUT a matching keystroke, reset React's
# internal value tracker and re-dispatch a real "input" event so React (and
# therefore Streamlit) picks up the autofilled value immediately -- no
# extra click or retyping required. Runs in an invisible 0-height component,
# app-wide, since any text/password field could be autofilled, not just the
# sign-in form.
components.html(
    """
    <script>
    (function() {
        const doc = window.parent.document;
        const seen = new WeakMap();
        function sync() {
            const fields = doc.querySelectorAll('input[type="text"], input[type="password"], input[type="email"], textarea');
            fields.forEach(function(el) {
                // Treat an element we haven't checked before as having started
                // empty, NOT as "whatever it currently holds" -- otherwise a
                // value that's already autofilled by the time of our very
                // first check gets silently adopted as the baseline and never
                // actually synced to React/Streamlit.
                const prev = seen.has(el) ? seen.get(el) : '';
                if (el.value !== prev) {
                    seen.set(el, el.value);
                    try {
                        const tracker = el._valueTracker;
                        if (tracker) { tracker.setValue(prev); }
                    } catch (e) {}
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                } else {
                    seen.set(el, el.value);
                }
            });
        }
        sync();
        setInterval(sync, 300);

        // Sign-in links (Gmail / Outlook / Yandex): finish in ONE tab.
        //
        // st.link_button always renders target="_blank", so a plain click
        // opened a second tab, completed the sign-in THERE, and left the
        // original tab sitting on the old signed-out page.
        //
        // Not embedded (running at its own URL): '_self' -- an ordinary
        // same-tab round trip to the provider and back.
        //
        // Embedded in an iframe (Streamlit Community Cloud etc.): the
        // provider can't load inside the frame and the host may forbid
        // navigating the top window, so the click opens the provider in a
        // small popup instead. When the provider sends the popup back to
        // this app, the popup's page (see the "relay gate" right after the
        // OAuth callback handler in the Python code) passes the ?code=...
        // to THIS tab over a BroadcastChannel and closes itself; this tab
        // then reloads its app frame with that code, so the sign-in
        // completes in the tab the user started in. If nobody acknowledges
        // (popup blocked, original tab closed...), the popup simply
        // finishes the sign-in itself, exactly as it did before.
        function isFramed() {
            try { return window.parent.top !== window.parent; } catch (e) { return true; }
        }
        // This script runs in a sandboxed iframe, and browsers do not let a
        // sandboxed iframe navigate the page that CONTAINS it -- so
        // `window.parent.location.href = ...` is silently ignored. A link
        // element that belongs to the app frame's own document, clicked with
        // target="_self", navigates that frame as itself, which is allowed.
        // (A tiny script injected into the app frame is the backup if the
        // click is somehow ignored; if the navigation worked, it never runs.)
        function navigateAppFrame(url) {
            try {
                var a = doc.createElement('a');
                a.href = url; a.target = '_self'; a.rel = 'noopener';
                a.style.display = 'none';
                doc.body.appendChild(a);
                a.click();
            } catch (e) {}
            setTimeout(function () {
                try {
                    var sc = doc.createElement('script');
                    sc.textContent = 'window.location.href = ' + JSON.stringify(url) + ';';
                    doc.head.appendChild(sc);
                } catch (e) {}
            }, 800);
        }
        var waitingSince = 0;   // set when THIS tab launched a sign-in window
        var lastPopup = null;   // handle to the sign-in popup we opened
        // The opener is the one party Chrome always lets close a popup it
        // created, even after the popup went through Google's pages.
        function closePopupFromHere() {
            [0, 250, 700, 1500, 3000].forEach(function (ms) {
                setTimeout(function () {
                    try { if (lastPopup && !lastPopup.closed) lastPopup.close(); } catch (e) {}
                }, ms);
            });
        }
        var channel = null;
        try { channel = new BroadcastChannel('sih26106_oauth_relay'); } catch (e) {}
        if (channel) {
            channel.onmessage = function (ev) {
                var d = ev.data || {};
                if (d.type !== 'oauth_return' || !waitingSince) return;
                if (Date.now() - waitingSince > 10 * 60 * 1000) return;
                waitingSince = 0;
                try { channel.postMessage({ type: 'oauth_ack' }); } catch (e) {}
                closePopupFromHere();
                try {
                    var p = new URLSearchParams(d.search || '');
                    p.set('sih_relayed', '1');
                    var loc = window.parent.location;
                    navigateAppFrame(loc.origin + loc.pathname + '?' + p.toString());
                } catch (e) {}
            };
        }
        var SIGNIN_SELECTOR = (
            '.st-key-google_signin_link_btn a, ' +
            '.st-key-microsoft_signin_link_btn a, ' +
            '.st-key-yandex_signin_link_btn a'
        );
        // st.link_button always renders target="_blank" at the instant it's
        // (re-)created, and a plain click can land in that window before the
        // old per-element fix-up (run on an interval) ever got a chance to
        // correct it -- opening a second tab that finishes the sign-in on
        // its own, stranding the original tab. A single click listener on
        // the document, added ONCE and using capture, sees every click on
        // these links immediately, including on a link that was rendered a
        // moment ago, so there's no window for the default "_blank" to win.
        function onSignInClick(ev) {
            var a = ev.target && ev.target.closest ? ev.target.closest(SIGNIN_SELECTOR) : null;
            if (!a) return;
            var href = a.href;
            if (!href) return;
            if (isFramed() && channel) {
                waitingSince = Date.now();
                var w = 520, h = 720, popup = null;
                try {
                    var pw = window.parent;
                    var left = Math.max(0, (pw.screenX || 0) + ((pw.outerWidth || 1024) - w) / 2);
                    var top = Math.max(0, (pw.screenY || 0) + ((pw.outerHeight || 768) - h) / 2);
                    var feat = 'popup=yes,width=' + w + ',height=' + h + ',left=' + left + ',top=' + top;
                    try { popup = pw.open(href, 'sih26106_oauth_popup', feat); } catch (e) {}
                    if (!popup) { popup = window.open(href, 'sih26106_oauth_popup', feat); }
                } catch (e) {}
                ev.preventDefault();
                if (popup) {
                    lastPopup = popup;
                    try { popup.focus(); } catch (e) {}
                } else {
                    // Popup blocked -- fall back to the same-tab navigation
                    // below instead of letting target="_blank" open a tab.
                    waitingSince = 0;
                    navigateAppFrame(href);
                }
                return;
            }
            // Not embedded: always finish in this same tab, regardless of
            // whatever the anchor's own target attribute currently says.
            ev.preventDefault();
            navigateAppFrame(href);
        }
        doc.addEventListener('click', onSignInClick, true);
        function fixLinkTargets() {
            doc.querySelectorAll(SIGNIN_SELECTOR).forEach(function (a) {
                if (a.target !== '_self') a.target = '_self';
            });
        }
        fixLinkTargets();
        setInterval(fixLinkTargets, 300);
    })();
    </script>
    """,
    height=0,
    width=0,
)

# Correlation case store and AI dossier store
_corr_cases = st.session_state.setdefault("correlation_cases", {})
st.session_state.setdefault("single_ai_reports", {})

# --------------------------------------------------------------------------
# Google OAuth redirect callback -- handled here, at the very top of the
# script, before ANY widget is created (especially before the "Email
# address" text_input, key="imap_user", far below).
#
# Google sends the browser back to this app's own URL with
# ?code=...&state=... (or ?error=...) after sign-in, which Streamlit treats
# as a brand-new session (see google_Oauth.py's module docstring). This
# used to be handled from inside the Gmail sign-in section, *after* that
# text_input had already been instantiated for the run -- writing to
# st.session_state["imap_user"] at that point raises a
# StreamlitAPIException ("...cannot be modified after the widget with key
# imap_user is instantiated"), which the broad except-block around the
# token exchange silently swallowed as a generic "Google sign-in failed"
# error. Net effect: however the address was resolved, it never actually
# reached the field, so it always had to be typed in by hand.
#
# Doing it here and calling st.rerun() immediately afterward means that
# widget is never created during *this* run at all, so there's nothing to
# conflict with -- the very next run picks up st.session_state["imap_user"]
# cleanly, exactly like any other pre-seeded default value.
# Page shown (briefly) in the sign-in popup / new tab when the provider sends
# it back to this app. Instead of finishing the sign-in HERE -- which would
# strand the user in this second window while the tab they started in stays
# signed out -- it offers the ?code=... to the original tab over a
# BroadcastChannel. The original tab (waiting in the JS above) acknowledges,
# reloads itself with that code and finishes the sign-in there; this window
# then closes. Not embedded, or no acknowledgement within ~2s: it falls back
# to finishing the sign-in locally, exactly like the old behaviour.
_OAUTH_RELAY_GATE_HTML = """
<style>
  html, body { margin:0; padding:0; height:100%; background:#0a0e16; }
  .gate-wrap {
      min-height:100vh; display:flex; align-items:center; justify-content:center;
      font-family:Inter,'Segoe UI',Arial,sans-serif; padding:24px 16px; box-sizing:border-box;
      background:radial-gradient(ellipse at 50% 0%, #121a2a 0%, #0a0e16 70%);
  }
  .gate-card {
      width:100%; max-width:360px; text-align:center;
      background:linear-gradient(180deg,#111827,#0d131f);
      border:1px solid #232c3d; border-radius:16px;
      padding:36px 28px 30px 28px; box-shadow:0 20px 50px rgba(0,0,0,.45);
  }
  .gate-icon {
      width:52px; height:52px; margin:0 auto 18px auto; border-radius:50%;
      display:flex; align-items:center; justify-content:center;
      background:rgba(59,130,246,.14); border:1px solid rgba(59,130,246,.35);
  }
  .gate-spinner {
      width:22px; height:22px; border-radius:50%;
      border:2.5px solid rgba(59,130,246,.25); border-top-color:#3b82f6;
      animation:gate-spin .8s linear infinite;
  }
  @keyframes gate-spin { to { transform:rotate(360deg); } }
  .gate-title { color:#f3f6fb; font-size:16px; font-weight:700; margin-bottom:6px; letter-spacing:.1px; }
  .gate-sub { color:#8b96a5; font-size:13px; line-height:1.5; }
  .gate-btn {
      display:none; margin-top:20px; width:100%; border:none; cursor:pointer;
      background:linear-gradient(90deg,#3b82f6,#6366f1); color:#fff;
      font:700 13.5px/1 Inter,'Segoe UI',Arial,sans-serif; letter-spacing:.2px;
      padding:11px 0; border-radius:10px; transition:opacity .15s ease;
  }
  .gate-btn:hover { opacity:.88; }
</style>
<div class="gate-wrap">
  <div class="gate-card">
    <div class="gate-icon" id="gi"><div class="gate-spinner"></div></div>
    <div class="gate-title" id="gt">Completing sign-in</div>
    <div class="gate-sub" id="m">Verifying your account&hellip;</div>
    <button class="gate-btn" id="gb" type="button">Close this window</button>
  </div>
</div>
<script>
(function () {
    var pw = window.parent, doc = null, done = false, acked = false, ch = null;
    try { doc = pw.document; } catch (e) {}
    var _elIcon = document.getElementById('gi'), _elTitle = document.getElementById('gt'), _elBtn = document.getElementById('gb');
    function say(t) { var m = document.getElementById('m'); if (m) m.textContent = t; }
    function setStage(title, sub, opts) {
        opts = opts || {};
        if (_elTitle) _elTitle.textContent = title;
        say(sub);
        if (opts.done && _elIcon) {
            _elIcon.innerHTML = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
            _elIcon.style.background = 'rgba(74,222,128,.14)';
            _elIcon.style.borderColor = 'rgba(74,222,128,.35)';
        }
        if (opts.showButton && _elBtn) _elBtn.style.display = 'block';
    }

    function framed() { try { return pw.top !== pw; } catch (e) { return true; } }
    // A sandboxed iframe (this page) may not navigate the frame that
    // contains it, so go through a link owned by that frame's own document.
    function go(url) {
        try {
            var a = doc.createElement('a');
            a.href = url; a.target = '_self'; a.rel = 'noopener';
            a.style.display = 'none';
            doc.body.appendChild(a);
            a.click();
        } catch (e) {}
        setTimeout(function () {
            try {
                var sc = doc.createElement('script');
                sc.textContent = 'window.location.href = ' + JSON.stringify(url) + ';';
                doc.head.appendChild(sc);
            } catch (e) {}
        }, 800);
    }
    function attemptClose() {
        try { pw.top.close(); } catch (e) {}
        try { pw.close(); } catch (e) {}
        try { window.close(); } catch (e) {}
        try {
            var sc = doc.createElement('script');
            sc.textContent = 'window.close();';
            doc.head.appendChild(sc);
        } catch (e) {}
    }
    function local() {
        if (done) return; done = true;
        setStage('Completing sign-in', 'One moment\\u2026');
        var p = new URLSearchParams(pw.location.search);
        p.set('sih_local', '1');
        var url = pw.location.origin + pw.location.pathname + '?' + p.toString();
        go(url);
        // Never leave the user staring at "Completing sign-in" forever.
        setTimeout(function () {
            if (!_elTitle) return;
            setStage('Taking longer than expected', 'Use the link below to continue manually.');
            var l = document.createElement('a');
            l.href = url; l.target = '_blank'; l.rel = 'noopener';
            l.textContent = 'Continue sign-in \u2192';
            l.style.cssText = 'display:inline-block;margin-top:6px;color:#8fb4ff;font-size:13px;font-weight:600;text-decoration:none;';
            var m = document.getElementById('m');
            if (m) { m.innerHTML = ''; m.appendChild(l); }
        }, 5000);
    }
    function finish() {
        if (done) return; done = true;
        setStage('Signed in', 'Returning you to the app\\u2026');
        // Bring the original tab to the front right away -- some browsers
        // (current Chrome included) now permanently refuse a scripted
        // close() on a popup once it has navigated through more than one
        // page, which Google's own login flow always does, so close()
        // below can silently fail no matter what. Shifting focus back to
        // the tab that's actually signed in now is the one thing that
        // reliably still works, so the leftover popup at least stops being
        // the thing in front of the user.
        try { pw.opener && pw.opener.focus(); } catch (e) {}
        // Plan A: a plain close(). Works as long as this popup's session
        // history is still exactly 1 entry long -- but Google's own login
        // pages add several entries as you sign in, so by the time we get
        // here Chrome/Firefox usually refuse this silently (an anti-abuse
        // rule: script may only auto-close a window it opened AND that
        // never navigated elsewhere).
        attemptClose();
        setTimeout(function () {
            if (pw.closed) return;
            // Plan B: the standard workaround for that exact rule --
            // re-opening the window "onto itself" resets its session
            // history to a single entry, which satisfies the same check
            // and lets close() succeed immediately after.
            try { pw.open('', '_self'); } catch (e) {}
            attemptClose();
            var tries = 0;
            var retry = setInterval(function () {
                if (pw.closed) { clearInterval(retry); return; }
                attemptClose();
                if (++tries >= 8) clearInterval(retry);
            }, 300);
            setTimeout(function () {
                if (pw.closed) return;
                // Neither worked (some browsers block even Plan B) -- offer
                // one manual click instead of a dead-end message.
                setStage('Signed in successfully', 'You can close this window now.', { done: true, showButton: true });
            }, 2600);
        }, 300);
    }
    if (_elBtn) _elBtn.addEventListener('click', function () { attemptClose(); });
    if (!framed()) { local(); return; }
    try { ch = new BroadcastChannel('sih26106_oauth_relay'); } catch (e) {}
    if (!ch) { local(); return; }
    ch.onmessage = function (ev) {
        var d = ev.data || {};
        if (d.type === 'oauth_ack') { acked = true; finish(); }
    };
    setTimeout(function () { if (!acked) local(); }, 2000);
    try { ch.postMessage({ type: 'oauth_return', search: pw.location.search }); } catch (e) {}
})();
</script>
"""

if GOOGLE_OAUTH_READY or MICROSOFT_OAUTH_READY or YANDEX_OAUTH_READY:
    _oauth_code = st.query_params.get("code")
    _oauth_state = st.query_params.get("state")
    _oauth_error = st.query_params.get("error")
    # Fresh from the provider (no relay/local marker yet): run the relay
    # gate above and render nothing else. The markers are added by the gate
    # itself (local) or by the original tab (relayed), so this runs once.
    if (_oauth_code or _oauth_error) and not (
        st.query_params.get("sih_relayed") or st.query_params.get("sih_local")
    ):
        components.html(_OAUTH_RELAY_GATE_HTML, height=420)
        st.stop()
    # The redirect URI is shared across every provider (it's the same
    # running app), so the same ?code=/?state= callback can belong to
    # Google, Microsoft or Yandex. Each provider's own get_authorization_url()
    # prefixes its `state` value (msoauth:/yaoauth:) precisely so this one
    # handler can tell them apart and call the right exchange function --
    # anything without a recognized prefix falls through to Google, exactly
    # matching the original behavior from before Microsoft/Yandex existed.
    if _oauth_state and MICROSOFT_OAUTH_READY and _oauth_state.startswith(microsoft_oauth.STATE_PREFIX):
        if _oauth_error:
            st.query_params.clear()
            st.session_state["_microsoft_oauth_error"] = _oauth_error
        elif _oauth_code:
            try:
                _ms_token, _ms_email = microsoft_oauth.exchange_code_for_token(_oauth_code, state=_oauth_state)
                st.query_params.clear()
                st.session_state["microsoft_oauth_token"] = _ms_token
                if _ms_email:
                    st.session_state["imap_user"] = _ms_email
                    _save_cached_provider_email("microsoft", _ms_email)
                st.session_state["imap_provider"] = "Outlook / Microsoft 365"
                st.session_state["show_imap_connection_form"] = True
                st.rerun()
            except Exception as _ms_exc:
                st.query_params.clear()
                st.session_state["_microsoft_oauth_error"] = f"Microsoft sign-in failed while completing sign-in: {_ms_exc}"
    elif _oauth_state and YANDEX_OAUTH_READY and _oauth_state.startswith(yandex_oauth.STATE_PREFIX):
        if _oauth_error:
            st.query_params.clear()
            st.session_state["_yandex_oauth_error"] = _oauth_error
        elif _oauth_code:
            try:
                _ya_token, _ya_email = yandex_oauth.exchange_code_for_token(_oauth_code, state=_oauth_state)
                st.query_params.clear()
                st.session_state["yandex_oauth_token"] = _ya_token
                if _ya_email:
                    st.session_state["imap_user"] = _ya_email
                    _save_cached_provider_email("yandex", _ya_email)
                st.session_state["imap_provider"] = "Yandex"
                st.session_state["show_imap_connection_form"] = True
                st.rerun()
            except Exception as _ya_exc:
                st.query_params.clear()
                st.session_state["_yandex_oauth_error"] = f"Yandex sign-in failed while completing sign-in: {_ya_exc}"
    elif GOOGLE_OAUTH_READY and _oauth_error:
        st.query_params.clear()
        st.session_state["_google_oauth_error"] = _oauth_error
    elif GOOGLE_OAUTH_READY and _oauth_code:
        try:
            _token, _email_hint = exchange_code_for_token(_oauth_code, state=_oauth_state)
            st.query_params.clear()
            st.session_state["google_oauth_token"] = _token
            # Ask Google directly which account this token belongs to --
            # that's the account actually just signed in with, and takes
            # priority over `email_hint` (only ever non-empty if the user
            # manually typed an address in before clicking "Sign in with
            # Google").
            _resolved_email = _fetch_google_email_from_token(_token) or _email_hint
            if _resolved_email:
                st.session_state["imap_user"] = _resolved_email
                _save_cached_google_email(_resolved_email)
            # Land straight back on the Live Mailbox Interceptor with Gmail
            # already selected and the connection form open -- the whole
            # point of signing in was to get straight to the inbox, not
            # back to a blank landing screen.
            st.session_state["imap_provider"] = "Gmail"
            st.session_state["show_imap_connection_form"] = True
            st.rerun()
        except Exception as _oauth_exc:
            st.query_params.clear()
            st.session_state["_google_oauth_error"] = f"Google sign-in failed while completing sign-in: {_oauth_exc}"

# --------------------------------------------------------------------------
# PROFESSIONAL SOC / FORENSICS UI
# --------------------------------------------------------------------------
st.markdown(
    r"""
    <style>
    :root {
        /* -------------------------------------------------------------
           REDESIGNED PALETTE (color-only retint — every token name below
           is unchanged, so every rule in this file that already reads
           var(--cyan)/var(--violet)/etc. picks up the new look for free,
           with zero risk to layout or logic). Moved off the old
           teal-green-dominant scheme onto a cooler electric-blue + violet
           primary family, which reads as a more deliberate, modern
           "SOC console" identity and gives the brand gradient / active
           states more contrast against the near-black background. Severity
           colors (critical/high/medium/low, further down) are intentionally
           left alone -- they carry meaning and must stay universally
           recognizable (red = bad, green = fine) regardless of re-skinning.
           ------------------------------------------------------------- */
        --bg: #0a0d12;
        --panel: #131922;
        --panel-2: #171e28;
        --panel-3: #0e131a;
        --line: #232b37;
        --line-strong: #313c4b;
        --text: #dde3ea;
        --muted: #8b96a5;
        /* -------------------------------------------------------------
           TRUE multi-color scheme -- three distinct, muted hues each
           owning a different job, instead of one hue family stretched
           across everything (the "eye-burning" problem was saturation,
           not the number of colors, so each of these is desaturated/
           darkened before it ever gets used). Severity colors further
           down are intentionally a separate, untouched set -- decoration
           should never compete with red/amber/green meaning.
           - teal-green (--cyan): primary actions, focus states, active nav
           - warm terracotta (--teal): brand chrome -- kicker text, one
             provider accent -- the warm counterweight to the cool hues
           - dusty plum (--violet): AI/assistant surfaces, a second
             provider accent -- signals "a different kind of content"
           ------------------------------------------------------------- */
        --cyan: #3b82f6;
        --violet: #6366f1;
        --teal: #c98a5c;
        --green: #6fae8c;
        --amber: #c99a5b;
        --red: #c26868;
        /* Severity scale — reserved strictly for threat-level meaning, never
           used decoratively elsewhere, so color always carries information. */
        --sev-critical: #ef4444;
        --sev-high: #f2994a;
        --sev-medium: #f2a93c;
        --sev-low: #2fce87;
        --r-sm: 8px;
        --r-md: 11px;
        --r-lg: 16px;
        --shadow-sm: 0 4px 14px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.03);
        --shadow-md: 0 10px 26px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.03);
        /* Calm, single-tone focus shadow for primary actions -- a soft
           blue lift instead of a saturated violet halo, so it reads as a
           clean product accent rather than a neon glow. */
        --glow-violet: 0 0 0 1px rgba(59,130,246,.25), 0 6px 16px rgba(0,0,0,.24);
        /* Signature brand accent: teal-green into dusty plum -- a real
           duotone (not two shades of the same hue) for every primary
           action / active state, muted enough to sit calmly on dark. */
        --brand-gradient: linear-gradient(90deg,#3b82f6,#6366f1);
        /* Action-button tokens -- the whole button family (primary = brand
           cyan-to-violet gradient key, secondary = graphite key) is tinted
           from here, so the look can be re-colored in one place without
           touching any rule. Was a flat teal; now the same punchier
           cyan-to-violet gradient the Synapse Copilot button used, applied
           app-wide so every primary button matches instead of just one. */
        --act-1-top:#3b82f6; --act-1-bot:#6366f1; --act-1-border:rgba(99,102,241,.45); --act-1-text:#f2f5f8;
        --act-1-top-hover:#5b9bf8; --act-1-bot-hover:#7c7ff3; --act-1-border-hover:rgba(99,102,241,.7);
        --act-2-top:#161d2a; --act-2-bot:#0e141e; --act-2-border:#2a3444; --act-2-text:#dbe4ef;
        --act-2-top-hover:#1b2432; --act-2-bot-hover:#111a26; --act-2-border-hover:rgba(59,130,246,.5);
        --ease: cubic-bezier(.4,0,.2,1);
        /* Streamlit's own stock theme color (a coral red, #FF4B4B by
           default) still drives focus/selected states on any BaseWeb
           control our own rules don't explicitly restyle -- overriding the
           variable it reads from here, app-wide, is the one fix that
           catches every one of those leaks at the source instead of
           chasing each control individually. */
        --primary-color: var(--cyan) !important;
    }

    /* Belt-and-braces catch-all: force every native focus/selected state
       in the app (inputs, selects, the BaseWeb dropdown shell, radios,
       checkboxes, sliders) onto the app's own blue, so Streamlit's default
       red primary color can never surface through a control our targeted
       rules below don't happen to reach. Sits above those targeted rules
       on purpose -- they refine the exact look per-widget; this just
       guarantees the color is always right even before that refinement. */
    .stApp input:focus,
    .stApp textarea:focus,
    .stApp select:focus,
    .stApp [data-baseweb="select"]:focus-within > div,
    .stApp [data-baseweb="select"] > div:focus-within,
    .stApp [data-baseweb="base-input"]:focus-within,
    .stApp [data-baseweb="input"]:focus-within,
    .stApp [role="combobox"]:focus,
    .stApp [role="combobox"][aria-expanded="true"] > div {
        border-color: var(--cyan) !important;
        box-shadow: 0 0 0 3px rgba(59,130,246,.14) !important;
        outline: none !important;
    }
    .stApp input:invalid, .stApp select:invalid, .stApp textarea:invalid,
    .stApp input:required:invalid {
        box-shadow: none !important;
    }

    /* App-wide radio-dot leak fix. Three earlier attempts at this (hiding
       `label > div:first-child`, hiding `[data-baseweb="radio"]`, then
       `label > *:not(:has(p))`) still didn't clear it in the user's
       browser -- at this point, stop guessing at a single selector and
       stack every independent way of suppressing an element, so this
       survives even if one technique is neutralized by something else in
       the stylesheet or the browser's own defaults: `display:none` alone,
       zero size + clipped overflow, moved off-screen, and made fully
       transparent, all at once, on every plausible target (the circle
       wrapper, the raw input, any svg, and the accent-color a browser
       uses to paint a native checked radio red by default). */
    .stRadio label > *:not(:has(p)),
    .stRadio label input[type="radio"],
    .stRadio label svg,
    .stRadio label [data-baseweb="radio"] {
        display:none !important;
        width:0 !important; height:0 !important;
        margin:0 !important; padding:0 !important;
        border:0 !important; opacity:0 !important;
        overflow:hidden !important;
        position:absolute !important; left:-9999px !important;
        pointer-events:none !important;
    }
    .stRadio input[type="radio"] {accent-color:var(--cyan) !important;}

    /* The real element (confirmed from the actual rendered DOM, via
       inspector): each radio option's marker is a plain, contentless
       `<div>` -- not a Material icon span, which is what every earlier
       attempt here wrongly assumed. An empty div is reliably selectable
       with `:empty` regardless of Streamlit's internal (unstable,
       hash-named) emotion classes, so this targets it directly instead
       of guessing at an attribute again. Unselected stays a plain quiet
       outline; selected gets a soft white halo so it reads as a real
       "active" indicator instead of a flat dot. */
    .stRadio label:has(input:checked) div:empty {
        box-shadow:0 0 0 4px rgba(255,255,255,.20), 0 0 12px 3px rgba(255,255,255,.6) !important;
        transition:box-shadow .2s var(--ease) !important;
    }

    /* Quality-floor: a visible, on-brand focus ring everywhere, so keyboard
       navigation is never invisible -- this replaces the browser default
       rather than removing it. */
    *:focus-visible {outline:2px solid var(--cyan) !important; outline-offset:2px !important;}

    /* Slim, on-theme scrollbars instead of the default OS chrome. */
    ::-webkit-scrollbar {width:10px; height:10px;}
    ::-webkit-scrollbar-track {background:#081420;}
    ::-webkit-scrollbar-thumb {background:linear-gradient(180deg, var(--cyan), var(--violet)); border-radius:8px; border:2px solid #081420;}
    ::-webkit-scrollbar-thumb:hover {background:linear-gradient(180deg, #5b9bf8, #7c7ff3);}
    * {scrollbar-color:#2c5877 #081420; scrollbar-width:thin;}


    #MainMenu, footer {display:none !important;}
    /* The native Streamlit deploy toolbar (Share / star / rename / GitHub
       icons) used to float directly over our own banner's bell + account
       chip. `display:none` on the whole toolbar fixed the overlap but
       also silently killed the sidebar collapse/expand arrow, which lives
       in this same header region in this Streamlit build -- so instead of
       removing the toolbar, it's just dimmed to near-invisible until
       hovered. That keeps every native control (sidebar toggle included)
       fully clickable while no longer visually competing with the banner
       below it (which also got its own top margin -- see .topbar-shell). */
    [data-testid="stToolbar"] {opacity:.35 !important; transition:opacity .15s var(--ease) !important;}
    [data-testid="stToolbar"]:hover {opacity:1 !important;}
    [data-testid="stHeader"] {
    background:transparent !important;
    height:2.75rem !important;
}
    [data-testid="collapsedControl"] {
        display:flex !important; visibility:visible !important; opacity:1 !important;
        align-items:center !important; gap:7px !important;
        position:fixed !important; top:14px !important; left:14px !important; z-index:999999 !important;
        background:#0c1929 !important; border:1px solid var(--cyan) !important; border-radius:8px !important;
        padding:9px 14px 9px 11px !important;
        box-shadow:0 0 0 1px rgba(59,130,246,.25), 0 8px 22px rgba(0,0,0,.4) !important;
        transition:transform .15s var(--ease), box-shadow .15s var(--ease) !important;
    }
    [data-testid="collapsedControl"]:hover {
        transform:scale(1.04) !important;
        box-shadow:0 0 0 1px rgba(59,130,246,.4), 0 10px 26px rgba(0,0,0,.45) !important;
    }
    /* The native arrow only ever means "open the nav" -- spell that out so
       it isn't mistaken for decoration and missed on a dark, busy header. */
    [data-testid="collapsedControl"]::after {
        content:"Menu";
        color:var(--cyan) !important;
        font:800 12.5px/1 Inter,"Segoe UI",Arial,sans-serif !important;
        letter-spacing:.4px !important;
    }
    [data-testid="collapsedControl"] svg {color:var(--cyan) !important; fill:var(--cyan) !important; width:19px !important; height:19px !important;}
    /* .stApp is intentionally not part of this selector group: the
       dedicated ".stApp {...}" rule further down in this stylesheet has
       the same specificity and comes later, so it always wins for .stApp
       anyway -- keeping it here too was dead weight (an extra gradient
       background computed and immediately discarded on every rerun). */
    [data-testid="stAppViewContainer"],
    [data-testid="stMain"] {
        background:
            radial-gradient(circle at 12% -8%, rgba(59,130,246,.05), transparent 28%),
            radial-gradient(circle at 92% 0%, rgba(19,139,181,.045), transparent 26%),
            radial-gradient(circle at 55% 105%, rgba(59,130,246,.025), transparent 32%),
            var(--bg) !important;
        color: var(--text) !important;
    }
    .block-container {
        max-width: 100% !important;
        padding-top: 1.5rem !important;
        padding-bottom: 3rem !important;
        /* Fill whatever width the sidebar frees up when it collapses,
           instead of staying capped at a fixed px width regardless of
           sidebar state -- that fixed cap is what left a dead strip of
           empty background down one side whenever the sidebar closed.
           The transition mirrors Streamlit's own sidebar-slide timing so
           the content reflows *with* it instead of snapping after it. */
        transition: max-width .3s var(--ease) !important;
    }
    .stApp, .stApp p, .stApp span, .stApp label, .stApp small {font-family: Inter, "Segoe UI", Arial, sans-serif !important;}
    h1,h2,h3,h4,h5,h6 {color:var(--text) !important; font-family:Inter,"Segoe UI",Arial,sans-serif !important; font-weight:750 !important;}
    [data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] * {color:var(--muted) !important;}

    [data-testid="stSidebar"] {background:#06101c !important; border-right:1px solid var(--line) !important;}
    [data-testid="stSidebar"] > div {background:#06101c !important;}
    [data-testid="stSidebar"] * {color:#ccd9e7 !important;}


    /* Numbered workflow-step cards (Live Mailbox Interceptor, etc.) --
       previously a flat single-color box with plain caption text. Now a
       layered card with a colored accent spine, a soft corner glow, and a
       pill-style step badge, so the step-by-step flow reads as a real
       product wizard instead of a stack of identical gray rectangles.
       `.stage-card-success` is an additive modifier class (markup keeps
       the base `.stage-card` too) for the one "already connected" card,
       so that state reads as green/complete rather than as just another
       numbered step. */
    .stage-card {
        position:relative;
        overflow:hidden;
        background:var(--panel) !important;
        border:1px solid var(--line) !important;
        border-left:3px solid var(--cyan) !important;
        border-radius:var(--r-lg) !important;
        padding:16px 18px 16px 20px !important;
        margin:10px 0 !important;
        box-shadow:none !important;
        transition:transform .18s var(--ease), box-shadow .18s var(--ease), border-color .18s var(--ease) !important;
    }
    .stage-card:hover {
        transform:translateY(-1px) !important;
        border-color:var(--line-strong) !important;
        background:var(--panel-2) !important;
    }
    .stage-card-success {
        border-left-color:var(--green) !important;
        background:linear-gradient(135deg, rgba(47,206,135,.09), var(--panel) 60%) !important;
        box-shadow:0 10px 26px rgba(0,0,0,.2), inset 0 0 30px rgba(47,206,135,.04) !important;
    }
    .stage-card-success:hover {border-color:#2c5a45 !important; box-shadow:0 14px 30px rgba(0,0,0,.26), inset 0 0 30px rgba(47,206,135,.06) !important;}
    .stage-card-success::after {
        content:"✓"; position:absolute; z-index:1; top:12px; right:14px; width:22px; height:22px;
        display:flex; align-items:center; justify-content:center; border-radius:50%;
        background:rgba(47,206,135,.16); border:1px solid rgba(47,206,135,.4);
        color:var(--green); font:900 12px/1 sans-serif;
    }
    /* "Attached" variant: used when a stage-card is immediately followed by
       its own action bar (e.g. the mailbox-connected card + its Full
       Report/Change/Disconnect buttons) so the two read as one continuous
       panel instead of a card with three loose buttons floating under it. */
    .stage-card-attached {
        margin-bottom:0 !important;
        border-bottom-left-radius:0 !important;
        border-bottom-right-radius:0 !important;
    }
    /* Origin & Route maps: tall, but not full-width -- centered and capped
       so the box is narrower without losing height. */
    [class*="st-key-"][class*="_map_frame"] iframe {
        width:100% !important; max-width:1150px !important;
        display:block !important; margin:0 auto !important;
    }
    .st-key-imap_connected_actions {
        position:relative;
        background:var(--panel) !important;
        border:1px solid var(--line) !important;
        border-top:1px solid rgba(47,206,135,.22) !important;
        border-left:3px solid var(--green) !important;
        border-bottom-left-radius:var(--r-lg) !important;
        border-bottom-right-radius:var(--r-lg) !important;
        padding:14px 18px 16px 20px !important;
        margin-top:0 !important;
        margin-bottom:10px !important;
    }
    .st-key-imap_connected_actions .stCaption {
        margin-bottom:10px !important;
    }
    .st-key-imap_connected_actions .stCaption p {
        font-size:11.5px !important; color:#7993a8 !important; line-height:1.5 !important;
    }
    .st-key-imap_connected_actions [data-testid="column"]:nth-of-type(2) .stButton button,
    .st-key-imap_connected_actions [data-testid="column"]:nth-of-type(3) .stButton button {
        font-size:12.5px !important;
    }
    .stage-label {
        position:relative; z-index:1;
        display:inline-flex !important; align-items:center !important;
        color:var(--cyan) !important; font-size:10px !important; font-weight:800 !important;
        letter-spacing:1.5px !important; text-transform:uppercase !important;
        background:rgba(59,130,246,.08) !important; border:1px solid rgba(59,130,246,.22) !important;
        border-radius:20px !important; padding:3px 10px !important;
    }
    .stage-card-success .stage-label {color:var(--green) !important; background:rgba(47,206,135,.10) !important; border-color:rgba(47,206,135,.28) !important;}
    .stage-title {position:relative; z-index:1; color:#ebf6ff !important; font-size:16px !important; font-weight:750 !important; margin-top:7px !important;}
    .stage-help {position:relative; z-index:1; color:#8299b2 !important; font-size:12px !important; margin-top:3px !important; line-height:1.45 !important;}

    /* Per-step color coding for the numbered workflow cards (01 Mail
       server / 02 Authentication / 03 Mail scope). They used to all share
       one cyan accent, so three different steps of one workflow read as
       one repeated block. Each step now gets its own hue -- cyan
       (connect), violet (authenticate), amber (scope) -- carried through
       the spine, the corner glow and the step pill, so the steps are
       visually distinct while still reading as one family of card. */
    .stage-card {background:linear-gradient(135deg, rgba(59,130,246,.05), var(--panel) 55%) !important;}
    .stage-card-auth {border-left-color:#6366f1 !important; background:linear-gradient(135deg, rgba(99,102,241,.06), var(--panel) 55%) !important;}
    .stage-card-auth:hover {border-color:rgba(99,102,241,.55) !important;}
    .stage-card-auth .stage-label {color:#c2aee0 !important; background:rgba(99,102,241,.12) !important; border-color:rgba(99,102,241,.32) !important;}
    .stage-card-scope {border-left-color:#f4b23d !important; background:linear-gradient(135deg, rgba(244,178,61,.06), var(--panel) 55%) !important;}
    .stage-card-scope:hover {border-color:rgba(244,178,61,.55) !important;}
    .stage-card-scope .stage-label {color:#ffd98a !important; background:rgba(244,178,61,.12) !important; border-color:rgba(244,178,61,.32) !important;}

    /* ------------------------------------------------------------------
       BUTTON SYSTEM v3 -- slim, multi-colour "aurora" buttons.
       Every button is a slim dark-glass key with a thin multi-colour edge.
       Colour comes from three stops (--b1/--b2/--b3) set per button TYPE,
       so different kinds of action read as different colours:
         * st.button         aurora : blue -> violet -> magenta
         * download buttons  ocean  : teal -> sky -> indigo
         * form-submit       sunset : amber -> rose -> plum
       Secondary: quiet -- graphite fill, faint colour in the edge; on
       hover the edge lights up and a soft wash of the three colours
       slides across.
       Primary: same slim key, edge in full colour and a tinted wash at
       rest; on hover the wash floods the whole key and the glow lifts.
       Deliberately NOT a big solid-colour slab: at rest nothing here is a
       large bright block, so it stays easy on the eyes.

       Selectors are DESCENDANT (`.stButton button`), not child: Streamlit
       wraps any button that has a `help=` tooltip in an extra element, and
       the child form skipped those buttons (they showed Streamlit's flat
       default colour). Primary is matched by `kind` OR `data-testid`
       because newer Streamlit builds dropped the `kind` attribute.
       ------------------------------------------------------------------ */
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) {--b1:#3b82f6; --b2:#7c3aed; --b3:#db2777;}
    .stDownloadButton {--b1:#0d9488; --b2:#0284c7; --b3:#4f46e5;}
    .stFormSubmitButton {--b1:#d97706; --b2:#e11d48; --b3:#a21caf;}

    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button {
        position:relative; overflow:hidden; isolation:isolate;
        min-height:40px !important;
        padding:0 18px !important;
        border-radius:10px !important;
        /* fallback if color-mix() is unsupported */
        background:linear-gradient(180deg,#131a27,#0c121c) !important;
        border:1px solid #2a3444 !important;
        color:#e6edf7 !important;
        font-size:13px !important; font-weight:600 !important;
        letter-spacing:.01em !important; text-transform:none !important;
        box-shadow:0 1px 2px rgba(0,0,0,.4) !important;
        transition:box-shadow .3s var(--ease), color .2s var(--ease), transform .14s var(--ease) !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button {
        /* dark key + a faint multi-colour edge (graphite mixed into the 3 stops) */
        background:
            linear-gradient(180deg,#131a27,#0c121c) padding-box,
            linear-gradient(115deg,
                color-mix(in srgb, var(--b1) 42%, #2a3444),
                color-mix(in srgb, var(--b2) 42%, #2a3444),
                color-mix(in srgb, var(--b3) 42%, #2a3444)) border-box !important;
        background-origin:border-box !important;
        background-clip:padding-box, border-box !important;
        border:1px solid transparent !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button p {
        margin:0 !important; font-size:inherit !important; font-weight:inherit !important;
        letter-spacing:inherit !important; text-transform:inherit !important;
    }
    /* the colour wash that sits behind the label */
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button::after {
        content:""; position:absolute; inset:0; z-index:-1; pointer-events:none; border-radius:9px;
        background:linear-gradient(115deg,var(--b1),var(--b2),var(--b3));
        background-size:220% 100%; background-position:0% 0;
        opacity:0;
        transition:opacity .3s var(--ease), background-position .9s var(--ease);
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button:hover {
        color:#ffffff !important; transform:translateY(-1px);
        box-shadow:0 8px 22px -8px rgba(0,0,0,.6) !important;
        box-shadow:0 8px 22px -10px color-mix(in srgb, var(--b2) 70%, transparent) !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button:hover {
        background:
            linear-gradient(180deg,#131a27,#0c121c) padding-box,
            linear-gradient(115deg, var(--b1), var(--b2), var(--b3)) border-box !important;
        background-origin:border-box !important;
        background-clip:padding-box, border-box !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button:hover::after {opacity:.16; background-position:100% 0;}
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button:active {
        transform:translateY(0) scale(.99) !important; transition-duration:.07s !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button:focus-visible {
        outline:2px solid var(--b1) !important; outline-offset:3px !important;
    }

    /* Primary: full-colour edge + tinted wash at rest, flood on hover */
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) :is(button[kind^="primary"], button[data-testid^="stBaseButton-primary"]) {
        background:
            linear-gradient(180deg,#131a27,#0c121c) padding-box,
            linear-gradient(115deg, var(--b1), var(--b2), var(--b3)) border-box !important;
        background-origin:border-box !important;
        background-clip:padding-box, border-box !important;
        color:#ffffff !important;
        box-shadow:0 1px 2px rgba(0,0,0,.4), 0 8px 20px -10px color-mix(in srgb, var(--b2) 80%, transparent) !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) :is(button[kind^="primary"], button[data-testid^="stBaseButton-primary"])::after {opacity:.22;}
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) :is(button[kind^="primary"], button[data-testid^="stBaseButton-primary"]):hover {
        box-shadow:0 1px 2px rgba(0,0,0,.4), 0 12px 28px -8px color-mix(in srgb, var(--b2) 90%, transparent) !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) :is(button[kind^="primary"], button[data-testid^="stBaseButton-primary"]):hover::after {opacity:.92; background-position:100% 0;}

    @media (prefers-reduced-motion: reduce) {
        :is(.stButton, .stDownloadButton, .stFormSubmitButton) button,
        :is(.stButton, .stDownloadButton, .stFormSubmitButton) button::after {transition:none !important;}
    }
    /* Disabled keys: dimmed and inert, so they never look clickable. */
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button:disabled {opacity:.38 !important; filter:saturate(.5) !important; pointer-events:none !important; box-shadow:none !important;}
    /* Sidebar nav buttons have their own look (accent bar etc.): no wash,
       and don't clip their ::before bar. */
    [data-testid="stSidebar"] :is(.stButton, .stDownloadButton, .stFormSubmitButton) button {overflow:visible !important;}
    [data-testid="stSidebar"] :is(.stButton, .stDownloadButton, .stFormSubmitButton) button::after {display:none !important;}

    /* "Download Forensic Report" row -- these three used to all be plain
       identical secondary/graphite buttons (the default for any
       non-primary button), which reads as three interchangeable options
       when they aren't: AI Only and Machine Only are two different
       partial views, and Combined is the one most people actually want.
       Recolored per-column so they read as distinct choices at a glance
       -- violet for AI, cyan/blue for Machine, and the app's own primary
       gradient for Combined (it's the recommended pick, so it gets the
       "main action" treatment instead of blending into the graphite
       row). The container key is fixed even though the download keys
       inside it change per email, so this survives switching emails. */
    .st-key-forensic_download_row [data-testid="column"]:nth-of-type(1) .stDownloadButton button {
        background:linear-gradient(180deg,#241a3d,#160f28) !important;
        border:1px solid rgba(99,102,241,.55) !important;
        color:#f1ecff !important;
        box-shadow:0 1px 2px rgba(0,0,0,.4), 0 8px 20px rgba(99,102,241,.20), inset 0 1px 0 rgba(255,255,255,.08) !important;
    }
    .st-key-forensic_download_row [data-testid="column"]:nth-of-type(1) .stDownloadButton button:hover {
        box-shadow:0 0 0 1px rgba(99,102,241,.35), 0 10px 26px rgba(99,102,241,.30), inset 0 1px 0 rgba(255,255,255,.14) !important;
    }
    .st-key-forensic_download_row [data-testid="column"]:nth-of-type(2) .stDownloadButton button {
        background:linear-gradient(180deg,#0f3350,#0a2032) !important;
        border:1px solid rgba(99,102,241,.5) !important;
        color:#eaf6ff !important;
        box-shadow:0 1px 2px rgba(0,0,0,.4), 0 8px 20px rgba(99,102,241,.18), inset 0 1px 0 rgba(255,255,255,.08) !important;
    }
    .st-key-forensic_download_row [data-testid="column"]:nth-of-type(2) .stDownloadButton button:hover {
        box-shadow:0 0 0 1px rgba(99,102,241,.32), 0 10px 26px rgba(99,102,241,.28), inset 0 1px 0 rgba(255,255,255,.14) !important;
    }
    .st-key-forensic_download_row [data-testid="column"]:nth-of-type(3) .stDownloadButton button {
        background:linear-gradient(135deg,var(--act-1-top) 0%,var(--act-1-bot) 100%) !important;
        color:var(--act-1-text) !important;
        border:1px solid var(--act-1-border) !important;
        box-shadow:0 1px 2px rgba(0,0,0,.4), 0 8px 20px rgba(99,102,241,.28), inset 0 1px 0 rgba(255,255,255,.20) !important;
        font-weight:800 !important;
    }
    .st-key-forensic_download_row [data-testid="column"]:nth-of-type(3) .stDownloadButton button:hover {
        background:linear-gradient(135deg,var(--act-1-top-hover) 0%,var(--act-1-bot-hover) 100%) !important;
        border-color:var(--act-1-border-hover) !important;
    }
    .st-key-forensic_download_row [data-testid="column"] .stDownloadButton button:disabled {
        background:linear-gradient(180deg,var(--act-2-top) 0%,var(--act-2-bot) 100%) !important;
        border:1px solid var(--act-2-border) !important;
        color:var(--act-2-text) !important;
    }

    /* Action-color semantics: color should tell you what a button *does*,
       not just decorate it. Everywhere else in the app, "primary" (the
       cyan-to-violet gradient) means "the main/confirm action" -- that's
       already correct on "Connect & Load Mailbox", so it's untouched.
       These are the app's only genuinely destructive/irreversible
       actions, scoped by key so nothing else changes:
       - "Delete my data & sign out" permanently deletes local data ->
         solid red, the one truly destructive action in the app.
       - "Disconnect mailbox" ends a live session but is trivially
         reversible (just reconnect) -> a red *outline* instead of a
         solid fill, so it still reads as "be careful" without carrying
         the same weight as an irreversible delete.
       Plain session actions that aren't destructive (Sign out of Google,
       Clear graph highlight, Sync feed) are left as the ordinary
       secondary/graphite button -- not everything needs a warning color,
       and coloring low-risk actions red would just teach people to
       ignore red on the actually risky ones. */
    .st-key-delete_my_data_btn .stButton button {
        background:linear-gradient(135deg,#ef5a5a 0%,#c73f3f 100%) !important;
        border:1px solid rgba(239,90,90,.6) !important;
        color:#ffffff !important;
        box-shadow:0 1px 2px rgba(0,0,0,.4), 0 6px 16px rgba(239,90,90,.25), inset 0 1px 0 rgba(255,255,255,.18) !important;
    }
    .st-key-delete_my_data_btn .stButton button:hover {
        background:linear-gradient(135deg,#f56b6b 0%,#d84c4c 100%) !important;
        border-color:rgba(239,90,90,.85) !important;
        box-shadow:0 0 0 1px rgba(239,90,90,.3), 0 10px 22px rgba(239,90,90,.35), inset 0 1px 0 rgba(255,255,255,.22) !important;
    }
    .st-key-imap_disconnect_btn .stButton button {
        background:transparent !important;
        border:1px solid rgba(239,90,90,.55) !important;
        color:#ff9d9d !important;
    }
    .st-key-imap_disconnect_btn .stButton button:hover {
        background:rgba(239,90,90,.12) !important;
        border-color:rgba(239,90,90,.85) !important;
        color:#ffbcbc !important;
    }

    /* Secondary actions on the two acquisition-mode cards get their own
       accent instead of the plain graphite default -- each one tied back
       to the color of the mode it belongs to (indigo for Live IMAP,
       teal-green for Upload), so a user tracks "which flow am I in" by
       color the same way they did when picking the mode card itself. */
    .st-key-imap_show_form_btn .stButton button {
        background:transparent !important;
        border:1px solid rgba(147,167,255,.45) !important;
        color:#c3ccff !important;
    }
    .st-key-imap_show_form_btn .stButton button:hover {
        background:rgba(147,167,255,.10) !important;
        border-color:rgba(147,167,255,.8) !important;
        color:#e4e8ff !important;
    }
    .st-key-evidence_show_form_btn .stButton button {
        background:transparent !important;
        border:1px solid rgba(56,189,248,.45) !important;
        color:#9bdcfb !important;
    }
    .st-key-evidence_show_form_btn .stButton button:hover {
        background:rgba(56,189,248,.10) !important;
        border-color:rgba(56,189,248,.8) !important;
        color:#d4fbef !important;
    }
    .st-key-imap_reload_folder_btn .stButton button {
        background:transparent !important;
        border:1px solid rgba(59,130,246,.4) !important;
        color:#8fe9cf !important;
    }
    .st-key-imap_reload_folder_btn .stButton button:hover {
        background:rgba(59,130,246,.1) !important;
        border-color:rgba(59,130,246,.75) !important;
        color:#d4fbef !important;
    }

    /* Google-branded "Sign in with Google" link-button. Plain HTML/CSS
       (not a Streamlit widget) so it renders identically across Streamlit
       versions -- it needs to be a real <a> so clicking it navigates the
       browser straight to Google, rather than a server-side st.button. */
    /* "Sign in with Gmail/Outlook/Yandex" -- these are now native
       st.link_button widgets (see the sign-in form code) rather than
       hand-rolled <a> tags via st.markdown(unsafe_allow_html=True); the
       custom anchor approach rendered fine but its click sometimes did
       nothing at all depending on host/browser handling of a raw
       target="_top" link inside sanitized markdown. st.link_button is a
       first-class widget built for exactly this (navigate to an external
       URL on click) and isn't subject to that. Targeted by the widget's
       key wrapper so the brand look (white Google pill, dark Microsoft
       tile, red Yandex tile) carries over unchanged.
       Streamlit renders st.link_button as an <a> styled like a button
       inside its key wrapper -- select it generically so it survives
       minor Streamlit DOM-structure differences across versions. */
    .st-key-google_signin_link_btn a {
        display:flex !important; align-items:center !important; justify-content:center !important;
        width:100% !important; min-height:42px !important; box-sizing:border-box !important;
        background:#ffffff !important; color:#3c4043 !important;
        border:1px solid #dadce0 !important; border-radius:12px !important;
        font-family:Inter,"Segoe UI",Arial,sans-serif !important; font-weight:600 !important; font-size:14px !important;
        text-decoration:none !important; box-shadow:0 1px 3px rgba(0,0,0,.2) !important;
        padding:10px 16px 10px 44px !important; background-repeat:no-repeat !important;
        background-position:14px center !important; background-size:20px 20px !important;
        background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cpath fill='%23FFC107' d='M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z'/%3E%3Cpath fill='%23FF3D00' d='M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4c-7.682 0-14.344 4.337-17.694 10.691z'/%3E%3Cpath fill='%234CAF50' d='M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238C29.211 35.091 26.715 36 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z'/%3E%3Cpath fill='%231976D2' d='M43.611 20.083H42V20H24v8h11.303c-.792 2.237-2.231 4.166-4.087 5.571l6.19 5.238C40.463 35.751 44 30.5 44 24c0-1.341-.138-2.65-.389-3.917z'/%3E%3C/svg%3E") !important;
        transition:box-shadow .15s ease, border-color .15s ease !important;
    }
    .st-key-google_signin_link_btn a:hover {
        box-shadow:0 2px 8px rgba(0,0,0,.3) !important; border-color:#c6c9cc !important; color:#3c4043 !important;
    }
    .st-key-microsoft_signin_link_btn a {
        display:flex !important; align-items:center !important; justify-content:center !important;
        width:100% !important; min-height:42px !important; box-sizing:border-box !important;
        background:#2f2f2f !important; color:#ffffff !important;
        border:1px solid #505050 !important; border-radius:12px !important;
        font-family:Inter,"Segoe UI",Arial,sans-serif !important; font-weight:600 !important; font-size:14px !important;
        text-decoration:none !important; box-shadow:0 1px 3px rgba(0,0,0,.3) !important;
        padding:10px 16px 10px 44px !important; background-repeat:no-repeat !important;
        background-position:14px center !important; background-size:18px 18px !important;
        background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 21 21'%3E%3Crect x='1' y='1' width='9' height='9' fill='%23f25022'/%3E%3Crect x='11' y='1' width='9' height='9' fill='%2300a4ef'/%3E%3Crect x='1' y='11' width='9' height='9' fill='%23ffb900'/%3E%3Crect x='11' y='11' width='9' height='9' fill='%237fba00'/%3E%3C/svg%3E") !important;
        transition:box-shadow .15s ease, border-color .15s ease, background-color .15s ease !important;
    }
    .st-key-microsoft_signin_link_btn a:hover {
        background:#3c3c3c !important; box-shadow:0 2px 8px rgba(0,0,0,.35) !important; border-color:#6b6b6b !important; color:#ffffff !important;
    }
    .st-key-yandex_signin_link_btn a {
        display:flex !important; align-items:center !important; justify-content:center !important;
        width:100% !important; min-height:42px !important; box-sizing:border-box !important;
        background:#fc3f1d !important; color:#ffffff !important;
        border:1px solid #ff5a3c !important; border-radius:12px !important;
        font-family:Inter,"Segoe UI",Arial,sans-serif !important; font-weight:700 !important; font-size:14px !important;
        text-decoration:none !important; box-shadow:0 1px 3px rgba(0,0,0,.3) !important;
        padding:10px 16px 10px 44px !important; background-repeat:no-repeat !important;
        background-position:16px center !important; background-size:16px 16px !important;
        background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ctext x='4' y='19' font-family='Arial,sans-serif' font-weight='900' font-size='20' fill='white'%3EЯ%3C/text%3E%3C/svg%3E") !important;
        transition:box-shadow .15s ease, border-color .15s ease, background-color .15s ease !important;
    }
    .st-key-yandex_signin_link_btn a:hover {
        background:#ff5333 !important; box-shadow:0 2px 8px rgba(252,63,29,.45) !important; border-color:#ff7a5c !important; color:#ffffff !important;
    }

    .stTextInput input, .stNumberInput input, textarea {
        background:linear-gradient(180deg,#0d2035,#091729) !important;
        color:#eaf2fa !important;
        border:1px solid #2f5c56 !important;
        border-radius:10px !important;
        box-shadow:inset 0 1px 3px rgba(0,0,0,.35) !important;
        transition:border-color .15s var(--ease), box-shadow .15s var(--ease) !important;
    }
    .stTextInput input:hover, .stNumberInput input:hover, textarea:hover {border-color:#3d8a6f !important;}
    .stTextInput input:focus, .stNumberInput input:focus, textarea:focus {
        border-color:var(--cyan) !important;
        box-shadow:0 0 0 3px rgba(59,130,246,.14), inset 0 1px 3px rgba(0,0,0,.3) !important;
    }
    /* Number input stepper (+/-) buttons -- previously unstyled and left on
       Streamlit's stock grey/red-focus default, which read as a jarring,
       unfinished patch next to the themed field beside it. Same dark glass
       material as every other control, seated flush against the field with
       no gap, so the whole "input + steppers" group reads as one control. */
    .stNumberInput [data-testid="stNumberInputStepDown"],
    .stNumberInput [data-testid="stNumberInputStepUp"],
    .stNumberInput button {
        background:linear-gradient(180deg,#14293e,#0d1c2c) !important;
        border:1px solid #2f5c56 !important;
        color:#9fc3e6 !important;
        box-shadow:none !important;
        transition:background .15s var(--ease), border-color .15s var(--ease), color .15s var(--ease) !important;
    }
    .stNumberInput [data-testid="stNumberInputStepDown"]:hover,
    .stNumberInput [data-testid="stNumberInputStepUp"]:hover,
    .stNumberInput button:hover {
        background:linear-gradient(180deg,#1c3a58,#122438) !important;
        border-color:var(--cyan) !important; color:#eaf6ff !important;
    }
    /* Selects used to fall back to BaseWeb's default grey box -- the
       "Messages to browse" dropdown next to themed text inputs was the
       giveaway. The outer shell alone carries the border/background/radius;
       every layer nested inside it (value text, the indicator/arrow well)
       is forced transparent and border-less, so the control reads as one
       seamless field instead of a bordered box glued to a second one for
       the arrow. The options list (which opens in its own portal outside
       this DOM subtree) gets the same dark treatment below. */
    .stSelectbox [data-baseweb="select"] > div,
    .stMultiSelect [data-baseweb="select"] > div {
        background:linear-gradient(180deg,#0d2035,#091729) !important;
        color:#eaf2fa !important;
        border:1px solid #2f5c56 !important;
        border-radius:10px !important;
        box-shadow:inset 0 1px 3px rgba(0,0,0,.35) !important;
        transition:border-color .15s var(--ease) !important;
    }
    .stSelectbox [data-baseweb="select"] > div > div,
    .stSelectbox [data-baseweb="select"] > div > div > div,
    .stMultiSelect [data-baseweb="select"] > div > div,
    .stMultiSelect [data-baseweb="select"] > div > div > div {
        background:transparent !important;
        border:none !important;
        box-shadow:none !important;
        color:#eaf2fa !important;
    }
    .stSelectbox [data-baseweb="select"]:hover > div,
    .stMultiSelect [data-baseweb="select"]:hover > div {border-color:#3d8a6f !important;}
    .stSelectbox [data-baseweb="select"]:focus-within > div,
    .stMultiSelect [data-baseweb="select"]:focus-within > div {
        border-color:var(--cyan) !important;
        box-shadow:0 0 0 3px rgba(59,130,246,.14), inset 0 1px 3px rgba(0,0,0,.3) !important;
    }
    .stSelectbox svg, .stMultiSelect svg {color:var(--cyan) !important;}
    div[data-baseweb="popover"] ul[role="listbox"] {
        background:#0d1a2b !important;
        border:1px solid #2f5c56 !important;
        border-radius:10px !important;
        box-shadow:0 14px 30px rgba(0,0,0,.4) !important;
        padding:4px !important;
    }
    div[data-baseweb="popover"] li[role="option"] {color:#dfeaf4 !important; border-radius:7px !important;}
    div[data-baseweb="popover"] li[role="option"]:hover,
    div[data-baseweb="popover"] li[aria-selected="true"] {background:rgba(59,130,246,.14) !important; color:#ffffff !important;}
    /* Widget labels ("Mail provider", "IMAP server", "Port"...) previously
       rode on Streamlit's plain default text -- a touch brighter, a firm
       weight and tighter line-height reads as deliberate field labelling
       instead of leftover placeholder-grey. */
    [data-testid="stWidgetLabel"] p {
        color:#a9c1d8 !important; font-size:12.5px !important; font-weight:650 !important;
        letter-spacing:.15px !important; margin-bottom:2px !important;
    }
    /* Plain section headings for the login form -- replaces the old
       colored "stage card" boxes (01/02/03) with normal software-login
       typography: a thin divider, then a simple bold label. No borders,
       no background tint, no accent spine. */
    .login-plain-divider {border-top:1px solid var(--line); margin:22px 0 16px 0;}
    .login-plain-heading {
        color:#eef5ff; font-size:15px; font-weight:750; margin:4px 0 2px 0;
    }
    /* Professional centered sign-in card: wraps the whole email/password +
       one-click-provider flow in a single bordered panel instead of loose
       widgets sitting directly on the dark dashboard background -- same
       idea as a typical consumer login screen (logo, title, fields,
       primary button, divider, provider row), just themed to match the
       rest of this app instead of any one brand. */
    .st-key-imap_signin_card {
        max-width:100% !important; width:100% !important; margin:18px 0 !important;
        background:linear-gradient(180deg,#0d1c2e,#09141f) !important;
        border:1px solid #1e3853 !important; border-radius:20px !important;
        box-shadow:0 24px 60px rgba(0,0,0,.55), inset 0 1px 0 rgba(255,255,255,.03) !important;
        padding:36px 48px 30px 48px !important;
    }
    @media (max-width: 720px) {
        .st-key-imap_signin_card {padding:28px 22px 24px 22px !important; border-radius:16px !important;}
    }
    /* Card header: icon badge + title + subtitle, so the sign-in card opens
       with real product framing ("what is this, why am I here") instead of
       jumping straight into a bare "Email address" label with no context --
       the same pattern any production login screen uses above its fields. */
    .signin-card-header {
        display:flex !important; align-items:flex-start !important; gap:14px !important;
        margin-bottom:24px !important;
    }
    .signin-card-icon {
        flex:0 0 44px !important; width:44px !important; height:44px !important; border-radius:12px !important;
        display:flex !important; align-items:center !important; justify-content:center !important;
        background:linear-gradient(145deg, rgba(59,130,246,.24), rgba(59,130,246,.06)) !important;
        border:1px solid rgba(59,130,246,.38) !important; font-size:19px !important;
        box-shadow:inset 0 0 0 1px rgba(255,255,255,.04) !important;
    }
    .signin-card-title {color:#f2f8ff !important; font-size:18px !important; font-weight:800 !important; line-height:1.3 !important;}
    .signin-card-sub {color:#87a0b8 !important; font-size:12.5px !important; margin-top:3px !important; line-height:1.45 !important;}
    .auth-divider {
        display:flex !important; align-items:center !important; gap:12px !important;
        margin:22px 0 14px 0 !important; color:#7c93aa !important;
        font-size:12px !important; font-weight:650 !important; text-transform:uppercase !important; letter-spacing:.4px !important;
    }
    .auth-divider::before, .auth-divider::after {
        content:"" !important; flex:1 1 auto !important; height:1px !important; background:var(--line) !important;
    }
    /* Primary "Log in" button for the manual email/password path -- uses
       the app's own teal accent (matches the Gmail box's top stripe and
       the rest of the dashboard) instead of a red pill, with a soft
       rounded-rectangle shape rather than a full pill. */
    .st-key-manual_login_btn {margin:14px 0 6px 0 !important;}
    .st-key-manual_login_btn button {
        background:#3b82f6 !important; border:1px solid #3b82f6 !important;
        color:#0d1a24 !important; font-weight:800 !important; font-size:15px !important;
        border-radius:12px !important; min-height:46px !important;
        box-shadow:0 6px 16px rgba(59,130,246,.28) !important;
        transition:background .15s var(--ease), box-shadow .15s var(--ease), transform .15s var(--ease) !important;
    }
    .st-key-manual_login_btn button:hover {
        background:#7ba9cc !important; border-color:#7ba9cc !important;
        box-shadow:0 8px 20px rgba(59,130,246,.4) !important; transform:translateY(-1px) !important;
        color:#0d1a24 !important;
    }
    /* "Custom" toggle -- an advanced/escape-hatch option almost nobody
       needs (their provider auto-detects above), so it should read as a
       quiet secondary link, not another bordered card competing for
       attention right under the sign-in card's primary flow. Rendered as
       a centered, borderless text link with a settings glyph; the
       generic .stButton hover/focus glow is explicitly zeroed out below
       so it stays a plain link on every interactive state, not a button
       that flashes into a box on click. */
    .st-key-imap_custom_toggle_btn {
        display:flex !important; justify-content:center !important;
        margin:4px 0 20px 0 !important;
    }
    .st-key-imap_custom_toggle_btn .stButton {width:auto !important;}
    .st-key-imap_custom_toggle_btn button {
        background:transparent !important; border:none !important; box-shadow:none !important;
        color:#7a9ab5 !important; font-weight:650 !important; font-size:12.5px !important;
        letter-spacing:.15px !important; min-height:0 !important; height:auto !important;
        width:auto !important; padding:6px 8px !important;
    }
    .st-key-imap_custom_toggle_btn button:hover,
    .st-key-imap_custom_toggle_btn button:focus,
    .st-key-imap_custom_toggle_btn button:focus-visible,
    .st-key-imap_custom_toggle_btn button:active {
        background:transparent !important; border:none !important; box-shadow:none !important;
        color:#bfe3ff !important; text-decoration:underline !important; transform:none !important;
    }
    /* ------------------------------------------------------------------
       Segmented control -- every st.radio in the app.
       Only the options TRACK is boxed; the widget's own title ("Graph
       view", "Filter by Severity Level:" ...) is plain eyebrow text.
       The previous `.stRadio > div` rule matched BOTH children of the
       widget -- the title wrapper AND the track -- so every labelled
       radio drew its title inside a bordered, padded box: a heading that
       looked exactly like a button.
       The selected option is a tinted chip with an accent hairline rather
       than the loud primary-button gradient, so a toggle no longer reads
       as a call-to-action. The main nav / tab strips keep their own
       gradient further down (their selectors are equal-or-more specific
       and come later, so they still win). */
    .stRadio [role="radiogroup"] {
        background:var(--surface-sunken, #0a111a) !important;
        border:1px solid var(--line-strong) !important;
        border-radius:10px !important; padding:3px !important; gap:2px !important;
    }
    .stRadio [data-testid="stWidgetLabel"] {
        background:transparent !important; border:0 !important; box-shadow:none !important;
        padding:0 !important; margin:0 0 6px 0 !important; min-height:0 !important;
    }
    .stRadio [data-testid="stWidgetLabel"] p {
        font-size:11px !important; font-weight:700 !important; letter-spacing:.09em !important;
        text-transform:uppercase !important; color:var(--muted) !important; margin:0 !important;
    }
    .stRadio [role="radiogroup"] label {
        color:#c2cedb !important; cursor:pointer !important;
        border-radius:8px !important; border:1px solid transparent !important;
        padding:6px 14px !important;
        transition:background .18s var(--ease), border-color .18s var(--ease), color .18s var(--ease) !important;
    }
    .stRadio [role="radiogroup"] label:hover {
        background:rgba(255,255,255,.045) !important; color:#fff !important;
    }
    .stRadio [role="radiogroup"] label:has(input:checked) {
        background:rgba(59,130,246,.16) !important;
        background:color-mix(in srgb, var(--cyan) 18%, transparent) !important;
        border-color:rgba(59,130,246,.5) !important;
        border-color:color-mix(in srgb, var(--cyan) 55%, transparent) !important;
    }
    .stRadio [role="radiogroup"] label:has(input:checked) p {color:#ffffff !important; font-weight:700 !important;}
    .stFileUploader {background:#091625 !important; border:1px dashed #31584f !important; border-radius:12px !important;}
    .stFileUploader section {background:transparent !important;}

    div[data-testid="stMetric"] {
        background:linear-gradient(180deg,#102238,#0c1b2d) !important;
        border:1px solid #213c37 !important;
        border-radius:var(--r-md) !important;
        padding:13px 15px !important;
        box-shadow:var(--shadow-sm) !important;
        transition:transform .15s var(--ease), box-shadow .15s var(--ease), border-color .15s var(--ease) !important;
        position:relative !important;
        overflow:hidden !important;
    }
    div[data-testid="stMetric"]:before {
        content:""; position:absolute; left:0; top:0; right:0; height:2px;
        background:linear-gradient(90deg, var(--cyan), var(--teal) 70%, transparent 95%); opacity:.85;
    }
    div[data-testid="stMetric"]:hover {
        transform:translateY(-1px) !important; border-color:#2c5877 !important;
        box-shadow:var(--shadow-md) !important;
    }
    /* Metrics almost always show up in a row of several side by side
       (KPIs, dashboard summaries) -- with every card using the same cyan
       top-bar, a row of four reads as one repeated tile rather than four
       distinct numbers. Rotating the top-bar hue by position (cyan ->
       violet -> amber -> green, repeating) keeps each card legible as its
       own thing while staying inside the app's existing accent family --
       nothing here overrides severity-meaningful color used elsewhere. */
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+1) div[data-testid="stMetric"]:before {
        background:linear-gradient(90deg, var(--cyan), transparent 95%) !important;
    }
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+2) div[data-testid="stMetric"]:before {
        background:linear-gradient(90deg, var(--violet), transparent 95%) !important;
    }
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+3) div[data-testid="stMetric"]:before {
        background:linear-gradient(90deg, var(--amber), transparent 95%) !important;
    }
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+4) div[data-testid="stMetric"]:before {
        background:linear-gradient(90deg, var(--green), transparent 95%) !important;
    }
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+1) div[data-testid="stMetric"]:hover {border-color:rgba(59,130,246,.45) !important;}
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+2) div[data-testid="stMetric"]:hover {border-color:rgba(99,102,241,.5) !important;}
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+3) div[data-testid="stMetric"]:hover {border-color:rgba(244,178,61,.5) !important;}
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+4) div[data-testid="stMetric"]:hover {border-color:rgba(47,206,135,.5) !important;}
    div[data-testid="stMetricLabel"] {color:#7d94ad !important;}
    div[data-testid="stMetricValue"] {color:#f2f8ff !important; font-variant-numeric:tabular-nums !important;}
    div[data-testid="stMetricDelta"] {font-variant-numeric:tabular-nums !important;}
    /* st.success/info/warning/error previously rendered as a flat, edge-
       to-edge, sharp-cornered fill in Streamlit's raw theme color -- the
       ".stAlert" selector below no longer matches this component's actual
       markup in current Streamlit (it now hooks in via data-testid, not a
       stable class), so the override was silently a no-op. Both are
       targeted here for cross-version safety, styled as the same layered
       card used for .stage-card instead of a solid banner, with a
       left accent spine (not a full-color fill) carrying the severity. */
    .stAlert,
    div[data-testid="stAlertContainer"],
    div[data-testid="stAlert"] {
        background:linear-gradient(180deg,#101f33 0%,#0c1a2a 100%) !important;
        border:1px solid #1d3630 !important;
        border-left:3px solid var(--line-strong) !important;
        border-radius:var(--r-md) !important;
        box-shadow:0 8px 20px rgba(0,0,0,.18) !important;
        padding:12px 16px !important;
    }
    .stAlert:has([data-testid="stAlertContentSuccess"]),
    div[data-testid="stAlertContainer"]:has([data-testid="stAlertContentSuccess"]),
    div[data-testid="stAlert"]:has([data-testid="stAlertContentSuccess"]) {border-left-color:var(--green) !important;}
    .stAlert:has([data-testid="stAlertContentInfo"]),
    div[data-testid="stAlertContainer"]:has([data-testid="stAlertContentInfo"]),
    div[data-testid="stAlert"]:has([data-testid="stAlertContentInfo"]) {border-left-color:var(--cyan) !important;}
    .stAlert:has([data-testid="stAlertContentWarning"]),
    div[data-testid="stAlertContainer"]:has([data-testid="stAlertContentWarning"]),
    div[data-testid="stAlert"]:has([data-testid="stAlertContentWarning"]) {border-left-color:var(--amber) !important;}
    .stAlert:has([data-testid="stAlertContentError"]),
    div[data-testid="stAlertContainer"]:has([data-testid="stAlertContentError"]),
    div[data-testid="stAlert"]:has([data-testid="stAlertContentError"]) {border-left-color:var(--red) !important;}
    [data-testid="stAlertContentSuccess"] {color:#9be8c7 !important;}
    [data-testid="stAlertContentInfo"] {color:#bfe9ff !important;}
    [data-testid="stAlertContentWarning"] {color:#ffe3a3 !important;}
    [data-testid="stAlertContentError"] {color:#ffb4bc !important;}
    [data-testid="stExpander"] {background:#0b1828 !important; border:1px solid #1e3954 !important; border-left:3px solid var(--violet) !important; border-radius:var(--r-md) !important; transition:border-color .15s var(--ease) !important;}
    [data-testid="stExpander"]:hover {border-color:#2c5877 !important; border-left-color:var(--violet) !important;}

    /* "Custom IMAP server" toggle: this is a one-off setting most people
       never touch, sitting between two full-width form fields -- as a
       full-width expander it read as another big bar to fill the row,
       when all it needs is a small, clearly-optional link/button. Shrink
       just this one expander's clickable header to fit its text (a real
       compact button, not a stretched full-width strip); the fields
       inside still lay out normally once it's opened. */
    .st-key-imap_custom_server_wrap [data-testid="stExpander"] {
        background:transparent !important; border:none !important;
    }
    .st-key-imap_custom_server_wrap [data-testid="stExpander"] summary {
        display:inline-flex !important; width:fit-content !important;
        background:#0b1828 !important; border:1px solid #3a3358 !important;
        border-radius:999px !important; padding:6px 14px !important;
        font-size:12.5px !important; color:#c2aee0 !important;
    }
    .st-key-imap_custom_server_wrap [data-testid="stExpander"] summary:hover {
        border-color:var(--violet) !important; color:#eaf6ff !important;
    }
    .st-key-imap_custom_server_wrap [data-testid="stExpander"] summary svg {
        width:13px !important; height:13px !important;
    }
    .st-key-imap_custom_server_wrap [data-testid="stExpander"] > div:last-child {
        margin-top:8px !important; padding:12px !important;
        background:#0b1828 !important; border:1px solid #1e3954 !important;
        border-left:3px solid var(--violet) !important; border-radius:var(--r-md) !important;
    }

    /* Two always-open, side-by-side sign-in option boxes (App password /
       Google account) -- replaces a layout where Google sign-in stood
       alone and the app-password field hid behind a collapsed expander,
       which meant one path was a click-to-reveal search while the other
       wasn't. Both now read as equal, permanently visible choices in a
       clean two-column card row. Targeted by the container `key=` Streamlit
       emits as a `st-key-*` class, since these need to actually wrap the
       widgets inside them (a markdown div can't nest around a widget). */
    /* One shared card shell for every provider box -- same neutral border,
       background and padding across all of them, so the row reads as one
       consistent set of options rather than four differently-colored,
       differently-weighted boxes competing for attention. Each provider's
       identity now comes from a single thin top accent stripe (below) and
       its icon/label, not from tinting the whole card -- the same pattern
       integration-picker rows use in most professional dashboards. */
    .st-key-auth_password_box, .st-key-auth_google_box,
    .st-key-auth_password_box_ms, .st-key-auth_microsoft_box,
    .st-key-auth_password_box_ya, .st-key-auth_yandex_box {
        border-radius:var(--r-md) !important;
        background:linear-gradient(180deg,#0d1a2b,#0a1522) !important;
        border:1px solid #1c3247 !important;
        border-top:3px solid #1c3247 !important;
        padding:14px 15px 16px !important;
        box-shadow:var(--shadow-sm) !important;
        height:100% !important;
        transition:border-color .15s var(--ease), transform .15s var(--ease), box-shadow .15s var(--ease) !important;
    }
    .st-key-auth_password_box:hover, .st-key-auth_google_box:hover,
    .st-key-auth_password_box_ms:hover, .st-key-auth_microsoft_box:hover,
    .st-key-auth_password_box_ya:hover, .st-key-auth_yandex_box:hover {
        transform:translateY(-2px) !important;
        box-shadow:0 8px 20px rgba(0,0,0,.28) !important;
    }
    /* Header row inside each card: a small brand-colored dot + uppercase
       label side by side, instead of a bare label floating on its own --
       gives each card a consistent anchor point at the top before the
       button/status content starts. */
    .auth-option-label {
        display:flex !important; align-items:center !important; gap:7px !important;
        font-size:11px !important; font-weight:800 !important; letter-spacing:1.3px !important;
        text-transform:uppercase !important; margin-bottom:12px !important;
        padding-bottom:10px !important; border-bottom:1px solid rgba(255,255,255,.06) !important;
    }
    .auth-option-label::before {
        content:"" !important; width:7px !important; height:7px !important; border-radius:50% !important;
        flex:0 0 7px !important; box-shadow:0 0 8px currentColor !important;
    }
    /* Warm neutral (sand/taupe) instead of a desaturated blue-grey, so the
       manual app-password option doesn't quietly reintroduce blue into a
       row that's otherwise teal / terracotta / plum. */
    .st-key-auth_password_box, .st-key-auth_password_box_ms, .st-key-auth_password_box_ya {border-top-color:#a6947c !important;}
    .auth-option-label-violet {color:#c2b29a !important;}
    .st-key-auth_google_box:hover {border-color:rgba(59,130,246,.4) !important;}
    .st-key-auth_google_box {border-top-color:#3b82f6 !important;}
    .auth-option-label-cyan {color:#8fc2b8 !important;}
    /* Each provider gets a genuinely different hue from the app's own
       palette, muted enough that no single card pops as a bright outline:
       Gmail = teal-green, Outlook = warm terracotta, Yandex = red/orange
       (matching Yandex's own brand red, desaturated to fit the dark UI). */
    .st-key-auth_microsoft_box:hover {border-color:rgba(201,138,92,.4) !important;}
    .st-key-auth_microsoft_box {border-top-color:#c98a5c !important;}
    .auth-option-label-msblue {color:#dba87e !important;}
    .st-key-auth_yandex_box:hover {border-color:rgba(214,95,69,.4) !important;}
    .st-key-auth_yandex_box {border-top-color:#d65f45 !important;}
    .auth-option-label-yandex {color:#e8a08c !important;}
    /* st.tabs() is gone from this app entirely now -- its BaseWeb tab-list/
       tab-highlight internals kept rendering as plain unstyled default
       tabs (with the theme's raw red underline) no matter how this was
       styled, because they're painted by BaseWeb via inline styles at
       render time that these selectors evidently weren't matching in the
       installed Streamlit version. Every former st.tabs() spot (Email
       Results/Antivirus Scan, VPN/Datacenter/Tor Exit Nodes) is now the
       same st.radio "pill" segmented control the top nav already uses
       (see .st-key-topnav) -- styled below via the proven, version-proof
       label:has(input:checked) pattern instead of guessing at BaseWeb's
       DOM. */
    .stDataFrame {border:1px solid #203b57 !important; border-radius:var(--r-md) !important; overflow:hidden !important; box-shadow:var(--shadow-sm) !important;}

    /* Polished static table -- used in place of st.dataframe wherever the
       table is a plain read-only grid (no row-click selection, no
       column_config widgets). st.dataframe renders those onto a canvas,
       so it can never pick up the app's own dark theme (font, colors,
       hover, spacing) no matter what CSS targets it -- it just sits there
       looking like an unstyled default grid next to everything else that
       *is* themed. This is real HTML/CSS instead, so it matches. */
    .polished-table-wrap {
        border:1px solid #203b57;
        border-radius:var(--r-md);
        overflow:hidden;
        box-shadow:var(--shadow-sm);
        background:linear-gradient(180deg,#0b1524,#091120);
        margin:6px 0 4px 0;
    }
    .polished-table-wrap[style*="overflow-y:auto"] {overflow:auto;}
    table.polished-table {
        width:100%;
        border-collapse:collapse;
        font-family:Inter,"Segoe UI",Arial,sans-serif;
        font-size:13.5px;
    }
    table.polished-table thead th {
        position:sticky; top:0; z-index:1;
        text-align:left;
        padding:11px 16px;
        background:linear-gradient(180deg,#132a42,#0f2135);
        color:#9fd6f5;
        font-size:11.5px;
        font-weight:750;
        letter-spacing:.55px;
        text-transform:uppercase;
        border-bottom:2px solid rgba(59,130,246,.35);
        white-space:nowrap;
    }
    table.polished-table tbody td {
        padding:10px 16px;
        color:var(--text);
        border-bottom:1px solid #16283c;
        vertical-align:top;
    }
    table.polished-table tbody tr:last-child td {border-bottom:none;}
    table.polished-table tbody tr:nth-child(even) {background:rgba(255,255,255,.014);}
    table.polished-table tbody tr {transition:background .12s var(--ease);}
    table.polished-table tbody tr:hover {background:rgba(59,130,246,.10);}
    table.polished-table tbody td:first-child {color:#cfe3f5; font-weight:600;}
    .polished-table-empty {
        padding:16px; text-align:center; color:var(--muted); font-size:13px;
        border:1px dashed #203b57; border-radius:var(--r-md); background:#0a121f;
    }
    hr {border-color:#20364f !important;}
    .stMarkdown code {background:#07131f !important; color:#9beaff !important;}

    /* Flat, clean product background -- a couple of very soft glows over
       plain navy, no grid/scanline texture, so the surface reads as a
       polished SaaS console rather than an industrial SCADA panel. */
    .stApp {
        background:
            radial-gradient(circle at 15% 0%, rgba(59,130,246,.035), transparent 26%),
            radial-gradient(circle at 100% 15%, rgba(59,130,246,.03), transparent 30%),
            var(--bg) !important;
        background-size: auto !important;
    }
    /* Global horizontal-overflow guard. The topnav min-width:0 fix stops
       THAT one element from forcing the page wide, but it's a narrow,
       component-specific fix -- it only helps if that element is the
       cause. Any other element anywhere in the app that ever ends up
       wider than the viewport (a long unbroken string, a wide chart, a
       future widget nobody thought to bound) would reproduce the exact
       same symptom: the whole page gets a horizontal scrollbar and a
       blank gap opens up on the side, because the browser's default
       behavior is to grow the page to fit its widest child rather than
       clip it. Nothing in this app is meant to be scrolled at the page
       level -- every intentional horizontal scroller (like the topnav
       tab row) does its own scrolling internally via its own
       overflow-x:auto -- so clipping overflow at the document root is
       safe and simply removes this entire bug class outright, rather
       than chasing it one oversized element at a time. */
    html, body {overflow-x:hidden !important; max-width:100vw !important;}
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
        overflow-x:hidden !important; max-width:100vw !important;
    }
    .block-container {padding-left:1.35rem !important; padding-right:1.35rem !important;}
    [data-testid="stSidebar"] {
        background:linear-gradient(180deg,#060b13 0%,#05090f 100%) !important;
        border-right:1px solid #131f2c !important;
    }
    /* Scoped to the expanded state only. An unscoped min-width here fights
       Streamlit's own collapse mechanism (it toggles aria-expanded rather
       than removing the element), so the sidebar was being held open at
       290px even while "collapsed" -- exactly the dead strip down the left
       edge that persisted after the earlier block-container fix, since that
       fix addressed the content's own max-width but not this. */
    [data-testid="stSidebar"][aria-expanded="true"] {
        min-width:290px !important;
    }
    [data-testid="stSidebar"][aria-expanded="false"] {
        min-width:0 !important;
        width:0 !important;
    }
    [data-testid="stSidebar"] > div:first-child {padding-top:0 !important;}
    /* Streamlit reserves a tall header strip inside the sidebar to clear
       the collapse icon, and the inner content wrapper below it carries
       its own default top padding on top of that -- neither is touched by
       the plain "> div:first-child" padding above, which is why the brand
       block still sat far down the sidebar. 2.75rem matches our own
       stHeader height (just enough to clear the icon); the content
       wrapper is trimmed to a small, deliberate gap instead. */
    [data-testid="stSidebarHeader"] {
        height:2rem !important;
        min-height:2rem !important;
        padding-top:0 !important;
        padding-bottom:0 !important;
    }
    [data-testid="stSidebarUserContent"] {
        padding-top:0 !important;
    }

    /* Right summary panel: a real dock, not a block that happens to sit in
       a column. It sticks to the top of the viewport as the center pane
       scrolls, is flush to the right edge and runs the panel's full height
       -- same visual language as the left sidebar (square outer corners,
       a single edge border, no floating-card look) -- and only exists in
       the layout at all while toggled open -- see the header ✕ button
       inside it, and the floating reopen tab below, that render it
       conditionally.

       One real limitation, unlike the native left sidebar: Streamlit's own
       sidebar collapse is a pure CSS toggle (the element stays in the DOM,
       just its width animates), so it can transition smoothly. This dock's
       open/closed state is decided in Python -- the column either exists
       or doesn't -- so there's no single element to animate a slide on.
       What's fixed here is the *layout* side of "screen adaptive" (open =
       reserves real space next to the center pane at whatever width the
       screen allows, closed = zero width, nothing left behind); toggling
       itself is still an instant swap rather than a slide. */
    .st-key-right_summary_pane, .st-key-bulk_command_dock {
        position:sticky !important;
        top:88px !important;
        background:linear-gradient(180deg,#0b1a29 0%,#081522 100%) !important;
        border:none !important;
        border-left:1px solid #1c3a52 !important;
        border-radius:0 !important;
        box-shadow:-14px 0 30px rgba(0,0,0,.3) !important;
    }
    /* Below tablet width Streamlit stacks columns vertically instead of
       side-by-side, so a "sticky, flush-right, full-height" treatment would
       just float oddly under the center content instead of reading as a
       sidebar. There, let it behave like a normal full-width block that
       flows below the center pane -- and move the reopen tab to a bottom
       corner so it doesn't sit awkwardly mid-page over stacked content. */
    @media (max-width: 900px) {
    .st-key-right_summary_pane, .st-key-bulk_command_dock {
        position:static !important;
        top:auto !important;
        max-height:none !important;
        border-left:none !important;
        border-top:1px solid #1c3a52 !important;
        box-shadow:0 -10px 24px rgba(0,0,0,.25) !important;
        margin-top:14px !important;
    }
    /* Force the actual st.columns row to stack -- don't assume Streamlit
       already did it, since its own breakpoint is narrower than 900px. */
    [data-testid="stHorizontalBlock"]:has(.st-key-right_summary_pane),
    [data-testid="stHorizontalBlock"]:has(.st-key-bulk_command_dock) {
        flex-direction:column !important;
    }
    [data-testid="stHorizontalBlock"]:has(.st-key-right_summary_pane) > div,
    [data-testid="stHorizontalBlock"]:has(.st-key-bulk_command_dock) > div {
        width:100% !important;
        flex:1 1 100% !important;
        min-width:0 !important;
    }
    .st-key-right_dock_reopen {
        top:auto !important;
        bottom:14px !important;
    }
}
    .right-dock-title {
        font:800 11px/1.3 monospace; letter-spacing:1.2px; color:#5fdfff;
        padding:8px 0 4px 2px;
    }
    /* Small ✕ control docked in the panel's own header -- clicking it is
       what closes the sidebar. */
    .st-key-toggle_right_summary_open button {
        background:transparent !important; border:1px solid #1c3a52 !important;
        color:#8fa5bd !important; min-height:30px !important; padding:0 !important;
    }
    .st-key-toggle_right_summary_open button:hover {
        border-color:var(--cyan) !important; color:var(--cyan) !important;
    }
    /* The reopen tab is pinned with position:fixed, so while the sidebar
       is closed it claims zero layout width -- the center pane is simply
       full-width, exactly like a normal single-column page, and this is
       the only thing left on screen as the (weightless) way back in. */
    .st-key-right_dock_reopen {
        position:fixed !important; right:0 !important; top:150px !important; z-index:9999 !important;
        width:auto !important;
    }
    .st-key-right_dock_reopen button {
        background:#0a1d2b !important; border:1px solid var(--cyan) !important; border-right:none !important;
        color:var(--cyan) !important; border-radius:8px 0 0 8px !important;
        padding:12px 10px !important; box-shadow:-6px 0 18px rgba(0,0,0,.35) !important;
        writing-mode:vertical-rl !important; text-transform:uppercase !important; letter-spacing:1px !important;
        font-size:11px !important; font-weight:800 !important;
    }
    /* Bulk scan dock (Threat Summary + Synapse Copilot) reuses
       the same dock shell as the per-email summary pane above, just under
       its own key since both can never coexist as columns in the same
       Streamlit run. Stretches to fill the column height like the native
       left sidebar, gap included, so it reads as one continuous panel
       rather than a card floating in whitespace. */
    .st-key-bulk_command_dock {
        padding:14px 14px 16px !important;
        border-left:none !important;
        border:1px solid #17364c !important;
        border-radius:var(--r-lg) !important;
        box-shadow:0 12px 30px rgba(0,0,0,.22) !important;
    }
    @media (max-width: 900px) {
        .st-key-bulk_command_dock {border:1px solid #17364c !important; box-shadow:0 -6px 20px rgba(0,0,0,.2) !important;}
    }
    /* Consistent, generously-rounded corner scale for every "box" in the
       app (cards, buttons, tabs) instead of near-sharp 3-4px slabs -- the
       industrial grid/scanline textures elsewhere stay; this only softens
       the container shapes to read as a modern product rather than a
       flat SCADA panel. */
    [data-testid="stExpander"], div[data-testid="stMetric"] {border-radius:var(--r-lg) !important;}
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) button {border-radius:10px !important;}
    /* (Tab radius/case/size is fully owned by the .stRadio segmented-control
       rules and the per-panel .st-key-* overrides further down -- this
       used to re-declare a conflicting tiny-uppercase variant here,
       fighting the readable design set everywhere else. Removed rather
       than left to silently compete. ) */

    /* Native Streamlit uploader only — no synthetic Browse Evidence labels.
       Richer layered background (soft cyan/green glows over the industrial
       grid, instead of a flat panel) plus a hover/focus animation chain so
       the intake zone reads as an inviting, professional drop target
       rather than a plain dashed box. */
    section[data-testid="stFileUploaderDropzone"] {
        min-height:150px !important; border:1.5px dashed var(--line-strong) !important; border-radius:var(--r-md) !important;
        padding:28px 20px 22px !important;
        background:var(--panel-3) !important;
        box-shadow:none !important;
        display:flex !important; flex-direction:column !important; align-items:center !important; justify-content:center !important;
        transition:border-color .2s var(--ease), background .2s var(--ease), transform .18s var(--ease) !important;
    }
    section[data-testid="stFileUploaderDropzone"]:hover {
        border-color:var(--teal) !important;
        background:rgba(56,189,248,.05) !important;
    }
    /* A calm, centered "upload cloud" glyph above the native button, drawn
       as a pure-CSS icon (border-radius + rotated square) so the dropzone
       reads as a deliberate, designed drop target instead of a bare dashed
       rectangle with a tiny button floating in it. */
    section[data-testid="stFileUploaderDropzone"]::before {
        content:"";
        display:block;
        width:44px; height:44px; margin:0 auto 12px;
        border-radius:50%;
        background:rgba(56,189,248,.12);
        border:1px solid rgba(56,189,248,.32);
        background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2322c7ac' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M16.5 16.7H7.8a4.3 4.3 0 0 1-.6-8.55A5.8 5.8 0 0 1 18 7.9a4.3 4.3 0 0 1-1.5 8.8z'/%3E%3Cpath d='M12 20.5v-7.2'/%3E%3Cpath d='M9.3 15.8L12 13l2.7 2.8'/%3E%3C/svg%3E");
        background-repeat:no-repeat;
        background-position:center;
        background-size:21px 21px;
        transition:transform .2s var(--ease);
    }
    section[data-testid="stFileUploaderDropzone"]:hover::before {transform:translateY(-2px);}
    section[data-testid="stFileUploaderDropzone"] > div {gap:8px !important; align-items:center !important;}
    /* The native drag-and-drop instructions ("Drag and drop file here")
       normally render in Streamlit's default shouty, letter-spaced
       all-caps mono style -- reset to calm, regular-case sans-serif so it
       reads as a designed product surface rather than a raw form control. */
    [data-testid="stFileUploaderDropzoneInstructions"] {text-align:center !important;}
    [data-testid="stFileUploaderDropzoneInstructions"] svg {display:none !important;}
    [data-testid="stFileUploaderDropzoneInstructions"] > div > span {
        font-size:14px !important; font-weight:650 !important; text-transform:none !important; letter-spacing:0 !important;
    }
    [data-testid="stFileUploaderDropzoneInstructions"] > div > small {
        font-size:11.5px !important; text-transform:none !important; letter-spacing:.1px !important;
        font-family:'Inter', system-ui, sans-serif !important; font-weight:500 !important;
    }
    section[data-testid="stFileUploaderDropzone"] small {color:var(--muted) !important;}
    section[data-testid="stFileUploaderDropzone"] [data-testid="stFileUploaderDropzoneInstructions"] {color:#c9d4e0 !important;}

    .acq-panel {
        border:1px solid var(--line); border-left:3px solid var(--cyan);
        background:var(--panel);
        border-radius:var(--r-lg); padding:14px 16px 14px 14px; margin:8px 0 14px; position:relative;
        box-shadow:none;
        transition:border-color .2s var(--ease), background .2s var(--ease);
    }
    .acq-panel:hover {border-color:var(--line-strong); background:var(--panel-2);}
    .acq-panel:after {content:"01";position:absolute;right:14px;top:11px;color:var(--line-strong);font:900 12px monospace;}
    .acq-label {font-size:10px;font-weight:900;letter-spacing:1.5px;color:var(--cyan);text-transform:uppercase;}
    .acq-help {font-size:11px;color:#7993a8;margin-top:4px;}

    /* "Select Threat Acquisition Mode" -- two large selectable cards
       instead of small pill buttons, matching the enterprise mode-select
       pattern (icon + bold title, plain unselected border, blue selected
       border + soft ring). Scoped to this one radio only via its key. */
    .st-key-input_mode_radio [role="radiogroup"] {
        display:flex !important; flex-wrap:wrap !important; gap:14px !important;
        background:transparent !important; border:none !important; padding:2px 0 !important;
    }
    .st-key-input_mode_radio label {
        flex:1 1 280px !important;
        display:flex !important; align-items:center !important;
        gap:0 !important;
        background:var(--panel-2) !important;
        border:1.5px solid var(--line) !important;
        border-radius:var(--r-lg) !important;
        padding:18px 20px !important;
        min-height:0 !important;
        cursor:pointer !important;
        transition:border-color .18s var(--ease), background .18s var(--ease), box-shadow .18s var(--ease) !important;
    }
    .st-key-input_mode_radio label > div:first-child {display:none !important;}
    .st-key-input_mode_radio label p {
        color:#dbe6f2 !important; font-size:14.5px !important; font-weight:700 !important;
        line-height:1.4 !important; white-space:normal !important; letter-spacing:normal !important;
        text-transform:none !important;
    }
    .st-key-input_mode_radio label:hover {
        border-color:#33597c !important; background:#122439 !important;
    }
    .st-key-input_mode_radio label:has(input:checked) {
        border-color:var(--cyan) !important;
        background:linear-gradient(180deg,#122b46,#0e1f34) !important;
        box-shadow:0 0 0 3px rgba(59,130,246,.14) !important;
    }
    .st-key-input_mode_radio label:has(input:checked) p {color:#eef5ff !important;}

    /* Acquisition-mode picker v2: real icon-tile cards (icon box + bold
       title + muted subtitle) instead of a single-line radio pill, so the
       two acquisition modes read as enterprise "choose a method" cards.
       The card itself is pure display HTML; an invisible full-size button
       (.st-key-acq_pick_*) is stacked exactly on top of it via negative
       margin so the whole card is one click target while st.session_state
       stays the single source of truth for which mode is selected. */
    .mode-select-heading {
        color:#f2f8ff !important; font-size:16px !important; font-weight:800 !important;
        letter-spacing:.1px !important; margin:2px 0 12px 2px !important;
    }
    .mode-card-row {display:flex !important; flex-wrap:wrap !important; gap:14px !important; margin-bottom:2px !important;}
    .mode-card {
        position:relative; overflow:hidden; flex:1 1 300px; display:flex; align-items:center; gap:16px;
        background:linear-gradient(155deg, rgba(147,167,255,.05), var(--panel) 60%);
        border:1px solid var(--line); border-left:3px solid var(--mode-accent, var(--line-strong)); border-radius:var(--r-lg);
        padding:18px 44px 18px 20px; box-shadow:0 10px 24px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.03);
        transition:border-color .18s var(--ease), background .18s var(--ease), box-shadow .18s var(--ease), transform .18s var(--ease);
    }
    /* Soft color wash bleeding from the icon corner, so each card reads as
       genuinely colored rather than a gray box with a small colored icon
       floating in it. */
    .mode-card::before {
        content:""; position:absolute; inset:0; pointer-events:none;
        background:radial-gradient(160px 110px at -10px -30px, var(--mode-glow, rgba(59,130,246,.16)), transparent 72%);
        opacity:.9;
    }
    .mode-card-live {--mode-accent:rgba(147,167,255,.55); --mode-glow:rgba(147,167,255,.22);}
    .mode-card-upload {--mode-accent:rgba(56,189,248,.55); --mode-glow:rgba(56,189,248,.22);}
    /* Unselected-state indicator: an empty ring sitting where the
       "SELECTED" pill goes once active, so an idle card still visibly
       reads as "pick me" instead of looking like inert static text. It
       cross-fades into the checkmark/pill via .mode-card-active below. */
    .mode-card::after {
        content:""; position:absolute; z-index:1; top:16px; right:16px; width:20px; height:20px;
        border-radius:50%; border:1.5px solid var(--line-strong);
        background:rgba(255,255,255,.02);
        transition:border-color .18s var(--ease), background .18s var(--ease);
    }
    .mode-card:hover::after {border-color:#4a6a86;}
    .mode-card-icon {
        position:relative; z-index:1; flex:0 0 46px; width:46px; height:46px; border-radius:var(--r-md);
        display:flex; align-items:center; justify-content:center; font-size:19px;
        box-shadow:inset 0 0 0 1px rgba(255,255,255,.05), 0 4px 10px rgba(0,0,0,.22);
    }
    .mode-card-icon-blue {
        background:linear-gradient(145deg, rgba(147,167,255,.30), rgba(147,167,255,.09));
        border:1px solid rgba(147,167,255,.45); color:#c3ccff;
    }
    .mode-card-icon-neutral {
        background:linear-gradient(145deg, rgba(56,189,248,.30), rgba(56,189,248,.09));
        border:1px solid rgba(56,189,248,.45); color:#9bdcfb;
    }
    .mode-card-title {position:relative; z-index:1; color:#f4f9ff; font-size:14.5px; font-weight:800; line-height:1.3;}
    .mode-card-sub {position:relative; z-index:1; color:#93a7bf; font-size:12px; margin-top:3px; line-height:1.4;}
    .mode-card:hover {
        border-color:var(--line-strong); background:linear-gradient(155deg, rgba(147,167,255,.08), var(--panel-2) 60%);
        transform:translateY(-2px); box-shadow:0 14px 30px rgba(0,0,0,.26);
    }
    @keyframes modeCardSelect {
        0%   {transform:scale(.97); box-shadow:0 0 0 0 rgba(59,130,246,.0);}
        55%  {transform:scale(1.012);}
        100% {transform:scale(1); box-shadow:0 0 0 1px rgba(59,130,246,.4), 0 14px 32px rgba(59,130,246,.10);}
    }
    @keyframes modeCardIconPop {
        0%   {transform:scale(.75) rotate(-6deg);}
        60%  {transform:scale(1.1) rotate(3deg);}
        100% {transform:scale(1) rotate(0deg);}
    }
    .mode-card-active {
        border-left-color:var(--cyan) !important;
        border-color:var(--cyan) !important;
        background:linear-gradient(155deg, rgba(59,130,246,.14), var(--panel-2) 62%) !important;
        box-shadow:0 0 0 1px rgba(59,130,246,.4), 0 14px 32px rgba(59,130,246,.10) !important;
        animation:modeCardSelect .4s var(--ease);
        padding-right:20px !important;
    }
    .mode-card-active::after {
        content:"✓ SELECTED"; width:auto; height:auto; border-radius:20px;
        top:12px; right:14px; padding:3px 10px;
        font:900 9px/1.6 monospace; letter-spacing:1.2px; color:var(--green);
        background:rgba(47,206,135,.12); border:1px solid rgba(47,206,135,.32);
        display:flex; align-items:center;
    }
    .mode-card-active .mode-card-icon {animation:modeCardIconPop .45s var(--ease);}
    @media (prefers-reduced-motion: reduce) {
        .mode-card-active, .mode-card-active .mode-card-icon {animation:none !important;}
    }
    .st-key-acq_pick_live, .st-key-acq_pick_upload {
        margin-top:-82px !important; position:relative !important; z-index:5 !important;
    }
    .st-key-acq_pick_live button, .st-key-acq_pick_upload button {
        height:82px !important; width:100% !important; min-height:0 !important;
        background:transparent !important; border:none !important; box-shadow:none !important;
        color:transparent !important; cursor:pointer !important; outline:none !important;
    }
    /* The generic .stButton button:hover / :active rules elsewhere in this
       stylesheet paint a visible gradient + glow on every button -- without
       an explicit override here those rules (same selector specificity,
       but matching a real interactive state) win over the plain default
       rule above the moment the mouse is down or focus lands on the
       button, which is exactly what made the invisible overlay flash into
       a solid blue box on click. Every interactive state is pinned back
       to fully transparent so the card underneath is always what's seen. */
    .st-key-acq_pick_live button:hover, .st-key-acq_pick_upload button:hover,
    .st-key-acq_pick_live button:focus, .st-key-acq_pick_upload button:focus,
    .st-key-acq_pick_live button:focus-visible, .st-key-acq_pick_upload button:focus-visible,
    .st-key-acq_pick_live button:active, .st-key-acq_pick_upload button:active {
        background:transparent !important; border:none !important; box-shadow:none !important;
        color:transparent !important; outline:none !important; transform:none !important;
    }
    @media (max-width: 900px) {
        .st-key-acq_pick_live, .st-key-acq_pick_upload {margin-top:-104px !important;}
        .st-key-acq_pick_live button, .st-key-acq_pick_upload button {height:104px !important;}
    }

    .feedback-terminal {
        background:linear-gradient(180deg,#091a27,#07141f) !important;
        border:1px solid #1f425d !important;
        border-left:3px solid !important;
        border-radius:var(--r-lg) !important;
        padding:11px 14px !important;
        margin:10px 0 12px 0 !important;
        color:#dff4ff !important;
        font-family:"Consolas","Cascadia Code",monospace !important;
        font-size:13px !important;
        letter-spacing:.15px !important;
        box-shadow:inset 0 0 18px rgba(59,130,246,.03) !important;
    }
    .feedback-icon { font-weight:900 !important; margin-right:9px !important; }
    .feedback-cursor { animation:feedbackBlink .8s steps(1) infinite; }
    @keyframes feedbackBlink { 0%,49%{opacity:1} 50%,100%{opacity:0} }

    .ai-console-head {
        position:relative; overflow:hidden; margin:6px 0 14px 0; padding:18px 20px 16px;
        border:1px solid #3d3168; border-left:3px solid var(--violet); border-radius:var(--r-lg);
        background:linear-gradient(180deg,#101f33 0%,#0c1a2a 100%);
        box-shadow:inset 0 0 26px rgba(59,130,246,.05),0 14px 34px rgba(0,0,0,.20);
    }
    .ai-console-status {font:800 9px/1.3 monospace; letter-spacing:1.4px; color:#9584b8; text-transform:uppercase;}
    .ai-pulse {display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 12px rgba(47,206,135,.8);margin-right:7px;}
    .ai-console-title {margin-top:7px;color:#f1fbff;font-size:27px;font-weight:850;letter-spacing:.3px;}
    .ai-console-sub {margin-top:5px;color:#8f83ac;font:800 10px/1.5 monospace;letter-spacing:1px;}
    .ai-console-track {margin-top:13px;height:2px;background:#241c3c;position:relative;overflow:hidden;}
    .ai-console-track span {display:block;width:36%;height:100%;background:linear-gradient(90deg,transparent,var(--violet),transparent);animation:aiSweep 2.8s linear infinite;}
    @keyframes aiSweep {0%{transform:translateX(-120%)}100%{transform:translateX(330%)}}
    .ai-report-frame {border:1px solid #3d3168;border-radius:var(--r-lg);overflow:hidden;background:linear-gradient(180deg,#0f0c1e,#0a0816);box-shadow:inset 0 0 30px rgba(59,130,246,.05),0 12px 28px rgba(0,0,0,.2);}
    .ai-report-bar {display:flex;justify-content:space-between;align-items:center;padding:10px 13px;border-bottom:1px solid #2a2140;background:#150f24;color:#c9a8ff;font:900 10px/1.2 monospace;letter-spacing:1px;}
    .ai-report-chip {padding:4px 9px;border:1px solid #4a3a7a;background:#1c1530;color:#c9a8ff;border-radius:999px;}
    .ai-report-body {padding:18px 20px;color:#e2dcf0;font-size:14px;line-height:1.78;white-space:normal;}

    .nav-caption {
        color:#6f8aa5 !important; font-size:10px !important; font-weight:800 !important;
        letter-spacing:1.8px !important; text-transform:uppercase !important; margin:4px 0 6px 0 !important;
    }

    /* Top "FORENSIC WORKFLOW / ACTIVE MODULE" nav only (scoped to the
       .st-key-topnav container below), redesigned as a clean single-line
       tab bar:
         - roomier spacing and no native radio dot, so items read as
           simple text chips instead of a crowded checklist
         - single line, horizontally auto-scrollable with smooth-scroll,
           snap-to-tab, a slim accent scrollbar, and an edge shadow that
           only appears once there is actually more to scroll left/right
           (so nothing ever looks cut off when everything already fits)
         - a bolder, glowing, underlined active state so the current
           section is unmistakable at a glance
       Every other st.radio pill-bar in the app (acquisition mode,
       severity filter, etc.) is untouched -- every rule below is scoped
       under .st-key-topnav. */
    /* Thin progress-style underline spanning the full tab bar, echoing a
       stepper track beneath the workflow tabs (purely decorative, additive
       element -- doesn't affect the radio widget itself). */
    .st-key-topnav {position:relative !important;}
    /* Belt-and-braces: harmless on the normal block-level wrappers Streamlit
       puts around this widget (min-width:0 is already their default), but
       guards against any of them turning out to be a flex/grid item too --
       without this, a fix on the innermost row alone can still get undone
       by the same min-width:auto trap one level up. */
    .st-key-topnav, .st-key-topnav [data-testid="stRadio"] {min-width:0 !important;}
    .st-key-topnav::after {
        content:""; position:absolute; left:12px; right:12px; bottom:0; height:2px;
        background:linear-gradient(90deg,#3b82f6 0%,rgba(59,130,246,.12) 60%,transparent 100%);
        border-radius:2px; pointer-events:none;
    }
    .st-key-topnav .stRadio > div {
        /* min-width:0 is the actual fix for the horizontal page-overflow
           bug: flex items default to an implicit min-width:auto, which
           locks their minimum size to their content's natural (nowrap)
           width. With 13 nowrap pills in here, that pushed this box --
           and the whole page along with it -- wider than the viewport
           instead of respecting overflow-x:auto below. Setting it to 0
           is what lets this box actually shrink to the space it's given
           and scroll its own contents internally, as intended. */
        min-width:0 !important;
        flex-wrap:nowrap !important;
        gap:8px !important;
        padding:9px 12px !important;
        overflow-x:auto !important;
        overflow-y:hidden !important;
        scroll-behavior:smooth !important;
        scroll-snap-type:x proximity !important;
        scroll-padding-inline:12px !important;
        -webkit-overflow-scrolling:touch !important;
        scrollbar-width:thin !important;
        scrollbar-color:rgba(59,130,246,.4) transparent !important;
        /* Scroll-shadow trick: the two "cover" gradients scroll with the
           content (background-attachment:local) and cancel themselves
           out at the true start/end, while the two dark gradients stay
           fixed to the viewport (background-attachment:scroll) and only
           peek out once content has actually scrolled past them. */
        background-image:
            linear-gradient(to right, #081522, rgba(8,21,34,0) 30px),
            linear-gradient(to left, #081522, rgba(8,21,34,0) 30px),
            linear-gradient(to right, rgba(0,0,0,.4), rgba(0,0,0,0)),
            linear-gradient(to left, rgba(0,0,0,.4), rgba(0,0,0,0)) !important;
        background-position:left, right, left, right !important;
        background-repeat:no-repeat !important;
        background-size:30px 100%, 30px 100%, 14px 100%, 14px 100% !important;
        background-attachment:local, local, scroll, scroll !important;
    }
    .st-key-topnav .stRadio > div::-webkit-scrollbar {height:5px !important;}
    .st-key-topnav .stRadio > div::-webkit-scrollbar-track {background:transparent !important;}
    .st-key-topnav .stRadio > div::-webkit-scrollbar-thumb {
        background:rgba(59,130,246,.4) !important; border-radius:6px !important;
        transition:background .25s ease !important;
    }
    .st-key-topnav .stRadio > div::-webkit-scrollbar-thumb:hover {background:rgba(59,130,246,.7) !important;}

    /* Roomier pills with no leading radio dot -- this bar behaves like a
       tab strip, not a checklist, so each item is one clean text chip. */
    .st-key-topnav .stRadio label {
        flex-shrink:0 !important;
        white-space:nowrap !important;
        scroll-snap-align:start !important;
        padding:11px 20px !important;
        border-radius:10px !important;
        letter-spacing:.15px !important;
    }
    .st-key-topnav .stRadio label p {white-space:nowrap !important;}
    .st-key-topnav .stRadio label > div:first-child {display:none !important;}

    /* Active tab, all three tab-strip radios (top nav, bulk infra scan,
       technical logs) -- now pulls from the exact same --act-1-* tokens
       every primary button uses (see :root), instead of its own separate
       flat teal. One "this is the selected/primary thing" language for
       the whole app: tabs and buttons read as the same design system
       instead of two different ones that happen to sit near each other. */
    .st-key-topnav .stRadio label:has(input:checked),
    .st-key-bulk_infra_scan [data-testid="stRadio"] label:has(input:checked),
    .st-key-tech_logs_tabs [data-testid="stRadio"] [role="radiogroup"] label:has(input:checked) {
        background:linear-gradient(135deg,var(--act-1-top) 0%,var(--act-1-bot) 100%) !important;
        border-color:var(--act-1-border) !important;
        box-shadow:0 2px 8px rgba(99,102,241,.35) !important;
        transform:translateY(-1px) !important;
    }
    .st-key-topnav .stRadio label:has(input:checked) p,
    .st-key-bulk_infra_scan [data-testid="stRadio"] label:has(input:checked) p,
    .st-key-tech_logs_tabs [data-testid="stRadio"] [role="radiogroup"] label:has(input:checked) p {
        color:#ffffff !important; font-weight:700 !important; letter-spacing:.15px !important;
    }

    [data-testid="stIconMaterial"],
    [class*="material-symbols"],
    span[data-testid="stIconMaterial"],
    .stTextInput button span,
    section[data-testid="stFileUploaderDropzone"] [data-testid="stIconMaterial"],
    section[data-testid="stFileUploaderDropzone"] span {
        font-family: 'Material Symbols Rounded', 'Material Icons' !important;
        font-weight: normal !important;
        font-style: normal !important;
        letter-spacing: normal !important;
        text-transform: none !important;
        display: inline-block !important;
        white-space: nowrap !important;
        word-wrap: normal !important;
        direction: ltr !important;
    }
    
    .stTextInput div[data-baseweb="input"] button {
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
    }

    section[data-testid="stFileUploaderDropzone"] button {
        min-width: 150px !important;
        height: 40px !important;
        padding: 0 22px !important;
        border-radius: var(--r-sm) !important;
        border: 1px solid var(--line-strong) !important;
        background: var(--panel-2) !important;
        color: var(--text) !important;
        font-family: 'Inter', system-ui, sans-serif !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        text-transform: none !important;
        letter-spacing: 0.2px !important;
        box-shadow: none !important;
        transition: border-color 0.15s var(--ease), background 0.15s var(--ease) !important;
    }

    section[data-testid="stFileUploaderDropzone"] button:hover {
        background: var(--panel-3) !important;
        border-color: var(--teal) !important;
        color: #ffffff !important;
        box-shadow: none !important;
    }

    section[data-testid="stFileUploaderDropzone"] button:active {
        background: var(--panel-3) !important;
        transform: translateY(1px) !important;
        border-color: var(--line-strong) !important;
    }

    /* ================= NEW DASHBOARD-STYLE UI SHELL ================= */
    .topbar-shell {
        display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:18px;
        background:linear-gradient(180deg,#161c26 0%,#0d1219 100%);
        border:1px solid #263140; border-radius:var(--r-lg);
        padding:28px 34px; margin-top:8px; margin-bottom:18px;
        box-shadow:0 16px 40px rgba(0,0,0,.32), inset 0 1px 0 rgba(255,255,255,.05);
        position:relative; overflow:hidden;
    }
    /* Network/globe background graphic (image itself set in a small
       separate <style> tag right before this markup, since the big
       stylesheet this rule lives in is a raw, non-interpolated string --
       see _TOPBAR_MAP_SRC). Faded out toward the left with a mask so the
       banner text on the left stays fully legible and the graphic only
       reads on the right, same balance as the reference picture. */
    .topbar-shell::after {
        content:""; position:absolute; inset:0;
        background-repeat:no-repeat; background-position:right center; background-size:cover;
        -webkit-mask-image:linear-gradient(90deg, transparent 0%, rgba(0,0,0,.85) 42%, rgba(0,0,0,1) 100%);
        mask-image:linear-gradient(90deg, transparent 0%, rgba(0,0,0,.85) 42%, rgba(0,0,0,1) 100%);
        pointer-events:none; z-index:0;
    }
    .topbar-brand, .topbar-status-wrap {position:relative; z-index:1;}
    .topbar-brand {display:flex; align-items:center; gap:20px;}
    /* Logo + name are the whole point of this banner, so both got a real
       size increase (34px logo -> 64px, 23px title -> 34px) instead of
       sharing the header row with an unrelated, non-functional search
       box. That search input never filtered anything (see the removed
       .st-key-topbar_utility rule this replaced) -- it just sat above the
       banner as clutter with no real feature behind it, so it's gone
       rather than kept and restyled. The bell + account chip it used to
       carry are folded into this same shell instead (top-right), so
       there's one prominent header, not two stacked bars. */
    .topbar-logo {
        width:64px; height:64px; flex:0 0 64px; border-radius:16px;
        background:radial-gradient(circle at 35% 30%, rgba(99,102,241,.22), transparent 70%);
        box-shadow:0 0 0 1px rgba(99,102,241,.28), 0 8px 20px rgba(0,0,0,.3);
        display:flex; align-items:center; justify-content:center; padding:8px;
    }
    .topbar-logo img {width:100%; height:100%; object-fit:contain; display:block;}
    .topbar-actions {display:flex; align-items:center; justify-content:flex-end; gap:10px; margin-bottom:8px;}
    .topbar-icon-btn {
        width:36px; height:36px; border-radius:50%;
        display:flex; align-items:center; justify-content:center;
        background:linear-gradient(180deg,#0d1420,#0a0f18); border:1px solid #1e3350;
        color:#9fb4cc; cursor:pointer; transition:border-color .18s var(--ease), color .18s var(--ease);
        padding:0;
    }
    .topbar-icon-btn:hover {border-color:var(--cyan); color:#eaf1ff;}
    .topbar-account-chip {
        display:flex; align-items:center; gap:8px;
        background:linear-gradient(180deg,#0d1420,#0a0f18); border:1px solid #1e3350;
        border-radius:999px; padding:5px 14px 5px 5px;
        max-width:230px;
    }
    .topbar-account-avatar {
        width:26px; height:26px; border-radius:50%; flex:0 0 26px;
        display:flex; align-items:center; justify-content:center;
        background:var(--brand-gradient); color:#fff; font-weight:800; font-size:12px;
    }
    .topbar-account-email {
        font-size:12.5px; color:var(--text); font-weight:600;
        overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
    }
    .topbar-account-chevron {color:#5b7690; flex:0 0 13px; margin-left:2px; transition:color .18s var(--ease), transform .18s var(--ease);}
    .topbar-account-chip:hover .topbar-account-chevron {color:#9fb4cc;}
    .topbar-kicker {font-size:11.5px; font-weight:800; letter-spacing:1.8px; color:var(--teal); text-transform:uppercase; margin-bottom:5px;}
    .topbar-title {font-size:34px; font-weight:900; letter-spacing:.2px; color:#eef1f5; line-height:1.2; text-shadow:0 2px 14px rgba(0,0,0,.35);}
    .topbar-subtitle {font-size:12.5px; color:#93abc3; line-height:1.5; margin-top:6px;}
    .topbar-status-wrap {display:flex; flex-direction:column; align-items:flex-end; gap:9px;}
    .topbar-status-pill {
        display:flex; align-items:center; gap:8px; font-size:11.5px; color:#b9d2c3; white-space:nowrap;
        background:rgba(111,174,140,.09); border:1px solid rgba(111,174,140,.25); border-radius:999px;
        padding:6px 14px; order:-1;
    }
    .topbar-status-dot {width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 6px rgba(111,174,140,.6);display:inline-block; animation:sbPulse 2.2s ease-in-out infinite;}
    .topbar-status-online {color:#b9d2c3; font-weight:650;}
    .topbar-status-time {font-size:10.5px; color:#5b7690; letter-spacing:.3px; white-space:nowrap;}

    /* ============ SIDEBAR — full redesign ============
       A shared "breathing" pulse keyframe for every live-status dot in the
       sidebar (brand session dot, system-status dot) so they read as one
       consistent "this is live" language rather than a static icon. */
    @keyframes sbPulse {0%,100%{opacity:1; box-shadow:0 0 6px rgba(47,206,135,.6);} 50%{opacity:.55; box-shadow:0 0 14px rgba(47,206,135,.9);}}

    .sidebar-brand-v2 {padding:2px 6px 14px; border-bottom:1px solid #452760; margin-bottom:10px;}
    .brand-row {display:flex; align-items:center; gap:10px;}
    .brand-mark {
        width:34px; height:34px; flex:0 0 34px; border-radius:var(--r-md);
        display:flex; align-items:center; justify-content:center; font-size:17px;
        background:linear-gradient(180deg,#12233a,#0d1c2c); border:1px solid #4a2a63;
        box-shadow:0 0 0 1px rgba(178,91,240,.20), 0 6px 14px rgba(0,0,0,.3), inset 0 1px 0 rgba(255,255,255,.06);
    }
    /* Real logo variant: same footprint/frame as the old plain icon mark
       above, just filled with the actual brand image instead of an SVG
       glyph, so swapping it in didn't require touching the surrounding
       layout at all. */
    .brand-mark--logo {padding:2px; overflow:hidden;}
    .brand-mark--logo img {width:100%; height:100%; object-fit:contain; border-radius:8px;}
    .brand-text .name {color:var(--teal); font-weight:900; font-size:16.5px; letter-spacing:1.2px; line-height:1.15;}
    .brand-text .role {color:#6f8aa5; font-size:9px; letter-spacing:1px; text-transform:uppercase; margin-top:2px;}
    .brand-meta {display:flex; align-items:center; gap:6px; margin-top:12px; font-size:9.5px; color:#5b7690; letter-spacing:.4px;}
    .brand-dot {width:6px; height:6px; border-radius:50%; background:var(--green); box-shadow:0 0 8px rgba(47,206,135,.75); display:inline-block; animation:sbPulse 2.2s ease-in-out infinite;}

    /* Section headers: a small monospace index tag + label + a gradient
       rule that fills the remaining width, so each group reads like a
       labelled divider in a real product sidebar instead of floating text. */
    .sidebar-group-label {
        display:flex !important; align-items:center !important; gap:7px !important;
        color:#5b7690 !important; font-size:10px !important; font-weight:800 !important;
        letter-spacing:1.6px !important; text-transform:uppercase !important; margin:18px 4px 12px !important;
    }
    /* The selected nav button's glow/gradient used to sit close enough to
       the group-label's divider line above it that it visually crossed
       into it (almost no breathing room between the "01 THREAT
       OPERATIONS" rule and the first pill below). The extra bottom-margin
       above is the fix -- simple and guaranteed to apply, rather than a
       sibling-selector that depends on exact DOM nesting Streamlit
       doesn't guarantee. */
    .sidebar-group-label .grp-index {
        color:var(--teal); font:900 9px/1 "Consolas","Cascadia Code",monospace; letter-spacing:0;
        border:1px solid #4a2a63; border-radius:6px; padding:1.5px 4px; background:#0a1826;
    }
    .sidebar-group-label:after {content:""; flex:1; height:1px; background:linear-gradient(90deg,#4a2a63,transparent);}
    /* Per-group accent: Threat Operations (teal, the app's core action),
       Visualization (green, matches the map/geo panels), Intelligence
       (violet, matches the AI Copilot & correlation graph), Security
       (rose, a distinct warning-adjacent hue not used elsewhere in the
       sidebar), System (neutral slate -- settings/about, deliberately
       the quietest one). */
    .sidebar-group-teal .grp-index {color:var(--teal) !important; border-color:rgba(59,130,246,.4) !important;}
    .sidebar-group-teal:after {background:linear-gradient(90deg,rgba(59,130,246,.4),transparent) !important;}
    .sidebar-group-green .grp-index {color:#7be0a8 !important; border-color:rgba(47,206,135,.4) !important;}
    .sidebar-group-green:after {background:linear-gradient(90deg,rgba(47,206,135,.4),transparent) !important;}
    .sidebar-group-violet .grp-index {color:#d9c7ff !important; border-color:rgba(178,91,240,.4) !important;}
    .sidebar-group-violet:after {background:linear-gradient(90deg,rgba(178,91,240,.4),transparent) !important;}
    .sidebar-group-rose .grp-index {color:#ffb0c0 !important; border-color:rgba(255,90,130,.4) !important;}
    .sidebar-group-rose:after {background:linear-gradient(90deg,rgba(255,90,130,.4),transparent) !important;}
    .sidebar-group-slate .grp-index {color:#9db3c8 !important; border-color:#2c4a60 !important;}
    .sidebar-group-slate:after {background:linear-gradient(90deg,#2c4a60,transparent) !important;}

    [data-testid="stSidebar"] .stButton button {
        position:relative !important;
        justify-content:flex-start !important; text-align:left !important;
        background:transparent !important; border:1px solid transparent !important;
        box-shadow:none !important; color:#a9bed3 !important; font-weight:600 !important;
        text-transform:none !important; letter-spacing:normal !important;
        padding:8px 10px 8px 15px !important; min-height:38px !important; width:100% !important;
        border-radius:var(--r-md) !important;
        transition:background .2s var(--ease), border-color .2s var(--ease), color .2s var(--ease),
                   transform .15s var(--ease), padding-left .2s var(--ease) !important;
    }
    /* Streamlit wraps the button label in its own inner div/p, which ships
       with its own centered flex layout -- overriding justify-content on
       the <button> alone doesn't reach it, so the label still renders
       centered. Force the same left alignment on that inner wrapper. */
    [data-testid="stSidebar"] .stButton button > div {
        width:100% !important; display:flex !important; justify-content:flex-start !important;
    }
    [data-testid="stSidebar"] .stButton button p {
        text-align:left !important; width:100% !important;
    }
    /* A left accent bar as a pseudo-element (not a border) so it animates
       in/out on hover/select without ever nudging the row's own layout. */
    [data-testid="stSidebar"] .stButton button::before {
        content:""; position:absolute; left:0; top:7px; bottom:7px; width:3px; border-radius:2px;
        background:var(--teal); opacity:0; transform:scaleY(.3);
        transition:opacity .2s var(--ease), transform .2s var(--ease);
    }
    [data-testid="stSidebar"] .stButton button:hover {
        background:rgba(178,91,240,.14) !important; border-color:#4a2a63 !important; color:#eaf6ff !important;
        padding-left:18px !important;
    }
    [data-testid="stSidebar"] .stButton button:hover::before {opacity:.5; transform:scaleY(.7);}
    [data-testid="stSidebar"] .stButton button:active {transform:scale(.985) !important; transition-duration:.08s !important;}
    [data-testid="stSidebar"] .stButton button[kind="primary"] {
        background:linear-gradient(90deg,rgba(178,91,240,.22),rgba(178,91,240,.02)) !important;
        border:1px solid #4a2a63 !important;
        color:#eefaff !important; box-shadow:inset 0 0 0 1px rgba(178,91,240,.12) !important;
        padding-left:18px !important;
    }
    [data-testid="stSidebar"] .stButton button[kind="primary"]::before {
        opacity:1 !important; transform:scaleY(1) !important; box-shadow:0 0 8px rgba(178,91,240,.7);
    }
    /* Uniform, tight vertical rhythm between sidebar nav rows. Streamlit's
       own default gap between stacked element-containers is larger and can
       read as uneven next to the primary (active) button's glow, which
       visually "pushes" the row below it further away even though the
       real spacing is identical. Pin the gap explicitly so every row -- 
       active or not -- sits the same distance from its neighbours. */
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
        gap: 0.15rem !important;
    }
    [data-testid="stSidebar"] .stButton {
        margin-bottom: 0 !important;
    }
    /* System-status widget: a small two-tile "health" card instead of a
       plain list of rows, with its own pulse dot and hover lift so it
       reads as a live product widget, not a static footer. */
    .sidebar-status-card-v2 {
        margin-top:16px; padding:13px 13px 11px; border:1px solid #1b465a; position:relative; overflow:hidden;
        background:linear-gradient(180deg,#101f33 0%,#0c1a2a 100%); border-radius:var(--r-lg);
        box-shadow:0 8px 20px rgba(0,0,0,.2), inset 0 0 20px rgba(59,130,246,.02);
        transition:border-color .2s var(--ease), box-shadow .2s var(--ease);
    }
    .sidebar-status-card-v2:hover {border-color:#2c5877; box-shadow:0 10px 24px rgba(0,0,0,.26), inset 0 0 26px rgba(59,130,246,.04);}
    .sidebar-status-card-v2:before {content:""; position:absolute; left:0; top:0; bottom:0; width:3px; background:linear-gradient(180deg,var(--green),transparent 80%);}
    .ssc-head {display:flex; align-items:center; gap:7px; margin-bottom:10px;}
    .ssc-pulse {width:7px; height:7px; border-radius:50%; background:var(--green); box-shadow:0 0 10px rgba(47,206,135,.8); animation:sbPulse 2.2s ease-in-out infinite; flex:0 0 7px;}
    .ssc-title {font-size:10px; font-weight:800; letter-spacing:1.2px; color:#dff7ff; text-transform:uppercase;}
    .ssc-grid {display:grid; grid-template-columns:1fr 1fr; gap:8px;}
    .ssc-tile {background:#081722; border:1px solid #16334a; border-radius:var(--r-md); padding:8px 9px; transition:border-color .2s var(--ease), transform .15s var(--ease);}
    .ssc-tile:hover {border-color:var(--teal); transform:translateY(-1px);}
    .ssc-tile-value {font-size:17px; font-weight:800; color:var(--teal); font-variant-numeric:tabular-nums; line-height:1.2;}
    .ssc-tile-label {font-size:9px; color:#7d94ad; margin-top:2px; letter-spacing:.3px;}
    .ssc-tile-alert {border-color:#4a2130;}
    .ssc-tile-alert:hover {border-color:#ff8a94;}
    .ssc-tile-alert .ssc-tile-value {color:#ff9f9f;}
    .ssc-foot {margin-top:10px; font-size:9px; color:#5b7690; letter-spacing:.3px; border-top:1px solid #142a3c; padding-top:7px;}

    /* Severity-coded tile variants for the bulk-scan dock -- same .ssc-tile
       shell, colored via the shared --sev-* palette so a glance at the
       sidebar reads the same severity language as the rest of the app. */
    .ssc-tile-critical {border-color:rgba(255,71,87,.35);}
    .ssc-tile-critical:hover {border-color:var(--sev-critical);}
    .ssc-tile-critical .ssc-tile-value {color:var(--sev-critical);}
    .ssc-tile-high {border-color:rgba(255,159,67,.35);}
    .ssc-tile-high:hover {border-color:var(--sev-high);}
    .ssc-tile-high .ssc-tile-value {color:var(--sev-high);}
    .ssc-tile-medium {border-color:rgba(244,201,93,.35);}
    .ssc-tile-medium:hover {border-color:var(--sev-medium);}
    .ssc-tile-medium .ssc-tile-value {color:var(--sev-medium);}
    .ssc-tile-low {border-color:rgba(47,206,135,.35);}
    .ssc-tile-low:hover {border-color:var(--sev-low);}
    .ssc-tile-low .ssc-tile-value {color:var(--sev-low);}

    /* Compact right-dock summary widgets: st.metric's own card padding
       runs ~2-3x taller than these, and stacking Threat + Investigation
       Summary + Top Threat Signal Breakdown on top of Synapse Copilot in
       a max-height sticky dock needs every one of those rows back, or the
       dock scrolls internally before you ever reach the Copilot panel.

       v2: given a left accent spine (same device as .acq-panel/.stage-card
       elsewhere in the app) and a visible gap before/after so each
       section (KEY METRICS, INVESTIGATION SUMMARY, TOP THREAT SIGNAL
       BREAKDOWN) reads as its own distinct card instead of a flat strip
       glued to the one above it. */
    .panel-card-head {
        display:flex; justify-content:space-between; align-items:center;
        padding:12px 16px; border:1px solid #193a50; border-left:3px solid var(--cyan);
        border-bottom:none;
        background:linear-gradient(180deg,#0e2233,#0a1d2b); border-radius:var(--r-lg) var(--r-lg) 0 0;
        color:#5fdfff; font:800 11px/1.2 monospace; letter-spacing:1.2px;
        margin-top:26px !important;
    }
    .panel-card-head:first-child { margin-top:0 !important; }
    .panel-card-body {
        border:1px solid #193a50; border-left:3px solid var(--cyan); border-top:none;
        border-radius:0 0 var(--r-lg) var(--r-lg); padding:16px 16px 17px; background:#081522;
        box-shadow:var(--shadow-sm);
        line-height:2;
    }
    .panel-card-body b { color:#dbe6f2; font-weight:700; }

    /* Color variants for .panel-card-head/.panel-card-body -- section
       headers across the dashboard (Key Metrics, Investigation Summary,
       Top Threat Signal Breakdown, Globe-Scan, Network Correlation...)
       previously all shared the same cyan spine regardless of what they
       actually showed, so a stacked dock of them read as one long cyan
       strip. Add class="panel-card-head panel-card-head-violet" (etc.) at
       the call site to give a section its own identity color while
       keeping the same card shape/spacing as every other panel. */
    .panel-card-head-violet, .panel-card-body-violet {border-left-color:var(--violet) !important;}
    .panel-card-head-violet {color:#d9c7ff !important; background:linear-gradient(180deg,#20163a,#170f2a) !important; border-color:#3a2a5c !important;}
    .panel-card-body-violet {border-color:#3a2a5c !important;}
    .panel-card-head-amber, .panel-card-body-amber {border-left-color:var(--amber) !important;}
    .panel-card-head-amber {color:#ffdf9e !important; background:linear-gradient(180deg,#332510,#241a0b) !important; border-color:#5c4520 !important;}
    .panel-card-body-amber {border-color:#5c4520 !important;}
    .panel-card-head-green, .panel-card-body-green {border-left-color:var(--green) !important;}
    .panel-card-head-green {color:#a4f0c9 !important; background:linear-gradient(180deg,#0e2a1e,#0a1f17) !important; border-color:#1e4a35 !important;}
    .panel-card-body-green {border-color:#1e4a35 !important;}

    /* The right dock (border=True container) previously relied on
       Streamlit's own default inner padding, which reads tight next to
       the generous spacing everywhere else in the app -- give it real
       breathing room on every side, and soften the dock's square outer
       edge into the same rounded-card language the rest of the UI uses. */
    .st-key-right_summary_pane, .st-key-bulk_command_dock {
        padding:22px 18px 26px !important;
        border-radius:var(--r-lg) 0 0 var(--r-lg) !important;
    }
    @media (max-width: 900px) {
        .st-key-right_summary_pane, .st-key-bulk_command_dock { border-radius:var(--r-lg) var(--r-lg) 0 0 !important; }
    }
    
    .threattype-row {display:flex; align-items:center; gap:10px; margin:12px 0; font-size:12px; color:#c9d8e7;}
    .threattype-row .bar-track {flex:1; height:7px; border-radius:5px; background:#0d1f30; overflow:hidden;}
    .threattype-row .bar-fill {height:100%; border-radius:5px;}
    .threattype-row .pct {width:38px; text-align:right; color:#8fa5bd; font-size:11px;}

    .copilot-header {display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;}
    .copilot-title {font-weight:800; color:#eaf6ff; font-size:13px;}
    .copilot-active {font-size:9px; color:var(--green); font-weight:800; letter-spacing:1px; display:inline-flex; align-items:center;}
    .copilot-msg {background:#0a1826; border:1px solid #1c3a52; border-radius:var(--r-md); padding:10px 12px; font-size:12.5px; color:#c9d8e7; line-height:1.5; margin-bottom:9px;}
    .copilot-msg-user {background:linear-gradient(180deg,#16273c,#101f30); border:1px solid #2a4a6a; border-radius:var(--r-md); padding:9px 12px; font-size:12.5px; color:#eaf6ff; line-height:1.5; margin:0 0 9px 20px;}
    .copilot-caption {font:700 10.5px/1.4 monospace; color:#6f8aa3; margin:2px 0 10px 0;}

    /* Compact one-line "scan complete" status that replaces a lingering
       full-width progress bar once a bulk scan finishes -- pairs with a
       small "new upload" action instead of leaving a static 100% bar on
       screen (mirrors the single-line confirmation the Live IMAP flow
       already uses). */
    .st-key-scan_status_bar {
        position:relative; overflow:hidden;
        background:linear-gradient(135deg, rgba(47,206,135,.08), var(--panel) 65%) !important;
        border:1px solid rgba(47,206,135,.28) !important; border-left:3px solid var(--green) !important;
        border-radius:var(--r-lg) !important; padding:12px 18px !important; margin:6px 0 14px 0 !important;
        box-shadow:0 10px 24px rgba(0,0,0,.18) !important;
    }
    .st-key-scan_status_bar [data-testid="stHorizontalBlock"] {align-items:center !important;}
    .scan-compact-status {display:flex; align-items:center; gap:9px; font:700 13px/1.4 "Inter","Segoe UI",sans-serif; color:#e4f3ea;}
    .scan-compact-status b {color:#eef5ff;}

    /* Copilot panel container -- a real st.container(border=True, key=...)
       styled to match the .copilot-header/.copilot-msg family above it, so
       native widgets (buttons, the command input) sit genuinely inside the
       box instead of an HTML div spliced across separate st.markdown calls. */
    .st-key-copilot_panel {
        border:1px solid #223c58 !important; border-top:none !important;
        border-radius:0 0 var(--r-lg) var(--r-lg) !important;
        background:linear-gradient(180deg,#0d1c2c,#091623) !important;
        padding:16px 16px 18px 16px !important;
    }
    /* The quick-action row and the command input were sitting flush
       against the message bubble above them with no gap at all -- give
       each of the copilot's three stacked blocks (message, quick
       actions, command input) real separation instead of reading as one
       dense paragraph-and-buttons blob. */
    .st-key-copilot_quick_actions { margin-top:14px !important; }
    .st-key-copilot_command_row { margin-top:12px !important; }
    .st-key-copilot_quick_actions .stButton button {
        font-size:10.5px !important; padding:6px 6px !important; min-height:34px !important;
        white-space:normal !important; line-height:1.2 !important;
    }
    .st-key-copilot_command_row .stTextInput input {
        background:#0a1826 !important; border-color:#1c3a52 !important; font-size:12.5px !important;
    }
    .st-key-copilot_command_row .stFormSubmitButton button {
        min-height:38px !important; padding:0 !important; font-weight:900 !important;
    }

    /* Bulk infrastructure scan -- an always-open section directly under the
       Origin & Route map (it used to hide inside a collapsed expander much
       further down the page, which made the VPN / Tor scans hard to find). */
    .st-key-bulk_infra_scan {
        margin-top:14px !important;
        border:1px solid var(--line-strong) !important;
        border-left:3px solid var(--teal) !important;
        border-radius:var(--r-lg) !important;
        background:linear-gradient(180deg,#0f1622 0%,#0a0f18 100%) !important;
        padding:14px 18px 16px 18px !important;
    }
    .infra-scan-head {margin-bottom:6px;}
    .infra-scan-eyebrow {font:800 10px/1 monospace; letter-spacing:1.4px; color:var(--teal); text-transform:uppercase;}
    .infra-scan-title {margin-top:8px; color:#f2f8ff; font-size:21px; font-weight:800; letter-spacing:.2px;}
    .infra-scan-sub {margin-top:5px; color:var(--muted); font-size:13px; line-height:1.55;}

    /* Bulk Infrastructure Scan segmented control -- built on st.radio, the
       same "pill" pattern the top nav uses (see .st-key-topnav): full-width
       equal segments, plain text (no per-option colour dot -- those were
       adding visual noise and were also colliding with a native radio
       circle that CSS wasn't fully suppressing), flat single-accent active
       state. Minimal and consistent with every other tab strip in the app. */
    .st-key-bulk_infra_scan [data-testid="stRadio"] > div {
        display:flex !important; flex-wrap:nowrap !important; gap:8px !important;
        background:linear-gradient(180deg,#081726,#060f1a) !important;
        border:1px solid #1c3a55 !important;
        padding:6px !important;
        border-radius:var(--r-md) !important;
    }
    .st-key-bulk_infra_scan [data-testid="stRadio"] label {
        flex:1 1 0 !important; justify-content:center !important;
        display:flex !important; align-items:center !important;
        text-align:center !important; white-space:nowrap !important;
        min-height:24px !important;
        font-size:13px !important; font-weight:700 !important; letter-spacing:.2px !important;
        padding:12px 16px !important; border-radius:9px !important;
        border:1px solid transparent !important;
        transition:background .18s var(--ease), box-shadow .18s var(--ease), border-color .18s var(--ease) !important;
    }
    .st-key-bulk_infra_scan [data-testid="stRadio"] label p {
        font-size:13px !important; font-weight:700 !important; white-space:nowrap !important;
    }
    /* The Scan buttons themselves used to be identical generic teal
       primary buttons in both tabs -- functionally fine but visually
       interchangeable, giving no sense that one drives a VPN/datacenter
       check and the other a Tor check. Recolored per button key to match
       that view's own dot colour (cyan for VPN/Datacenter, violet for
       Tor), still clearly a "primary action" button, just no longer a
       copy-paste twin of the other view's. */
    .st-key-run_vpn_bulk_scan button[kind^="primary"] {
        background:linear-gradient(180deg,#123a5c,#0c283f) !important;
        border:1px solid rgba(59,130,246,.55) !important;
        color:#eaf6ff !important;
        box-shadow:0 1px 2px rgba(0,0,0,.4), 0 8px 22px rgba(59,130,246,.22), inset 0 1px 0 rgba(255,255,255,.10) !important;
    }
    .st-key-run_vpn_bulk_scan button[kind^="primary"]:hover {
        box-shadow:0 0 0 1px rgba(59,130,246,.35), 0 10px 26px rgba(59,130,246,.32), inset 0 1px 0 rgba(255,255,255,.16) !important;
    }
    .st-key-run_tor_bulk_scan button[kind^="primary"] {
        background:linear-gradient(180deg,#291c47,#190f2b) !important;
        border:1px solid rgba(178,91,240,.55) !important;
        color:#f1ecff !important;
        box-shadow:0 1px 2px rgba(0,0,0,.4), 0 8px 22px rgba(178,91,240,.22), inset 0 1px 0 rgba(255,255,255,.10) !important;
    }
    .st-key-run_tor_bulk_scan button[kind^="primary"]:hover {
        box-shadow:0 0 0 1px rgba(178,91,240,.35), 0 10px 26px rgba(178,91,240,.32), inset 0 1px 0 rgba(255,255,255,.16) !important;
    }
    /* Live-status chip shown above each Scan button (freshness + source
       count) -- filled in with real fetch results after each scan run. */
    .infra-scan-livebar {
        display:flex; align-items:center; gap:8px; margin:2px 0 12px 0;
        font:600 11.5px/1 "Inter", monospace; color:var(--muted);
        letter-spacing:.2px;
    }
    .infra-scan-livebar .dot {
        width:6px; height:6px; border-radius:50%; background:var(--green);
        box-shadow:0 0 6px 1px rgba(47,206,135,.7); flex:none;
    }
    .infra-scan-livebar.stale .dot {background:var(--amber); box-shadow:0 0 6px 1px rgba(242,169,60,.7);}

    /* Technical Logs & Antivirus segmented control -- same st.radio "pill"
       pattern as the top nav and the bulk infra scan above. Plain text
       pills, no per-option colour dot (dropped along with bulk infra
       scan's, for the same reason: minimal, one consistent look, and one
       less thing colliding with the native radio circle).
       Scoped to [role="radiogroup"] specifically -- the earlier bare
       "label" selector also matched the widget's own group label (the
       hidden "Technical Logs & Antivirus view" text from
       label_visibility="collapsed"), and its `display:flex !important`
       was overriding Streamlit's own hiding rule, re-displaying that
       label as its own bordered box above the two real pills. */
    .st-key-tech_logs_tabs [data-testid="stWidgetLabel"] {
        display:none !important;
    }
    .st-key-tech_logs_tabs [data-testid="stRadio"] > div {
        display:flex !important; flex-wrap:nowrap !important; gap:8px !important;
        background:linear-gradient(180deg,#0d1420,#0a0f18) !important;
        border:1px solid #1e3350 !important;
        padding:6px !important;
        border-radius:var(--r-md) !important;
    }
    .st-key-tech_logs_tabs [data-testid="stRadio"] [role="radiogroup"] label {
        text-align:center !important;
        text-transform:none !important;
        display:flex !important; align-items:center !important; justify-content:center !important;
        white-space:nowrap !important; min-height:20px !important;
        font-size:13.5px !important;
        font-weight:700 !important;
        letter-spacing:.2px !important;
        padding:11px 20px !important;
        border-radius:9px !important;
        border:1px solid transparent !important;
        transition:background .18s var(--ease), box-shadow .18s var(--ease), border-color .18s var(--ease) !important;
    }
    .st-key-tech_logs_tabs [data-testid="stRadio"] [role="radiogroup"] label p {
        font-size:13.5px !important; font-weight:700 !important; white-space:nowrap !important;
    }

    /* Rich email-results grid -- replaces st.dataframe's canvas-rendered
       ProgressColumn/plain verdict text (which, like every st.dataframe
       in this app, can't pick up the dark theme) with real HTML: a
       coloured bar + coloured pill, both keyed off the same severity
       colours the map markers already use, so LOW/MEDIUM/HIGH/CRITICAL
       mean the same colour everywhere in the app. */
    .email-score-cell {display:flex; align-items:center; gap:10px; min-width:130px;}
    .email-score-track {flex:1; height:6px; border-radius:4px; background:#121f30; overflow:hidden;}
    .email-score-fill {height:100%; border-radius:4px; transition:width .3s var(--ease);}
    .email-score-num {font-variant-numeric:tabular-nums; font-weight:750; font-size:12.5px; min-width:34px; text-align:right; color:#dfeaf4;}
    .verdict-pill {display:inline-block; padding:3px 11px; border-radius:20px; font-size:11px; font-weight:800; letter-spacing:.5px; text-transform:uppercase; white-space:nowrap;}
    .ip-chip {font-family:'JetBrains Mono','SFMono-Regular',Consolas,monospace; font-size:12.5px; color:#9fd6f5; background:rgba(59,130,246,.09); padding:2px 8px; border-radius:6px; white-space:nowrap;}
    .row-chip {font-family:'JetBrains Mono','SFMono-Regular',Consolas,monospace; font-size:12px; color:#7c93ac; font-weight:700;}

    /* ------------------------------------------------------------------
       DASHBOARD SECTION HEADER -- replaces the bare st.caption("MIDDLE
       PREVIEW PANE") label, which rendered as a small gray debug-style
       line with no visual weight, out of step with every other titled
       section in the app. Same family as .panel-card-head/.right-dock-title
       (cyan monospace eyebrow) but sized for a top-level section rather
       than a nested card, plus a bottom rule so it reads as a real
       divider between the page header/controls above and the map +
       correlation graph content below. */
    .dash-section-title {
        display:flex; align-items:center; gap:9px;
        margin:18px 0 10px !important;
        padding-bottom:9px;
        border-bottom:1px solid var(--line);
        color:#5fdfff; font:800 12px/1.3 monospace; letter-spacing:1.4px; text-transform:uppercase;
    }
    .dash-section-title .dash-section-dot {
        width:7px; height:7px; border-radius:50%; background:var(--cyan);
        box-shadow:0 0 10px rgba(59,130,246,.75); flex:0 0 7px;
    }
    .dash-section-title .dash-section-sub {
        color:#6f8aa3; font-weight:600; letter-spacing:.3px; text-transform:none; font-size:11px;
    }

    /* Breathing room between the map-view radio toggle (All senders / By
       email) and the GLOBE-SCAN card header sitting right underneath it --
       previously flush against each other and read as one crowded block. */
    .st-key-dash_map_mode [role="radiogroup"] { gap:8px !important; }

    /* Right-hand THREAT SUMMARY dock header: vertically center the title
       against the close (X) button instead of relying on default column
       baseline alignment, and give the row a touch more breathing room so
       the two don't read as jammed against the card's top edge. */
    .st-key-right_summary_pane [data-testid="stHorizontalBlock"]:first-of-type {
        align-items:center !important;
        margin-bottom:12px !important;
    }
    .right-dock-title { padding:2px 0 !important; }

    /* Synapse Copilot quick-action row (FULL REPORT / LAST WEEK / NOMIC
       MATCH): force an even 3-up grid instead of letting buttons wrap
       into a ragged 2+1 layout at narrower sidebar widths. */
    .st-key-copilot_quick_actions [data-testid="stHorizontalBlock"] {
        flex-wrap:nowrap !important; gap:6px !important;
    }
    .st-key-copilot_quick_actions [data-testid="column"] { min-width:0 !important; }

    /* KEY METRICS 2x2 grid inside the right dock: tighten the gap between
       metric cards so all four (Threat Score / ML Phishing / Auth Pass /
       Anomalies) read as one compact cluster under their header instead
       of floating with uneven whitespace. */
    .st-key-right_summary_pane div[data-testid="stMetric"] { padding:11px 12px !important; }
    .st-key-right_summary_pane [data-testid="stHorizontalBlock"] { gap:8px !important; }

    /* Group the four KEY METRICS tiles (Threat Score / ML Phishing /
       Auth Pass / Anomalies) inside the same bordered-card shell the
       Investigation Summary and Top Threat Signal Breakdown sections
       use, so all three sit as clearly separated cards of equal weight
       instead of one loose grid floating free next to two boxed ones --
       that inconsistency was a big part of the "congested" feel: some
       content had a visible boundary, some didn't. Also gives the two
       metric rows real breathing room between them instead of sitting
       flush against each other. */
    .st-key-right_dock_metrics_body, .st-key-dd_dock_metrics_body {
        border:1px solid #193a50; border-left:3px solid var(--cyan); border-top:none;
        border-radius:0 0 var(--r-lg) var(--r-lg); padding:16px 14px 4px !important; background:#081522;
        box-shadow:var(--shadow-sm);
    }
    .st-key-right_dock_metrics_body [data-testid="stHorizontalBlock"],
    .st-key-dd_dock_metrics_body [data-testid="stHorizontalBlock"] {
        gap:12px !important; margin-bottom:12px !important;
    }

    /* Origin & Correlation card (map + graph, side by side): give the
       generic bordered container real presence -- rounded corners, a
       touch of depth, and a hover-quiet static look consistent with
       .stage-card/.acq-panel -- instead of Streamlit's flat thin-gray
       default border every other unstyled st.container(border=True)
       still uses. */
    .st-key-dash_map_graph_card {
        border:1px solid var(--line-strong) !important;
        border-radius:var(--r-lg) !important;
        background:linear-gradient(180deg,var(--panel) 0%,var(--panel-3) 100%) !important;
        box-shadow:var(--shadow-md) !important;
        padding:24px !important;
    }
    /* The GLOBE-SCAN / NETWORK INFRASTRUCTURE card headers inside it get
       the same left-accent treatment as the right-dock cards, so the two
       halves of the dashboard read as one consistent card system. */
    .st-key-dash_map_graph_card .panel-card-head { margin-top:0 !important; }
    .st-key-dash_map_graph_card .panel-card-head span:last-child {
        font:700 10px/1.2 'Inter',sans-serif; letter-spacing:.3px; color:#8fa5bd; text-transform:none;
    }
    /* The map-view radio toggle sits directly above the GLOBE-SCAN card
       on the left side only -- give it real clearance so it doesn't read
       as glued to the card header underneath it, matching the breathing
       room the right dock now has between its own sections. */
    .st-key-dash_map_mode { margin-bottom:16px !important; }

    /* =================================================================
       DESIGN POLISH LAYER (last on purpose, CSS only)
       One pass that pulls the leftover navy hard-codes (#06101c, #0b1828,
       #102238, #203b57 ...) onto the same graphite tokens the rest of the
       app already uses, and gives every component the same radius, border,
       hover and focus behavior. Severity colors, layout, widths and
       behavior are untouched.
       ================================================================= */
    :root {
        --ring: 0 0 0 3px rgba(59,130,246,.18);
        --surface-sunken: var(--panel-3);
    }
    .stApp {-webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; text-rendering:optimizeLegibility;}
    ::selection {background:rgba(59,130,246,.35); color:#ffffff;}

    /* Chrome: sidebar and scrollbars join the graphite palette. */
    [data-testid="stSidebar"], [data-testid="stSidebar"] > div {background:var(--panel-3) !important;}
    ::-webkit-scrollbar-track {background:var(--panel-3);}
    ::-webkit-scrollbar-thumb {background:var(--line-strong); border:2px solid var(--panel-3); border-radius:8px;}
    ::-webkit-scrollbar-thumb:hover {background:var(--cyan);}
    @supports not selector(::-webkit-scrollbar) {
        * {scrollbar-width:thin; scrollbar-color:var(--line-strong) var(--panel-3);}
    }

    /* Typography rhythm. */
    h1, h2, h3 {letter-spacing:-.01em !important;}
    .stCaption, [data-testid="stCaptionContainer"] {color:var(--muted) !important; line-height:1.55 !important;}
    .stMarkdown a:where(:not([class])) {color:var(--cyan); text-decoration-color:rgba(59,130,246,.4); text-underline-offset:3px; transition:color .15s var(--ease);}
    .stMarkdown a:where(:not([class])):hover {color:#8ab4f8;}
    hr {border-color:var(--line) !important;}

    /* Segmented controls (every st.radio is used as a tab bar). */
    .stRadio [role="radiogroup"] {background:var(--surface-sunken) !important; border:1px solid var(--line-strong) !important;}

    /* KPI cards. */
    div[data-testid="stMetric"] {
        background:linear-gradient(180deg,var(--panel-2),var(--panel)) !important;
        border:1px solid var(--line) !important;
    }
    div[data-testid="stMetric"]:hover {border-color:var(--line-strong) !important;}
    div[data-testid="stMetricLabel"] p {font-size:12px !important; font-weight:600 !important; letter-spacing:.3px !important; color:var(--muted) !important;}
    div[data-testid="stMetricValue"] {letter-spacing:-.3px !important;}

    /* Alerts: same card material, severity keeps its own left-edge color. */
    .stAlert, div[data-testid="stAlertContainer"], div[data-testid="stAlert"] {
        background:linear-gradient(180deg,var(--panel-2),var(--panel)) !important;
        border-top-color:var(--line) !important; border-right-color:var(--line) !important; border-bottom-color:var(--line) !important;
    }

    /* Expanders. */
    [data-testid="stExpander"] {background:var(--panel) !important; border-top-color:var(--line) !important; border-right-color:var(--line) !important; border-bottom-color:var(--line) !important;}
    [data-testid="stExpander"]:hover {border-top-color:var(--line-strong) !important; border-right-color:var(--line-strong) !important; border-bottom-color:var(--line-strong) !important;}
    [data-testid="stExpander"] summary {font-weight:650; transition:color .15s var(--ease);}
    [data-testid="stExpander"] summary:hover {color:#ffffff;}

    /* Tables, code, uploader. */
    .stDataFrame {border:1px solid var(--line-strong) !important;}
    [data-testid="stCode"], .stCodeBlock {border:1px solid var(--line) !important; border-radius:var(--r-md) !important;}
    .stFileUploader {background:var(--surface-sunken) !important; border:1px dashed rgba(59,130,246,.4) !important; transition:border-color .15s var(--ease), background .15s var(--ease);}
    .stFileUploader:hover {border-color:var(--cyan) !important; background:var(--panel) !important;}

    /* Floating layers: dropdowns, tooltips, toasts. */
    div[data-baseweb="popover"] > div {
        border-radius:var(--r-md) !important; border:1px solid var(--line-strong) !important;
        box-shadow:0 18px 40px rgba(0,0,0,.45) !important;
    }
    [data-testid="stToast"] {border-radius:var(--r-md) !important; border:1px solid var(--line-strong) !important; background:var(--panel-2) !important;}

    /* Forensic Report: unmistakable split between the batch report and the
       single-email deep dive. */
    .part-banner {
        display:flex; align-items:center; gap:16px; flex-wrap:wrap;
        padding:18px 22px; margin:6px 0 16px 0; border-radius:var(--r-lg);
        border:1px solid var(--line-strong); box-shadow:var(--shadow-md);
    }
    .part-banner .pb-title {font:800 21px/1.25 Inter,"Segoe UI",sans-serif; color:#ffffff;}
    .part-banner .pb-sub {color:var(--muted); font-size:13px; margin-top:3px;}
    .part-banner .pb-step {
        font:800 11px/1 ui-monospace,Consolas,monospace; letter-spacing:1.6px;
        padding:8px 13px; border-radius:999px; white-space:nowrap; color:#fff;
    }
    .part-banner .pb-scope {
        margin-left:auto; font:800 10px/1 ui-monospace,Consolas,monospace; letter-spacing:1.4px;
        padding:7px 12px; border-radius:999px; border:1px solid var(--line-strong); color:#cbd5e1;
    }
    .part-banner-batch {background:linear-gradient(135deg, rgba(59,130,246,.18), var(--panel) 62%); border-left:5px solid var(--cyan);}
    .part-banner-batch .pb-step {background:var(--brand-gradient);}
    .part-banner-single {background:linear-gradient(135deg, rgba(201,138,92,.20), var(--panel) 62%); border-left:5px solid var(--teal);}
    .part-banner-single .pb-step {background:linear-gradient(90deg,#c98a5c,#d9a35f);}
    .part-sep {display:flex; align-items:center; gap:14px; margin:64px 0 22px 0;}
    .part-sep::before, .part-sep::after {content:""; flex:1; height:2px; background:linear-gradient(90deg, transparent, var(--teal), transparent);}
    .part-sep span {font:800 11px/1 ui-monospace,Consolas,monospace; letter-spacing:2.2px; color:var(--teal); white-space:nowrap;}
    .part-banner-ai {background:linear-gradient(135deg, rgba(99,102,241,.20), var(--panel) 62%); border-left:5px solid var(--violet);}
    .part-banner-ai .pb-step {background:linear-gradient(90deg,#6366f1,#8b5cf6);}
    .part-banner-intel {background:linear-gradient(135deg, rgba(111,174,140,.18), var(--panel) 62%); border-left:5px solid var(--green);}
    .part-banner-intel .pb-step {background:linear-gradient(90deg,#4f9d78,#6fae8c);}
    .sec-head {
        display:flex; align-items:baseline; gap:12px; flex-wrap:wrap;
        margin:26px 0 12px 0; padding:2px 0 2px 14px; border-left:4px solid var(--cyan);
    }
    .sec-head .sh-title {font:800 18px/1.3 Inter,"Segoe UI",sans-serif; color:#fff;}
    .sec-head .sh-sub {font-size:12.5px; color:var(--muted);}
    .sec-single {border-left-color:var(--teal);}
    .sec-ai {border-left-color:var(--violet);}
    .sec-intel {border-left-color:var(--green);}
    .part-banner-rose {background:linear-gradient(135deg, rgba(244,63,94,.18), var(--panel) 62%); border-left:5px solid #f43f5e;}
    .part-banner-rose .pb-step {background:linear-gradient(90deg,#f43f5e,#fb7185); color:#0b0e14;}
    .sec-rose {border-left-color:#f43f5e;}
    .part-banner-sky {background:linear-gradient(135deg, rgba(14,165,233,.18), var(--panel) 62%); border-left:5px solid #0ea5e9;}
    .part-banner-sky .pb-step {background:linear-gradient(90deg,#0ea5e9,#38bdf8); color:#0b0e14;}
    .sec-sky {border-left-color:#0ea5e9;}
    .part-banner-gold {background:linear-gradient(135deg, rgba(234,179,8,.18), var(--panel) 62%); border-left:5px solid #eab308;}
    .part-banner-gold .pb-step {background:linear-gradient(90deg,#eab308,#f59e0b); color:#0b0e14;}
    .sec-gold {border-left-color:#eab308;}
    .part-banner-teal {background:linear-gradient(135deg, rgba(20,184,166,.18), var(--panel) 62%); border-left:5px solid #14b8a6;}
    .part-banner-teal .pb-step {background:linear-gradient(90deg,#14b8a6,#2dd4bf); color:#0b0e14;}
    .sec-teal {border-left-color:#14b8a6;}
    .part-banner-plum {background:linear-gradient(135deg, rgba(217,70,239,.18), var(--panel) 62%); border-left:5px solid #d946ef;}
    .part-banner-plum .pb-step {background:linear-gradient(90deg,#d946ef,#e879f9); color:#0b0e14;}
    .sec-plum {border-left-color:#d946ef;}
    .part-banner-lime {background:linear-gradient(135deg, rgba(132,204,22,.18), var(--panel) 62%); border-left:5px solid #84cc16;}
    .part-banner-lime .pb-step {background:linear-gradient(90deg,#84cc16,#a3e635); color:#0b0e14;}
    .sec-lime {border-left-color:#84cc16;}
    .st-key-single_email_select {
        background:var(--panel); border:1px solid var(--line-strong); border-left:4px solid var(--teal);
        border-radius:var(--r-lg); padding:14px 18px 16px 18px; margin:0 0 26px 0;
    }
    .dossier-head {
        display:flex; align-items:center; justify-content:space-between; gap:14px; flex-wrap:wrap;
        padding:14px 20px; margin:6px 0 20px 0; border-radius:var(--r-lg);
        background:linear-gradient(90deg, rgba(201,138,92,.16), transparent 70%);
        border:1px solid var(--line-strong); border-left:5px solid var(--teal);
    }
    .dossier-head .dh-title {font:800 26px/1.2 Inter,"Segoe UI",sans-serif; color:#fff;}
    .dossier-head .dh-of {font-size:14px; font-weight:600; color:var(--muted); margin-left:6px;}
    .dossier-head .dh-pill {font:800 12px/1 ui-monospace,Consolas,monospace; letter-spacing:1.2px; padding:8px 14px; border-radius:999px; border:1px solid;}

    /* ==================================================================
       SECTION HEADER SYSTEM v2
       One quiet, consistent look for every module / part / section header
       (_banner, _sec, the dossier head and the AI report bar).
       Why the old ones read as buttons: solid-gradient rounded "step"
       pills and outlined "scope" pills are exactly what a button looks
       like, and a 5px coloured slab on the card edge made the whole card
       look pressable. Now: no pills at all on anything that is not
       clickable. The step becomes a small mono eyebrow with a leading
       rule, the scope becomes plain meta text with a status dot, and the
       accent is a slim inset bar (not a slab). Each tone only sets --tone.
       ================================================================== */
    .part-banner, .sec-head, .dossier-head {--tone:var(--cyan);}
    .part-banner-batch, .sec-batch {--tone:var(--cyan);}
    .part-banner-single, .sec-single, .dossier-head {--tone:var(--teal);}
    .part-banner-ai, .sec-ai {--tone:var(--violet);}
    .part-banner-intel, .sec-intel {--tone:var(--green);}
    .part-banner-rose, .sec-rose {--tone:#f43f5e;}
    .part-banner-sky, .sec-sky {--tone:#0ea5e9;}
    .part-banner-gold, .sec-gold {--tone:#eab308;}
    .part-banner-teal, .sec-teal {--tone:#14b8a6;}
    .part-banner-plum, .sec-plum {--tone:#d946ef;}
    .part-banner-lime, .sec-lime {--tone:#84cc16;}

    .part-banner, .dossier-head {
        position:relative; overflow:hidden;
        padding:18px 24px 18px 30px; margin:8px 0 18px 0;
        border-radius:var(--r-lg);
        border:1px solid var(--line-strong); border-left:1px solid var(--line-strong);
        background:
            radial-gradient(120% 150% at 0% 0%, color-mix(in srgb, var(--tone) 15%, transparent) 0%, transparent 58%),
            linear-gradient(180deg, var(--panel-2), var(--panel));
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), var(--shadow-md);
    }
    .part-banner::before, .dossier-head::before, .sec-head::before {
        content:""; position:absolute; left:0; top:16px; bottom:16px; width:3px;
        border-radius:0 3px 3px 0;
        background:linear-gradient(180deg, var(--tone), color-mix(in srgb, var(--tone) 20%, transparent));
    }
    .part-banner {display:flex; align-items:center; justify-content:space-between; gap:18px; flex-wrap:wrap;}
    .part-banner .pb-main {min-width:0; flex:1 1 320px;}
    .part-banner .pb-step {
        display:inline-flex !important; align-items:center; gap:10px; margin-bottom:9px;
        font:700 10.5px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.18em !important;
        text-transform:uppercase; white-space:nowrap;
        color:var(--tone) !important; background:none !important;
        padding:0 !important; border-radius:0 !important; border:0 !important;
    }
    .part-banner .pb-step::before {content:""; width:18px; height:1px; background:currentColor; opacity:.65;}
    .part-banner .pb-title {font:750 22px/1.25 Inter,"Segoe UI",sans-serif; color:#fff; letter-spacing:-.01em;}
    .part-banner .pb-sub {color:var(--muted); font-size:13px; line-height:1.5; margin-top:4px; max-width:78ch;}
    .part-banner .pb-scope {
        margin-left:0 !important; display:inline-flex; align-items:center; gap:9px;
        font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.14em; text-transform:uppercase;
        color:var(--muted) !important; background:none !important; border:0 !important; padding:0 !important;
    }
    .part-banner .pb-scope::before {
        content:""; width:6px; height:6px; border-radius:50%; background:var(--tone);
        box-shadow:0 0 0 3px color-mix(in srgb, var(--tone) 22%, transparent);
    }
    .part-sep::before, .part-sep::after {height:1px !important;}

    .sec-head {
        position:relative; display:block !important;
        margin:30px 0 14px 0 !important; padding:2px 0 2px 16px !important; border-left:0 !important;
    }
    .sec-head::before {top:3px; bottom:3px; border-radius:3px;}
    .sec-head .sh-title {font:750 17px/1.3 Inter,"Segoe UI",sans-serif; color:#f1f5f9; letter-spacing:-.005em;}
    .sec-head .sh-sub {margin-top:3px; font-size:12.5px; line-height:1.5; color:var(--muted); max-width:80ch;}

    .dossier-head .dh-title {font:750 24px/1.2 Inter,"Segoe UI",sans-serif; letter-spacing:-.01em;}
    .dossier-head .dh-pill {border-radius:6px; font-size:11.5px; letter-spacing:.1em; padding:7px 11px;}

    .ai-report-bar {padding:12px 16px; font:700 10.5px/1.2 ui-monospace,Consolas,monospace; letter-spacing:.16em;}
    .ai-report-chip {
        display:inline-flex; align-items:center; gap:9px;
        padding:0 !important; border:0 !important; background:none !important; border-radius:0 !important;
        color:var(--muted) !important; font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.14em;
    }
    .ai-report-chip::before {
        content:""; width:6px; height:6px; border-radius:50%; background:var(--violet);
        box-shadow:0 0 0 3px color-mix(in srgb, var(--violet) 25%, transparent);
    }

    /* ==================================================================
       DASHBOARD CARD SYSTEM v3
       Brings every dashboard card onto the same language as the Email
       Deep Dive headers above (.part-banner / .dossier-head): one quiet
       card material (graphite gradient + a faint tone wash from the top-
       left corner), a slim inset accent bar instead of a thick border
       slab, a small mono eyebrow with a leading hairline, and tabular
       numerals for data. Each card only sets --tone, so colour carries
       meaning (copper = origin/route, blue = intake, violet = AI/auth,
       amber = scope/caution, green = healthy/connected) rather than
       decoration. Severity colours used on pills/chips are untouched.
       ================================================================== */

    /* ---- tones ------------------------------------------------------ */
    .stage-card, .panel-card-head, .panel-card-body, div[data-testid="stMetric"],
    .st-key-bulk_infra_scan, .st-key-dash_map_graph_card,
    .st-key-right_dock_metrics_body, .st-key-dd_dock_metrics_body,
    .st-key-imap_connected_actions {--tone:var(--cyan);}
    .stage-card-auth {--tone:var(--violet);}
    .stage-card-scope {--tone:var(--amber);}
    .stage-card-success, .st-key-imap_connected_actions {--tone:var(--green);}
    .panel-card-head-violet, .panel-card-body-violet {--tone:var(--violet);}
    .panel-card-head-amber,  .panel-card-body-amber  {--tone:var(--amber);}
    .panel-card-head-green,  .panel-card-body-green  {--tone:var(--green);}
    .panel-card-head-copper, .panel-card-body-copper {--tone:var(--teal);}
    .st-key-bulk_infra_scan, .st-key-dash_map_graph_card {--tone:var(--teal);}
    .st-key-dd_dock_metrics_body {--tone:var(--teal);}
    .st-key-auth_password_box, .st-key-auth_password_box_ms, .st-key-auth_password_box_ya {--tone:#a6947c;}
    .st-key-auth_google_box {--tone:#3b82f6;}
    .st-key-auth_microsoft_box {--tone:#c98a5c;}
    .st-key-auth_yandex_box {--tone:#d65f45;}

    /* ---- shared card material -------------------------------------- */
    .stage-card, .st-key-bulk_infra_scan, .st-key-dash_map_graph_card,
    .st-key-imap_connected_actions,
    .st-key-auth_password_box, .st-key-auth_google_box,
    .st-key-auth_password_box_ms, .st-key-auth_microsoft_box,
    .st-key-auth_password_box_ya, .st-key-auth_yandex_box {
        position:relative;
        border:1px solid var(--line-strong) !important;
        border-top-width:1px !important; border-left-width:1px !important;
        border-radius:var(--r-lg) !important;
        background:
            radial-gradient(120% 150% at 0% 0%, color-mix(in srgb, var(--tone) 13%, transparent) 0%, transparent 58%),
            linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), var(--shadow-md) !important;
    }
    .stage-card::before, .st-key-bulk_infra_scan::before, .st-key-dash_map_graph_card::before,
    .st-key-imap_connected_actions::before,
    .st-key-auth_password_box::before, .st-key-auth_google_box::before,
    .st-key-auth_password_box_ms::before, .st-key-auth_microsoft_box::before,
    .st-key-auth_password_box_ya::before, .st-key-auth_yandex_box::before {
        content:""; position:absolute; left:0; top:16px; bottom:16px; width:3px;
        border-radius:0 3px 3px 0; pointer-events:none; z-index:2;
        background:linear-gradient(180deg, var(--tone), color-mix(in srgb, var(--tone) 20%, transparent));
    }
    /* Static cards don't lift on hover (they aren't clickable); the border
       just warms toward the card's own tone. */
    .stage-card:hover, .stage-card-auth:hover, .stage-card-scope:hover, .stage-card-success:hover,
    .st-key-auth_password_box:hover, .st-key-auth_google_box:hover,
    .st-key-auth_password_box_ms:hover, .st-key-auth_microsoft_box:hover,
    .st-key-auth_password_box_ya:hover, .st-key-auth_yandex_box:hover {
        transform:none !important;
        border-color:color-mix(in srgb, var(--tone) 42%, var(--line-strong)) !important;
        background:
            radial-gradient(120% 150% at 0% 0%, color-mix(in srgb, var(--tone) 16%, transparent) 0%, transparent 58%),
            linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), var(--shadow-md) !important;
    }
    .stage-card {padding:18px 22px 18px 28px !important; overflow:hidden;}
    .st-key-bulk_infra_scan {padding:18px 24px 20px 30px !important;}
    .st-key-dash_map_graph_card {padding:24px 24px 24px 30px !important;}
    .st-key-imap_connected_actions {
        border-top-color:var(--line-strong) !important;
        border-top-left-radius:0 !important; border-top-right-radius:0 !important;
        padding:14px 22px 16px 28px !important;
    }
    .stage-card-success::after {
        background:color-mix(in srgb, var(--green) 14%, transparent) !important;
        border-color:color-mix(in srgb, var(--green) 40%, transparent) !important;
    }

    /* ---- eyebrow / title / sub inside cards ------------------------ */
    .stage-card .stage-label, .stage-card-auth .stage-label,
    .stage-card-scope .stage-label, .stage-card-success .stage-label {
        gap:10px; padding:0 !important; border:0 !important; border-radius:0 !important;
        background:none !important; color:var(--tone) !important;
        font:700 10.5px/1 ui-monospace,Consolas,monospace !important;
        letter-spacing:.18em !important; text-transform:uppercase !important;
    }
    .stage-card .stage-label::before {content:""; width:18px; height:1px; background:currentColor; opacity:.65;}
    .stage-card .stage-title {font:750 18px/1.3 Inter,"Segoe UI",sans-serif !important; letter-spacing:-.01em; margin-top:9px !important;}
    .stage-card .stage-help {font-size:13px !important; line-height:1.5 !important; color:var(--muted) !important; margin-top:4px !important; max-width:78ch;}
    .infra-scan-eyebrow {
        display:inline-flex; align-items:center; gap:10px; color:var(--tone) !important;
        font:700 10.5px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.18em !important;
    }
    .infra-scan-eyebrow::before {content:""; width:18px; height:1px; background:currentColor; opacity:.65;}
    .infra-scan-title {font:750 20px/1.25 Inter,"Segoe UI",sans-serif !important; letter-spacing:-.01em !important;}
    .auth-option-label {
        font:700 10.5px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.16em !important;
        color:var(--tone) !important;
    }
    .auth-option-label::before {box-shadow:0 0 0 3px color-mix(in srgb, var(--tone) 22%, transparent) !important; background:var(--tone) !important;}

    /* ---- panel-card head + body (right dock, globe-scan, copilot) --- */
    .panel-card-head, .panel-card-body {
        position:relative;
        border:1px solid var(--line-strong) !important;
        border-left:1px solid var(--line-strong) !important;
    }
    .panel-card-head {
        padding:13px 18px 13px 26px !important;
        border-bottom:1px solid var(--line) !important;
        border-radius:var(--r-lg) var(--r-lg) 0 0 !important;
        background:
            radial-gradient(120% 220% at 0% 0%, color-mix(in srgb, var(--tone) 15%, transparent) 0%, transparent 60%),
            linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
        color:var(--tone) !important;
        font:700 10.5px/1.2 ui-monospace,Consolas,monospace !important; letter-spacing:.18em !important;
        text-transform:uppercase;
    }
    .panel-card-head > :first-child {display:inline-flex; align-items:center; gap:10px;}
    .panel-card-head > :first-child::before {content:""; width:18px; height:1px; background:currentColor; opacity:.65;}
    .panel-card-head > :last-child:not(:first-child) {
        font:600 10.5px/1.2 ui-monospace,Consolas,monospace !important; letter-spacing:.12em !important;
        color:var(--muted) !important; text-transform:uppercase;
    }
    .panel-card-body {
        padding:16px 18px 17px 26px !important; border-top:none !important;
        border-radius:0 0 var(--r-lg) var(--r-lg) !important;
        background:linear-gradient(180deg, var(--panel), var(--panel-3)) !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.03), var(--shadow-sm) !important;
    }
    .panel-card-head::before, .panel-card-body::before {
        content:""; position:absolute; left:0; width:3px; pointer-events:none;
        background:linear-gradient(180deg, var(--tone), color-mix(in srgb, var(--tone) 20%, transparent));
    }
    .panel-card-head::before {top:12px; bottom:0; border-radius:0 3px 0 0;}
    .panel-card-body::before {top:0; bottom:16px; border-radius:0 0 3px 0;}
    .st-key-dash_map_graph_card .panel-card-head span:last-child {
        font:600 10.5px/1.2 ui-monospace,Consolas,monospace !important; letter-spacing:.12em !important;
        color:var(--muted) !important; text-transform:uppercase;
    }
    .st-key-right_dock_metrics_body, .st-key-dd_dock_metrics_body {
        position:relative;
        border:1px solid var(--line-strong) !important; border-top:none !important;
        border-radius:0 0 var(--r-lg) var(--r-lg) !important;
        background:linear-gradient(180deg, var(--panel), var(--panel-3)) !important;
        padding:16px 14px 4px 22px !important;
    }
    .st-key-right_dock_metrics_body::before, .st-key-dd_dock_metrics_body::before {
        content:""; position:absolute; left:0; top:0; bottom:16px; width:3px;
        border-radius:0 0 3px 0; pointer-events:none;
        background:linear-gradient(180deg, var(--tone), color-mix(in srgb, var(--tone) 20%, transparent));
    }

    /* ---- KPI / metric tiles ---------------------------------------- */
    div[data-testid="stMetric"] {
        position:relative; overflow:hidden;
        padding:15px 16px 14px 20px !important;
        border:1px solid var(--line-strong) !important; border-radius:var(--r-md) !important;
        background:
            radial-gradient(130% 160% at 0% 0%, color-mix(in srgb, var(--tone) 13%, transparent) 0%, transparent 60%),
            linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), var(--shadow-sm) !important;
        transform:none !important;
    }
    /* Tone rotates by column so a row of four reads as four distinct
       numbers: copper, blue, violet, green (repeating). */
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+1) div[data-testid="stMetric"] {--tone:var(--teal);}
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+2) div[data-testid="stMetric"] {--tone:var(--cyan);}
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+3) div[data-testid="stMetric"] {--tone:var(--violet);}
    [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-of-type(4n+4) div[data-testid="stMetric"] {--tone:var(--green);}
    /* Replace the old 2px top bar with the same slim inset bar the cards use. */
    div[data-testid="stMetric"]:before,
    [data-testid="stHorizontalBlock"] > [data-testid="column"] div[data-testid="stMetric"]:before {
        content:"" !important; position:absolute !important; left:0 !important; right:auto !important;
        top:14px !important; bottom:14px !important; width:3px !important; height:auto !important;
        border-radius:0 3px 3px 0 !important; opacity:1 !important;
        background:linear-gradient(180deg, var(--tone), color-mix(in srgb, var(--tone) 20%, transparent)) !important;
    }
    div[data-testid="stMetric"]:hover,
    [data-testid="stHorizontalBlock"] > [data-testid="column"] div[data-testid="stMetric"]:hover {
        transform:none !important;
        border-color:color-mix(in srgb, var(--tone) 45%, var(--line-strong)) !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), var(--shadow-sm) !important;
    }
    div[data-testid="stMetricLabel"] p {
        display:inline-flex; align-items:center; gap:8px;
        font:600 10.5px/1.2 ui-monospace,Consolas,monospace !important;
        letter-spacing:.14em !important; text-transform:uppercase; color:var(--muted) !important;
    }
    div[data-testid="stMetricLabel"] p::before {content:""; width:12px; height:1px; background:var(--tone); opacity:.8;}
    div[data-testid="stMetricValue"] {font-weight:750 !important; letter-spacing:-.02em !important; color:#f4f7fb !important;}

    /* ---- dashboard section title: centred hairline divider ---------- */
    .dash-section-title {
        justify-content:center !important; gap:14px !important; border-bottom:0 !important;
        margin:34px 0 18px !important; padding-bottom:0 !important;
        color:var(--teal) !important; font:700 10.5px/1.3 ui-monospace,Consolas,monospace !important;
        letter-spacing:.2em !important;
    }
    .dash-section-title::before, .dash-section-title::after {
        content:""; flex:1; height:1px;
        background:linear-gradient(90deg, transparent, color-mix(in srgb, var(--teal) 70%, transparent), transparent);
    }
    .dash-section-title .dash-section-dot {background:var(--teal) !important; box-shadow:0 0 0 3px color-mix(in srgb, var(--teal) 22%, transparent) !important;}
    .dash-section-title .dash-section-sub {color:var(--muted) !important; letter-spacing:.04em !important;}

    /* ---- alerts + expanders share the same material ----------------- */
    .stAlert, div[data-testid="stAlertContainer"], div[data-testid="stAlert"] {
        border:1px solid var(--line-strong) !important;
        border-left:3px solid var(--line-strong) !important;
        background:linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), var(--shadow-sm) !important;
    }
    [data-testid="stExpander"] {
        border:1px solid var(--line-strong) !important; border-left:3px solid var(--violet) !important;
        border-radius:var(--r-md) !important;
        background:linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
    }
    [data-testid="stExpander"] summary {font-weight:650; letter-spacing:-.005em;}

    /* ==================================================================
       ACQUISITION MODE SWITCH v4
       Two channel tiles, laid out vertically: a mono channel tag and a
       real on/off switch on top, title + one-line description in the
       middle, capability chips along the bottom, and a large ghost icon
       as a watermark. Active = tone-filled with a full-width top bar and
       the switch turned on; standby = flat, quiet, switch off. Replaces
       the old icon-tile + ring card (.mode-card). The invisible button
       (.st-key-acq_pick_*) is stacked on the tile, sized from --acq-h.
       ================================================================== */
    .mode-select-heading {
        font:600 10.5px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.18em !important;
        text-transform:uppercase; color:var(--muted) !important; margin:6px 0 12px 2px !important;
    }
    :root {--acq-h:158px;}
    .acq2 {
        --tone:var(--cyan);
        position:relative; overflow:hidden; box-sizing:border-box; height:var(--acq-h);
        display:flex; flex-direction:column; padding:16px 20px 16px 20px;
        border:1px solid var(--line-strong); border-radius:14px;
        background:linear-gradient(180deg, var(--panel), var(--panel-3));
        transition:border-color .18s var(--ease), background .18s var(--ease), box-shadow .18s var(--ease);
    }
    .acq2-blue {--tone:#4c8dff;}
    .acq2-copper {--tone:#d49a66;}
    .acq2::before {                      /* top bar: hairline when idle, solid when active */
        content:""; position:absolute; left:0; right:0; top:0; height:2px;
        background:var(--line-strong); transition:background .18s var(--ease), height .18s var(--ease);
    }
    .acq2:hover {border-color:color-mix(in srgb, var(--tone) 45%, var(--line-strong));}
    .acq2-top {position:relative; z-index:1; display:flex; align-items:center; justify-content:space-between; gap:12px;}
    .acq2-tag {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.16em; text-transform:uppercase; color:var(--muted);}
    .acq2-state {display:inline-flex; align-items:center; gap:9px;}
    .acq2-state-txt {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.14em; text-transform:uppercase; color:var(--muted);}
    .acq2-sw {position:relative; width:32px; height:18px; border-radius:999px; background:#262f3c; border:1px solid var(--line-strong); transition:background .18s var(--ease), border-color .18s var(--ease);}
    .acq2-sw i {position:absolute; top:2px; left:2px; width:12px; height:12px; border-radius:50%; background:#76818f; transition:left .18s var(--ease), background .18s var(--ease);}
    .acq2-title {position:relative; z-index:1; margin-top:14px; font:750 18px/1.25 Inter,"Segoe UI",sans-serif; letter-spacing:-.01em; color:#c9d2de;}
    .acq2-sub {position:relative; z-index:1; margin-top:4px; max-width:46ch; font-size:12.5px; line-height:1.5; color:#7d8896;}
    .acq2-chips {position:relative; z-index:1; display:flex; flex-wrap:wrap; gap:6px; margin-top:auto;}
    .acq2-chip {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.06em; padding:5px 8px; border-radius:6px; border:1px solid var(--line-strong); color:#8b96a5; background:rgba(255,255,255,.02);}
    .acq2-ghost {position:absolute; right:-6px; bottom:-14px; width:104px; height:104px; color:var(--tone); opacity:.07; pointer-events:none; transition:opacity .18s var(--ease);}
    .acq2-ghost svg {width:100%; height:100%;}

    .acq2-on {
        border-color:color-mix(in srgb, var(--tone) 60%, var(--line-strong));
        background:
            radial-gradient(90% 120% at 100% 100%, color-mix(in srgb, var(--tone) 17%, transparent) 0%, transparent 62%),
            linear-gradient(180deg, var(--panel-2), var(--panel));
        box-shadow:0 0 0 3px color-mix(in srgb, var(--tone) 12%, transparent);
    }
    .acq2-on::before {height:3px; background:var(--tone);}
    .acq2-on .acq2-tag, .acq2-on .acq2-state-txt {color:var(--tone);}
    .acq2-on .acq2-sw {background:color-mix(in srgb, var(--tone) 35%, #12171f); border-color:color-mix(in srgb, var(--tone) 70%, transparent);}
    .acq2-on .acq2-sw i {left:16px; background:var(--tone);}
    .acq2-on .acq2-title {color:#ffffff;}
    .acq2-on .acq2-sub {color:#a3aebb;}
    .acq2-on .acq2-chip {color:var(--tone); border-color:color-mix(in srgb, var(--tone) 40%, transparent); background:color-mix(in srgb, var(--tone) 8%, transparent);}
    .acq2-on .acq2-ghost {opacity:.13;}

    /* click-catcher: exactly covers the tile (tile height + the 1rem flow gap) */
    .st-key-acq_pick_live, .st-key-acq_pick_upload {
        margin-top:calc(-1 * (var(--acq-h) + 1rem)) !important; position:relative !important; z-index:5 !important;
    }
    .st-key-acq_pick_live button, .st-key-acq_pick_upload button {height:var(--acq-h) !important;}
    @media (max-width: 900px) {
        .st-key-acq_pick_live, .st-key-acq_pick_upload {margin-top:calc(-1 * (var(--acq-h) + 1rem)) !important;}
        .st-key-acq_pick_live button, .st-key-acq_pick_upload button {height:var(--acq-h) !important;}
    }
    @media (prefers-reduced-motion: reduce) {.acq2, .acq2::before, .acq2-sw, .acq2-sw i {transition:none !important;}}

    /* ==================================================================
       EVIDENCE INTAKE v4 (Channel B)
       Same tile language as the acquisition switch: copper tone, hairline
       top bar, mono tag, chips. Fixes: (1) the dropzone's Material-Symbols
       font rule also hit the instruction text, so "Drag and drop" vanished
       and "csv" turned into an icon; (2) st.info rendered as a box inside a
       box because both the outer stAlert and inner stAlertContainer were
       styled. ================================================================== */
    .intake-head {
        --tone:#d49a66;
        position:relative; overflow:hidden; display:flex; align-items:center; justify-content:space-between;
        gap:18px; flex-wrap:wrap; margin:8px 0 14px; padding:18px 22px;
        border:1px solid var(--line-strong); border-radius:14px;
        background:radial-gradient(90% 140% at 100% 0%, color-mix(in srgb, var(--tone) 12%, transparent) 0%, transparent 60%),
                   linear-gradient(180deg, var(--panel-2), var(--panel));
    }
    .intake-head::before {content:""; position:absolute; left:0; right:0; top:0; height:2px; background:var(--tone);}
    .intake-main {min-width:0; flex:1 1 320px;}
    .intake-eyebrow {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.16em; text-transform:uppercase; color:var(--tone);}
    .intake-title {margin-top:10px; font:750 20px/1.25 Inter,"Segoe UI",sans-serif; letter-spacing:-.01em; color:#fff;}
    .intake-sub {margin-top:4px; max-width:70ch; font-size:13px; line-height:1.5; color:var(--muted);}
    .intake-meta {display:flex; align-items:center; flex-wrap:wrap; gap:6px;}
    .intake-chip {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.06em; padding:5px 8px; border-radius:6px;
        color:var(--tone); border:1px solid color-mix(in srgb, var(--tone) 40%, transparent); background:color-mix(in srgb, var(--tone) 8%, transparent);}
    .intake-limit {margin-left:8px; font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.12em; text-transform:uppercase; color:var(--muted);}

    /* dropzone: one horizontal row (icon | instructions | button) */
    .stApp section[data-testid="stFileUploaderDropzone"] {
        flex-direction:row !important; justify-content:flex-start !important; align-items:center !important;
        gap:20px !important; min-height:112px !important; padding:22px 26px !important;
        border:1.5px dashed color-mix(in srgb, #d49a66 45%, var(--line-strong)) !important; border-radius:14px !important;
        background:
            linear-gradient(180deg, rgba(255,255,255,.015), transparent),
            var(--panel-3) !important;
    }
    .stApp section[data-testid="stFileUploaderDropzone"]:hover {
        border-color:#d49a66 !important; background:color-mix(in srgb, #d49a66 6%, var(--panel-3)) !important;
    }
    .stApp section[data-testid="stFileUploaderDropzone"]::before {
        flex:0 0 48px; width:48px; height:48px; margin:0 !important; border-radius:12px;
        background-color:color-mix(in srgb, #d49a66 12%, transparent);
        border:1px solid color-mix(in srgb, #d49a66 38%, transparent);
        background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23d49a66' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M16 16l-4-4-4 4'/%3E%3Cpath d='M12 12v9'/%3E%3Cpath d='M20.4 18.4A5 5 0 0 0 18 9h-1.3A8 8 0 1 0 4 16.3'/%3E%3C/svg%3E");
        background-size:22px 22px;
    }
    .stApp section[data-testid="stFileUploaderDropzone"] > div {flex:1 1 auto; align-items:flex-start !important; margin:0 !important;}
    .stApp [data-testid="stFileUploaderDropzoneInstructions"] {text-align:left !important; align-items:flex-start !important;}
    .stApp [data-testid="stFileUploaderDropzoneInstructions"] > div {align-items:flex-start !important;}
    .stApp [data-testid="stFileUploaderDropzoneInstructions"] span,
    .stApp [data-testid="stFileUploaderDropzoneInstructions"] small {
        font-family:Inter,system-ui,"Segoe UI",sans-serif !important; font-feature-settings:normal !important;
        letter-spacing:0 !important; text-transform:none !important; display:block !important; white-space:normal !important;
    }
    .stApp [data-testid="stFileUploaderDropzoneInstructions"] > div > span {font-size:15px !important; font-weight:650 !important; color:#eef2f7 !important;}
    .stApp [data-testid="stFileUploaderDropzoneInstructions"] small {margin-top:3px; font-size:12px !important; font-weight:500 !important; color:var(--muted) !important;}
    .stApp section[data-testid="stFileUploaderDropzone"] button {
        flex:0 0 auto; min-width:140px !important; height:40px !important; margin-left:auto;
        border-color:color-mix(in srgb, #d49a66 55%, var(--line-strong)) !important;
        background:color-mix(in srgb, #d49a66 10%, var(--panel-2)) !important; color:#fff !important;
    }
    .stApp section[data-testid="stFileUploaderDropzone"] button:hover {border-color:#d49a66 !important; background:color-mix(in srgb, #d49a66 18%, var(--panel-2)) !important;}
    @media (max-width:700px) {
        .stApp section[data-testid="stFileUploaderDropzone"] {flex-wrap:wrap !important;}
        .stApp section[data-testid="stFileUploaderDropzone"] button {margin-left:0; width:100%;}
    }

    /* ready strip (replaces st.info) */
    .intake-status {
        --tone:#d49a66;
        display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin:14px 0 4px; padding:12px 18px;
        border:1px solid var(--line-strong); border-radius:12px; background:linear-gradient(180deg, var(--panel-2), var(--panel));
    }
    .intake-dot {width:7px; height:7px; border-radius:50%; background:var(--tone); box-shadow:0 0 0 3px color-mix(in srgb, var(--tone) 22%, transparent);}
    .intake-status-k {font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.16em; text-transform:uppercase; color:var(--tone);}
    .intake-status-v {font-size:13px; line-height:1.5; color:#b4bfcc;}

    /* alerts: style only the outer element; the inner container is reset
       so a single st.info/success/warning is one card, not two. */
    [data-testid="stAlert"] [data-testid="stAlertContainer"],
    .stAlert [data-testid="stAlertContainer"] {
        border:0 !important; border-radius:0 !important; background:transparent !important;
        box-shadow:none !important; padding:0 !important; margin:0 !important;
    }

    /* Dropzone, centred: icon, instructions and button stacked on the middle axis. */
    .stApp section[data-testid="stFileUploaderDropzone"] {
        flex-direction:column !important; justify-content:center !important; align-items:center !important;
        gap:14px !important; min-height:190px !important; padding:28px 26px !important; text-align:center;
    }
    .stApp section[data-testid="stFileUploaderDropzone"]::before {margin:0 auto !important;}
    .stApp section[data-testid="stFileUploaderDropzone"] > div {flex:0 0 auto; align-items:center !important; width:100%;}
    .stApp [data-testid="stFileUploaderDropzoneInstructions"],
    .stApp [data-testid="stFileUploaderDropzoneInstructions"] > div {text-align:center !important; align-items:center !important; justify-content:center !important;}
    .stApp [data-testid="stFileUploaderDropzoneInstructions"] small {display:none !important;}   /* size is stated in the header chips: 50 MB */
    .stApp section[data-testid="stFileUploaderDropzone"] button {margin:2px auto 0 !important; align-self:center !important;}
    @media (max-width:700px) {.stApp section[data-testid="stFileUploaderDropzone"] button {width:auto; min-width:140px !important;}}

    /* ==================================================================
       LIVE LOGIN v6  (Channel A, blue)
       Split card: an info pane on the left (what this is, what it will and
       won't do) and the sign-in form on the right. The card uses the full
       content width like the mode tiles above it, so the page lines up;
       below 900px it collapses to a single column. Provider buttons keep
       their brand colours. ================================================ */
    .live-head {margin:6px 0 6px;}
    .live-eyebrow {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.16em; text-transform:uppercase; color:#4c8dff;}
    .live-title {margin-top:9px; font:750 24px/1.2 Inter,"Segoe UI",sans-serif; letter-spacing:-.01em; color:#fff;}
    .live-sub {margin-top:4px; font-size:13px; line-height:1.5; color:var(--muted);}

    .st-key-imap_signin_card {
        --tone:#4c8dff; --pane:360px; --padx:40px;
        position:relative; overflow:hidden;
        display:grid !important; grid-template-columns:var(--pane) minmax(0,1fr); row-gap:0 !important; column-gap:0 !important;
        align-items:start; width:100% !important; max-width:1180px !important; margin:14px auto 20px !important;
        padding:34px 0 30px 0 !important;
        border:1px solid var(--line-strong) !important; border-radius:16px !important;
        background:linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), 0 18px 44px rgba(0,0,0,.35) !important;
    }
    .st-key-imap_signin_card::before {content:""; position:absolute; left:0; right:0; top:0; height:2px; background:var(--tone); z-index:3;}
    .st-key-imap_signin_card::after {                         /* tinted info pane */
        content:""; position:absolute; left:0; top:0; bottom:0; width:var(--pane); z-index:0; pointer-events:none;
        background:radial-gradient(120% 70% at 0% 0%, color-mix(in srgb, var(--tone) 13%, transparent) 0%, transparent 62%),
                   rgba(255,255,255,.012);
        border-right:1px solid var(--line-strong);
    }
    .st-key-imap_signin_card > * {position:relative; z-index:1; grid-column:2; margin:0 var(--padx) 14px var(--padx) !important; min-width:0;}
    .st-key-imap_signin_card > *:first-child {grid-column:1; grid-row:1 / span 40; margin:0 !important; padding:0 32px 0 var(--padx);}

    .signin-card-header {display:block !important; margin:0 !important;}
    .signin-card-eyebrow {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.16em; text-transform:uppercase; color:#4c8dff;}
    .signin-card-title {margin-top:12px; font:750 24px/1.2 Inter,"Segoe UI",sans-serif !important; letter-spacing:-.01em; color:#fff !important;}
    .signin-card-sub {margin-top:8px; font-size:13px !important; line-height:1.55 !important; color:var(--muted) !important;}
    .signin-facts {list-style:none; margin:26px 0 0; padding:0; display:flex; flex-direction:column; gap:16px;}
    .signin-facts li {position:relative; padding-left:18px; display:flex; flex-direction:column; gap:3px;}
    .signin-facts li::before {content:""; position:absolute; left:0; top:6px; width:7px; height:7px; border-radius:2px; background:var(--tone);}
    .signin-facts b {font:650 13px/1.3 Inter,"Segoe UI",sans-serif; color:#e6ecf4;}
    .signin-facts span {font-size:12.5px; line-height:1.5; color:var(--muted);}

    @media (max-width:900px) {
        .st-key-imap_signin_card {display:flex !important; flex-direction:column; --padx:22px; padding:26px 0 22px 0 !important;}
        .st-key-imap_signin_card::after {display:none;}
        .st-key-imap_signin_card > *:first-child {padding:0 var(--padx) 18px; margin:0 0 6px 0 !important; border-bottom:1px solid var(--line-strong);}
    }

    /* fields */
    .st-key-imap_signin_card [data-testid="stWidgetLabel"] p {
        font:600 10.5px/1.2 ui-monospace,Consolas,monospace !important; letter-spacing:.14em !important;
        text-transform:uppercase; color:var(--muted) !important;
    }
    .st-key-imap_signin_card .stTextInput input,
    .st-key-imap_signin_card div[data-baseweb="input"],
    .st-key-imap_signin_card div[data-baseweb="base-input"] {background:var(--panel-3) !important; border-radius:10px !important;}
    .st-key-imap_signin_card .stTextInput input {
        border:1px solid var(--line-strong) !important; min-height:44px; padding:0 14px !important;
        color:#eef2f7 !important; box-shadow:none !important;
    }
    .st-key-imap_signin_card .stTextInput input::placeholder {color:#5f6b79 !important;}
    .st-key-imap_signin_card .stTextInput input:focus {border-color:#4c8dff !important; box-shadow:0 0 0 3px color-mix(in srgb, #4c8dff 22%, transparent) !important;}
    .st-key-manual_login_btn {margin:12px 0 0 0 !important;}
    .st-key-manual_login_btn button {
        background:#4c8dff !important; border:1px solid #4c8dff !important; color:#fff !important;
        font:700 14.5px/1 Inter,"Segoe UI",sans-serif !important; letter-spacing:.01em;
        border-radius:10px !important; min-height:44px !important; box-shadow:none !important; transform:none !important;
    }
    .st-key-manual_login_btn button:hover {background:#6aa0ff !important; border-color:#6aa0ff !important; color:#fff !important; box-shadow:none !important; transform:none !important;}

    /* divider + note */
    .auth-divider {
        justify-content:center !important; gap:14px !important; margin:10px 0 0 0 !important;
        font:600 10.5px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.18em !important; color:var(--muted) !important;
    }
    .auth-divider::before, .auth-divider::after {background:linear-gradient(90deg, transparent, var(--line-strong), transparent) !important;}
    .st-key-imap_signin_card [data-testid="stCaptionContainer"] {text-align:center;}

    /* provider tiles */
    .st-key-auth_google_box, .st-key-auth_microsoft_box, .st-key-auth_yandex_box {padding:12px 14px 14px 20px !important; border-radius:12px !important;}
    .auth-option-label {margin-bottom:10px !important; padding-bottom:0 !important; border-bottom:0 !important;}
    .st-key-google_signin_link_btn a, .st-key-microsoft_signin_link_btn a, .st-key-yandex_signin_link_btn a {
        border-radius:10px !important; min-height:42px !important; box-shadow:none !important;
        font-size:13.5px !important; padding-left:40px !important;
    }
    .st-key-google_signin_link_btn a:hover, .st-key-microsoft_signin_link_btn a:hover, .st-key-yandex_signin_link_btn a:hover {box-shadow:0 0 0 3px rgba(255,255,255,.10) !important;}

    /* ==================================================================
       LIVE LOGIN v7  (Channel A) -- overflow fix + the acq2 card language
       1) The clipping bug: Streamlit gives every element container
          width:100%, and v6 also put left+right margins on each grid
          child, so every child was (column width + 2*margin) wide and ran
          past the card's right edge (the card is overflow:hidden, so the
          inputs, Log in and the third provider tile were cut off). The
          width is now calc(100% - 2*margin), which fits exactly.
       2) Styling now follows .acq2 / .stage-label: top hairline accent,
          mono eyebrow with a dash, tinted icon tiles, chips, a faint
          ghost glyph. The three providers keep distinct hues -- blue,
          copper, red -- instead of side stripes. ====================== */
    .st-key-imap_signin_card > * {width:calc(100% - 2 * var(--padx)) !important; max-width:none !important; box-sizing:border-box !important;}
    .st-key-imap_signin_card > *:first-child {width:100% !important;}

    .st-key-imap_signin_card::before {height:3px !important; background:linear-gradient(90deg,#4c8dff 0%,#6c9bff 34%,#d49a66 70%,#e0634a 100%) !important;}
    .st-key-imap_signin_card {
        background:
            radial-gradient(55% 45% at 100% 100%, rgba(212,154,102,.07), transparent 70%),
            radial-gradient(40% 40% at 100% 0%, rgba(76,141,255,.06), transparent 70%),
            linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
    }

    /* left pane */
    .signin-card-eyebrow {display:inline-flex; align-items:center; gap:10px;}
    .signin-card-eyebrow::before {content:""; width:18px; height:1px; background:currentColor; opacity:.65;}
    .signin-facts {margin:28px 0 0 !important; gap:12px !important;}
    .signin-facts li {flex-direction:row !important; align-items:flex-start; gap:12px !important; padding:12px !important; border:1px solid var(--line); border-radius:12px; background:rgba(255,255,255,.015); --t:#4c8dff; transition:border-color .18s var(--ease);}
    .signin-facts li::before {display:none !important;}
    .signin-facts li.sf-blue {--t:#4c8dff;}
    .signin-facts li.sf-copper {--t:#d49a66;}
    .signin-facts li.sf-green {--t:var(--green);}
    .signin-facts li:hover {border-color:color-mix(in srgb, var(--t) 40%, var(--line-strong));}
    .signin-facts .sf-ico {
        flex:0 0 34px; width:34px; height:34px; border-radius:10px; font-style:normal;
        display:flex; align-items:center; justify-content:center; color:var(--t);
        background:color-mix(in srgb, var(--t) 12%, transparent);
        border:1px solid color-mix(in srgb, var(--t) 38%, transparent);
    }
    .signin-facts .sf-ico svg {width:17px; height:17px;}
    .signin-facts .sf-txt {display:flex; flex-direction:column; gap:3px; min-width:0;}
    .signin-chips {display:flex; flex-wrap:wrap; gap:6px; margin-top:22px;}
    .signin-chips span {
        font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.06em; padding:5px 8px; border-radius:6px;
        color:#4c8dff; border:1px solid color-mix(in srgb, #4c8dff 40%, transparent); background:color-mix(in srgb, #4c8dff 8%, transparent);
    }

    /* right pane: header row, then the form */
    .signin-form-head {display:flex; align-items:center; justify-content:space-between; gap:12px; padding-bottom:12px; border-bottom:1px solid var(--line);}
    .sfh-tag {display:inline-flex; align-items:center; gap:10px; font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.18em; text-transform:uppercase; color:#4c8dff;}
    .sfh-tag::before {content:""; width:18px; height:1px; background:currentColor; opacity:.65;}
    .sfh-hint {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.14em; text-transform:uppercase; color:var(--muted);}

    /* Log in: tinted glass in the Channel A tone (same recipe as the active
       .acq2 tile) instead of a flat bright-blue slab, with a nudge arrow. */
    .st-key-manual_login_btn button {
        background:linear-gradient(180deg, color-mix(in srgb, #4c8dff 30%, #101722), color-mix(in srgb, #4c8dff 17%, #0e131a)) !important;
        border:1px solid color-mix(in srgb, #4c8dff 62%, transparent) !important; color:#fff !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.08), 0 0 0 3px color-mix(in srgb, #4c8dff 9%, transparent) !important;
        transition:border-color .18s var(--ease), background .18s var(--ease), box-shadow .18s var(--ease) !important;
    }
    .st-key-manual_login_btn button:hover {
        background:linear-gradient(180deg, color-mix(in srgb, #4c8dff 42%, #101722), color-mix(in srgb, #4c8dff 26%, #0e131a)) !important;
        border-color:#6c9bff !important; box-shadow:inset 0 1px 0 rgba(255,255,255,.10), 0 0 0 4px color-mix(in srgb, #4c8dff 14%, transparent) !important;
    }
    .st-key-manual_login_btn button p::after {content:"\2192"; display:inline-block; margin-left:10px; transition:transform .18s var(--ease);}
    .st-key-manual_login_btn button:hover p::after {transform:translateX(4px);}

    /* divider + helper line: real breathing room, no collision */
    .st-key-imap_signin_card > *:has(.auth-divider) {margin-top:10px !important; margin-bottom:8px !important;}
    .auth-divider {margin:0 !important; font:600 10.5px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.2em !important; text-transform:uppercase !important;}
    .st-key-imap_signin_card > *:has([data-testid="stCaptionContainer"]) {margin-bottom:16px !important;}
    .st-key-imap_signin_card > *:has([data-testid="stCaptionContainer"]) [data-testid="stCaptionContainer"] {font-size:12px !important; line-height:1.5 !important; color:var(--muted) !important; max-width:62ch; margin:0 auto;}

    /* provider tiles: one shared tile, three hues */
    .st-key-imap_signin_card .st-key-auth_google_box {--tone:#4c8dff;}
    .st-key-imap_signin_card .st-key-auth_microsoft_box {--tone:#d49a66;}
    .st-key-imap_signin_card .st-key-auth_yandex_box {--tone:#e0634a;}
    .st-key-imap_signin_card .st-key-auth_google_box,
    .st-key-imap_signin_card .st-key-auth_microsoft_box,
    .st-key-imap_signin_card .st-key-auth_yandex_box {
        position:relative; overflow:hidden !important; min-width:0; padding:16px 16px 16px 16px !important;
        border:1px solid var(--line-strong) !important; border-radius:14px !important;
        background:
            radial-gradient(90% 120% at 100% 100%, color-mix(in srgb, var(--tone) 14%, transparent) 0%, transparent 62%),
            linear-gradient(180deg, var(--panel), var(--panel-3)) !important;
        box-shadow:none !important;
        transition:border-color .18s var(--ease), box-shadow .18s var(--ease) !important;
    }
    .st-key-imap_signin_card .st-key-auth_google_box::before,
    .st-key-imap_signin_card .st-key-auth_microsoft_box::before,
    .st-key-imap_signin_card .st-key-auth_yandex_box::before {
        content:""; position:absolute; left:0; right:0; top:0; bottom:auto; width:auto; height:2px;
        border-radius:0; background:var(--tone) !important; opacity:.85; z-index:2; pointer-events:none;
    }
    .st-key-imap_signin_card .st-key-auth_google_box::after,
    .st-key-imap_signin_card .st-key-auth_microsoft_box::after,
    .st-key-imap_signin_card .st-key-auth_yandex_box::after {
        content:""; position:absolute; right:-8px; bottom:-16px; width:92px; height:92px; z-index:0; pointer-events:none;
        background:var(--tone); opacity:.09;
        -webkit-mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='5' width='18' height='14' rx='2'/%3E%3Cpath d='M3 7l9 6 9-6'/%3E%3C/svg%3E") center/contain no-repeat;
        mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='5' width='18' height='14' rx='2'/%3E%3Cpath d='M3 7l9 6 9-6'/%3E%3C/svg%3E") center/contain no-repeat;
    }
    .st-key-imap_signin_card .st-key-auth_google_box > *,
    .st-key-imap_signin_card .st-key-auth_microsoft_box > *,
    .st-key-imap_signin_card .st-key-auth_yandex_box > * {position:relative; z-index:1;}
    .st-key-imap_signin_card .st-key-auth_google_box:hover,
    .st-key-imap_signin_card .st-key-auth_microsoft_box:hover,
    .st-key-imap_signin_card .st-key-auth_yandex_box:hover {
        border-color:color-mix(in srgb, var(--tone) 55%, var(--line-strong)) !important;
        box-shadow:0 0 0 3px color-mix(in srgb, var(--tone) 10%, transparent) !important;
    }
    .st-key-imap_signin_card .auth-option-label {color:var(--tone) !important; margin-bottom:12px !important; gap:9px !important;}
    .st-key-imap_signin_card .auth-option-label::after {
        content:"OAuth 2.0"; margin-left:auto; font:600 9.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.12em;
        text-transform:uppercase; color:var(--muted); padding:4px 6px; border:1px solid var(--line-strong); border-radius:5px;
    }

    /* "Set IMAP server / port manually": centred under the card, aligned to it */
    .stApp .st-key-imap_custom_toggle_btn {display:flex !important; justify-content:center !important; max-width:1180px; margin:2px auto 22px !important;}
    .stApp .st-key-imap_custom_toggle_btn button {
        background:transparent !important; border:1px dashed var(--line-strong) !important; border-radius:999px !important;
        padding:9px 18px !important; min-height:0 !important; box-shadow:none !important; text-decoration:none !important;
        color:var(--muted) !important; font:600 10.5px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.14em !important; text-transform:uppercase;
        transition:border-color .18s var(--ease), color .18s var(--ease) !important;
    }
    .stApp .st-key-imap_custom_toggle_btn button p::before {content:"\2699\FE0E"; margin-right:9px; font-size:12px;}
    .stApp .st-key-imap_custom_toggle_btn button:hover {border-color:#4c8dff !important; color:#fff !important; text-decoration:none !important;}

    /* ==================================================================
       LIVE LOGIN v8  (Channel A) -- compact card, refined left panel + form.
       CSS only. The provider tiles keep their v7 look; the "Set IMAP server /
       port manually" toggle now sits inside the card under them. Delete this
       block to go back to v7.
       ================================================================== */
    .st-key-imap_signin_card {
        --pane:340px; --padx:36px;
        --c-blue:#4c8dff; --c-indigo:#8b7cff; --c-amber:#e0a458; --c-mint:#4fc3a1;
        grid-template-rows:repeat(24, min-content) minmax(0,1fr) !important;
        align-content:start !important;
        margin-top:10px !important;
        padding:0 0 26px 0 !important;
    }
    .st-key-imap_signin_card > * {margin-top:0 !important;}
    .st-key-imap_signin_card > *:first-child {grid-row:1 / span 25 !important; padding:0 !important;}
    .st-key-imap_signin_card > *:nth-child(2) {margin-top:30px !important;}

    /* Streamlit gives every st.markdown a -1rem bottom margin (cancelled by a <p>'s
       margin; our raw <div> markup has no <p>), which pulled the next element up
       over it -- the "OR CONTINUE WITH" / caption overlap. Neutralise it here. */
    .st-key-imap_signin_card [data-testid="stMarkdown"] {margin-bottom:0 !important;}

    /* left pane */
    .st-key-imap_signin_card::after {
        background:
            radial-gradient(circle at center, transparent 0 38%, rgba(139,124,255,.16) 38.4%, transparent 39.2%) right -80px bottom -80px / 300px 300px no-repeat,
            radial-gradient(circle at center, transparent 0 56%, rgba(76,141,255,.14) 56.4%, transparent 57.2%) right -80px bottom -80px / 300px 300px no-repeat,
            radial-gradient(circle at center, transparent 0 74%, rgba(79,195,161,.12) 74.4%, transparent 75.2%) right -80px bottom -80px / 300px 300px no-repeat,
            radial-gradient(circle at center, transparent 0 92%, rgba(224,164,88,.10) 92.4%, transparent 93.2%) right -80px bottom -80px / 300px 300px no-repeat,
            radial-gradient(120% 55% at 0% 0%, rgba(76,141,255,.20), transparent 65%),
            radial-gradient(90% 45% at 100% 100%, rgba(139,124,255,.14), transparent 70%),
            linear-gradient(180deg, #121a2b 0%, #0e1521 100%) !important;
        border-right:1px solid #243046 !important;
    }
    .signin-card-header {padding:34px 28px 26px var(--padx) !important; box-sizing:border-box; width:100%;}
    .signin-card-eyebrow {
        display:inline-flex; align-items:center; gap:9px; padding:5px 11px 5px 9px; border-radius:999px;
        font:600 10px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.14em !important; text-transform:uppercase;
        color:#9fbfff !important; background:rgba(76,141,255,.10); border:1px solid rgba(76,141,255,.32);
    }
    .signin-card-eyebrow::before {width:6px !important; height:6px !important; border-radius:50%; background:var(--c-blue) !important; opacity:1 !important; box-shadow:0 0 0 3px rgba(76,141,255,.22);}
    .signin-card-title {margin-top:16px !important; font:750 25px/1.14 Inter,"Segoe UI",sans-serif !important; letter-spacing:-.025em !important;
        background:linear-gradient(180deg,#fff 30%,#b9c8e6); -webkit-background-clip:text; background-clip:text; color:transparent !important; -webkit-text-fill-color:transparent;}
    .signin-card-sub {margin-top:8px !important; font-size:13px !important; line-height:1.55 !important; color:#9aa7ba !important;}

    .signin-facts {margin:30px 0 0 !important; gap:0 !important;}
    .signin-facts li {padding:0 0 26px 0 !important; border:0 !important; border-radius:0 !important; background:none !important; gap:14px !important; position:relative;}
    .signin-facts li:last-child {padding-bottom:0 !important;}
    .signin-facts li:hover {border:0 !important;}
    .signin-facts li.sf-blue {--t:var(--c-blue);}
    .signin-facts li.sf-copper {--t:var(--c-amber);}
    .signin-facts li.sf-green {--t:var(--c-mint);}
    .signin-facts li:not(:last-child)::after {content:""; position:absolute; left:17px; top:42px; bottom:6px; width:1px;
        background:linear-gradient(180deg, color-mix(in srgb, var(--t) 55%, transparent), rgba(255,255,255,.05));}
    .signin-facts .sf-ico {flex:0 0 36px !important; width:36px !important; height:36px !important; border-radius:11px !important;
        background:linear-gradient(145deg, color-mix(in srgb, var(--t) 22%, #0f1623), color-mix(in srgb, var(--t) 8%, #0f1623)) !important;
        border:1px solid color-mix(in srgb, var(--t) 50%, transparent) !important; box-shadow:0 6px 14px color-mix(in srgb, var(--t) 12%, transparent), inset 0 1px 0 rgba(255,255,255,.07);}
    .signin-facts .sf-ico svg {width:17px; height:17px;}
    .signin-facts .sf-txt {padding-top:1px; gap:3px !important;}
    .signin-facts b {font:650 14px/1.3 Inter,"Segoe UI",sans-serif !important; color:#f1f5fb !important;}
    .signin-facts span {font-size:12.5px !important; line-height:1.5 !important; color:#8d99ac !important;}

    .signin-chips {margin-top:30px !important; padding-top:16px; border-top:1px solid #243046; gap:6px !important;}
    .signin-chips span {font:600 10px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.02em !important; padding:5px 8px !important; border-radius:999px !important;}
    .signin-chips span:nth-child(1) {color:#9dbcff !important; border-color:rgba(76,141,255,.4) !important; background:rgba(76,141,255,.10) !important;}
    .signin-chips span:nth-child(2) {color:#ecc088 !important; border-color:rgba(224,164,88,.4) !important; background:rgba(224,164,88,.10) !important;}
    .signin-chips span:nth-child(3) {color:#86d9bf !important; border-color:rgba(79,195,161,.4) !important; background:rgba(79,195,161,.10) !important;}

    /* right pane heading */
    .signin-form-head {align-items:center !important; padding-bottom:14px !important; border-bottom:1px solid #243046 !important;}
    .st-key-imap_signin_card > *:has(.signin-form-head) {margin-bottom:16px !important;}
    .sfh-tag {font:700 17px/1.2 Inter,"Segoe UI",sans-serif !important; letter-spacing:-.01em !important; text-transform:none !important; color:#fff !important; gap:0 !important;}
    .sfh-tag::before {display:none !important;}
    .sfh-hint {font:600 10px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.12em !important; color:#8d99ac !important;
        padding:6px 10px; border:1px solid #2a3750; border-radius:999px; background:rgba(255,255,255,.02);}

    /* fields */
    .st-key-imap_signin_card [data-testid="stWidgetLabel"] p {font:600 12.5px/1.2 Inter,"Segoe UI",sans-serif !important; letter-spacing:0 !important; text-transform:none !important; color:#b3bdcb !important;}
    .st-key-imap_signin_card .stTextInput input {
        min-height:44px !important; padding:0 14px 0 44px !important; font-size:14px !important;
        background-color:#0c121c !important; border:1px solid #2a3750 !important; border-radius:10px !important; color:#eef2f7 !important;
        background-repeat:no-repeat !important; background-position:15px center !important; background-size:17px 17px !important;
        box-shadow:inset 0 1px 2px rgba(0,0,0,.35) !important;
    }
    .st-key-imap_signin_card .stTextInput input:hover {border-color:#3b4a66 !important;}
    .st-key-imap_signin_card .stTextInput input:focus {border-color:var(--c-blue) !important; box-shadow:0 0 0 3px rgba(76,141,255,.22) !important;}
    .st-key-imap_signin_card .st-key-imap_user input {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%238d99ac' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='5' width='18' height='14' rx='2.5'/%3E%3Cpath d='M3.5 7.5l8.5 6 8.5-6'/%3E%3C/svg%3E") !important;}
    .st-key-imap_signin_card .st-key-imap_manual_password input {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%238d99ac' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='4' y='11' width='16' height='10' rx='2.5'/%3E%3Cpath d='M8 11V8a4 4 0 018 0v3'/%3E%3C/svg%3E") !important;}

    /* Log in: same graphite-key family as the rest of the app's buttons --
       dark fill, thin blue->indigo->copper edge, no saturated gradient slab. */
    .st-key-manual_login_btn {margin:6px 0 0 0 !important;}
    .st-key-manual_login_btn button {
        min-height:44px !important; border-radius:10px !important;
        background:
            linear-gradient(180deg,#1b2638,#111926) padding-box,
            linear-gradient(115deg,#3b82f6 0%,#6366f1 55%,#c98a5c 100%) border-box !important;
        background-origin:border-box !important; background-clip:padding-box, border-box !important;
        border:1px solid transparent !important; color:#eef3fa !important;
        font:650 14px/1 Inter,"Segoe UI",sans-serif !important; letter-spacing:.02em !important;
        box-shadow:0 1px 2px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.06) !important;
    }
    .st-key-manual_login_btn button::after {background:linear-gradient(115deg,#3b82f6,#6366f1) !important; border-radius:9px;}
    .st-key-manual_login_btn button:hover {
        background:
            linear-gradient(180deg,#202d42,#131c2b) padding-box,
            linear-gradient(115deg,#5b9bf8 0%,#7c7ff3 55%,#d99a66 100%) border-box !important;
        background-origin:border-box !important; background-clip:padding-box, border-box !important;
        color:#fff !important; transform:translateY(-1px) !important;
        box-shadow:0 10px 24px -12px rgba(99,102,241,.65), inset 0 1px 0 rgba(255,255,255,.08) !important;
    }
    .st-key-manual_login_btn button:hover::after {opacity:.14 !important;}

    /* divider/caption spacing (helper text itself is unchanged) */
    .st-key-imap_signin_card > *:has(.auth-divider) {margin-top:18px !important; margin-bottom:6px !important;}
    .st-key-imap_signin_card > *:has([data-testid="stCaptionContainer"]) {margin-bottom:12px !important;}
    /* The tiles are height:100% + padding on a content-box, so each rendered ~34px taller than its
       grid row measured and ran over whatever sat beneath. border-box makes them fit exactly. */
    .st-key-imap_signin_card .st-key-auth_google_box,
    .st-key-imap_signin_card .st-key-auth_microsoft_box,
    .st-key-imap_signin_card .st-key-auth_yandex_box {box-sizing:border-box !important;}
    .st-key-imap_signin_card > *:has([data-testid="stHorizontalBlock"]) {margin-bottom:18px !important;}

    /* IMAP toggle now lives inside the card, under the provider tiles */
    .st-key-imap_signin_card .st-key-imap_custom_toggle_btn {display:flex !important; justify-content:center !important; max-width:none; margin:2px var(--padx) 0 !important;}
    .st-key-imap_signin_card .st-key-imap_custom_toggle_btn button {padding:8px 16px !important;}

    /* ---- v9 login polish -------------------------------------------------
       a) "OR CONTINUE WITH" + helper note live in ONE block now, in normal
          flow, so they can't collide (Streamlit's negative markdown margin
          used to drag the note up onto the divider). The padding-bottom
          cancels that margin wherever it is applied.
       b) Gmail button label: solid dark text on the white pill.
       c) "Set IMAP server / port manually": full-width row that matches the
          provider tiles instead of a floating dashed pill.
       Delete this block to go back to v8. ----------------------------- */
    .auth-divider-wrap {display:flex; flex-direction:column; align-items:center; gap:12px; padding-bottom:16px;}
    .auth-divider-wrap .auth-divider {width:100%; margin:0 !important; line-height:1 !important; color:#9aa7ba !important;}
    .auth-divider-wrap .auth-note {
        margin:0 !important; max-width:56ch; text-align:center;
        font:400 12.5px/1.55 Inter,"Segoe UI",sans-serif !important; color:#8d99ac !important;
    }

    .st-key-imap_signin_card .st-key-google_signin_link_btn a,
    .st-key-imap_signin_card .st-key-google_signin_link_btn a *,
    .st-key-imap_signin_card .st-key-google_signin_link_btn a:hover,
    .st-key-imap_signin_card .st-key-google_signin_link_btn a:hover * {
        color:#1f2328 !important; -webkit-text-fill-color:#1f2328 !important;
        opacity:1 !important; text-shadow:none !important;
    }
    .st-key-imap_signin_card .st-key-google_signin_link_btn a,
    .st-key-imap_signin_card .st-key-google_signin_link_btn a p {font-weight:650 !important; font-size:14px !important; letter-spacing:.01em !important;}

    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn {display:block !important; margin:6px var(--padx) 0 !important;}
    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn [data-testid="stButton"],
    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn .stButton {width:100% !important;}
    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn button {
        width:100% !important; min-height:46px !important; padding:0 14px 0 10px !important;
        display:flex !important; align-items:center !important; justify-content:flex-start !important;
        background:linear-gradient(180deg, rgba(255,255,255,.035), rgba(255,255,255,.012)) !important;
        border:1px solid #2a3750 !important; border-radius:12px !important; box-shadow:none !important;
        color:#c3cddb !important; text-transform:none !important; letter-spacing:0 !important;
        font:600 13px/1.2 Inter,"Segoe UI",sans-serif !important;
        transition:border-color .18s var(--ease), background .18s var(--ease), color .18s var(--ease) !important;
    }
    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn button > div {width:100% !important;}
    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn button p {
        display:flex !important; align-items:center !important; gap:12px; width:100%; margin:0 !important;
        font:600 13px/1.2 Inter,"Segoe UI",sans-serif !important; letter-spacing:0 !important; text-transform:none !important;
    }
    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn button p::before {
        content:"\2699\FE0E"; margin:0 !important; flex:0 0 28px; width:28px; height:28px; border-radius:8px;
        display:inline-flex; align-items:center; justify-content:center; font-size:15px; color:#9fbfff;
        background:rgba(76,141,255,.12); border:1px solid rgba(76,141,255,.35);
    }
    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn button p::after {
        content:"\203A"; margin-left:auto; font-size:20px; line-height:1; color:#6f7d92; transition:transform .18s var(--ease), color .18s var(--ease);
    }
    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn button:hover {
        border-color:rgba(76,141,255,.6) !important; color:#fff !important; text-decoration:none !important;
        background:linear-gradient(180deg, rgba(76,141,255,.12), rgba(76,141,255,.04)) !important;
    }
    .stApp .st-key-imap_signin_card .st-key-imap_custom_toggle_btn button:hover p::after {transform:translateX(3px); color:#9fbfff;}

    /* ---- v11 workflow nav (FORENSIC WORKFLOW / ACTIVE MODULE) -------------
       Single-row, horizontally scrollable tab strip sized to match the rest
       of the app (15px Inter, same as the buttons and headings). Slim themed
       scrollbar, soft fade at both edges, wheel / drag scrolling, and the
       active tab is scrolled into view (small script after the nav). Each
       module has its own colour + icon (generated from NAV_OPTIONS).
       The collapsed widget title is hidden -- it was being styled as a tab.
       Delete this block (and the _NAV_STYLE generator) to go back. ------ */

    .stApp .st-key-topnav {
        position:relative !important; overflow:hidden !important;
        padding:10px 4px 20px 4px !important; margin:4px 0 8px 0 !important; border:1px solid #243046 !important; border-radius:16px !important;
        background:
            radial-gradient(50% 160% at 0% 0%, rgba(76,141,255,.09), transparent 70%),
            radial-gradient(40% 160% at 100% 100%, rgba(212,154,102,.07), transparent 70%),
            linear-gradient(180deg,#101826,#0a1019) !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), 0 14px 30px -18px rgba(0,0,0,.8) !important;
    }
    .stApp .st-key-topnav::before {
        content:""; position:absolute; left:0; right:0; top:0; height:2px; z-index:2; opacity:.85; pointer-events:none;
        background:linear-gradient(90deg,#4c8dff 0%,#8b7cff 30%,#34d399 55%,#d49a66 80%,#e0634a 100%);
    }
    /* slim scroll indicator (native bar is hidden): --nav-w = visible fraction,
       --nav-p = scroll position 0..1, --nav-on = 1 only when the strip overflows.
       All three are set by the helper script after the nav. */
    .stApp .st-key-topnav::after {
        content:"" !important; display:block !important; position:absolute; left:28px; right:28px; bottom:8px; height:3px; border-radius:3px;
        pointer-events:none; opacity:var(--nav-on,0); transition:opacity .25s var(--ease);
        background:
            linear-gradient(90deg,#3b82f6,#8b7cff) no-repeat,
            rgba(255,255,255,.06);
        background-size:calc(var(--nav-w,1) * 100%) 100%, 100% 100%;
        background-position:calc(var(--nav-p,0) * 100%) 0, 0 0;
    }
    .stApp .st-key-topnav .stRadio [data-testid="stWidgetLabel"],
    .stApp .st-key-topnav .stRadio label[data-testid="stWidgetLabel"] {
        display:none !important; height:0 !important; width:0 !important; margin:0 !important; padding:0 !important;
        border:0 !important; overflow:hidden !important; visibility:hidden !important;
    }

    /* the scroller */
    .stApp .st-key-topnav [data-testid="stRadio"] [role="radiogroup"],
    .stApp .st-key-topnav .stRadio > div:not([data-testid="stWidgetLabel"]) {
        display:flex !important; flex-wrap:nowrap !important; align-items:stretch !important; gap:6px !important; width:100% !important;
        background:none !important; border:0 !important; border-radius:0 !important; box-shadow:none !important;
        padding:4px 26px !important; box-sizing:border-box !important;
        overflow-x:auto !important; overflow-y:hidden !important; scroll-behavior:auto !important; scroll-snap-type:none !important;
        overscroll-behavior-x:contain !important; -webkit-overflow-scrolling:touch !important; cursor:grab;
        scrollbar-width:none !important; -ms-overflow-style:none !important;
        -webkit-mask-image:linear-gradient(90deg, transparent 0, #000 26px, #000 calc(100% - 26px), transparent 100%);
        mask-image:linear-gradient(90deg, transparent 0, #000 26px, #000 calc(100% - 26px), transparent 100%);
    }

    /* no radio marker, however deep Streamlit nests it */
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label *:not(:has(p)):not(p):not(p *),
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label input,
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label svg,
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label::before {
        display:none !important; width:0 !important; height:0 !important; min-width:0 !important; margin:0 !important; padding:0 !important;
        border:0 !important; box-shadow:none !important; background:none !important; opacity:0 !important;
        position:absolute !important; left:-9999px !important; pointer-events:none !important;
    }

    .stApp .st-key-topnav .stRadio [role="radiogroup"] label {
        position:relative !important; flex:0 0 auto !important;
        display:flex !important; align-items:center !important; justify-content:center !important;
        padding:13px 20px !important; border-radius:12px !important; cursor:pointer !important;
        border:1px solid transparent !important; background:transparent !important; box-shadow:none !important;
        transform:none !important; overflow:hidden !important;
        transition:background .2s var(--ease), border-color .2s var(--ease), box-shadow .22s var(--ease), transform .2s var(--ease) !important;
    }
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label > div {width:auto !important; margin:0 !important;}
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label p {
        display:inline-flex !important; align-items:center; gap:10px; margin:0 !important; white-space:nowrap !important;
        font:600 15px/1.2 Inter,"Segoe UI",Arial,sans-serif !important; letter-spacing:.005em !important; color:#a9b6c8 !important;
        transition:color .2s var(--ease);
    }
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label p::before {
        content:""; flex:0 0 18px; width:18px; height:18px; background-color:var(--c,#4c8dff); opacity:.8;
        -webkit-mask-repeat:no-repeat; mask-repeat:no-repeat; -webkit-mask-position:center; mask-position:center;
        -webkit-mask-size:contain; mask-size:contain;
        transition:opacity .2s var(--ease), transform .25s var(--ease), filter .25s var(--ease);
    }
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label::after {
        content:""; position:absolute; left:50%; bottom:0; width:0; height:2px; border-radius:2px; transform:translateX(-50%);
        background:var(--c,#4c8dff); transition:width .25s var(--ease), box-shadow .25s var(--ease);
    }

    .stApp .st-key-topnav .stRadio [role="radiogroup"] label:hover {
        background:color-mix(in srgb, var(--c,#4c8dff) 11%, transparent) !important;
        border-color:color-mix(in srgb, var(--c,#4c8dff) 30%, transparent) !important;
        transform:translateY(-1px) !important;
    }
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label:hover p {color:#fff !important;}
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label:hover p::before {opacity:1; transform:translateY(-1px) scale(1.12);}
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label:hover::after {width:42%;}

    .stApp .st-key-topnav .stRadio [role="radiogroup"] label:has(input:checked) {
        background:
            linear-gradient(180deg, color-mix(in srgb, var(--c,#4c8dff) 26%, #0f1724), color-mix(in srgb, var(--c,#4c8dff) 9%, #0b111a)) padding-box,
            linear-gradient(140deg, var(--c,#4c8dff), color-mix(in srgb, var(--c,#4c8dff) 16%, transparent) 72%) border-box !important;
        border:1px solid transparent !important; transform:none !important;
        box-shadow:0 10px 20px -16px var(--c,#4c8dff), inset 0 1px 0 rgba(255,255,255,.08) !important;
        animation:navPop .35s var(--ease);
    }
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label:has(input:checked) p {color:#fff !important; font-weight:700 !important;}
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label:has(input:checked) p::before {opacity:1; filter:drop-shadow(0 0 6px var(--c,#4c8dff));}
    .stApp .st-key-topnav .stRadio [role="radiogroup"] label:has(input:checked)::after {width:calc(100% - 32px); box-shadow:0 0 12px var(--c,#4c8dff);}
    @keyframes navPop {from {transform:translateY(3px); opacity:.65;} to {transform:none; opacity:1;}}
    @media (prefers-reduced-motion: reduce) {
        .stApp .st-key-topnav .stRadio [role="radiogroup"] label, .stApp .st-key-topnav .stRadio [role="radiogroup"] label::after {transition:none !important; animation:none !important;}
        .stApp .st-key-topnav [role="radiogroup"] {scroll-behavior:auto !important;}
    }
    /* the zero-height helper iframe must not leave a gap */
    .stApp [data-testid="stElementContainer"]:has(iframe[height="0"]), .stApp .stElementContainer:has(iframe[height="0"]) {
        position:absolute !important; height:0 !important; margin:0 !important; overflow:hidden !important; visibility:hidden !important;
    }

    .stApp .st-key-topnav [role="radiogroup"]::-webkit-scrollbar {display:none !important; width:0 !important; height:0 !important;}

    /* ---- v11 sidebar ------------------------------------------------------
       Same language as the main panels: graphite glass, thin blue/violet
       glow, per-section colours, an icon on every item. Hover tints the row
       in its own colour and nudges it; the active row is a solid tinted key
       with a coloured edge, a glowing spine and a lit dot. Per-item colour
       and icon come from _SB_NAV_STYLE (Python, just above the sidebar).
       Delete this block to go back to the old violet sidebar. ------------- */
    .stApp [data-testid="stSidebar"] {
        background:
            radial-gradient(90% 36% at 0% 0%, rgba(76,141,255,.11), transparent 70%),
            radial-gradient(80% 32% at 100% 100%, rgba(139,124,255,.08), transparent 70%),
            linear-gradient(180deg,#0c1322 0%,#080d16 60%,#070b12 100%) !important;
        border-right:1px solid #1a2538 !important;
        box-shadow:inset -1px 0 0 rgba(255,255,255,.02), 18px 0 40px -30px rgba(0,0,0,.9) !important;
        scrollbar-color:#2a3750 transparent;
    }
    .stApp [data-testid="stSidebar"] > div {background:transparent !important;}
    .stApp [data-testid="stSidebar"] [data-testid="stSidebarUserContent"] {padding-left:14px !important; padding-right:14px !important; padding-bottom:28px !important;}

    /* brand card */
    .stApp .sidebar-brand-v2 {
        position:relative; overflow:hidden; margin:8px 0 14px 0; padding:17px 16px 16px 16px;
        border:1px solid #243046; border-bottom:1px solid #243046; border-radius:16px;
        background:
            radial-gradient(90% 130% at 0% 0%, rgba(76,141,255,.16), transparent 62%),
            linear-gradient(180deg,#101826,#0b111a);
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), 0 14px 28px -20px rgba(0,0,0,.9);
    }
    .stApp .sidebar-brand-v2::before {
        content:""; position:absolute; left:0; right:0; top:0; height:2px; opacity:.9;
        background:linear-gradient(90deg,#4c8dff,#8b7cff 45%,#d49a66 80%,#e0634a);
    }
    .stApp .sidebar-brand-v2 .brand-row {gap:12px;}
    .stApp .sidebar-brand-v2 .brand-mark {
        width:44px; height:44px; flex:0 0 44px; border-radius:13px; border:1px solid rgba(76,141,255,.5);
        background:linear-gradient(145deg,#15233b,#0c1524);
        box-shadow:0 0 0 3px rgba(76,141,255,.10), 0 10px 20px -10px rgba(76,141,255,.8), inset 0 1px 0 rgba(255,255,255,.08);
    }
    .stApp .sidebar-brand-v2 .brand-text .name {
        font:800 15.5px/1.1 Inter,"Segoe UI",sans-serif; letter-spacing:.14em;
        background:linear-gradient(180deg,#fff 30%,#a9c3f2); -webkit-background-clip:text; background-clip:text;
        -webkit-text-fill-color:transparent; color:transparent !important;
    }
    .stApp .sidebar-brand-v2 .brand-text .role {font:600 9px/1.3 ui-monospace,Consolas,monospace; letter-spacing:.14em; color:#7f98b3 !important; margin-top:5px;}
    .stApp .sidebar-brand-v2 .brand-meta {
        display:inline-flex; align-items:center; gap:8px; margin-top:13px; padding:6px 11px; border-radius:999px;
        font:700 9.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.14em; text-transform:uppercase;
        color:#6ee7b7 !important; border:1px solid rgba(52,211,153,.38); background:rgba(52,211,153,.08);
    }
    .stApp .sidebar-brand-v2 .brand-dot {width:6px; height:6px; background:#34d399; box-shadow:0 0 0 3px rgba(52,211,153,.22), 0 0 10px rgba(52,211,153,.9);}

    /* section headers */
    .stApp .sidebar-group-label {--g:#4c8dff; margin:34px 6px 14px 6px !important; gap:10px !important;
        font:700 10.5px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.16em !important;
        color:color-mix(in srgb, var(--g) 62%, #8d99ac) !important;}
    .stApp .sidebar-group-label.sidebar-group-green {--g:#34d399;}
    .stApp .sidebar-group-label.sidebar-group-violet {--g:#a78bfa;}
    .stApp .sidebar-group-label.sidebar-group-rose {--g:#fb7185;}
    .stApp .sidebar-group-label.sidebar-group-slate {--g:#94a3b8;}
    .stApp .sidebar-group-label .grp-index {
        color:var(--g) !important; font:700 9.5px/1 ui-monospace,Consolas,monospace !important; letter-spacing:.04em;
        padding:4px 6px !important; border-radius:999px !important;
        border:1px solid color-mix(in srgb, var(--g) 50%, transparent) !important;
        background:color-mix(in srgb, var(--g) 13%, #0a111b) !important;
    }
    .stApp .sidebar-group-label:after {
        background:linear-gradient(90deg, color-mix(in srgb, var(--g) 50%, transparent), transparent) !important;
    }

    /* nav rows */
    .stApp [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {gap:.5rem !important;}
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button {
        position:relative !important; min-height:46px !important; padding:11px 16px !important; border-radius:12px !important;
        border:1px solid transparent !important; background:transparent !important; box-shadow:none !important;
        color:#a9b6c8 !important; transform:none !important; overflow:hidden !important;
        transition:background .2s var(--ease), border-color .2s var(--ease), box-shadow .2s var(--ease), transform .2s var(--ease) !important;
    }
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button p {
        display:flex !important; align-items:center !important; gap:14px; width:100% !important; margin:0 !important;
        font:600 14px/1.2 Inter,"Segoe UI",sans-serif !important; letter-spacing:.005em !important; color:#a9b6c8 !important;
        transition:color .2s var(--ease);
    }
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button p::before {
        content:""; flex:0 0 18px; width:18px; height:18px; background-color:var(--c,#4c8dff); opacity:.78;
        -webkit-mask-repeat:no-repeat; mask-repeat:no-repeat; -webkit-mask-position:center; mask-position:center;
        -webkit-mask-size:contain; mask-size:contain;
        transition:opacity .2s var(--ease), transform .25s var(--ease), filter .25s var(--ease);
    }
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button p::after {
        content:"\203A"; margin-left:auto; font-size:20px; line-height:1; color:var(--c,#4c8dff);
        opacity:0; transform:translateX(-6px); transition:opacity .2s var(--ease), transform .2s var(--ease);
    }
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button::before {
        content:""; position:absolute; left:0; top:9px; bottom:9px; width:3px; border-radius:0 3px 3px 0;
        background:var(--c,#4c8dff); opacity:0; transform:scaleY(.3);
        transition:opacity .2s var(--ease), transform .2s var(--ease);
    }
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button:hover {
        background:color-mix(in srgb, var(--c,#4c8dff) 10%, transparent) !important;
        border-color:color-mix(in srgb, var(--c,#4c8dff) 30%, transparent) !important;
        transform:translateX(2px) !important; padding-left:16px !important;
    }
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button:hover p {color:#fff !important;}
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button:hover p::before {opacity:1; transform:scale(1.14);}
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button:hover p::after {opacity:.85; transform:none;}
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button:hover::before {opacity:.55; transform:scaleY(.7);}
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button:active {transform:scale(.985) !important; transition-duration:.08s !important;}

    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button[kind="primary"] {
        background:
            linear-gradient(90deg, color-mix(in srgb, var(--c,#4c8dff) 26%, #0f1724), color-mix(in srgb, var(--c,#4c8dff) 7%, #0b111a)) padding-box,
            linear-gradient(120deg, var(--c,#4c8dff), color-mix(in srgb, var(--c,#4c8dff) 14%, transparent) 75%) border-box !important;
        border:1px solid transparent !important; padding-left:16px !important; transform:none !important;
        box-shadow:0 12px 22px -16px var(--c,#4c8dff), inset 0 1px 0 rgba(255,255,255,.07) !important;
    }
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button[kind="primary"] p {color:#fff !important; font-weight:700 !important;}
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button[kind="primary"] p::before {opacity:1; filter:drop-shadow(0 0 6px var(--c,#4c8dff));}
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button[kind="primary"] p::after {
        content:""; width:7px; height:7px; border-radius:50%; background:var(--c,#4c8dff); opacity:1; transform:none; margin-right:2px;
        box-shadow:0 0 0 3px color-mix(in srgb, var(--c,#4c8dff) 25%, transparent), 0 0 10px var(--c,#4c8dff);
    }
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button[kind="primary"]::before {
        opacity:1 !important; transform:scaleY(1) !important; box-shadow:0 0 10px var(--c,#4c8dff);
    }
    .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button[kind="primary"]:hover {transform:none !important;}

    /* status card */
    .stApp .sidebar-status-card-v2 {
        margin-top:32px; padding:17px 17px 14px 19px; border:1px solid #243046; border-radius:16px;
        background:
            radial-gradient(80% 120% at 0% 0%, rgba(52,211,153,.10), transparent 62%),
            linear-gradient(180deg,#101826,#0b111a);
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), 0 14px 28px -20px rgba(0,0,0,.9);
    }
    .stApp .sidebar-status-card-v2:hover {border-color:#2f4363; box-shadow:inset 0 1px 0 rgba(255,255,255,.04), 0 16px 30px -18px rgba(0,0,0,.95);}
    .stApp .sidebar-status-card-v2:before {top:16px; bottom:16px; width:3px; border-radius:0 3px 3px 0; background:linear-gradient(180deg,#34d399,rgba(52,211,153,.15));}
    .stApp .sidebar-status-card-v2 .ssc-head {gap:9px; margin-bottom:14px;}
    .stApp .sidebar-status-card-v2 .ssc-pulse {background:#34d399; box-shadow:0 0 0 3px rgba(52,211,153,.22), 0 0 10px rgba(52,211,153,.9);}
    .stApp .sidebar-status-card-v2 .ssc-title {font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.16em; color:#6ee7b7 !important;}
    .stApp .sidebar-status-card-v2 .ssc-grid {gap:10px;}
    .stApp .sidebar-status-card-v2 .ssc-tile {padding:11px 12px; border-radius:12px; border:1px solid rgba(76,141,255,.3); background:rgba(76,141,255,.06);}
    .stApp .sidebar-status-card-v2 .ssc-tile:hover {border-color:#4c8dff; transform:translateY(-1px);}
    .stApp .sidebar-status-card-v2 .ssc-tile-value {font:750 23px/1.1 Inter,"Segoe UI",sans-serif; color:#9dbcff !important;}
    .stApp .sidebar-status-card-v2 .ssc-tile-label {font-size:10px; color:#8d99ac !important; margin-top:4px; letter-spacing:.02em;}
    .stApp .sidebar-status-card-v2 .ssc-tile-alert {border-color:rgba(251,113,133,.35); background:rgba(251,113,133,.06);}
    .stApp .sidebar-status-card-v2 .ssc-tile-alert:hover {border-color:#fb7185;}
    .stApp .sidebar-status-card-v2 .ssc-tile-alert .ssc-tile-value {color:#fda4af !important;}
    .stApp .sidebar-status-card-v2 .ssc-foot {margin-top:12px; padding-top:9px; border-top:1px solid #1d2a3f; font:500 9.5px/1.2 ui-monospace,Consolas,monospace; letter-spacing:.06em; color:#6f8aa5 !important;}
    @media (prefers-reduced-motion: reduce) {
        .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button, .stApp [data-testid="stSidebar"] [class*="st-key-nav_"] button p::before {transition:none !important;}
    }

    /* ---- v11 mailbox-connected panel ------------------------------------
       One card: identity header (avatar, status, address, host/folder/count
       chips, Live badge), a short note, then the action row. Replaces the old
       status card + separate button box. Delete this block and restore the
       old markup to go back. ------------------------------------------- */
    .stApp .st-key-imap_connected_panel {
        --tone:#34d399; position:relative; overflow:hidden; gap:14px !important;
        padding:22px 24px 22px 28px !important; margin:4px 0 14px 0 !important;
        border:1px solid #243046 !important; border-radius:16px !important;
        background:
            radial-gradient(60% 120% at 0% 0%, rgba(52,211,153,.10), transparent 62%),
            radial-gradient(45% 100% at 100% 0%, rgba(76,141,255,.07), transparent 70%),
            linear-gradient(180deg,#101826,#0b111a) !important;
        box-shadow:inset 0 1px 0 rgba(255,255,255,.04), 0 14px 30px -18px rgba(0,0,0,.8) !important;
    }
    .stApp .st-key-imap_connected_panel::before {
        content:""; position:absolute; left:0; top:18px; bottom:18px; width:3px; border-radius:0 3px 3px 0;
        background:linear-gradient(180deg,#34d399,rgba(52,211,153,.15)); pointer-events:none;
    }
    .stApp .st-key-imap_connected_panel [data-testid="stMarkdown"],
    .stApp .st-key-imap_connected_panel [data-testid="stMarkdownContainer"] {margin-bottom:0 !important;}

    .mbx-head {display:flex; align-items:center; gap:16px;}
    .mbx-avatar {
        flex:0 0 48px; width:48px; height:48px; border-radius:14px; display:flex; align-items:center; justify-content:center;
        font:750 20px/1 Inter,"Segoe UI",sans-serif; color:#d9fbee;
        background:linear-gradient(145deg,rgba(52,211,153,.34),rgba(52,211,153,.10)); border:1px solid rgba(52,211,153,.5);
        box-shadow:0 8px 18px -10px rgba(52,211,153,.8), inset 0 1px 0 rgba(255,255,255,.08);
    }
    .mbx-text {flex:1 1 auto; min-width:0;}
    .mbx-eyebrow {display:flex; align-items:center; gap:8px; font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.18em; text-transform:uppercase; color:#34d399;}
    .mbx-dot {width:7px; height:7px; border-radius:50%; background:#34d399; box-shadow:0 0 0 3px rgba(52,211,153,.22), 0 0 10px rgba(52,211,153,.8); animation:mbxPulse 2.4s ease-in-out infinite;}
    @keyframes mbxPulse {0%,100% {box-shadow:0 0 0 3px rgba(52,211,153,.22), 0 0 10px rgba(52,211,153,.8);} 50% {box-shadow:0 0 0 6px rgba(52,211,153,.08), 0 0 14px rgba(52,211,153,.5);}}
    .mbx-title {margin-top:8px; font:750 20px/1.2 Inter,"Segoe UI",sans-serif; letter-spacing:-.01em; color:#fff; overflow-wrap:anywhere;}
    .mbx-chips {display:flex; flex-wrap:wrap; gap:6px; margin-top:10px;}
    .mbx-chips span {font:600 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.05em; padding:5px 9px; border-radius:999px; color:#9fb3c8; border:1px solid #2a3750; background:rgba(255,255,255,.025);}
    .mbx-chips span:nth-child(1) {color:#9dbcff; border-color:rgba(76,141,255,.4); background:rgba(76,141,255,.09);}
    .mbx-chips span:nth-child(2) {color:#ecc088; border-color:rgba(224,164,88,.4); background:rgba(224,164,88,.09);}
    .mbx-chips span:nth-child(3) {color:#86d9bf; border-color:rgba(79,195,161,.4); background:rgba(79,195,161,.09);}
    .mbx-badge {flex:0 0 auto; align-self:flex-start; font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.14em; text-transform:uppercase; padding:7px 11px; border-radius:999px; color:#34d399; border:1px solid rgba(52,211,153,.4); background:rgba(52,211,153,.10);}
    .mbx-note {margin-top:14px; padding:12px 14px; border-radius:12px; border:1px dashed #2a3750; background:rgba(255,255,255,.02); font-size:12.5px; line-height:1.6; color:#8d99ac;}

    /* action row */
    .stApp .st-key-imap_connected_panel [data-testid="stHorizontalBlock"] {gap:12px !important; align-items:stretch !important;}
    .stApp .st-key-imap_connected_panel .stButton button {
        min-height:48px !important; border-radius:12px !important; font:650 14px/1 Inter,"Segoe UI",sans-serif !important; letter-spacing:.01em !important;
        transition:background .18s var(--ease), border-color .18s var(--ease), box-shadow .18s var(--ease), transform .18s var(--ease) !important;
    }
    .stApp .st-key-imap_connected_panel .stButton button:hover {transform:translateY(-1px) !important;}
    .stApp .st-key-imap_connected_panel .st-key-mailbox_quick_full_report_btn button {
        background:linear-gradient(180deg,#1f3a66,#16264a) padding-box, linear-gradient(115deg,#3b82f6,#6366f1 60%,#a78bfa) border-box !important;
        border:1px solid transparent !important; color:#fff !important;
        box-shadow:0 12px 24px -16px rgba(99,102,241,.9), inset 0 1px 0 rgba(255,255,255,.09) !important;
    }
    .stApp .st-key-imap_connected_panel .st-key-mailbox_quick_full_report_btn button:hover {
        background:linear-gradient(180deg,#27487f,#1b2f5c) padding-box, linear-gradient(115deg,#5b9bf8,#7c7ff3 60%,#b9a6ff) border-box !important;
        box-shadow:0 16px 28px -14px rgba(99,102,241,1), inset 0 1px 0 rgba(255,255,255,.12) !important;
    }
    .stApp .st-key-imap_connected_panel .st-key-imap_show_form_btn button {
        background:rgba(76,141,255,.06) !important; border:1px solid rgba(76,141,255,.45) !important; color:#b9ceff !important;
    }
    .stApp .st-key-imap_connected_panel .st-key-imap_show_form_btn button:hover {
        background:rgba(76,141,255,.14) !important; border-color:#6c9bff !important; color:#fff !important;
    }
    .stApp .st-key-imap_connected_panel .st-key-imap_disconnect_btn button {
        background:rgba(239,90,90,.05) !important; border:1px solid rgba(239,90,90,.5) !important; color:#ff9d9d !important;
    }
    .stApp .st-key-imap_connected_panel .st-key-imap_disconnect_btn button:hover {
        background:rgba(239,90,90,.14) !important; border-color:rgba(239,90,90,.9) !important; color:#ffd0d0 !important;
    }
    @media (max-width:760px) {
        .mbx-head {flex-wrap:wrap;} .mbx-badge {display:none;}
        .stApp .st-key-imap_connected_panel {padding:18px 16px 18px 20px !important;}
    }
    @media (prefers-reduced-motion: reduce) {.mbx-dot {animation:none;}}

    /* ---- v9 acquisition cards: aligned click-catcher + per-card hover ------
       Bug: the invisible button that sits on each card was lined up with a
       negative margin, which drifted ~20px off the card and let the generic
       button hover paint a tinted box outside it. Now the button is pinned
       to the top-left of its own column (position:absolute, same height as
       the card), so it can't drift, and every paint on it is forced off.
       The card reacts to hovering the button via :has().
         Channel A (blue)   -> live scan: moving top bar + light sweep
         Channel B (copper) -> batch: warm hatch rising from the corner
       Delete this block to go back to the old hover. ------------------- */
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has(.acq2) {position:relative !important;}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] {
        position:absolute !important; top:0 !important; left:0 !important; right:auto !important; bottom:auto !important;
        margin:0 !important; width:100% !important; height:var(--acq-h) !important; z-index:6 !important;
    }
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] > div,
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] [data-testid="stButton"],
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] .stButton {width:100% !important; height:100% !important;}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] button,
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] button:hover,
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] button:focus,
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] button:active {
        width:100% !important; height:100% !important; min-height:0 !important; margin:0 !important; padding:0 !important;
        background:transparent !important; background-image:none !important; border:0 !important; border-radius:14px !important;
        box-shadow:none !important; outline:none !important; transform:none !important; filter:none !important;
        color:transparent !important; cursor:pointer !important;
    }
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] button::before,
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] button::after {content:none !important; display:none !important;}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]) [class*="st-key-acq_pick_"] button * {color:transparent !important; opacity:0 !important;}

    .acq2 {transition:border-color .2s var(--ease), background .2s var(--ease), box-shadow .22s var(--ease), transform .22s var(--ease) !important;}
    .acq2::after {content:""; position:absolute; inset:0; pointer-events:none; opacity:0; z-index:0; transition:opacity .28s var(--ease), transform .8s var(--ease);}
    .acq2-blue::after {transform:translateX(-60%); background:linear-gradient(115deg, transparent 30%, rgba(130,175,255,.17) 50%, transparent 70%);}
    .acq2-copper::after {
        background:repeating-linear-gradient(135deg, rgba(212,154,102,.13) 0 1px, transparent 1px 10px);
        -webkit-mask-image:radial-gradient(90% 110% at 0% 100%, #000 0%, transparent 70%);
        mask-image:radial-gradient(90% 110% at 0% 100%, #000 0%, transparent 70%);
    }
    .acq2-ghost {transition:opacity .28s var(--ease), transform .35s var(--ease) !important;}
    .acq2-chip, .acq2-sw, .acq2-sw i {transition:all .22s var(--ease);}
    @keyframes acqScan {from {background-position:0 0;} to {background-position:-200% 0;}}
    @keyframes acqGrow {from {transform:scaleX(0);} to {transform:scaleX(1);}}

    /* Channel A -- blue: live scan */
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue {
        transform:translateY(-2px);
        border-color:#4c8dff !important;
        background:
            radial-gradient(70% 130% at 100% 0%, rgba(76,141,255,.22), transparent 66%),
            linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
        box-shadow:0 0 0 3px rgba(76,141,255,.16), 0 20px 36px -20px rgba(76,141,255,.65) !important;
    }
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue::before {
        height:3px; background:linear-gradient(90deg,#4c8dff,#8b7cff,#4c8dff,#8b7cff); background-size:200% 100%;
        animation:acqScan 1.8s linear infinite;
    }
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue::after {opacity:1; transform:translateX(60%);}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue .acq2-tag, .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue .acq2-state-txt {color:#7fb0ff;}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue .acq2-title {color:#fff;}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue .acq2-ghost {opacity:.24; transform:translateX(-6px) rotate(-8deg) scale(1.07);}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue .acq2-chip {color:#9dbcff; border-color:rgba(76,141,255,.5); background:rgba(76,141,255,.10);}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue:not(.acq2-on) .acq2-sw {border-color:rgba(76,141,255,.6);}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue:not(.acq2-on) .acq2-sw i {left:9px; background:#4c8dff;}

    /* Channel B -- copper: batch intake */
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper {
        transform:translateY(-2px);
        border-color:#d49a66 !important;
        background:
            radial-gradient(80% 130% at 0% 100%, rgba(212,154,102,.22), transparent 64%),
            linear-gradient(180deg, var(--panel-2), var(--panel)) !important;
        box-shadow:0 0 0 3px rgba(212,154,102,.15), 0 20px 36px -20px rgba(212,154,102,.6) !important;
    }
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper::before {
        height:3px; background:linear-gradient(90deg,#d49a66,#f0c58f 55%,#d49a66); transform-origin:left;
        animation:acqGrow .45s var(--ease) both;
    }
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper::after {opacity:1;}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper .acq2-tag, .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper .acq2-state-txt {color:#e3b585;}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper .acq2-title {color:#fff;}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper .acq2-ghost {opacity:.24; transform:translateY(-9px) scale(1.06);}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper .acq2-chip {color:#ecc088; border-color:rgba(212,154,102,.55); background:rgba(212,154,102,.12);}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper:not(.acq2-on) .acq2-sw {border-color:rgba(212,154,102,.6);}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper:not(.acq2-on) .acq2-sw i {left:9px; background:#d49a66;}

    /* keyboard focus: a clear ring on the card itself */
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:focus-visible) .acq2-blue {outline:2px solid #4c8dff; outline-offset:3px;}
    .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:focus-visible) .acq2-copper {outline:2px solid #d49a66; outline-offset:3px;}

    @media (prefers-reduced-motion: reduce) {
        .acq2, .acq2::after, .acq2-ghost {transition:none !important;}
        .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-blue::before, .stApp :is([data-testid="stColumn"],[data-testid="column"]):has([class*="st-key-acq_pick_"] button:hover) .acq2-copper::before {animation:none !important;}
    }

    @media (max-width:900px){
      .st-key-imap_signin_card {--padx:22px;}
      .signin-card-header {padding:26px var(--padx) 22px !important; border-bottom:1px solid #243046;}
      .st-key-imap_signin_card > *:nth-child(2) {margin-top:22px !important;}
    }

    /* Keyboard focus: one visible ring everywhere. */
    .stApp :is(a, [role="tab"], [role="radio"], summary):focus-visible {outline:2px solid rgba(59,130,246,.7); outline-offset:2px; border-radius:var(--r-sm);}
    </style>
    """,
    unsafe_allow_html=True,
)

# Resolve any pending sidebar "jump to this acquisition mode" request before
# anything below reads input_mode_radio. This has to happen here, ahead of
# both the sidebar's active-button highlighting AND the st.radio(key=
# "input_mode_radio", ...) widget further down -- doing it down next to the
# radio (its previous location) meant the sidebar, which renders earlier in
# the script on every run, was still reading last run's mode for one extra
# rerun after every "Upload Email(s)" / "Live Email Scan (IMAP)" click.
_MODE_OPTIONS = ["Live IMAP Mailbox Interceptor", "Evidence File Upload (.eml, .txt, .csv)"]
if st.session_state.get("nav_force_mode") in _MODE_OPTIONS:
    st.session_state["input_mode_radio"] = st.session_state.pop("nav_force_mode")

# Computed once, up here, so both the sidebar (which renders first) and the
# top workflow nav further down agree on it in the same run. Before any
# mailbox is connected or file uploaded there's no evidence for the analysis
# panels to show, so both navs collapse down to just Dashboard (to acquire
# evidence) + Settings/About instead of a full list of panels that would
# each just render their own "nothing to analyze yet" placeholder.
_has_evidence_loaded = bool(st.session_state.get("live_mailbox_messages")) or bool(
    st.session_state.get("stored_evidence_file")
)

# Sidebar nav: per-item colour (follows the section) + icon. Buttons carry
# stable keys, so Streamlit exposes them as .st-key-<key>; the rules are
# generated here so the SVG masks stay readable.
import urllib.parse as _sb_up
_SB_BLUE, _SB_GREEN, _SB_VIOLET, _SB_ROSE, _SB_SLATE = "#4c8dff", "#34d399", "#a78bfa", "#fb7185", "#94a3b8"
_SB_ICONS = {
    "grid": "<rect x='3' y='3' width='7' height='9' rx='1.5'/><rect x='14' y='3' width='7' height='5' rx='1.5'/><rect x='14' y='12' width='7' height='9' rx='1.5'/><rect x='3' y='16' width='7' height='5' rx='1.5'/>",
    "upload": "<path d='M12 16V4M7 9l5-5 5 5'/><path d='M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3'/>",
    "mail": "<rect x='3' y='5' width='18' height='14' rx='2.5'/><path d='M3.5 7.5l8.5 6 8.5-6'/>",
    "chip": "<rect x='6' y='6' width='12' height='12' rx='2'/><path d='M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4'/>",
    "radiate": "<circle cx='12' cy='12' r='3'/><path d='M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1'/>",
    "globe": "<circle cx='12' cy='12' r='9'/><path d='M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18'/>",
    "network": "<circle cx='6' cy='6' r='2.5'/><circle cx='18' cy='7' r='2.5'/><circle cx='12' cy='18' r='2.5'/><path d='M8.5 6.3l7 .6M7.3 8.3l3.6 7.4M16.8 9.3l-3.6 6.4'/>",
    "bars": "<path d='M4 20V10M10 20V4M16 20v-7M22 20H2'/>",
    "clock": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
    "search": "<circle cx='11' cy='11' r='7'/><path d='M21 21l-4.3-4.3'/>",
    "feed": "<path d='M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16'/><circle cx='5' cy='19' r='1.2'/>",
    "bug": "<path d='M12 21a5 5 0 0 1-5-5v-4a5 5 0 0 1 10 0v4a5 5 0 0 1-5 5z'/><path d='M12 7V4M7 12H3M21 12h-4M8 8L5 5M16 8l3-3M8 18l-3 3M16 18l3 3'/>",
    "sliders": "<path d='M4 7h10M18 7h2M4 17h2M10 17h10'/><circle cx='16' cy='7' r='2'/><circle cx='8' cy='17' r='2'/>",
    "info": "<circle cx='12' cy='12' r='9'/><path d='M12 11v5M12 8h.01'/>",
}
_SB_NAV_STYLE = {
    "nav_dash_top": (_SB_BLUE, "grid"), "nav_upload": (_SB_BLUE, "upload"), "nav_live": (_SB_BLUE, "mail"),
    "nav_ai_copilot_side": (_SB_BLUE, "chip"), "nav_nomic_side": (_SB_BLUE, "radiate"),
    "nav_map_side": (_SB_GREEN, "globe"), "nav_graph_side": (_SB_GREEN, "network"), "nav_analytics_side": (_SB_GREEN, "bars"),
    "nav_history_side": (_SB_VIOLET, "clock"), "nav_ioc_side": (_SB_VIOLET, "search"), "nav_urlhaus_side": (_SB_VIOLET, "feed"),
    "nav_av_side": (_SB_ROSE, "bug"),
    "nav_settings_side": (_SB_SLATE, "sliders"), "nav_about_side": (_SB_SLATE, "info"),
}
_sb_rules = []
for _sk, (_sc, _si) in _SB_NAV_STYLE.items():
    _suri = "data:image/svg+xml," + _sb_up.quote(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' "
        "stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'>" + _SB_ICONS[_si] + "</svg>",
        safe="/:=' ()",
    )
    _ssel = '.stApp [data-testid="stSidebar"] .st-key-' + _sk
    _sb_rules.append(_ssel + "{--c:" + _sc + ";}")
    _sb_rules.append(_ssel + ' button p::before{-webkit-mask-image:url("' + _suri + '");mask-image:url("' + _suri + '");}')
st.markdown("<style>" + "".join(_sb_rules) + "</style>", unsafe_allow_html=True)

with st.sidebar:
    st.markdown(
        f"""<div class="sidebar-brand-v2">
            <div class="brand-row">
                <div class="brand-mark brand-mark--logo"><img src="{_ALGORITHMISTIC_LOGO_SRC}" alt="Algorithmistic logo"/></div>
                <div class="brand-text">
                    <div class="name">ALGORITHMISTIC</div>
                    <div class="role">Forensic Intelligence Platform</div>
                </div>
            </div>
            <div class="brand-meta"><span class="brand-dot"></span>Active Session</div>
        </div>""",
        unsafe_allow_html=True,
    )

    def _nav_group(label, accent="teal"):
        """Section header for a run of sidebar nav buttons: a small
        auto-incrementing index tag + label + a gradient rule filling the
        rest of the row (see .sidebar-group-label), so groups read as
        labelled dividers rather than floating caption text. `accent`
        picks a distinct hue per section (see .sidebar-group-<accent>)
        so the sidebar's own sections are as visually distinguishable as
        the color-coded panels in the main content area."""
        _nav_group._n = getattr(_nav_group, "_n", 0) + 1
        st.markdown(
            f'<div class="sidebar-group-label sidebar-group-{accent}">'
            f'<span class="grp-index">{_nav_group._n:02d}</span>{label}</div>',
            unsafe_allow_html=True,
        )

    def _nav_button(label, panel_target=None, force_mode=None, key=None, active_when=None, on_click_set=None):
        """Sidebar nav item. `panel_target` is the page/tab this jumps to.

        Several entries intentionally share one panel_target -- "Upload
        Email(s)" and "Live Email Scan (IMAP)" both land on the Dashboard,
        just with a different acquisition mode already selected there; and
        "Nomic AI" / "Global Threat Map" both land on "Origin & Route".
        Highlighting purely on `active_panel == panel_target` made every
        button in a group glow together whenever that shared panel was
        showing (e.g. "Upload Email(s)" staying lit while looking at the
        Live Mailbox Interceptor). `active_when`, when given, overrides that
        default check with the real, current sub-state -- so exactly one
        button per group is ever active, and it stays correct even if that
        sub-state changed some other way (e.g. clicking the acquisition-mode
        radio directly instead of this sidebar shortcut).
        """
        is_active = active_when if active_when is not None else (
            panel_target is not None and st.session_state.get("active_panel") == panel_target
        )
        if st.button(label, key=key, use_container_width=True, type="primary" if is_active else "secondary"):
            if force_mode is not None:
                st.session_state["nav_force_mode"] = force_mode
            if on_click_set:
                for k, v in on_click_set.items():
                    st.session_state[k] = v
            if panel_target is not None:
                st.session_state["active_panel"] = panel_target
            st.rerun()

    _UPLOAD_MODE = "Evidence File Upload (.eml, .txt, .csv)"
    _LIVE_MODE = "Live IMAP Mailbox Interceptor"
    _on_dashboard = st.session_state.get("active_panel") == "Dashboard"
    _mode_now = st.session_state.get("input_mode_radio", _LIVE_MODE)
    _on_origin_route = st.session_state.get("active_panel") == "Origin & Route"
    _origin_focus = st.session_state.get("origin_route_focus", "map")

    _nav_button(
        "Dashboard", "Dashboard", key="nav_dash_top",
        active_when=_on_dashboard and _mode_now not in (_UPLOAD_MODE, _LIVE_MODE),
    )

    _nav_group("Threat Operations", accent="teal")
    _nav_button(
        "Upload Email(s)", "Dashboard", force_mode=_UPLOAD_MODE, key="nav_upload",
        active_when=_on_dashboard and _mode_now == _UPLOAD_MODE,
    )
    _nav_button(
        "Live Email Scan (IMAP)", "Dashboard", force_mode=_LIVE_MODE, key="nav_live",
        active_when=_on_dashboard and _mode_now == _LIVE_MODE,
    )

    # Everything below jumps to an analysis panel (AI Copilot, Nomic AI,
    # the map, correlation graph, analytics, history, IOC lookup, feed) --
    # all of them need evidence to already be loaded to show anything but a
    # placeholder. Keeping them out of the sidebar too, not just the top
    # nav, until a mailbox is connected or a file is uploaded means the
    # very first screen only offers what's actually usable right now:
    # acquire evidence (above), or Settings/About (below).
    if _has_evidence_loaded:
        _nav_button("AI Copilot", "AI Threat Analysis", key="nav_ai_copilot_side")
        _nav_button(
            "Nomic AI", "Origin & Route", key="nav_nomic_side",
            active_when=_on_origin_route and _origin_focus == "nomic",
            on_click_set={"origin_route_focus": "nomic"},
        )

        _nav_group("Visualization", accent="green")
        _nav_button(
            "Global Threat Map", "Origin & Route", key="nav_map_side",
            active_when=_on_origin_route and _origin_focus == "map",
            on_click_set={"origin_route_focus": "map"},
        )
        _nav_button("Correlation Graph", "Correlation", key="nav_graph_side")
        _nav_button("Analytics", "Classification", key="nav_analytics_side")

        _nav_group("Intelligence", accent="violet")
        _nav_button("Threat History", "Threat History", key="nav_history_side")
        _nav_button("IOC Lookup", "Indicators", key="nav_ioc_side")
        _nav_button("URLHaus Feed", "URLHaus Feed", key="nav_urlhaus_side")

        _nav_group("Security", accent="rose")
        _nav_button("Antivirus (ClamAV)", "Antivirus", key="nav_av_side")

    _nav_group("System", accent="slate")
    _nav_button("Settings", "Settings", key="nav_settings_side")
    _nav_button("About", "About", key="nav_about_side")

    if MULTIUSER:
        st.caption("Your emails, results and Google sign-in are private to this browser session.")
        if st.button("Delete my data & sign out", key="delete_my_data_btn"):
            delete_my_data()
            st.cache_data.clear()
            for _k in list(st.session_state.keys()):
                del st.session_state[_k]
            st.rerun()

    try:
        _sb_conn = get_connection()
        _sb_c = _sb_conn.cursor()
        _sb_c.execute("SELECT COUNT(*) FROM attackers")
        _sb_total = _sb_c.fetchone()[0] or 0
        _sb_c.execute("SELECT COUNT(*) FROM attackers WHERE verdict IN ('CRITICAL','HIGH')")
        _sb_threats = _sb_c.fetchone()[0] or 0
        _sb_conn.close()
    except Exception:
        _sb_total, _sb_threats = 0, 0

    st.markdown(
        f"""<div class="sidebar-status-card-v2">
            <div class="ssc-head">
                <span class="ssc-pulse"></span>
                <span class="ssc-title">All Systems Online</span>
            </div>
            <div class="ssc-grid">
                <div class="ssc-tile">
                    <div class="ssc-tile-value">{_sb_total}</div>
                    <div class="ssc-tile-label">Emails Analyzed</div>
                </div>
                <div class="ssc-tile ssc-tile-alert">
                    <div class="ssc-tile-value">{_sb_threats}</div>
                    <div class="ssc-tile-label">Threats Detected</div>
                </div>
            </div>
            <div class="ssc-foot">Last DB update &middot; {datetime.now().strftime('%d %b, %H:%M')}</div>
        </div>""",
        unsafe_allow_html=True,
    )

# The account chip shows the actually-connected mailbox address when there
# is one (st.session_state["imap_user"], set by the live IMAP connect flow
# elsewhere in this file) instead of a placeholder name, so it's always
# telling the truth about who's signed in. This used to sit in a separate
# utility row above the banner alongside a search box that never filtered
# anything -- that box is gone (see the redesign note by .topbar-logo), and
# the bell + account chip now render as plain markup inside the banner
# itself (below), so there's one header, not two stacked bars.
_acct_email = (
    # live_mailbox_config is the real source of truth once a mailbox is
    # actually connected: it's a plain dict set exactly once, on a
    # successful connect (see the "Synapse Copilot" / reload paths below),
    # and it's never bound to any widget -- unlike session_state["imap_user"],
    # which doubles as the live st.text_input(key="imap_user") field's own
    # value. That dual role is what caused the chip to show correctly for
    # one run right after OAuth sign-in and then revert to "Not signed in"
    # on the very next interaction: once that text_input re-renders on a
    # later rerun (e.g. after switching tabs) with nothing explicitly
    # re-filling it, Streamlit's widget binding can overwrite the session
    # value the OAuth handler had set. Checking the connected mailbox's own
    # config first sidesteps that entirely for anyone actually connected.
    (st.session_state.get("live_mailbox_config") or {}).get("user")
    or st.session_state.get("imap_user")
    # Covers the brief window right after OAuth success but before a full
    # mailbox connection object exists yet, and the case where the OAuth
    # redirect landed in a different Streamlit session than the one that
    # started sign-in (see _save_cached_google_email / _load_cached_*).
    or _load_cached_google_email()
    or _load_cached_provider_email("microsoft")
    or _load_cached_provider_email("yandex")
    or ""
)
_acct_initial = html.escape(_acct_email[:1].upper()) if _acct_email else "?"
_acct_label = html.escape(_acct_email) if _acct_email else "Not signed in"

# Just the background-image url() for .topbar-shell::after, in its own
# tiny interpolated <style> tag -- the main stylesheet above is one large
# raw (non-f) string, so a variable like _TOPBAR_MAP_SRC can't be dropped
# into it directly without escaping every literal `{ }` in that entire
# block. Isolating just this one rule here avoids that risk entirely.
st.markdown(
    f"<style>.topbar-shell::after {{background-image:url('{_TOPBAR_MAP_SRC}');}}</style>",
    unsafe_allow_html=True,
)

st.markdown(
    f"""<div class="topbar-shell">
      <div class="topbar-brand">
        <div class="topbar-logo"><img src="{_ALGORITHMISTIC_LOGO_SRC}" alt="Algorithmistic logo"/></div>
        <div>
          <div class="topbar-kicker">ALGORITHMISTIC · Forensic Intelligence Platform</div>
          <div class="topbar-title">AI-Powered Email Threat Detection &amp; Forensic Intelligence</div>
          <div class="topbar-subtitle">Evidence acquisition · header authentication · IOC intelligence · origin tracing · campaign correlation · local AI assessment</div>
        </div>
      </div>
      <div class="topbar-status-wrap">
        <div class="topbar-actions">
            <div class="topbar-account-chip" title="{_acct_label}">
                <span class="topbar-account-avatar">{_acct_initial}</span>
                <span class="topbar-account-email">{_acct_label}</span>
            </div>
        </div>
        <div class="topbar-status-pill">
          <span class="topbar-status-dot"></span>
          <span class="topbar-status-online">System operational</span>
        </div>
        <div class="topbar-status-time">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
      </div>
    </div>""",
    unsafe_allow_html=True,
)

# Before any evidence exists (no live mailbox connected, no file uploaded)
# there is nothing yet for the analysis panels to show -- AI Threat
# Analysis, Forensic Report, Classification, Headers & Auth, Origin &
# Route, Indicators, Correlation and Threat History would all just render
# their own "please acquire evidence first" placeholder. Keeping them out
# of the nav (and out of NAV_OPTIONS, so their panel bodies further down
# never even evaluate) until there's something to analyze keeps the first
# screen to the two things that are actually usable pre-evidence --
# Dashboard (to acquire evidence) and Settings/About -- instead of a full
# workflow bar of dead links. The moment a mailbox connects or a file is
# loaded, the rest of the workflow reappears automatically on the next run.
# (_has_evidence_loaded is computed once, up near the sidebar, and reused here.)
if _has_evidence_loaded:
    NAV_OPTIONS = [
        "Dashboard",
        "AI Threat Analysis",
        "Forensic Report",
        "Classification",
        "Headers & Auth",
        "Origin & Route",
        "Indicators",
        "Correlation",
        "Threat History",
        "URLHaus Feed",
        "Antivirus",
        "Settings",
        "About",
    ]
else:
    NAV_OPTIONS = ["Dashboard", "Settings", "About"]
# Bind the radio directly to the "active_panel" session_state key instead of
# re-deriving `index=` from that same key on every run. Computing index from
# session_state and then writing session_state back from the widget's return
# value creates a one-run lag: on the run where the click event arrives, the
# script still reads the *old* active_panel to build `index`, so the pill bar
# shows the previous selection and only catches up on the next rerun -- the
# "have to click twice" bug. Giving the widget `key="active_panel"` makes
# Streamlit own that state directly, so a click takes effect immediately.
# The sidebar's _nav_button() still works: it sets st.session_state["active_panel"]
# and calls st.rerun() *before* this widget is instantiated in the new run,
# which is exactly when it's safe to seed a keyed widget's value.
if "_pending_active_panel" in st.session_state:
    # Safe to write here — this runs before the st.radio(key="active_panel")
    # widget below is instantiated for this run.
    st.session_state["active_panel"] = st.session_state.pop("_pending_active_panel")
elif st.session_state.get("active_panel") not in NAV_OPTIONS:
    st.session_state["active_panel"] = NAV_OPTIONS[0]
# Per-module colour + icon for the workflow tabs. Radio labels carry no
# per-option attribute, so the rules are generated by position from NAV_OPTIONS
# (which already reflects whether evidence is loaded).
import urllib.parse as _nav_up
_NAV_STYLE = {
    "Dashboard": ("#4c8dff", "<rect x='3' y='3' width='7' height='9' rx='1.5'/><rect x='14' y='3' width='7' height='5' rx='1.5'/><rect x='14' y='12' width='7' height='9' rx='1.5'/><rect x='3' y='16' width='7' height='5' rx='1.5'/>"),
    "AI Threat Analysis": ("#a78bfa", "<rect x='6' y='6' width='12' height='12' rx='2'/><path d='M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4'/>"),
    "Forensic Report": ("#38bdf8", "<path d='M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z'/><path d='M14 3v5h5M9 13h6M9 17h6'/>"),
    "Classification": ("#f59e0b", "<path d='M12 3l9 5-9 5-9-5z'/><path d='M3 13l9 5 9-5'/>"),
    "Headers & Auth": ("#34d399", "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/><path d='M9 12l2 2 4-4'/>"),
    "Origin & Route": ("#22d3ee", "<path d='M12 21s7-6.2 7-11a7 7 0 0 0-14 0c0 4.8 7 11 7 11z'/><circle cx='12' cy='10' r='2.5'/>"),
    "Indicators": ("#fb7185", "<circle cx='12' cy='12' r='8'/><circle cx='12' cy='12' r='3'/><path d='M12 2v3M12 19v3M2 12h3M19 12h3'/>"),
    "Correlation": ("#c084fc", "<circle cx='6' cy='6' r='2.5'/><circle cx='18' cy='7' r='2.5'/><circle cx='12' cy='18' r='2.5'/><path d='M8.5 6.3l7 .6M7.3 8.3l3.6 7.4M16.8 9.3l-3.6 6.4'/>"),
    "Threat History": ("#fbbf24", "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>"),
    "URLHaus Feed": ("#fb923c", "<circle cx='12' cy='12' r='9'/><path d='M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18'/>"),
    "Antivirus": ("#4ade80", "<path d='M12 21a5 5 0 0 1-5-5v-4a5 5 0 0 1 10 0v4a5 5 0 0 1-5 5z'/><path d='M12 7V4M7 12H3M21 12h-4M8 8L5 5M16 8l3-3M8 18l-3 3M16 18l3 3'/>"),
    "Settings": ("#94a3b8", "<path d='M4 7h10M18 7h2M4 17h2M10 17h10'/><circle cx='16' cy='7' r='2'/><circle cx='8' cy='17' r='2'/>"),
    "About": ("#60a5fa", "<circle cx='12' cy='12' r='9'/><path d='M12 11v5M12 8h.01'/>"),
}
_nav_rules = []
for _ni, _nopt in enumerate(NAV_OPTIONS, start=1):
    _ncol, _nsvg = _NAV_STYLE.get(_nopt, ("#4c8dff", "<circle cx='12' cy='12' r='9'/>"))
    _nuri = "data:image/svg+xml," + _nav_up.quote(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' "
        "stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'>" + _nsvg + "</svg>",
        safe="/:=' ()",
    )
    _nsel = '.stApp .st-key-topnav [role="radiogroup"] > :nth-child(' + str(_ni) + ")"
    _nav_rules.append(_nsel + "{--c:" + _ncol + ";}")
    _nav_rules.append(_nsel + ' p::before{-webkit-mask-image:url("' + _nuri + '");mask-image:url("' + _nuri + '");}')
st.markdown("<style>" + "".join(_nav_rules) + "</style>", unsafe_allow_html=True)
components.html(
    """<script>
    (function () {
      var last = null, target = 0, raf = null, dragging = false;
      function ease(box) {
        // critically-damped glide towards `target`: fast start, soft landing
        var d = target - box.scrollLeft;
        if (Math.abs(d) < 0.5) { box.scrollLeft = target; raf = null; return; }
        box.scrollLeft += d * 0.16;
        raf = requestAnimationFrame(function () { ease(box); });
      }
      function glide(box, to) {
        var max = box.scrollWidth - box.clientWidth;
        target = Math.max(0, Math.min(max, to));
        if (!raf) raf = requestAnimationFrame(function () { ease(box); });
      }
      function bind(box) {
        box.style.scrollBehavior = "auto";          // our own easing replaces CSS smooth
        box.addEventListener("wheel", function (e) {
          var max = box.scrollWidth - box.clientWidth;
          if (max <= 0) return;
          var dx = Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.deltaY;
          if (e.deltaMode === 1) dx *= 32;           // line -> px
          var base = raf ? target : box.scrollLeft;
          if ((dx > 0 && base < max - 1) || (dx < 0 && base > 1)) {
            glide(box, base + dx * 1.4); e.preventDefault();
          }
        }, { passive: false });
        var sx = 0, sl = 0, moved = false;
        box.addEventListener("pointerdown", function (e) {
          if (e.pointerType === "touch" || e.button !== 0) return;
          dragging = true; moved = false; sx = e.clientX; sl = box.scrollLeft;
        });
        window.parent.addEventListener("pointermove", function (e) {
          if (!dragging) return;
          var dx = e.clientX - sx;
          if (Math.abs(dx) > 4) { moved = true; box.style.cursor = "grabbing"; }
          if (moved) { box.scrollLeft = sl - dx; target = box.scrollLeft; }
        });
        window.parent.addEventListener("pointerup", function () {
          dragging = false; box.style.cursor = "";
        });
        // a drag must not count as a tab click
        box.addEventListener("click", function (e) {
          if (moved) { e.stopPropagation(); e.preventDefault(); moved = false; }
        }, true);
      }
      function metrics(box) {
        var panel = box.closest('.st-key-topnav');
        if (!panel) return;
        var max = box.scrollWidth - box.clientWidth;
        panel.style.setProperty('--nav-on', max > 2 ? 1 : 0);
        panel.style.setProperty('--nav-w', max > 2 ? (box.clientWidth / box.scrollWidth).toFixed(4) : 1);
        panel.style.setProperty('--nav-p', max > 2 ? (box.scrollLeft / max).toFixed(4) : 0);
      }
      function tick() {
        try {
          var d = window.parent.document;
          var box = d.querySelector('.st-key-topnav [role="radiogroup"]');
          if (!box) return;
          if (!box.dataset.navWheel) {
            box.dataset.navWheel = "1"; bind(box);
            box.addEventListener("scroll", function () { metrics(box); }, { passive: true });
          }
          metrics(box);
          var act = box.querySelector("label:has(input:checked)");
          var key = act ? act.innerText : null;
          if (act && key !== last) {
            last = key;
            var x = act.getBoundingClientRect().left - box.getBoundingClientRect().left + box.scrollLeft;
            glide(box, x - (box.clientWidth - act.offsetWidth) / 2);
          }
        } catch (err) {}
      }
      tick(); setInterval(tick, 400);
    })();
    </script>""",
    height=0,
)
with st.container(key="topnav"):
    active_panel = st.radio(
        "Forensic workflow",
        NAV_OPTIONS,
        key="active_panel",
        horizontal=True,
        label_visibility="collapsed",
    )

def _clean_ai_display(text):
    cleaned = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if stripped and len(stripped) >= 8 and set(stripped) <= {"=", "-", "_", "~", "*"}:
            continue
        cleaned.append(line.rstrip())
    return "\n".join(cleaned).strip()


def _annotate_email_labels(text, report_items):
    """Replace bare 'Email #N' / 'Email #N, #M' references in a batch AI
    report with the sender and subject for each position, so 'Email #3'
    reads as something identifiable instead of a number the reader has to
    cross-reference against a separate table."""
    labels = {}
    for it in report_items or []:
        parsed = ((it.get("result") or {}).get("parsed") or {})
        subject = str(parsed.get("subject") or "No Subject").strip()
        if len(subject) > 40:
            subject = subject[:37] + "..."
        sender = str(parsed.get("from_addr") or parsed.get("from") or "Unknown sender").strip()
        labels[it.get("position")] = f'{sender} — "{subject}"'

    def _replace(match):
        nums = [int(n) for n in re.findall(r"#(\d+)", match.group(0))]
        parts = [f"#{n} ({labels[n]})" if n in labels else f"#{n}" for n in nums]
        return "Email " + ", ".join(parts)

    return re.sub(r"Email\s+#\d+(?:\s*,\s*#\d+)*", _replace, text)

def _ai_markdown_to_html(text):
    src = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    src = _clean_ai_display(src)
    lines = src.split("\n")
    out = []
    in_ul = False
    in_ol = False

    def inline(value):
        value = html.escape(value, quote=False)
        value = re.sub(r'`([^`]+)`', r'<code>\1</code>', value)
        value = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', value)
        value = re.sub(r'__(.+?)__', r'<strong>\1</strong>', value)
        value = re.sub(r'\*([^*\n]+)\*', r'<em>\1</em>', value)
        return value

    def close_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    for line in lines:
        s = line.strip()
        if not s:
            close_lists()
            continue
        if re.fullmatch(r'[-_=~*]{8,}', s):
            continue
        heading = re.match(r'^#{1,6}\s+(.+)$', s)
        if heading:
            close_lists()
            level = min(len(s) - len(s.lstrip("#")), 3)
            out.append(f"<h{level}>{inline(heading.group(1).strip())}</h{level}>")
            continue
        bullet = re.match(r'^[-*•]\s+(.+)$', s)
        if bullet:
            if in_ol:
                out.append("</ol>")
                in_ol = False
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{inline(bullet.group(1))}</li>")
            continue
        numbered = re.match(r'^\d+[.)]\s+(.+)$', s)
        if numbered:
            if in_ul:
                out.append("</ul>")
                in_ul = False
            if not in_ol:
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{inline(numbered.group(1))}</li>")
            continue
        close_lists()
        out.append(f"<p>{inline(s)}</p>")

    close_lists()
    return "\n".join(out)

def show_feedback_typing(message, message_type="success"):
    icon = "✓" if message_type == "success" else "ℹ"
    accent = "#35d399" if message_type == "success" else "#2fd8ff"
    placeholder = st.empty()
    typed = ""
    for char in str(message):
        typed += char
        placeholder.markdown(
            f"""<div class="feedback-terminal" style="border-left-color:{accent};">
                <span class="feedback-icon" style="color:{accent};">{icon}</span>
                <span>{typed}</span><span class="feedback-cursor" style="color:{accent};">▌</span>
            </div>""",
            unsafe_allow_html=True,
        )
        time.sleep(0.012)
    placeholder.markdown(
        f"""<div class="feedback-terminal" style="border-left-color:{accent};">
            <span class="feedback-icon" style="color:{accent};">{icon}</span>
            <span>{message}</span>
        </div>""",
        unsafe_allow_html=True,
    )

SEV_COLOR = {"high": "#b71c1c", "medium": "#f9a825", "low": "#78909c", "info": "#546e7a"}
AUTH_COLOR = {"pass": "#2e7d32", "fail": "#b71c1c", "softfail": "#e65100", "none": "#78909c", "neutral": "#78909c"}

@st.cache_resource(show_spinner="Loading phishing model...")
def get_model(model_version=0):
    return load_or_train()

@st.cache_data(show_spinner="Analysing shipped samples...")
def get_sample_results():
    return analyze_all_samples(get_model())

@st.cache_data(show_spinner="Analysing message...")
def analyze_bytes(raw_bytes, name, analysis_nonce=0):
    return analyze_email(raw_bytes, name, get_model())

def panel(fn, label):
    try:
        fn()
    except Exception:
        st.error(f"The **{label}** panel failed. Everything else still works.")
        with st.expander("Technical detail"):
            st.code(traceback.format_exc())


# Settings and About need no evidence (they only read config.py, the Google
# sign-in status and README.md), so they are defined here -- ahead of the
# "No evidence loaded yet" gate further down -- which keeps both openable
# before any mailbox is connected or file is uploaded.
def _settings():
    st.subheader("Settings")
    st.caption("Live view of the scoring configuration this build is actually running with (config.py) - editing requires changing that file.")

    st.markdown("##### Risk signal weights")
    _render_polished_table(pd.DataFrame([{"Signal": k, "Weight": v} for k, v in C.WEIGHTS.items()]))

    st.markdown("##### Risk level thresholds")
    _render_polished_table(pd.DataFrame([{"Score ≥": t, "Level": n} for t, n, _ in C.RISK_LEVELS]))

    st.markdown("##### Reference lists")
    st.write(f"Known brands tracked: **{len(C.KNOWN_BRANDS)}**")
    st.write(f"Freemail domains tracked: **{len(C.FREEMAIL_DOMAINS)}**")
    st.write(f"URL shorteners tracked: **{len(C.URL_SHORTENERS)}**")

    st.markdown("##### Google Sign-In")
    st.write("Configured" if GOOGLE_OAUTH_READY and oauth_available() else "Not configured")

def _about():
    st.subheader("About ALGORITHMISTIC")
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"), encoding="utf-8") as fh:
            st.markdown(fh.read())
    except Exception:
        st.info("README.md was not found alongside app.py.")


# --------------------------------------------------------------------------
# Shared hop-map helpers -- used by both the Dashboard preview map and the
# Origin & Route panel's main map. Both need the same toggle: look at every
# loaded email's origin at once (capped so the map stays readable), or drill
# into one email's full hop chain picked from a dropdown -- instead of only
# ever being able to see whichever single message happens to be loaded.
# --------------------------------------------------------------------------
_MAP_MODE_ALL = "All emails (up to 10)"
_MAP_MODE_ONE = "Single email"

_TILE_LAYERS = (
    ("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
     "Esri World Imagery", "Satellite"),
)

_LEVEL_MARKER_COLORS = {
    "CRITICAL": "#ff4757", "HIGH": "#ff9f43", "MEDIUM": "#f5c542", "LOW": "#2fd8ff",
}


_MAP_MAX_ZOOM = 10  # Esri imagery is reliable worldwide up to here; deeper shows gray "Map data not yet available" tiles


def _add_base_tiles(m):
    for tiles, attr, name in _TILE_LAYERS:
        folium.TileLayer(
            tiles=tiles, attr=attr, name=name, control=False, no_wrap=True,
            max_zoom=_MAP_MAX_ZOOM, max_native_zoom=_MAP_MAX_ZOOM,
            bounds=[[-85.0511, -180], [85.0511, 180]],
        ).add_to(m)


def _case_label(case, fallback):
    p = case.get("parsed", {}) or {}
    frm = (p.get("from_addr") or "").strip()
    nm = (case.get("name") or "").strip()
    if frm and nm:
        return f"{frm}  ·  {nm}"
    return frm or nm or fallback


def _case_origin_point(case):
    """This case's origin as a map point, or None if it has no resolvable
    lat/lon yet (unresolved hop, error case, etc.)."""
    g = case.get("geo", {}) or {}
    o = g.get("origin", {}) or {}
    if o.get("lat") is None or o.get("lon") is None:
        return None
    p = case.get("parsed", {}) or {}
    return {
        "sender": p.get("from_addr") or "Unknown sender",
        "case_name": case.get("name") or "Unnamed",
        "ip": o.get("ip", "Unknown"),
        "city": o.get("city", ""),
        "country": o.get("country", ""),
        "infra_label": o.get("infra_label", "Unattributed"),
        "lat": o["lat"], "lon": o["lon"],
        "level": str(case.get("level", "unknown")).upper(),
    }


def _case_row_number(case):
    """Best-effort CSV row index for a case, parsed from its case name
    (e.g. 'mydata.csv (Row 7)'). Returns None for cases that didn't come
    from a CSV row (a single uploaded .eml, a live IMAP message, etc.)."""
    m = re.search(r"\(Row (\d+)\)", str(case.get("name") or ""))
    return int(m.group(1)) if m else None


def _case_recency_key(case, idx, source_rows):
    """Sort key for 'most recent first': parses the Date header off the
    case's own raw CSV row when one can be identified, otherwise falls
    back to CSV row order (higher row = more recent), same convention the
    Forensic Report and AI Threat Analysis panels already use everywhere
    they pick a handful of emails out of a full CSV -- so every single-
    email picker in the app agrees on what 'most recent' means."""
    row = _case_row_number(case)
    dt = None
    if row is not None and source_rows and row < len(source_rows):
        dt = get_email_date(source_rows[row])
    tiebreak = row if row is not None else idx
    return (dt is not None, dt or datetime.min.replace(tzinfo=timezone.utc), tiebreak)


def _pick_case_for_map(cases, result, case_name, key, source_rows=None):
    """Dropdown of every loaded email, most-recent-first (see
    _case_recency_key), defaulting to whichever one is currently open, so
    'by email' starts exactly where the analyst is already looking and
    only moves on purpose."""
    if not cases:
        return result
    ordered_cases = [
        c for _, c in sorted(
            enumerate(cases),
            key=lambda pair: _case_recency_key(pair[1], pair[0], source_rows),
            reverse=True,
        )
    ]
    labels = [_case_label(c, f"Email #{i + 1}") for i, c in enumerate(ordered_cases)]
    default_idx = 0
    for i, c in enumerate(ordered_cases):
        if c is result or (case_name and c.get("name") == case_name):
            default_idx = i
            break
    sel_idx = st.selectbox(
        "Email to inspect", options=list(range(len(ordered_cases))), index=default_idx,
        format_func=lambda i: labels[i], key=key,
    )
    return ordered_cases[sel_idx]


_EMAIL_ROUTE_COLORS = (
    "#ff4757", "#2fd8ff", "#f5c542", "#35d399", "#a389f4",
    "#ff9f43", "#f47ab0", "#7bed9f", "#70a1ff", "#eccc68",
)


def _case_hop_points(case):
    """Geolocatable hops of one case, in route order. Falls back to the
    case's origin point when the hop list has no coordinates."""
    g = case.get("geo", {}) or {}
    hops = [h for h in (g.get("hops") or []) if h.get("lat") is not None and h.get("lon") is not None]
    if hops:
        return hops
    o = g.get("origin", {}) or {}
    if o.get("lat") is not None and o.get("lon") is not None:
        return [dict(o, hop_index=1)]
    return []


_MAP_CSS = """<style>
.leaflet-container{background:#0a1322 !important;font-family:Inter,'Segoe UI',system-ui,-apple-system,sans-serif;border-radius:12px;}
.leaflet-control-attribution{display:none !important;}
.leaflet-bar{border:none !important;box-shadow:0 4px 14px rgba(0,0,0,.45) !important;border-radius:10px !important;overflow:hidden;}
.leaflet-bar a{background:rgba(15,27,45,.94) !important;color:#cfe3ff !important;border-bottom:1px solid rgba(255,255,255,.08) !important;width:34px !important;height:34px !important;line-height:34px !important;}
.leaflet-bar a:hover{background:#1b2d4a !important;color:#fff !important;}
.leaflet-bar a.leaflet-disabled{opacity:.3 !important;cursor:not-allowed !important;background:rgba(15,27,45,.94) !important;}
.leaflet-popup-content-wrapper{background:rgba(12,22,38,.97);color:#e6eefc;border:1px solid rgba(110,170,255,.28);border-radius:12px;box-shadow:0 12px 32px rgba(0,0,0,.6);}
.leaflet-popup-tip{background:rgba(12,22,38,.97);border:1px solid rgba(110,170,255,.18);}
.leaflet-popup-content{margin:12px 14px;font-size:12px;line-height:1.5;}
.leaflet-container a.leaflet-popup-close-button{color:#8fb4e8;}
.leaflet-tooltip{background:rgba(12,22,38,.96);color:#e6eefc;border:1px solid rgba(110,170,255,.32);border-radius:8px;box-shadow:0 4px 14px rgba(0,0,0,.5);font-size:11px;padding:4px 9px;}
.leaflet-tooltip-top:before{border-top-color:rgba(12,22,38,.96);}
.ps-pin{background:none !important;border:none !important;}
.ps-pin > div{filter:drop-shadow(0 3px 3px rgba(0,0,0,.65));transition:transform .15s ease;transform-origin:50% 100%;}
.ps-pin:hover > div{transform:scale(1.16);}
.ps-pop .ps-h{font-size:13px;font-weight:700;color:#fff;}
.ps-pop .ps-sub{color:#8fb4e8;margin-top:1px;}
.ps-pop .ps-row{margin-top:6px;padding-top:6px;border-top:1px solid rgba(255,255,255,.08);}
</style>"""


from branca.element import MacroElement
from jinja2 import Template


class _KeepWorldInView(MacroElement):
    """Stops the map ever showing anything outside the world imagery.

    Works out, from the real pixel size of the map box, the smallest zoom at
    which the world still covers the whole box, and makes that the minimum
    zoom (so the zoom-out button greys out there). Also pins panning to the
    world's edges. Re-runs when the box is resized."""
    _template = Template("""
        {% macro script(this, kwargs) %}
        (function () {
            var map = {{ this._parent.get_name() }};
            var world = L.latLngBounds([[-85.0511, -180], [85.0511, 180]]);
            var base = map.options.minZoom || 0;
            map.options.maxBoundsViscosity = 1.0;
            map.setMaxBounds(world);
            function fit() {
                var s = map.getSize();
                if (!s.x || !s.y) { return; }
                var need = Math.log(Math.max(s.x, s.y) / 256) / Math.LN2;
                var mz = Math.max(base, Math.ceil(need * 2) / 2);
                map.setMinZoom(mz);
                if (map.getZoom() < mz) { map.setZoom(mz, {animate: false}); }
                map.panInsideBounds(world, {animate: false});
            }
            map.whenReady(fit);
            map.on('resize', fit);
            setTimeout(fit, 60);
            setTimeout(fit, 400);
            setTimeout(fit, 1200);
        })();
        {% endmacro %}
    """)


def _new_map(location, zoom_start=3, min_zoom=3):
    """Satellite-only map with a dark, branded look: no attribution box,
    no repeated world copies, restyled controls and popups.

    min_zoom=3 (not 2): at zoom 2 the whole world is only ~1024px wide, so
    on a full-width panel the sides show gray "Map data not yet available"
    strips. At zoom 3 the world is 2048px wide, which covers the panel
    width, so those gray areas never appear."""
    zoom_start = min(max(zoom_start, min_zoom), _MAP_MAX_ZOOM)
    try:
        m = folium.Map(
            location=location, zoom_start=zoom_start, tiles=None, min_zoom=min_zoom,
            max_zoom=_MAP_MAX_ZOOM, max_bounds=True, zoom_snap=0.5, attribution_control=False,
        )
    except Exception:
        m = folium.Map(location=location, zoom_start=zoom_start, tiles=None)
    _add_base_tiles(m)
    m.get_root().header.add_child(folium.Element(_MAP_CSS))
    try:
        m.add_child(_KeepWorldInView())
    except Exception:
        pass
    return m


def _chip(label, color, size=18):
    """Small round, colour-coded number badge (email number / hop number)."""
    return (
        f'<span style="display:inline-flex;align-items:center;justify-content:center;width:{size}px;'
        f'height:{size}px;border-radius:50%;background:{color};color:#fff;font:700 {max(size - 8, 9)}px/1 '
        f'Inter,Segoe UI,sans-serif;box-shadow:0 0 0 1.5px rgba(255,255,255,.85);flex:none;">{html.escape(str(label))}</span>'
    )


def _pin_marker(lat, lon, color, text, popup_html, tooltip=None, big=False,
                glyph=None, chips=None, chips_caption=""):
    """A map pin (teardrop) in any hex colour.

    text   - short label inside the pin (email / hop number)
    glyph  - "stack" draws a layered-cards icon instead of text (several
             emails share this spot)
    chips  - [(label, colour), ...] drawn as a pill beside the pin, so you
             can read WHICH emails/hops are here without clicking."""
    w, h = (36, 48) if big else (28, 38)
    fs = 13 if big else 11
    top = round(h * 0.375 - fs / 2, 1)
    glyph_svg = ""
    if glyph == "stack":
        glyph_svg = (
            '<g fill="none" stroke="#fff" stroke-width="1.5" stroke-linejoin="round">'
            '<rect x="7.2" y="7" width="6.4" height="6.4" rx="1.2"/>'
            '<rect x="10" y="10" width="6.4" height="6.4" rx="1.2" fill="rgba(255,255,255,0.35)"/></g>'
        )
    svg = (
        f'<svg viewBox="0 0 24 32" width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg">'
        f'<path d="M12 1C5.9 1 1 5.9 1 12c0 8.5 11 19 11 19s11-10.5 11-19C23 5.9 18.1 1 12 1z" '
        f'fill="{color}" stroke="#ffffff" stroke-width="1.5"/>'
        f'<circle cx="12" cy="12" r="8.2" fill="rgba(0,0,0,0.30)"/>{glyph_svg}'
        f'<path d="M5 8.5C6.5 4.5 10.5 2.6 14 3.2" stroke="rgba(255,255,255,0.45)" stroke-width="1.3" '
        f'fill="none" stroke-linecap="round"/></svg>'
    )
    label = ""
    if glyph is None:
        label = (
            f'<span style="position:absolute;left:0;right:0;top:{top}px;text-align:center;color:#fff;'
            f'font:700 {fs}px/1.1 Inter,Segoe UI,sans-serif;letter-spacing:.2px;">{html.escape(str(text))}</span>'
        )
    pill = ""
    if chips:
        shown = chips[:6]
        more = f'<span style="color:#9db4d6;">+{len(chips) - 6}</span>' if len(chips) > 6 else ""
        cap = (f'<span style="color:#9db4d6;font-weight:600;margin-right:2px;">{html.escape(chips_caption)}</span>'
               if chips_caption else "")
        pill = (
            f'<div style="position:absolute;left:{w + 3}px;top:{max(top - 4, 0)}px;display:flex;align-items:center;'
            f'gap:4px;padding:3px 8px 3px 7px;border-radius:999px;background:rgba(10,19,34,.93);'
            f'border:1px solid rgba(255,255,255,.22);box-shadow:0 2px 8px rgba(0,0,0,.55);white-space:nowrap;'
            f'font:600 10px/1 Inter,Segoe UI,sans-serif;pointer-events:none;">{cap}'
            + "".join(_chip(lab, col, 16) for lab, col in shown) + more + "</div>"
        )
    icon = folium.DivIcon(
        html=f'<div style="position:relative;width:{w}px;height:{h}px;">{svg}{label}{pill}</div>',
        icon_size=(w, h), icon_anchor=(w // 2, h), class_name="ps-pin",
    )
    mk = folium.Marker(location=[lat, lon], icon=icon, popup=folium.Popup(popup_html, max_width=380))
    if tooltip:
        mk.add_child(folium.Tooltip(tooltip))
    return mk


def _loc_key(h):
    return (round(float(h["lat"]), 3), round(float(h["lon"]), 3))


_BANNER_TONES = ("batch", "single", "ai", "intel", "rose", "sky", "gold", "teal", "plum", "lime")


def _banner_html(step, title, sub="", scope="", tone="batch"):
    """HTML for the module-level header (see SECTION HEADER SYSTEM v2 in the
    CSS): small mono eyebrow, title, one-line sub, and a plain meta tag on
    the right. No pill/button-shaped pieces -- nothing in it is clickable."""
    tone = tone if tone in _BANNER_TONES else "batch"
    return (
        f'<div class="part-banner part-banner-{tone}">'
        f'<div class="pb-main"><div class="pb-step">{html.escape(str(step))}</div>'
        f'<div class="pb-title">{html.escape(str(title))}</div>'
        + (f'<div class="pb-sub">{html.escape(str(sub))}</div>' if sub else '')
        + '</div>'
        + (f'<span class="pb-scope">{html.escape(str(scope))}</span>' if scope else '')
        + '</div>'
    )


def _banner(step, title, sub="", scope="", tone="batch"):
    """Module-level header: eyebrow + title + one-line sub + scope tag.
    Same component as the Forensic Report PART 1 / PART 2 banners."""
    st.markdown(_banner_html(step, title, sub, scope, tone), unsafe_allow_html=True)


def _sec(title, sub="", tone="batch"):
    """Slim section header (accent bar + title + optional sub) for the
    sections inside a module."""
    tone = tone if tone in _BANNER_TONES else "batch"
    st.markdown(
        f'<div class="sec-head sec-{tone}"><div class="sh-title">{html.escape(str(title))}</div>'
        + (f'<div class="sh-sub">{html.escape(str(sub))}</div>' if sub else '')
        + '</div>',
        unsafe_allow_html=True,
    )


def _render_all_hops_map(cases, key_prefix, height=560, max_emails=10, source_rows=None):
    """Hop route of up to max_emails emails (most recent first) on one map.

    Every hop is a pin in its email's colour with the email number inside.
    When several emails land on the same spot they share ONE violet
    'stacked' pin; a pill beside it lists the colour-coded numbers of every
    email there, and the details table underneath shows, per email, which
    other emails it shares a spot with."""
    ordered = [
        c for _, c in sorted(
            enumerate(cases),
            key=lambda pair: _case_recency_key(pair[1], pair[0], source_rows),
            reverse=True,
        )
    ]
    routed = [(c, _case_hop_points(c)) for c in ordered]
    routed = [(c, pts) for c, pts in routed if pts]
    total_routed = len(routed)
    routed = routed[:max_emails]
    if not routed:
        st.info("No geolocatable hops across the loaded emails yet.")
        return
    all_coords = [[h["lat"], h["lon"]] for _, pts in routed for h in pts]
    m = _new_map(all_coords[0], zoom_start=3)

    info = {}
    spots = {}
    for n, (case, pts) in enumerate(routed, start=1):
        color = _EMAIL_ROUTE_COLORS[(n - 1) % len(_EMAIL_ROUTE_COLORS)]
        parsed = case.get("parsed", {}) or {}
        sender = (parsed.get("from_addr") or "").strip() or "Unknown sender"
        subject = re.sub(r"^\s*Live IMAP:\s*", "", str(case.get("name") or "")).strip() or "(no subject)"
        origin = (case.get("geo", {}) or {}).get("origin", {}) or {}
        where = ", ".join(p for p in [origin.get("city"), origin.get("country")] if p) or "Unknown location"
        info[n] = {
            "color": color, "sender": sender, "subject": subject,
            "ip": origin.get("ip") or (pts[-1].get("ip") if pts else "") or "Unknown",
            "where": where, "hops": len(pts), "shares": set(),
        }
        coords = [[h["lat"], h["lon"]] for h in pts]
        if len(coords) > 1:
            folium.PolyLine(coords, color=color, weight=8, opacity=0.14).add_to(m)
            folium.PolyLine(coords, color=color, weight=2.5, opacity=0.9, dash_array="7 9").add_to(m)
        for i, h in enumerate(pts, start=1):
            spot = spots.setdefault(_loc_key(h), {"lat": h["lat"], "lon": h["lon"], "ips": set(), "rows": [], "last": False, "city": ""})
            if h.get("ip"):
                spot["ips"].add(str(h.get("ip")))
            spot["city"] = spot["city"] or f"{h.get('city', '')} {h.get('country', '')}".strip()
            spot["rows"].append((n, i, len(pts)))
            spot["last"] = spot["last"] or (i == len(pts))

    for spot in spots.values():
        emails_here = sorted({r[0] for r in spot["rows"]})
        multi = len(emails_here) > 1
        if multi:
            for a in emails_here:
                info[a]["shares"].update(x for x in emails_here if x != a)
        ips = ", ".join(sorted(spot["ips"])) or "Unknown"
        rows_html = "".join(
            f'<div class="ps-row" style="display:flex;gap:9px;align-items:flex-start;">{_chip(n, info[n]["color"], 20)}'
            f'<div><b>{html.escape(info[n]["sender"])}</b><br>'
            f'<span style="color:#aab9d0;">{html.escape(info[n]["subject"][:90])}</span><br>'
            f'<span style="color:#8fb4e8;">hop {i} of {tot}</span></div></div>'
            for n, i, tot in spot["rows"]
        )
        head = (f"{len(emails_here)} emails share this spot" if multi else f"Email {emails_here[0]}")
        popup = (
            f'<div class="ps-pop"><div class="ps-h">{head}</div>'
            f'<div class="ps-sub">IP {html.escape(ips)} &middot; {html.escape(spot["city"])}</div>{rows_html}</div>'
        )
        if multi:
            _pin_marker(
                spot["lat"], spot["lon"], "#7c3aed", "", popup,
                tooltip=f"{ips} · emails " + ", ".join(str(x) for x in emails_here),
                big=spot["last"], glyph="stack",
                chips=[(x, info[x]["color"]) for x in emails_here], chips_caption="Emails",
            ).add_to(m)
        else:
            n0 = emails_here[0]
            _pin_marker(
                spot["lat"], spot["lon"], info[n0]["color"], str(n0), popup,
                tooltip=f"Email {n0} · {ips}", big=spot["last"],
            ).add_to(m)

    if len(all_coords) > 1:
        try:
            m.fit_bounds(all_coords, max_zoom=5)
        except Exception:
            pass
    with st.container(key=f"{key_prefix}_all_hops_map_frame"):
        st_folium(m, width="stretch", height=height, returned_objects=[], key=f"{key_prefix}_all_hops_map")

    # ---- details table under the map ----
    th = ("padding:9px 12px;text-align:left;font:700 10px/1 Inter,Segoe UI,sans-serif;letter-spacing:.9px;"
          "text-transform:uppercase;color:#8fb4e8;background:rgba(20,36,60,.9);")
    td = "padding:9px 12px;border-top:1px solid rgba(255,255,255,.07);vertical-align:middle;"
    cut = "overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
    body = ""
    for n in sorted(info):
        d = info[n]
        shared = (
            '<span style="display:inline-flex;gap:4px;flex-wrap:wrap;">'
            + "".join(_chip(x, info[x]["color"], 18) for x in sorted(d["shares"])) + "</span>"
            if d["shares"] else '<span style="color:#6f8199;">alone</span>'
        )
        body += (
            f'<tr><td style="{td}">{_chip(n, d["color"], 22)}</td>'
            f'<td style="{td}{cut}" title="{html.escape(d["sender"])}"><b style="color:#fff;">{html.escape(d["sender"])}</b></td>'
            f'<td style="{td}{cut}color:#c9d6ea;" title="{html.escape(d["subject"])}">{html.escape(d["subject"])}</td>'
            f'<td style="{td}{cut}color:#c9d6ea;" title="{html.escape(d["ip"])} &middot; {html.escape(d["where"])}">'
            f'{html.escape(d["where"])}<br><span style="color:#7f93b0;font-size:11px;">{html.escape(str(d["ip"]))}</span></td>'
            f'<td style="{td}text-align:center;color:#c9d6ea;">{d["hops"]}</td>'
            f'<td style="{td}">{shared}</td></tr>'
        )
    table = (
        '<div style="margin-top:10px;border:1px solid rgba(110,170,255,.2);border-radius:12px;overflow:hidden;'
        'background:rgba(12,22,38,.65);">'
        '<table style="width:100%;border-collapse:collapse;table-layout:fixed;font:13px/1.35 Inter,Segoe UI,sans-serif;color:#e6eefc;">'
        '<colgroup><col style="width:56px"><col style="width:23%"><col style="width:29%"><col style="width:22%">'
        '<col style="width:64px"><col></colgroup>'
        f'<thead><tr><th style="{th}">No.</th><th style="{th}">Sender</th><th style="{th}">Subject</th>'
        f'<th style="{th}">Origin</th><th style="{th}text-align:center;">Hops</th><th style="{th}">Same spot as</th></tr></thead>'
        f'<tbody>{body}</tbody></table></div>'
    )
    st.markdown(table, unsafe_allow_html=True)
    st.caption(
        f"Showing {len(routed)} of {total_routed} emails with geolocatable hops (most recent {max_emails} max). "
        "A pin with a number is one email. A violet stacked pin means several emails share that exact spot - "
        "the pill beside it lists their numbers. Click any pin for sender and subject. Imagery © Esri."
    )


# --------------------------------------------------------------------------
# One-click pipeline: machine analysis ->AI campaign summary -> semantic
# origin correlation ->Forensic Report, for a small recent batch of raw
# messages. Triggered right where the evidence shows up (Live IMAP connected
# card, CSV upload, AI Copilot chat) so the user doesn't have to hunt for it.
# --------------------------------------------------------------------------
def _collect_recent_live_imap_items(n=10):
    """Fetch the n most recent full messages from the connected mailbox.
    Returns (items, error_message)."""
    cfg = st.session_state.get("live_mailbox_config")
    if not cfg:
        return None, "No active mailbox connection. Connect a mailbox first."
    # Reuse already-loaded headers from the connect step when we have enough
    # of them, instead of re-querying IMAP for headers again.
    headers = st.session_state.get("live_mailbox_messages") or []
    if len(headers) < n:
        try:
            headers = fetch_mailbox_messages(
                cfg["host"], cfg["user"], cfg["credential"],
                max_messages=n, folder=cfg["folder"], port=cfg["port"], auth_mode=cfg["auth_mode"],
            )
        except Exception as exc:
            return None, f"Mailbox fetch failed: {exc}"
    # Fetch all n message bodies over ONE IMAP session instead of the old
    # loop-of-fetch_message_by_uid, which reconnected and re-authenticated
    # for every single message -- N full TLS-handshake-plus-login round
    # trips instead of one.
    try:
        raw_by_uid = fetch_messages_by_uids(
            cfg["host"], cfg["user"], cfg["credential"],
            [h["uid"] for h in headers[:n]],
            folder=cfg["folder"], port=cfg["port"], auth_mode=cfg["auth_mode"],
        )
    except Exception:
        raw_by_uid = {}
    items = []
    for i, h in enumerate(headers[:n], start=1):
        raw_bytes = raw_by_uid.get(str(h.get("uid")))
        if isinstance(raw_bytes, bytes) and raw_bytes:
            items.append({
                "position": i, "row": h.get("uid"),
                "date": str(h.get("date") or "Unknown"),
                "_raw": raw_bytes,
            })
    if not items:
        return None, "No messages could be retrieved from the mailbox."
    return items, None


def _collect_recent_csv_items(email_texts, source_name, n=10):
    """Pick the n most recent rows (by Date header, CSV order as fallback)
    from a parsed CSV's raw email texts and turn them into raw bytes."""
    recent = []
    for idx, email_text in enumerate(email_texts):
        recent.append({"row": idx, "text": email_text, "date": get_email_date(email_text)})
    recent.sort(
        key=lambda x: (
            x["date"] is not None,
            x["date"] if x["date"] is not None else datetime.min.replace(tzinfo=timezone.utc),
            x["row"],
        ),
        reverse=True,
    )
    items = []
    for i, item in enumerate(recent[:n], start=1):
        row_raw = item["text"].replace("\\n", "\n").encode("utf-8")
        items.append({
            "position": i, "row": item["row"],
            "date": item["date"].astimezone().isoformat() if item["date"] is not None else "Unknown",
            "_raw": row_raw,
        })
    return items


def _run_batch_pipeline(source_items, source_label):
    """Runs machine analysis, AI campaign analysis and semantic origin
    correlation across source_items, then hands everything to the Forensic
    Report panel and jumps straight there."""
    if not source_items:
        st.warning("No messages were available to analyze.")
        return

    machine_progress = st.progress(0, text="Running machine forensic analysis...")
    batch_items = []
    for i, item in enumerate(source_items, start=1):
        res = analyze_bytes(item["_raw"], f"{source_label} #{item['position']}")
        ehash = hashlib.sha256(item["_raw"]).hexdigest()
        tagged = dict(res)
        tagged["_evidence_hash"] = ehash
        _corr_cases[ehash] = tagged
        batch_items.append({
            "position": item["position"],
            "row": item.get("row"),
            "date": item.get("date"),
            "result": res,
            "_raw": item["_raw"],
        })
        machine_progress.progress(i / len(source_items), text=f"Machine analysis {i}/{len(source_items)}")
    machine_progress.empty()

    ai_progress = st.progress(0, text="Running AI threat analysis...")

    def _ai_cb(percent, message):
        ai_progress.progress(max(0.0, min(1.0, percent / 100.0)), text=f"AI analysis: {int(percent)}% - {message}")

    batch_ai_result = analyze_batch_with_ollama(batch_items, timeout=600, progress_callback=_ai_cb)
    ai_progress.progress(1.0, text="AI analysis complete")

    semantic_lines = []
    semantic_matches_by_position = {}
    semantic_matches_all = {}
    if _nomic_ready():
        sem_progress = st.progress(0, text="Running semantic origin correlation...")
        # Pass 1 indexes EVERY email in the batch; pass 2 searches. Searching
        # inside the same loop meant email #1 was compared before emails
        # #2-#10 existed in the index, so batch-mates could never match it.
        _sem_total = max(1, 2 * len(batch_items))
        _sem_hashes = {}
        for i, bi in enumerate(batch_items, start=1):
            ehash = hashlib.sha256(bi["_raw"]).hexdigest()
            _sem_hashes[bi["position"]] = ehash
            try:
                _sem_index(ehash, bi["result"].get("geo", {}) or {})
            except Exception:
                pass
            sem_progress.progress(i / _sem_total, text=f"Indexing origin profiles {i}/{len(batch_items)}")
        for i, bi in enumerate(batch_items, start=1):
            geo_i = bi["result"].get("geo", {}) or {}
            try:
                matches = _sem_find(_sem_hashes[bi["position"]], geo_i.get("origin", {}) or {}, top_k=3)
                if matches:
                    top = matches[0]
                    semantic_matches_by_position[bi["position"]] = top
                    semantic_matches_all[bi["position"]] = matches
                    semantic_lines.append(
                        f"Email #{bi['position']}: **{top['band']}** match ({top['score']:.0%}) to origin "
                        f"{top.get('ip') or 'unknown IP'} ({top.get('infra_label') or 'unknown infra'}) - "
                        f"{_sem_reason_text(top)}."
                    )
            except Exception:
                pass
            sem_progress.progress((len(batch_items) + i) / _sem_total, text=f"Semantic correlation {i}/{len(batch_items)}")
        sem_progress.empty()
    else:
        semantic_lines.append("Semantic correlation skipped — Ollama / nomic-embed-text isn't available right now.")

    st.session_state["pipeline_batch_result"] = {
        "source": source_label,
        "count": len(batch_items),
        "result": batch_ai_result,
        "semantic_summary": semantic_lines,
        "semantic_matches": semantic_matches_by_position,
        "semantic_matches_all": semantic_matches_all,
    }
    st.session_state["pipeline_batch_items"] = batch_items
    st.session_state["forensic_report_source"] = "pipeline"
    # NOTE: don't write st.session_state["active_panel"] here — by this point
    # in the script the st.radio(key="active_panel") widget below has already
    # been instantiated for this run, and Streamlit forbids mutating a keyed
    # widget's session_state value after that (StreamlitAPIException). Stage
    # the target panel in a plain, non-widget key instead; it's applied to
    # "active_panel" on the rerun, *before* the radio widget is created.
    st.session_state["_pending_active_panel"] = "Forensic Report"
    st.session_state["_scroll_to_joint_report"] = True
    st.success(f"Analyzed {len(batch_items)} emails. Opening the Forensic Report...")
    st.rerun()


class _StoredUpload:
    """Lightweight stand-in for a Streamlit UploadedFile, backed by bytes
    already captured in st.session_state. Streamlit forgets a widget's
    value on any rerun where the widget itself isn't rendered -- so once
    the compact 'Evidence Loaded' card replaces the native file_uploader
    on screen, this takes over as `uploaded` for the rest of the script,
    exposing just the two members (`.name`, `.getvalue()`) the rest of the
    app actually uses."""
    def __init__(self, name, data):
        self.name = name
        self._data = data

    def getvalue(self):
        return self._data


# These three helpers are used both by the Dashboard's evidence-acquisition
# UI below AND by other panels (AI Threat Analysis, Forensic Report, Threat
# History) that read CSV-derived data without re-rendering that UI -- so
# they must stay defined unconditionally (outside the `if active_panel ==
# "Dashboard"` gate), not nested inside it.
@st.cache_data(show_spinner=False)
def parse_email_csv(file_bytes):
    csv.field_size_limit(50 * 1024 * 1024)
    text = file_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        return []
    fields = [str(f).strip() for f in reader.fieldnames if f is not None]
    preferred = ["raw_email", "raw_message", "email", "email_text", "message", "body", "content", "text"]
    selected = None
    for wanted in preferred:
        for field in fields:
            normalized = field.lower().strip().replace(" ", "_").replace("-", "_")
            if normalized == wanted:
                selected = field
                break
        if selected:
            break
    data = []
    for row in reader:
        if selected:
            value = row.get(selected, "")
        else:
            values = [str(v or "") for v in row.values()]
            value = max(values, key=len, default="")
        value = str(value or "")
        if value.strip():
            data.append(value)
    return data

def get_email_date(email_text):
    try:
        for line in email_text.replace("\r\n", "\n").split("\n"):
            if line.lower().startswith("date:"):
                value = line.split(":", 1)[1].strip()
                dt = parsedate_to_datetime(value)
                if dt is not None:
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
    except Exception:
        pass
    return None

def _render_polished_table(df, empty_text="No data available.", max_height=None):
    """Presentation-only replacement for st.dataframe on plain, read-only
    tables -- draws real themed HTML/CSS (see '.polished-table' in the
    global stylesheet) instead of Streamlit's own canvas-rendered grid,
    which never picks up the app's dark theme no matter what CSS targets
    it. Never used on a table that needs on_select row-clicks or
    column_config widgets (progress bars, etc.) -- those keep st.dataframe
    since HTML can't reproduce that behavior. Renders exactly the rows/
    columns handed to it; no data is added, dropped, or reordered."""
    if df is None or getattr(df, "empty", True):
        st.markdown(f'<div class="polished-table-empty">{html.escape(empty_text)}</div>', unsafe_allow_html=True)
        return
    cols = list(df.columns)
    thead = "".join(f"<th>{html.escape(str(c))}</th>" for c in cols)
    body_rows = []
    for _, row in df.iterrows():
        tds = []
        for c in cols:
            v = row[c]
            text = "" if (v is None or (isinstance(v, float) and pd.isna(v))) else str(v)
            tds.append(f"<td>{html.escape(text)}</td>")
        body_rows.append(f"<tr>{''.join(tds)}</tr>")
    tbody = "".join(body_rows)
    wrap_style = f' style="max-height:{int(max_height)}px;overflow-y:auto;"' if max_height else ""
    st.markdown(
        f'<div class="polished-table-wrap"{wrap_style}>'
        f'<table class="polished-table"><thead><tr>{thead}</tr></thead>'
        f'<tbody>{tbody}</tbody></table></div>',
        unsafe_allow_html=True,
    )


def _render_email_results_table(df, height=300):
    """Rich HTML replacement for the Email Results / Threat History grids,
    which used to go through st.dataframe + _display_email_table's
    ProgressColumn config. st.dataframe renders that onto a canvas (see
    _render_polished_table's docstring for why that can never pick up the
    app's dark theme), so Threat Score sat there as a flat, always-red
    default bar no matter the actual severity, and Verdict as plain
    unstyled text -- both look like an unstyled default grid next to
    everything else in the app that *is* themed.

    This draws the same rows as real HTML instead: Threat Score becomes a
    coloured progress bar, Verdict a coloured pill, Origin IP/IP a
    monospace chip -- all keyed off the same _LEVEL_MARKER_COLORS map the
    map markers already use, so severity means the same colour everywhere
    in the app. Read-only, presentation-only: same rows/columns in, none
    added, dropped, or reordered."""
    if df is None or getattr(df, "empty", True):
        st.markdown('<div class="polished-table-empty">No data available.</div>', unsafe_allow_html=True)
        return
    cols = list(df.columns)
    thead = "".join(f"<th>{html.escape(str(c))}</th>" for c in cols)
    body_rows = []
    for _, row in df.iterrows():
        tds = []
        verdict_key = str(row.get("Verdict", "")).upper()
        for c in cols:
            v = row[c]
            text = "" if (v is None or (isinstance(v, float) and pd.isna(v))) else str(v)
            if c == "Threat Score":
                try:
                    score = float(v)
                except (TypeError, ValueError):
                    score = 0.0
                bar_color = _LEVEL_MARKER_COLORS.get(verdict_key, "#3b82f6")
                pct = max(0.0, min(100.0, score))
                tds.append(
                    '<td><div class="email-score-cell">'
                    f'<div class="email-score-track"><div class="email-score-fill" '
                    f'style="width:{pct}%;background:{bar_color};"></div></div>'
                    f'<span class="email-score-num">{score:.1f}</span>'
                    '</div></td>'
                )
            elif c == "Verdict":
                color = _LEVEL_MARKER_COLORS.get(verdict_key, "#8fa5bd")
                tds.append(
                    f'<td><span class="verdict-pill" style="background:{color}22;color:{color};'
                    f'box-shadow:inset 0 0 0 1px {color}55;">{html.escape(verdict_key or "UNKNOWN")}</span></td>'
                )
            elif c in ("Origin IP", "IP"):
                tds.append(f'<td><span class="ip-chip">{html.escape(text)}</span></td>')
            elif c == "Row #":
                tds.append(f'<td><span class="row-chip">{html.escape(text)}</span></td>')
            else:
                tds.append(f"<td>{html.escape(text)}</td>")
        body_rows.append(f"<tr>{''.join(tds)}</tr>")
    tbody = "".join(body_rows)
    st.markdown(
        f'<div class="polished-table-wrap" style="max-height:{int(height)}px;overflow-y:auto;">'
        f'<table class="polished-table"><thead><tr>{thead}</tr></thead>'
        f'<tbody>{tbody}</tbody></table></div>',
        unsafe_allow_html=True,
    )


raw = None
case_name = ""
uploaded = None
data = []
geo = {}
csv_scan_key = None


def _copilot_handle_command(command, cases, raw, case_name, result, current_evidence_hash):
    """Real intent dispatch for the Synapse Copilot panel -- each branch
    calls actual app functions (live IMAP fetch, the cached analyzer,
    tracker.db, Nomic search), not a canned reply. Shared by every place
    the copilot panel is rendered so there is exactly one command
    vocabulary in the app."""
    text = command.lower()

    digit_match = re.search(r"(\d{1,3})\s*email", text)
    if ("track" in text or "scan" in text or "fetch" in text) and ("email" in text or digit_match):
        count = int(digit_match.group(1)) if digit_match else 10
        count = max(1, min(count, 20))
        # This now drives the SAME full pipeline the old standalone
        # "Analyze N Recent Emails" buttons used to (machine + AI + semantic
        # analysis, landing on a downloadable Forensic Report) instead of a
        # lighter machine-only pass, so the copilot command is a genuine
        # replacement for those buttons rather than a weaker lookalike.
        # `uploaded`/`data` are the same script-level evidence-source
        # variables every other panel reads; both are already resolved by
        # the time a copilot command can be typed.
        _is_csv_source = uploaded is not None and str(getattr(uploaded, "name", "") or "").lower().endswith(".csv") and data

        # BUG FIX: this used to check "is a live mailbox config saved
        # ANYWHERE in session_state" first, regardless of which acquisition
        # mode is actually selected on the Dashboard right now. That meant
        # connecting a Gmail mailbox once, then switching to Evidence File
        # Upload and loading a CSV, silently kept reporting on the old live
        # mailbox forever -- the leftover connection always won, so the two
        # modes never actually worked independently the way the Dashboard's
        # own mode picker implies they do. This now reads whichever mode is
        # the CURRENT one (the same input_mode_radio state the Dashboard's
        # acquisition-mode cards set), so each mode's data is only ever used
        # while that mode is actually selected -- switching modes switches
        # what the copilot reports on, instead of merging or getting stuck
        # on whichever was connected first.
        _copilot_mode = st.session_state.get("input_mode_radio", "Live IMAP Mailbox Interceptor")
        _copilot_is_live_mode = "Live IMAP Mailbox Interceptor" in _copilot_mode
        _copilot_is_upload_mode = "Evidence File Upload" in _copilot_mode

        if _copilot_is_live_mode:
            if not st.session_state.get("live_mailbox_config"):
                return ("You're on **Live IMAP Mailbox Interceptor** mode, but no mailbox is connected "
                        "yet. Connect one on the Dashboard, then ask me again.")
            with st.spinner(f"Fetching the {count} most recent messages..."):
                _pipeline_items, _pipeline_err = _collect_recent_live_imap_items(count)
            if _pipeline_err:
                return _pipeline_err
            if not _pipeline_items:
                return "No messages were available to analyze."
            # On success this reruns straight into the Forensic Report and
            # never returns to this line — the chat bubble this call would
            # have produced is superseded by actually landing on the report.
            _run_batch_pipeline(_pipeline_items, "Live IMAP")
            return ""
        elif _copilot_is_upload_mode:
            if not _is_csv_source:
                return ("You're on **Evidence File Upload** mode, but no CSV batch is loaded yet. "
                        "Upload a `.csv` of emails on the Dashboard, then ask me again. (A single "
                        "`.eml`/`.txt` file is already just one email, so there's nothing to batch.)")
            _pipeline_items = _collect_recent_csv_items(data, uploaded.name, count)
            if not _pipeline_items:
                return "No messages were available to analyze."
            _run_batch_pipeline(_pipeline_items, uploaded.name)
            return ""
        else:
            return ("I need an active mailbox connection first. Open **Live Email Scan (IMAP)** in the "
                    "sidebar, connect, then ask me again — or upload a CSV of emails instead.")

    if "threat" in text and ("week" in text or "show" in text or "last" in text):
        try:
            conn = get_connection()
            hist = pd.read_sql_query(
                "SELECT date, ip, country, score, verdict FROM attackers "
                "WHERE date >= datetime('now','-7 days') ORDER BY score DESC LIMIT 10",
                conn,
            )
            conn.close()
        except Exception:
            hist = pd.DataFrame()
        if hist.empty:
            return "No threats logged in the local threat history for the last 7 days."
        lines = [f"- **{row['verdict']}** (score {row['score']:.0f}) from `{row['ip']}` ({row['country']}) on {row['date']}"
                 for _, row in hist.iterrows()]
        return "Threats from the last 7 days:\n\n" + "\n".join(lines)

    if "analy" in text and ("upload" in text or "file" in text):
        if raw:
            return (f"The currently loaded evidence (**{case_name}**) scored "
                    f"**{result.get('score',0):.0f}/100** - **{result.get('level','?')}**. "
                    "See **Investigation Summary** above for the full breakdown.")
        return "No file is currently loaded. Use **Upload Email(s)** in the sidebar first."

    if "nomic" in text or "similar" in text:
        matches = _sem_find(current_evidence_hash, (result.get("geo") or {}).get("origin", {}) or {}, top_k=3)
        if not matches:
            return "No semantically similar origins are stored yet. Run **Nomic AI** (Origin & Route panel) on a few emails first."
        lines = [f"- **{m['band']}** ({m['score']:.0%}) - `{m.get('ip') or 'Unknown IP'}` ({m.get('country') or 'Unknown'}, {m.get('infra_label') or 'Unknown infra'}) - {_sem_reason_text(m)}"
                 for m in matches]
        return "Closest semantically similar origins:\n\n" + "\n".join(lines)

    return ("I can help with: **track my last N emails**, **show threats from last week**, "
            "**analyze uploaded file**, or **search similar with Nomic AI**.")


def _render_copilot_panel(cases, raw, case_name, result, current_evidence_hash):
    """Synapse Copilot: an always-visible quick-action chat, built from real
    Streamlit widgets inside one styled container rather than a plain
    default chat thread. Lives in whichever right-hand dock is on screen
    for the current mode -- the bulk-scan dock when a CSV bulk scan has
    results, otherwise the per-email dossier dock in _dashboard() -- and is
    only ever called once per run, so its keys are never instantiated
    twice. Shares _copilot_handle_command with every other place a command
    can be typed, so behaviour never diverges."""
    st.markdown(
        '<div class="panel-card-head panel-card-head-violet" style="margin-top:14px;">'
        '<span>SYNAPSE COPILOT</span><span style="color:#8fa5bd;font-size:9px;">QWEN 3.5 + NOMIC AI</span>'
        '</div>',
        unsafe_allow_html=True,
    )
    with st.container(key="copilot_panel"):
        st.markdown(
            '<div class="copilot-header"><span class="copilot-title">Ask about mailbox, threats, or origins</span>'
            '<span class="copilot-active"><span class="ssc-pulse" style="margin-right:5px;"></span>ACTIVE</span></div>',
            unsafe_allow_html=True,
        )

        _copilot_history = st.session_state.get("copilot_chat_history", [])
        if not _copilot_history:
            st.markdown(
                "<div class=\"copilot-msg\">Hi! Ask me to run a full machine + AI + semantic report "
                "on your recent mailbox (opens a downloadable Forensic Report), summarize last "
                "week's threats, or find semantically similar origins with Nomic AI. Try a shortcut "
                "below or type a request.</div>",
                unsafe_allow_html=True,
            )
        else:
            for _msg in _copilot_history[-6:]:
                _css_cls = "copilot-msg-user" if _msg["role"] == "user" else "copilot-msg"
                st.markdown(f'<div class="{_css_cls}">{_msg["content"]}</div>', unsafe_allow_html=True)

        with st.container(key="copilot_quick_actions"):
            _qa1, _qa2, _qa3 = st.columns(3)
            _quick_actions = [
                (_qa1, "Full report (10)", "Track my last 10 emails and assess their threat"),
                (_qa2, "Last week", "Show threats from last week"),
                (_qa3, "Nomic match", "Search similar with Nomic AI"),
            ]
            for _qcol, _qlabel, _qsample in _quick_actions:
                with _qcol:
                    if st.button(_qlabel, key=f"copilot_chip_{_qlabel}", use_container_width=True):
                        st.session_state.setdefault("copilot_chat_history", []).append({"role": "user", "content": _qsample})
                        st.session_state["copilot_chat_history"].append({
                            "role": "assistant",
                            "content": _copilot_handle_command(_qsample, cases, raw, case_name, result, current_evidence_hash),
                        })
                        st.rerun()

        with st.container(key="copilot_command_row"):
            with st.form(key="copilot_command_form", clear_on_submit=True):
                _fc1, _fc2 = st.columns([5, 1])
                with _fc1:
                    _typed_cmd = st.text_input(
                        "Command", key="copilot_command_text",
                        placeholder="Type your command...", label_visibility="collapsed",
                    )
                with _fc2:
                    _sent_cmd = st.form_submit_button("➤", use_container_width=True)
            if _sent_cmd and _typed_cmd.strip():
                st.session_state.setdefault("copilot_chat_history", []).append({"role": "user", "content": _typed_cmd.strip()})
                st.session_state["copilot_chat_history"].append({
                    "role": "assistant",
                    "content": _copilot_handle_command(_typed_cmd.strip(), cases, raw, case_name, result, current_evidence_hash),
                })
                st.rerun()


if active_panel == "Dashboard":
    st.write("")

    _MODE_OPTIONS = ["Live IMAP Mailbox Interceptor", "Evidence File Upload (.eml, .txt, .csv)"]
    _LIVE_OPT, _UPLOAD_OPT = _MODE_OPTIONS
    input_mode = st.session_state.get("input_mode_radio", _LIVE_OPT)
    if input_mode not in _MODE_OPTIONS:
        input_mode = _LIVE_OPT

    st.markdown('<div class="mode-select-heading">Select threat acquisition mode</div>', unsafe_allow_html=True)
    _mc_live, _mc_upload = st.columns(2)
    BOLT_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z"/></svg>'
    UPLOAD_SVG = '<svg viewBox="0 0 24 24"  fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5z"/><path d="M14 3v5h5"/><path d="M12 12.5v5.5M9.2 15.2h5.6"/></svg>'

    def _acq_card(tone, tag, title, sub, chips, svg, active):
        _chips = "".join(f'<span class="acq2-chip">{c}</span>' for c in chips)
        return (
            f'<div class="acq2 acq2-{tone} {"acq2-on" if active else ""}">'
            f'<div class="acq2-top"><span class="acq2-tag">{tag}</span>'
            f'<span class="acq2-state"><span class="acq2-state-txt">{"Active" if active else "Standby"}</span>'
            f'<span class="acq2-sw"><i></i></span></span></div>'
            f'<div class="acq2-title">{title}</div>'
            f'<div class="acq2-sub">{sub}</div>'
            f'<div class="acq2-chips">{_chips}</div>'
            f'<div class="acq2-ghost">{svg}</div>'
            f'</div>'
        )

    with _mc_live:
        st.markdown(
            _acq_card("blue", "Channel A &middot; Live", "Live IMAP mailbox interceptor",
                      "Connects straight to the mailbox and pulls messages in real time.",
                      ["Read-only", "IMAP over SSL"], BOLT_SVG, input_mode == _LIVE_OPT),
            unsafe_allow_html=True,
        )
        if st.button("Use live IMAP mailbox interceptor", key="acq_pick_live", use_container_width=True):
            st.session_state["input_mode_radio"] = _LIVE_OPT
            st.rerun()
    with _mc_upload:
        st.markdown(
            _acq_card("copper", "Channel B &middot; Batch", "Evidence file upload",
                      "Analyse saved evidence offline, one message or a whole export.",
                      [".eml", ".txt", ".csv"], UPLOAD_SVG, input_mode == _UPLOAD_OPT),
            unsafe_allow_html=True,
        )
        if st.button("Use evidence file upload", key="acq_pick_upload", use_container_width=True):
            st.session_state["input_mode_radio"] = _UPLOAD_OPT
            st.rerun()
    st.write("")

    if "Evidence File Upload" in input_mode:
        _stored_evidence = st.session_state.get("stored_evidence_file")
        st.session_state.setdefault("show_evidence_upload_form", _stored_evidence is None)
        _show_upload_form = st.session_state["show_evidence_upload_form"]

        if _stored_evidence is not None and not _show_upload_form:
            # Compact, single-line "loaded" card -- same pattern as the Live
            # IMAP "Mailbox connected" confirmation -- instead of leaving the
            # full drag-and-drop dropzone on screen for the rest of the
            # session. The file's bytes already live in session_state (see
            # below), so hiding the native widget here doesn't lose them.
            _kb = len(_stored_evidence["bytes"]) / 1024
            st.markdown(f"""
            <div class="stage-card stage-card-success">
              <div class="stage-label">EVIDENCE LOADED</div>
              <div class="stage-title">{html.escape(str(_stored_evidence["name"]))}</div>
              <div class="stage-help">{_kb:,.1f} KB in the secure analysis intake. Use the button below to load different evidence.</div>
            </div>
            """, unsafe_allow_html=True)
            if st.button("Change File / New Upload", key="evidence_show_form_btn", use_container_width=True):
                st.session_state["show_evidence_upload_form"] = True
                st.session_state["stored_evidence_file"] = None
                st.session_state["bulk_scan_file_key"] = None
                st.session_state["bulk_scan_results"] = None
                st.session_state["bulk_scan_cases"] = None
                st.session_state["bulk_scan_cases_hash"] = None
                st.session_state["unified_email_table"] = None
                st.session_state.pop("forensic_report_source", None)
                st.rerun()
            uploaded = _StoredUpload(_stored_evidence["name"], _stored_evidence["bytes"])
        else:
            st.markdown(
                """<div class="intake-head">
                    <div class="intake-main">
                        <div class="intake-eyebrow">Channel B &middot; Batch</div>
                        <div class="intake-title">Evidence intake</div>
                        <div class="intake-sub">Drop a suspicious EML, TXT or CSV evidence set into the secure analysis intake.</div>
                    </div>
                    <div class="intake-meta">
                        <span class="intake-chip">.eml</span><span class="intake-chip">.txt</span><span class="intake-chip">.csv</span>
                        <span class="intake-limit">50 MB per file</span>
                    </div>
                </div>""",
                unsafe_allow_html=True,
            )
            _up_c = st.container()
            with _up_c:
                _raw_uploaded = st.file_uploader(
                    "",
                    type=["eml", "txt", "csv"],
                    label_visibility="collapsed",
                    key="evidence_uploader",
                )
            if _raw_uploaded is not None:
                st.session_state["stored_evidence_file"] = {"name": _raw_uploaded.name, "bytes": _raw_uploaded.getvalue()}
                st.session_state["show_evidence_upload_form"] = False
                st.rerun()
            uploaded = None
            if not uploaded:
                st.markdown(
                    '<div class="intake-status"><span class="intake-dot"></span>'
                    '<span class="intake-status-k">Ready</span>'
                    '<span class="intake-status-v">Waiting for evidence. Accepts EML, TXT and CSV, up to 50 MB per file.</span></div>',
                    unsafe_allow_html=True,
                )
                st.stop()
    elif "Live IMAP Mailbox Interceptor" in input_mode:
        st.markdown(
            """<div class="live-head">
                <div class="live-eyebrow">Channel A &middot; Live</div>
                <div class="live-title">Live mailbox interceptor</div>
                <div class="live-sub">Read-only access. Connect, browse, select, then acquire evidence.</div>
            </div>""",
            unsafe_allow_html=True,
        )

        # Browser/password-manager autofill sets input.value directly via the
        # DOM without firing the "input" event Streamlit's frontend (React)
        # listens on -- so a filled-looking field still reads as empty to
        # Streamlit until something dispatches that event. Two failure modes
        # were possible with the animation-only approach: (1) the browser
        # can autofill the fields before this script's listener attaches, in
        # which case the animation already fired and we'd never see it, and
        # (2) some browsers don't reliably re-fire the animation on repeat
        # Streamlit reruns. This version does both: an immediate sweep of
        # whatever is already in the fields right now (covers case 1, with a
        # few retries since the fields may not exist in the DOM the instant
        # this script runs), plus the persistent animation listener for
        # anything filled after that (covers new autofills later, e.g. after
        # "Change mailbox / Reconnect").
        components.html(
            """
            <script>
            (function () {
                const parentDoc = window.parent.document;

                function forceSync(el) {
                    try {
                        const nativeSetter = Object.getOwnPropertyDescriptor(
                            window.HTMLInputElement.prototype, 'value'
                        ).set;
                        nativeSetter.call(el, el.value);
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        el.dispatchEvent(new Event('blur', { bubbles: true }));
                    } catch (err) { /* ignore */ }
                }

                // Case 1: sweep whatever is already filled right now.
                let tries = 0;
                const sweepTimer = setInterval(() => {
                    tries += 1;
                    parentDoc.querySelectorAll('input[type="text"], input[type="password"]').forEach((el) => {
                        if (el.value) forceSync(el);
                    });
                    if (tries > 15) clearInterval(sweepTimer);
                }, 200);

                // Case 2: catch autofill that happens after this point.
                if (!parentDoc.getElementById('imap-autofill-detect-style')) {
                    const style = parentDoc.createElement('style');
                    style.id = 'imap-autofill-detect-style';
                    style.textContent = `
                        @keyframes imapAutofillDetected { from {opacity: 1;} to {opacity: 1;} }
                        input:-webkit-autofill {
                            animation-name: imapAutofillDetected;
                            animation-duration: 0.001s;
                        }
                    `;
                    parentDoc.head.appendChild(style);
                }
                if (!parentDoc.__imapAutofillListenerAttached) {
                    parentDoc.__imapAutofillListenerAttached = true;
                    parentDoc.addEventListener('animationstart', function (e) {
                        if (e.animationName === 'imapAutofillDetected') forceSync(e.target);
                    }, true);
                }
            })();
            </script>
            """,
            height=0,
        )

        mailbox_loaded = bool(st.session_state.get("live_mailbox_messages"))
        if "show_imap_connection_form" not in st.session_state:
            st.session_state["show_imap_connection_form"] = not mailbox_loaded
        show_connection_form = st.session_state["show_imap_connection_form"]

        if mailbox_loaded and not show_connection_form:
            _cfg_summary = st.session_state.get("live_mailbox_config", {}) or {}
            _mbx_user = str(_cfg_summary.get("user", ""))
            _mbx_n = len(st.session_state.get("live_mailbox_messages", []))
            _mbx_initial = html.escape((_mbx_user[:1] or "?").upper())
            # One panel (header + note + actions) instead of a card with a
            # second box stacked under it.
            with st.container(key="imap_connected_panel"):
                st.markdown(f"""
                <div class="mbx-head">
                  <div class="mbx-avatar">{_mbx_initial}</div>
                  <div class="mbx-text">
                    <div class="mbx-eyebrow"><span class="mbx-dot"></span>Mailbox connected</div>
                    <div class="mbx-title">{html.escape(_mbx_user)}</div>
                    <div class="mbx-chips">
                      <span>{html.escape(str(_cfg_summary.get("host", "")))}</span>
                      <span>folder: {html.escape(str(_cfg_summary.get("folder", "INBOX")))}</span>
                      <span>{_mbx_n} headers loaded</span>
                    </div>
                  </div>
                  <div class="mbx-badge">&#10003; Live</div>
                </div>
                <div class="mbx-note">Full Report runs machine analysis, AI threat analysis and semantic origin correlation on the {min(_mbx_n, 10) or 10} newest messages, then opens the Forensic Report ready to download &mdash; no need to pick a message below. Connection details are hidden while you work.</div>
                """, unsafe_allow_html=True)
                _cc1, _cc2, _cc3 = st.columns([3, 1.4, 1.2])
                with _cc1:
                    if st.button(
                        "Synapse Copilot — Full Report (10 Emails)",
                        type="primary", use_container_width=True, key="mailbox_quick_full_report_btn",
                    ):
                        with st.spinner("Fetching the 10 most recent messages..."):
                            _quick_items, _quick_err = _collect_recent_live_imap_items(10)
                        if _quick_err:
                            st.error(_quick_err)
                        elif not _quick_items:
                            st.warning("No messages were available to analyze.")
                        else:
                            _run_batch_pipeline(_quick_items, "Live IMAP")
                with _cc2:
                    if st.button("Change mailbox", use_container_width=True, key="imap_show_form_btn"):
                        st.session_state["show_imap_connection_form"] = True
                        st.session_state["_imap_auto_connected"] = False
                        st.session_state["manual_login_submitted"] = False
                        st.rerun()
                with _cc3:
                    if st.button("Disconnect", use_container_width=True, key="imap_disconnect_btn"):
                        for _k in [
                            "live_mailbox_messages", "live_mailbox_config", "live_selected_uid",
                            "live_selected_raw", "live_rescan_nonce", "forensic_report_source",
                            "pipeline_batch_result", "pipeline_batch_items",
                        ]:
                            st.session_state.pop(_k, None)
                        st.session_state["show_imap_connection_form"] = True
                        st.session_state["_imap_auto_connected"] = False
                        st.session_state["manual_login_submitted"] = False
                        # Also clear whichever provider's cached OAuth token
                        # got this mailbox connected (same thing each
                        # provider's own "Sign out" button does below).
                        # Without this, the next rerun's autofill still
                        # finds a live cached token, refills "imap_user",
                        # flips sign-in state back to true and the
                        # auto-connect-after-login logic immediately
                        # reconnects the very mailbox that was just
                        # disconnected.
                        _was_user = st.session_state.get("imap_user", "")
                        _was_domain = _was_user.rsplit("@", 1)[-1].lower() if "@" in _was_user else ""
                        _is_gmail = "gmail" in _was_domain
                        _is_outlook = any(n in _was_domain for n in ("outlook", "hotmail", "live.", "office365", "office 365"))
                        _is_yandex = "yandex" in _was_domain
                        if _is_gmail and GOOGLE_OAUTH_READY:
                            clear_saved_token()
                            if not MULTIUSER:
                                try:
                                    os.remove(_GOOGLE_EMAIL_CACHE_PATH)
                                except OSError:
                                    pass
                        elif _is_outlook and MICROSOFT_OAUTH_READY:
                            microsoft_oauth.clear_saved_token()
                            if not MULTIUSER:
                                try:
                                    os.remove(_PROVIDER_EMAIL_CACHE_PATHS["microsoft"])
                                except OSError:
                                    pass
                        elif _is_yandex and YANDEX_OAUTH_READY:
                            yandex_oauth.clear_saved_token()
                            if not MULTIUSER:
                                try:
                                    os.remove(_PROVIDER_EMAIL_CACHE_PATHS["yandex"])
                                except OSError:
                                    pass
                        for _k in [
                            "google_oauth_token", "microsoft_oauth_token", "yandex_oauth_token",
                            "_google_email_autofill_tried", "_microsoft_email_autofill_tried", "_yandex_email_autofill_tried",
                            "_google_email_cache", "_microsoft_email_cache", "_yandex_email_cache",
                            "imap_user", "imap_manual_password",
                        ]:
                            st.session_state.pop(_k, None)
                        st.toast(f"Disconnected {_was_user}." if _was_user else "Disconnected.")
                        st.rerun()
            imap_host = _cfg_summary.get("host", "")
            imap_port = _cfg_summary.get("port", 993)
            imap_user = _cfg_summary.get("user", "")
            imap_credential = _cfg_summary.get("credential", "")
            folder = "INBOX"
            browse_count = st.session_state.get("imap_browse_count", 10)
            auth_mode = _cfg_summary.get("auth_mode", "App Password / Password")

            with st.container(key="imap_loaded_folder_bar"):
                _fc2, _fc3 = st.columns([3, 1])
                with _fc2:
                    _new_browse_count = st.selectbox(
                        "Messages to browse", [10, 25, 50, 100],
                        index=[10, 25, 50, 100].index(browse_count) if browse_count in [10, 25, 50, 100] else 0,
                        key="imap_loaded_browse_count",
                    )
                with _fc3:
                    st.markdown("<div style='height: 1.8rem'></div>", unsafe_allow_html=True)
                    _reload_clicked = st.button("Reload", use_container_width=True, key="imap_reload_folder_btn")
                if _reload_clicked:
                    try:
                        with st.spinner("Reloading inbox..."):
                            _reloaded_messages = fetch_mailbox_messages(
                                imap_host, imap_user, imap_credential,
                                max_messages=_new_browse_count, folder=folder,
                                port=int(imap_port), auth_mode=auth_mode,
                            )
                        st.session_state["live_mailbox_messages"] = _reloaded_messages
                        st.session_state["live_mailbox_config"] = {
                            "host": imap_host, "port": int(imap_port), "user": imap_user,
                            "folder": folder, "auth_mode": auth_mode, "credential": imap_credential,
                        }
                        st.session_state["imap_browse_count"] = _new_browse_count
                        st.session_state["live_selected_uid"] = None
                        st.session_state["live_selected_raw"] = None
                        st.session_state["live_rescan_nonce"] = 0
                        _start_prefetch(st.session_state["live_mailbox_config"], [_m.get("uid") for _m in (st.session_state.get("live_mailbox_messages") or [])])
                        st.success(f"Loaded {len(_reloaded_messages)} message headers.")
                        st.rerun()
                    except Exception as _e:
                        st.error(f"Couldn't reload the inbox: {_e}")
        else:
            with st.container(key="imap_signin_card"):
                st.markdown(
                    """<div class="signin-card-header">
                        <div class="signin-card-eyebrow">Mailbox access</div>
                        <div class="signin-card-title">Connect your mailbox</div>
                        <div class="signin-card-sub">Sign in to start pulling message headers for analysis.</div>
                        <ul class="signin-facts">
                            <li class="sf-blue"><i class="sf-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></i><div class="sf-txt"><b>Read-only</b><span>Nothing in your mailbox is changed.</span></div></li>
                            <li class="sf-copper"><i class="sf-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M4 12h10M4 18h14"/></svg></i><div class="sf-txt"><b>Headers first</b><span>Message headers are pulled for analysis.</span></div></li>
                            <li class="sf-green"><i class="sf-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg></i><div class="sf-txt"><b>Provider sign-in</b><span>For Gmail, Outlook and Yandex your password never passes through this app.</span></div></li>
                        </ul>
                        <div class="signin-chips"><span>Read-only</span><span>IMAP over SSL</span><span>OAuth 2.0</span></div>
                    </div>""",
                    unsafe_allow_html=True,
                )

                # Autofill from an already-signed-in provider's cached token --
                # runs BEFORE the Email address widget below is created (same
                # ordering the original per-provider version relied on) so the
                # field opens already filled in rather than needing an extra
                # rerun. Checks all three providers now, since there's no
                # provider dropdown left to gate this on.
                if not st.session_state.get("imap_user"):
                    if GOOGLE_OAUTH_READY and oauth_available():
                        _auto_tok = _fresh_token("google_oauth_token", get_cached_access_token, True)
                        if _auto_tok and not st.session_state.get("_google_email_autofill_tried"):
                            st.session_state["_google_email_autofill_tried"] = True
                            _auto_email = _load_cached_google_email() or _fetch_google_email_from_token(_auto_tok)
                            if _auto_email:
                                st.session_state["imap_user"] = _auto_email
                                _save_cached_google_email(_auto_email)
                    if not st.session_state.get("imap_user") and MICROSOFT_OAUTH_READY and microsoft_oauth.oauth_available():
                        _auto_tok = _fresh_token("microsoft_oauth_token", microsoft_oauth.get_cached_access_token)
                        if _auto_tok and not st.session_state.get("_microsoft_email_autofill_tried"):
                            st.session_state["_microsoft_email_autofill_tried"] = True
                            _auto_email = _load_cached_provider_email("microsoft") or microsoft_oauth.fetch_email(_auto_tok)
                            if _auto_email:
                                st.session_state["imap_user"] = _auto_email
                                _save_cached_provider_email("microsoft", _auto_email)
                    if not st.session_state.get("imap_user") and YANDEX_OAUTH_READY and yandex_oauth.oauth_available():
                        _auto_tok = _fresh_token("yandex_oauth_token", yandex_oauth.get_cached_access_token)
                        if _auto_tok and not st.session_state.get("_yandex_email_autofill_tried"):
                            st.session_state["_yandex_email_autofill_tried"] = True
                            _auto_email = _load_cached_provider_email("yandex") or yandex_oauth.fetch_email(_auto_tok)
                            if _auto_email:
                                st.session_state["imap_user"] = _auto_email
                                _save_cached_provider_email("yandex", _auto_email)

                st.markdown(
                    """<div class="signin-form-head"><span class="sfh-tag">Manual login</span><span class="sfh-hint">Email &amp; app password</span></div>""",
                    unsafe_allow_html=True,
                )

                # Wrapped in a form: Streamlit only sends the fields' current
                # values when the submit button is clicked (a single batched
                # read of the live DOM), rather than relying on each
                # keystroke's own debounced update. That's what makes this
                # work reliably with autofill -- including the Windows/Chrome
                # "suggestion" autofill that inserts a value without
                # necessarily firing the events a plain st.text_input expects
                # before you click away. No JS/event hacking needed.
                with st.form("imap_manual_login_form", clear_on_submit=False, border=False):
                    imap_user = st.text_input("Email address", placeholder="Enter your email address", key="imap_user")
                    manual_password = st.text_input(
                        "Password / App password", type="password", key="imap_manual_password",
                        placeholder="Enter your password or app password",
                    )
                    _manual_login_clicked = st.form_submit_button(
                        "Log in", use_container_width=True, key="manual_login_btn"
                    )
                if _manual_login_clicked:
                    if not imap_user or not manual_password:
                        st.error(
                            "Enter both your email address and password/app password first."
                        )
                    else:
                        st.session_state["manual_login_submitted"] = True

                # Detect provider from the typed email's domain -- same loose,
                # case-insensitive matching PROVIDERS' keys already used
                # elsewhere in this file, just driven by the domain instead of
                # a dropdown pick.
                def _find_provider_key(*needles):
                    for _name in PROVIDERS.keys():
                        _n = _name.lower()
                        if any(_needle in _n for _needle in needles):
                            return _name
                    return None

                _gmail_key = _find_provider_key("gmail")
                _outlook_key = _find_provider_key("outlook", "microsoft", "office 365", "office365")
                _yandex_key = _find_provider_key("yandex")

                _domain = imap_user.split("@")[-1].lower() if "@" in imap_user else ""
                if _domain and ("gmail" in _domain or "googlemail" in _domain):
                    _detected_key = _gmail_key
                elif _domain and any(_d in _domain for _d in ("outlook.", "hotmail.", "live.", "msn.", "office365.")):
                    _detected_key = _outlook_key
                elif _domain and ("yandex" in _domain or _domain == "ya.ru"):
                    _detected_key = _yandex_key
                else:
                    _detected_key = None

                provider = _detected_key or next(iter(PROVIDERS.keys()))
                provider_defaults = PROVIDERS[provider]
                _is_gmail = _detected_key == _gmail_key and _gmail_key is not None
                _is_outlook = _detected_key == _outlook_key and _outlook_key is not None
                _is_yandex = _detected_key == _yandex_key and _yandex_key is not None

                # One-click sign-in row: all three providers shown together,
                # always, instead of nested one-at-a-time behind a provider
                # dropdown. Each box is exactly the original per-provider OAuth
                # logic (redirect-URL setup, cached-token/sign-out state, the
                # real <a>-tag sign-in link that navigates in one click) --
                # just always rendered side by side rather than gated behind
                # `_is_gmail`/`_is_outlook`/`_is_yandex`.
                st.markdown(
                    """<div class="auth-divider-wrap"><div class="auth-divider"><span>or continue with</span></div><p class="auth-note">Opens the provider's own sign-in page. Your password never passes through this app for these three.</p></div>""",
                    unsafe_allow_html=True,
                )

                _b1, _b2, _b3 = st.columns(3)

                with _b1:
                    with st.container(border=True, key="auth_google_box"):
                        st.markdown('<div class="auth-option-label auth-option-label-cyan">GMAIL</div>', unsafe_allow_html=True)
                        if not GOOGLE_OAUTH_READY:
                            st.caption("Not available: google_Oauth.py failed to import.")
                        elif not oauth_available():
                            st.caption(f"Needs setup: {client_secret_issue()}")
                        else:
                            _cached_tok = _fresh_token("google_oauth_token", get_cached_access_token, True)
                            _pending_err = st.session_state.pop("_google_oauth_error", None)
                            if _pending_err:
                                st.caption(f"Sign-in didn't complete: {_pending_err}")
                            if _cached_tok:
                                st.success("Signed in.")
                                if st.button("Sign out", key="google_signout_btn", use_container_width=True):
                                    clear_saved_token()
                                    st.session_state.pop("google_oauth_token", None)
                                    st.session_state.pop("imap_user", None)
                                    st.session_state.pop("_google_email_autofill_tried", None)
                                    st.session_state.pop("_google_email_cache", None)
                                    if not MULTIUSER:
                                        try:
                                            os.remove(_GOOGLE_EMAIL_CACHE_PATH)
                                        except OSError:
                                            pass
                                    st.rerun()
                            else:
                                try:
                                    auth_url, _state = get_authorization_url(email_hint=imap_user)
                                    # Native st.link_button instead of a hand-rolled <a> via
                                    # st.markdown(unsafe_allow_html=True): the raw-HTML anchor
                                    # was visible and looked clickable, but depending on how
                                    # Streamlit's markdown sanitizer and this host handle a
                                    # custom target="_top" anchor, the click could silently do
                                    # nothing -- no navigation, no error, nothing in the
                                    # console. st.link_button is a first-class Streamlit widget
                                    # built specifically for "click -> go to this URL" and
                                    # isn't subject to any of that; it reliably navigates every
                                    # time. Styled via CSS to keep the same Google button look.
                                    st.link_button(
                                        "Sign in with Gmail", auth_url,
                                        use_container_width=True, key="google_signin_link_btn",
                                    )
                                except Exception as e:
                                    st.caption(f"Couldn't start sign-in: {e}")
                            if not MULTIUSER:
                                with st.expander("Redirect URL setup"):
                                    st.caption("Must match a redirect URI registered on the Google OAuth client.")
                                    _r = st.text_input("App URL", value=google_redirect_uri(), key="google_redirect_uri_input", label_visibility="collapsed")
                                    if _r.strip():
                                        os.environ["SIH26106_GOOGLE_REDIRECT_URI"] = _r.strip().rstrip("/")

                with _b2:
                    with st.container(border=True, key="auth_microsoft_box"):
                        st.markdown('<div class="auth-option-label auth-option-label-msblue">OUTLOOK</div>', unsafe_allow_html=True)
                        if not MICROSOFT_OAUTH_READY:
                            st.caption("Not available: microsoft_oauth.py failed to import.")
                        elif not microsoft_oauth.oauth_available():
                            st.caption(f"Needs setup: {microsoft_oauth.client_secret_issue()}")
                        else:
                            _cached_tok = _fresh_token("microsoft_oauth_token", microsoft_oauth.get_cached_access_token)
                            _pending_err = st.session_state.pop("_microsoft_oauth_error", None)
                            _why = microsoft_oauth.last_error() if hasattr(microsoft_oauth, "last_error") else None
                            if _why and not _cached_tok:
                                st.caption(f"Session expired: {_why}")
                            if _pending_err:
                                st.caption(f"Sign-in didn't complete: {_pending_err}")
                            if _cached_tok:
                                st.success("Signed in.")
                                if st.button("Sign out", key="microsoft_signout_btn", use_container_width=True):
                                    microsoft_oauth.clear_saved_token()
                                    st.session_state.pop("microsoft_oauth_token", None)
                                    st.session_state.pop("imap_user", None)
                                    st.session_state.pop("_microsoft_email_autofill_tried", None)
                                    st.session_state.pop("_microsoft_email_cache", None)
                                    if not MULTIUSER:
                                        try:
                                            os.remove(_PROVIDER_EMAIL_CACHE_PATHS["microsoft"])
                                        except OSError:
                                            pass
                                    st.rerun()
                            else:
                                try:
                                    auth_url, _state = microsoft_oauth.get_authorization_url(email_hint=imap_user)
                                    st.link_button(
                                        "Sign in with Outlook", auth_url,
                                        use_container_width=True, key="microsoft_signin_link_btn",
                                    )
                                except Exception as e:
                                    st.caption(f"Couldn't start sign-in: {e}")
                            if not MULTIUSER:
                                with st.expander("Redirect URL setup"):
                                    st.caption("Must match a redirect URI registered on the Azure app registration.")
                                    _r = st.text_input("App URL", value=microsoft_oauth.redirect_uri(), key="microsoft_redirect_uri_input", label_visibility="collapsed")
                                    if _r.strip():
                                        os.environ["SIH26106_MS_REDIRECT_URI"] = _r.strip().rstrip("/")

                with _b3:
                    with st.container(border=True, key="auth_yandex_box"):
                        st.markdown('<div class="auth-option-label auth-option-label-yandex">YANDEX</div>', unsafe_allow_html=True)
                        # Replaces the retired Yahoo OAuth box -- Yahoo's
                        # self-serve console no longer grants any Mail API
                        # permission to new apps (confirmed: its API
                        # Permissions list only offers Fantasy Sports /
                        # OpenID / TW Auction, nothing mail-related), so that
                        # integration was a dead end with nothing left to
                        # configure. Yandex's own self-serve app console
                        # still grants IMAP mail access (mail:imap_ro) to
                        # ordinary third-party apps, so this is a real,
                        # working one-click sign-in -- same pattern as the
                        # Gmail/Outlook boxes beside it.
                        if not YANDEX_OAUTH_READY:
                            st.caption(f"Not available: yandex_oauth.py failed to import -- {YANDEX_IMPORT_ERROR}")
                        elif not yandex_oauth.oauth_available():
                            st.caption(f"Needs setup: {yandex_oauth.client_secret_issue()}")
                        else:
                            _cached_tok = _fresh_token("yandex_oauth_token", yandex_oauth.get_cached_access_token)
                            _pending_err = st.session_state.pop("_yandex_oauth_error", None)
                            if _pending_err:
                                st.caption(f"Sign-in didn't complete: {_pending_err}")
                            if _cached_tok:
                                st.success("Signed in.")
                                if st.button("Sign out", key="yandex_signout_btn", use_container_width=True):
                                    yandex_oauth.clear_saved_token()
                                    st.session_state.pop("yandex_oauth_token", None)
                                    st.session_state.pop("_yandex_email_autofill_tried", None)
                                    st.session_state.pop("imap_user", None)
                                    st.session_state.pop("_yandex_email_cache", None)
                                    if not MULTIUSER:
                                        try:
                                            os.remove(_PROVIDER_EMAIL_CACHE_PATHS["yandex"])
                                        except OSError:
                                            pass
                                    st.rerun()
                            else:
                                try:
                                    auth_url, _state = yandex_oauth.get_authorization_url(email_hint=imap_user)
                                    st.link_button(
                                        "Sign in with Yandex", auth_url,
                                        use_container_width=True, key="yandex_signin_link_btn",
                                    )
                                except Exception as e:
                                    st.caption(f"Couldn't start sign-in: {e}")
                            if not MULTIUSER:
                                with st.expander("Redirect URL setup"):
                                    st.caption("Must match a redirect URI registered on the Yandex app.")
                                    _r = st.text_input("App URL", value=yandex_oauth.redirect_uri(), key="yandex_redirect_uri_input", label_visibility="collapsed")
                                    if _r.strip():
                                        os.environ["SIH26106_YANDEX_REDIRECT_URI"] = _r.strip().rstrip("/")

                if _detected_key:
                    st.caption(f"Using another provider? The email/password fields above are auto-detected as {provider} -- override the server if that's wrong.")

                # "Custom" acts exactly like the old always-visible expander did
                # -- same host/port/auth-mode fields, same behavior -- just
                # tucked behind one click instead of always taking up space,
                # since most people never need it (their provider auto-detects
                # above). It still opens itself automatically the moment an
                # unrecognised domain is typed, so nobody has to know to click
                # it in that case.
                st.session_state.setdefault("show_custom_imap_form", False)
                if _detected_key is None and imap_user:
                    st.session_state["show_custom_imap_form"] = True

                with st.container(key="imap_custom_toggle_btn"):
                    if st.button(
                        "Set IMAP server / port manually",
                        key="imap_custom_toggle",
                    ):
                        st.session_state["show_custom_imap_form"] = not st.session_state["show_custom_imap_form"]

                if st.session_state["show_custom_imap_form"]:
                    with st.container(key="imap_custom_server_wrap"):
                        if _detected_key is None and imap_user:
                            st.caption("Provider not recognised from the email domain -- set the server manually below.")
                        _cc1, _cc2 = st.columns([2, 1])
                        with _cc1:
                            imap_host = st.text_input("IMAP server", provider_defaults["host"], key=f"imap_host_{provider}")
                        with _cc2:
                            imap_port = st.number_input("Port", min_value=1, max_value=65535, value=int(provider_defaults["port"]), step=1, key=f"imap_port_{provider}")
                        if _detected_key is None:
                            custom_auth_mode = st.selectbox("Authentication", ["App Password / Password", "OAuth2 Access Token"], key="imap_auth_mode")
                        else:
                            custom_auth_mode = "App Password / Password"
                else:
                    imap_host = st.session_state.get(f"imap_host_{provider}", provider_defaults["host"])
                    imap_port = st.session_state.get(f"imap_port_{provider}", provider_defaults["port"])
                    custom_auth_mode = "App Password / Password"

            # Resolve the credential actually used by "Connect & Load
            # Mailbox" below: a cached OAuth token for the DETECTED
            # provider wins (same precedence the original per-provider
            # code used -- cached token beats a manually-typed password);
            # otherwise fall back to the password field above, in whichever
            # auth mode the custom-server section specifies for an
            # unrecognised domain.
            imap_credential = manual_password
            auth_mode = custom_auth_mode

            if _is_gmail and GOOGLE_OAUTH_READY and oauth_available():
                _tok = _fresh_token("google_oauth_token", get_cached_access_token, True)
                if _tok:
                    st.session_state["google_oauth_token"] = _tok
                    imap_credential = _tok
                    auth_mode = "OAuth2 Access Token"
            elif _is_outlook and MICROSOFT_OAUTH_READY and microsoft_oauth.oauth_available():
                _tok = _fresh_token("microsoft_oauth_token", microsoft_oauth.get_cached_access_token)
                if _tok:
                    st.session_state["microsoft_oauth_token"] = _tok
                    imap_credential = _tok
                    auth_mode = "OAuth2 Access Token"
            elif _is_yandex and YANDEX_OAUTH_READY and yandex_oauth.oauth_available():
                _tok = _fresh_token("yandex_oauth_token", yandex_oauth.get_cached_access_token)
                if _tok:
                    st.session_state["yandex_oauth_token"] = _tok
                    imap_credential = _tok
                    auth_mode = "OAuth2 Access Token"

            if _is_outlook and auth_mode == "App Password / Password":
                st.warning("Microsoft 365 commonly requires OAuth2 for IMAP. Use \"Sign in with Outlook\" below if password authentication is rejected.")

            _is_oauth_signed_in = auth_mode == "OAuth2 Access Token" and bool(imap_credential)
            _is_logged_in = bool(imap_user) and bool(imap_credential) and (
                st.session_state.get("manual_login_submitted", False) or _is_oauth_signed_in
            )

            # Browsing-window picker only shows up once you've actually
            # logged in -- clicked "Log in" with a valid email + password,
            # or completed a one-click sign-in (Gmail/Outlook/Yandex).
            # Nothing to browse yet, so no point showing this before then.
            # Folder is always INBOX -- no picker needed for that.
            folder = "INBOX"
            if _is_logged_in:
                st.markdown('<div class="login-plain-divider"></div><div class="login-plain-heading">Define the browsing window</div>', unsafe_allow_html=True)
                st.caption("Only headers are loaded during browsing. The complete raw message is fetched after selection.")

                browse_count = st.selectbox("Messages to browse", [10, 25, 50, 100], index=0, key="imap_browse_count")
                connect_clicked = st.button("Connect & Load Mailbox", type="primary", use_container_width=True, key="connect_imap")

                # Auto-scan right after a fresh login instead of making the
                # person click "Connect & Load Mailbox" separately -- the
                # count picker above still lets them change it before the
                # (one-time) auto-load, or afterwards via "Change mailbox /
                # Reconnect", which resets this flag.
                if not st.session_state.get("_imap_auto_connected", False) and not mailbox_loaded:
                    connect_clicked = True
                st.session_state["_imap_auto_connected"] = True
            else:
                st.markdown('<div class="login-plain-divider"></div>', unsafe_allow_html=True)
                st.caption("Click \"Log in\" above with your email + password, or use a one-click provider, to load your mailbox.")
                browse_count = st.session_state.get("imap_browse_count", 10)
                connect_clicked = False

            if connect_clicked:
                if not imap_user or not imap_credential or not imap_host:
                    st.error("Enter the mailbox address, server and authentication credential first.")
                elif not folder:
                    st.error("Enter a custom folder name, or pick one of the listed folders.")
                else:
                    try:
                        with st.spinner("Connecting securely and loading mailbox headers..."):
                            mailbox_messages = fetch_mailbox_messages(
                                imap_host, imap_user, imap_credential,
                                max_messages=browse_count, folder=folder,
                                port=int(imap_port), auth_mode=auth_mode,
                            )
                        st.session_state["live_mailbox_messages"] = mailbox_messages
                        st.session_state["live_mailbox_config"] = {
                            "host": imap_host, "port": int(imap_port), "user": imap_user,
                            "folder": folder, "auth_mode": auth_mode, "credential": imap_credential,
                        }
                        st.session_state["live_selected_uid"] = None
                        st.session_state["live_selected_raw"] = None
                        st.session_state["live_rescan_nonce"] = 0
                        _start_prefetch(st.session_state["live_mailbox_config"], [_m.get("uid") for _m in (st.session_state.get("live_mailbox_messages") or [])])
                        if mailbox_messages:
                            st.session_state["show_imap_connection_form"] = False
                            st.success(f"Mailbox connected. {len(mailbox_messages)} message headers loaded.")
                            st.rerun()
                        else:
                            st.info("No messages were returned for the selected mailbox window.")
                    except Exception as exc:
                        st.error(f"Mailbox connection failed: {exc}")
                        st.caption("No message data was sent to the forensic parser because the mailbox connection did not complete safely.")

        mailbox_messages = st.session_state.get("live_mailbox_messages", [])
        if mailbox_messages:
            display_rows = []
            for _no, item in enumerate(mailbox_messages, start=1):
                dt = item.get("date_dt")
                if dt is not None:
                    try:
                        date_text = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        date_text = str(item.get("date") or "Unknown")
                else:
                    date_text = str(item.get("date") or "Unknown")
                display_rows.append({
                    "No.": _no,
                    "Date": date_text,
                    "From": item.get("from", "Unknown sender"),
                    "Subject": item.get("subject", "No Subject"),
                })

            # Whole-row click-to-select. st.dataframe only ticks a row via its
            # checkbox column, so we ALSO listen for single-cell selections (a
            # click on any cell) and treat that as picking that row, then
            # mirror the choice back into the table as a real row selection.
            # Picking a message loads and scans it automatically.
            _TBL_KEY = "imap_message_table"
            _uid_list = [str(x.get("uid", "")) for x in mailbox_messages]

            _sel_uid = st.session_state.get("imap_sel_uid")
            if _sel_uid not in _uid_list:
                _sel_uid = None
                st.session_state["imap_sel_uid"] = None
            _sel_idx = _uid_list.index(_sel_uid) if _sel_uid is not None else None

            def _table_selection():
                try:
                    _s = st.session_state.get(_TBL_KEY)
                    _s = _s.get("selection", {}) if hasattr(_s, "get") else {}
                    _r = [int(x) for x in (_s.get("rows") or [])]
                    _c = [(int(x[0]), str(x[1])) for x in (_s.get("cells") or [])]
                except Exception:
                    _r, _c = [], []
                return _r, _c

            _rows_now, _cells_now = _table_selection()
            _clicked_idx = None
            if _rows_now and _rows_now != st.session_state.get("_imap_last_rows"):
                _clicked_idx = _rows_now[0]
            elif _cells_now and _cells_now != st.session_state.get("_imap_last_cells"):
                _clicked_idx = _cells_now[0][0]
            if _clicked_idx is not None and 0 <= _clicked_idx < len(_uid_list):
                _sel_idx = _clicked_idx
                _sel_uid = _uid_list[_clicked_idx]
                st.session_state["imap_sel_uid"] = _sel_uid

            _want_rows = [_sel_idx] if _sel_idx is not None else []
            if _rows_now != _want_rows:
                try:
                    st.session_state[_TBL_KEY] = {"selection": {"rows": _want_rows, "columns": [], "cells": []}}
                    _rows_now, _cells_now = _want_rows, []
                except Exception:
                    pass
            st.session_state["_imap_last_rows"] = list(_rows_now)
            st.session_state["_imap_last_cells"] = list(_cells_now)

            _tbl_df = pd.DataFrame(display_rows)
            _tbl_cfg = {"No.": st.column_config.NumberColumn("No.", width="small", format="%d")}
            for _mode in (["single-row", "single-cell"], "single-row"):
                _drawn = False
                for _wkw in ({"width": "stretch"}, {"use_container_width": True}):
                    try:
                        st.dataframe(
                            _tbl_df, hide_index=True, height=360, on_select="rerun",
                            selection_mode=_mode, key=_TBL_KEY, column_config=_tbl_cfg, **_wkw,
                        )
                        _drawn = True
                        break
                    except Exception:
                        continue
                if _drawn:
                    break
            st.caption("Click anywhere on a row to open and scan that email.")

            selected_meta = mailbox_messages[_sel_idx] if _sel_idx is not None else None
            selected_uid = _sel_uid
            already_loaded = (
                selected_uid is not None
                and st.session_state.get("live_selected_uid") == selected_uid
                and isinstance(st.session_state.get("live_selected_raw"), (bytes, bytearray))
                and bool(st.session_state.get("live_selected_raw"))
            )

            if selected_uid is None:
                pass
            elif not already_loaded:
                if st.session_state.get("_imap_fetch_failed_uid") == selected_uid:
                    st.error(f"Could not retrieve the selected message: {st.session_state.get('_imap_fetch_err', 'unknown error')}")
                    if st.button("Retry", type="primary", use_container_width=True, key="retry_imap_message"):
                        st.session_state["_imap_fetch_failed_uid"] = None
                        st.rerun()
                else:
                    cfg = st.session_state.get("live_mailbox_config", {})
                    credential = cfg.get("credential") or imap_credential
                    if not cfg or not credential:
                        st.error("Reconnect to the mailbox before selecting a message.")
                        st.stop()
                    fetch_ok = False
                    try:
                        selected_raw = _raw_cache().get(_raw_cache_key(cfg, selected_uid))
                        if selected_raw is None:
                            with st.spinner("Fetching message..."):
                                selected_raw = fetch_message_by_uid(
                                    cfg["host"], cfg["user"], credential, selected_uid,
                                    folder=cfg["folder"], port=cfg["port"], auth_mode=cfg["auth_mode"],
                                )
                            if not isinstance(selected_raw, bytes) or not selected_raw:
                                raise RuntimeError("The server returned an empty raw message.")
                            _store_raw(cfg, selected_uid, selected_raw)
                        st.session_state["live_selected_uid"] = selected_uid
                        st.session_state["live_selected_raw"] = selected_raw
                        st.session_state["_imap_fetch_failed_uid"] = None
                        fetch_ok = True
                    except Exception as exc:
                        st.session_state["live_selected_raw"] = None
                        st.session_state["_imap_fetch_failed_uid"] = selected_uid
                        st.session_state["_imap_fetch_err"] = str(exc)
                    # Stay on Dashboard; the rerun renders the analysis for the
                    # freshly loaded message (Threat Summary + Copilot).
                    st.rerun()

            if already_loaded:
                _raw_now = bytes(st.session_state["live_selected_raw"])
                st.text_area(
                    f"Message body · Email #{_sel_idx + 1} · {len(_raw_now):,} bytes",
                    value=_message_body_text(_raw_now), height=320, disabled=True,
                    key=f"imap_body_{selected_uid}",
                )

            # A completed "Analyze 10 Recent Emails" batch pipeline run (see
            # _run_batch_pipeline) jumps straight to the Forensic Report panel
            # without ever going through Load & Scan Selected Message, so
            # live_selected_raw is still empty at that point. Previously that
            # fell through to the "else" branches below and hit st.stop() on
            # every rerun -- which silently killed the ENTIRE script for that
            # run (Forensic Report, AI Threat Analysis, everything below this
            # point), even though the nav pill correctly showed "Forensic
            # Report" was selected. That's why the batch results only ever
            # appeared after manually clicking Load & Scan: only then did `raw`
            # get populated and let execution continue past this gate.
            #
            # Fix: when a batch just completed and no single message has been
            # individually loaded yet, fall back to the first batch item so the
            # rest of the script (including every panel below) has a valid
            # "current" message to work with, instead of hard-stopping.
            pipeline_ready = (
                st.session_state.get("forensic_report_source") == "pipeline"
                and bool(st.session_state.get("pipeline_batch_items"))
                and (st.session_state.get("pipeline_batch_result") or {}).get("source") == "Live IMAP"
            )

            def _use_pipeline_fallback_message():
                _fallback_item = st.session_state["pipeline_batch_items"][0]
                _raw = bytes(_fallback_item["_raw"])
                _case_name = f"Live IMAP: Batch item #{_fallback_item.get('position', 1)} (UID {_fallback_item.get('row', 'unknown')})"
                st.info(
                    "Showing the just-completed batch scan below. Pick a message above and click "
                    "an email in the table above if you want to inspect one individually instead."
                )
                return _raw, _case_name

            if selected_uid is not None and st.session_state.get("live_selected_uid") == selected_uid:
                candidate_raw = st.session_state.get("live_selected_raw")
                if isinstance(candidate_raw, (bytes, bytearray)) and candidate_raw:
                    raw = bytes(candidate_raw)
                    case_name = f"Live IMAP: {selected_meta.get('subject') or 'No Subject'}"
                elif pipeline_ready:
                    raw, case_name = _use_pipeline_fallback_message()
                else:
                    st.warning("This message is not loaded yet.")
                    st.stop()
            elif pipeline_ready:
                raw, case_name = _use_pipeline_fallback_message()
            else:
                st.info("Choose a mailbox message and load it for forensic analysis.")
                st.stop()
        else:
            st.info("Connect to Gmail, Yandex, Outlook/Microsoft 365, or a custom IMAP server to browse messages.")
            st.stop()
    else:
        st.info("Please select a threat acquisition mode.")
        st.stop()

    def _render_technical_logs_block(cases, raw, case_name, result, current_evidence_hash):
        """Shared 'Email Results / Antivirus Scan' tab block. Called once per
        run — either from the CSV Deep Dive flow (right after the row
        selector) or from the single-file Dashboard flow — never both, so
        there is exactly one copy of this section on screen.

        The AI Copilot used to live in a third tab here as a plain
        st.chat_message thread; it now lives as the always-visible Synapse
        Copilot panel in whichever right-hand dock is on screen (the bulk
        scan dock when a CSV bulk scan has results, otherwise the per-email
        dossier dock in _dashboard()) via the shared _render_copilot_panel()
        so the command vocabulary is identical either way."""

        st.markdown("#### Technical Logs & Antivirus")
        _tech_logs_container = st.container(key="tech_logs_tabs")
        with _tech_logs_container:
            _tech_logs_view = st.radio(
                "Technical Logs & Antivirus view", ["Email Results", "Antivirus Scan"],
                horizontal=True, label_visibility="collapsed", key="tech_logs_tabs_radio",
            )

        if _tech_logs_view == "Email Results":
            st.caption(
                "Want a full multi-email report? Ask the **Synapse Copilot** in the sidebar to "
                "*\"track my last 10 emails\"* — machine + AI + semantic analysis across your recent "
                "mail, ending on a downloadable Forensic Report."
            )
            st.divider()

            _is_current_csv = uploaded is not None and uploaded.name.lower().endswith(".csv")
            unified_table = st.session_state.get("unified_email_table") if _is_current_csv else None
            if unified_table is not None and not unified_table.empty:
                _render_email_results_table(unified_table, height=280)
            else:
                log_rows = [{
                    "Row #": i,
                    "Email": (r.get("parsed", {}) or {}).get("from_addr", "Unknown"),
                    "Origin IP": (r.get("geo", {}) or {}).get("origin", {}).get("ip", "Unknown"),
                    "Country": (r.get("geo", {}) or {}).get("origin", {}).get("country", "Unknown"),
                    "Threat Score": round(float(r.get("score", 0)), 1),
                    "Verdict": str(r.get("level", "unknown")).upper(),
                    "Subject": (r.get("parsed", {}) or {}).get("subject", "No Subject"),
                } for i, r in enumerate(cases)]
                _render_email_results_table(pd.DataFrame(log_rows), height=280)

        if _tech_logs_view == "Antivirus Scan":
            av_up = _clamd_up_cached()
            _av_backend = _antivirus_backend_cached()
            if av_up and _av_backend == "cloud":
                st.success("Antivirus scanning available via VirusTotal (cloud fallback) - local ClamAV daemon not reachable.")
            elif av_up:
                st.success(f" ClamAV connected - {clamd_version() or 'clamd daemon'}")
            else:
                st.warning("Antivirus scanning unavailable right now (no local clamd, no SIH26106_VT_API_KEY set) - showing the built-in risky-extension check instead.")
            files_scanned, threats_found, av_rows = 0, 0, []
            for r in cases:
                for att in (r.get("parsed", {}) or {}).get("attachments", []) or []:
                    files_scanned += 1
                    if av_up:
                        outcome = _scan_bytes_cached(att.get("data") or b"")
                        infected = bool(outcome.get("infected"))
                        status = "INFECTED" if infected else ("Scan error" if not outcome.get("ok") else "Clean")
                        detail = outcome.get("signature") or ("-" if outcome.get("ok") else outcome.get("error"))
                    else:
                        infected = bool(att.get("risky"))
                        status = "Risky extension" if infected else "Clean"
                        detail = "-"
                    if infected:
                        threats_found += 1
                    av_rows.append({"Case": r.get("name", "-"), "Filename": att.get("filename", "-"),
                                     "Size (bytes)": att.get("size", 0), "Status": status, "Detail": detail})
            am1, am2, am3 = st.columns(3)
            am1.metric("Files Scanned", files_scanned)
            am2.metric("Threats Found", threats_found)
            am3.metric("Clean", files_scanned - threats_found)
            if av_rows:
                _render_polished_table(pd.DataFrame(av_rows))
            else:
                st.info("No attachments found across the currently analyzed emails.")

    if uploaded is not None:
        if uploaded.name.endswith(".csv"):
            _csv_bytes = uploaded.getvalue()
            data = parse_email_csv(_csv_bytes)
            csv_scan_key = hashlib.sha256(_csv_bytes).hexdigest()

            if st.session_state.get("bulk_scan_file_key") != csv_scan_key:
                st.session_state["bulk_scan_file_key"] = csv_scan_key
                st.session_state["bulk_scan_results"] = None
                st.session_state["bulk_scan_cases"] = None
                st.session_state["bulk_scan_cases_hash"] = None
                st.session_state["unified_email_table"] = None
                st.session_state.pop("forensic_report_source", None)

            if not data:
                st.error("No email messages could be extracted from this CSV.")
                st.stop()

            saved_bulk_results = st.session_state.get("bulk_scan_results")

            if saved_bulk_results is None:
                # Full acquisition intro + both scan actions -- only needed
                # before there's anything to show. Once a scan completes
                # this whole block disappears in favor of the compact
                # status row + dock below, instead of sitting on screen
                # forever above a scan that's already finished.
                st.markdown("## Bulk Threat Scanner")
                st.caption("Dataset-wide forensic scan. The selected email still receives the complete forensic workflow below.")
                st.info(f" **{len(data):,}** email records loaded from **{uploaded.name}**")

                # These two used to be stacked full-width bars, one above
                # the other, for what are really two alternative actions
                # (a quick 10-email report vs. a full dataset scan) --
                # side by side instead, each with its own explanation
                # directly underneath it, so the choice reads as "pick
                # one of these two" instead of "do this, then also maybe
                # do this other thing".
                _bulk_a_col, _bulk_b_col = st.columns(2)
                with _bulk_a_col:
                    if st.button(
                        "Analyze 10 Most Recent — Full Report",
                        type="primary", use_container_width=True, key="csv_pipeline_btn",
                    ):
                        _pipeline_items = _collect_recent_csv_items(data, uploaded.name, 10)
                        _run_batch_pipeline(_pipeline_items, uploaded.name)
                    st.caption("Machine + AI analysis and semantic origin correlation on the 10 newest rows, then opens the Forensic Report ready to download.")
                with _bulk_b_col:
                    if st.button("Run Bulk Threat Scan", key="run_global_ip_scan", use_container_width=True, type="primary"):
                        progress_bar = st.progress(0, text="Initializing forensic scan... 0%")
                        bulk_results = []
                        bulk_case_results = []
                        update_every = max(1, min(25, max(1, len(data) // 25)))

                        for i, text in enumerate(data):
                            row_raw = text.replace("\\n", "\n").encode("utf-8")
                            res = analyze_bytes(row_raw, f"Row {i}")
                            res["_evidence_hash"] = hashlib.sha256(row_raw).hexdigest()
                            bulk_case_results.append(res)

                            origin = res.get("geo", {}).get("origin", {}) or {}
                            ip = origin.get("ip") or "Unknown"
                            country = origin.get("country") or "Unknown"
                            score = float(res.get("score", 0) or 0)
                            verdict = str(res.get("level", "unknown")).upper()

                            bulk_results.append({
                                "Row #": i,
                                "Email": (res.get("parsed", {}) or {}).get("from_addr") or "Unknown",
                                "Origin IP": ip,
                                "Country": country,
                                "Threat Score": round(score, 1),
                                "Verdict": verdict,
                                "Subject": res.get("parsed", {}).get("subject", "No Subject")[:45]
                            })

                            if (i + 1) % update_every == 0 or i + 1 == len(data):
                                pct = int(((i + 1) / len(data)) * 100)
                                progress_bar.progress((i + 1) / len(data), text=f"Analyzing evidence... {pct}% ({i + 1:,}/{len(data):,})")

                        # Full-width bar only exists while the scan is actually
                        # running -- once it's done, drop it rather than leaving a
                        # static 100% bar sitting on screen.
                        progress_bar.empty()

                        st.session_state["bulk_scan_results"] = bulk_results
                        st.session_state["bulk_scan_cases"] = bulk_case_results
                        st.session_state["bulk_scan_cases_hash"] = csv_scan_key
                        for _case in bulk_case_results:
                            _eh = _case.get("_evidence_hash")
                            if _eh:
                                _corr_cases[_eh] = _case
                        while len(_corr_cases) > 60:
                            _corr_cases.pop(next(iter(_corr_cases)))

                        # Rerun immediately so this intro collapses into the
                        # compact status row on the very screen that shows the
                        # results, instead of lingering above them for one extra
                        # render.
                        st.rerun()
                    st.caption("Scans every row for its own verdict and flags high-risk origins across the whole dataset.")

                saved_bulk_results = st.session_state.get("bulk_scan_results")

            if saved_bulk_results is not None:
                # Compact, single-line completion status (same pattern as the
                # Live IMAP "Mailbox connected" confirmation) instead of a
                # lingering progress bar + separate success banner, paired
                # with compact secondary actions instead of the full intro
                # block once there's something to show.
                with st.container(key="scan_status_bar"):
                    _status_col, _ai_col, _reset_col = st.columns([3, 1.5, 1.5])
                    with _status_col:
                        st.markdown(
                            f'<div class="scan-compact-status"><span class="ai-pulse"></span>'
                            f'Scan complete — <b>{len(saved_bulk_results):,}</b> emails analyzed</div>',
                            unsafe_allow_html=True,
                        )
                    with _ai_col:
                        if st.button(
                            "Full AI Report", key="csv_pipeline_btn_compact", use_container_width=True,
                            help="Machine + AI + semantic analysis on the 10 newest rows, then open the Forensic Report.",
                        ):
                            _pipeline_items = _collect_recent_csv_items(data, uploaded.name, 10)
                            _run_batch_pipeline(_pipeline_items, uploaded.name)
                    with _reset_col:
                        if st.button(
                            "Rescan Dataset", key="reset_bulk_scan", use_container_width=True,
                            help="Clear these results and run the classifier scan again on the same file.",
                        ):
                            st.session_state["bulk_scan_results"] = None
                            st.session_state["bulk_scan_cases"] = None
                            st.session_state["bulk_scan_cases_hash"] = None
                            st.session_state["unified_email_table"] = None
                            st.session_state.pop("forensic_report_source", None)
                            st.rerun()

                df_bulk = pd.DataFrame(saved_bulk_results)

                # Everything from here down shares one persistent, sticky
                # right-hand dock (Threat / Investigation Summary / Top
                # Threat Signal Breakdown for the row loaded in Deep Dive,
                # plus Synapse Copilot) instead of a handful of aggregate
                # tiles that left empty space down the right side of the
                # page -- the same dock pattern the per-email dossier view
                # uses further down.
                col_main, col_dock = st.columns([2.15, 1], gap="medium")

                with col_main:
                    sev_filter = st.radio("Filter by Severity Level:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], horizontal=True)
                    if sev_filter != "ALL":
                        filtered_df = df_bulk[df_bulk["Verdict"].isin(["LOW", "CLEAN", "INFO"])] if sev_filter == "LOW" else df_bulk[df_bulk["Verdict"] == sev_filter]
                    else:
                        filtered_df = df_bulk

                    # Single source of truth for the merged table — also reused by the
                    # bottom-pane "Email Results" tab so the data only appears once.
                    st.session_state["unified_email_table"] = filtered_df

                    st.markdown("### Deep Dive Analysis")
                    st.caption("Select any email record below to load its message content into the forensic workflow.")

                    available_rows = filtered_df["Row #"].tolist() if not filtered_df.empty else list(range(len(data)))
                    # Newest first: same Date-header-with-CSV-row-fallback
                    # convention as the Forensic Report / AI Threat Analysis
                    # panels, so this single-row picker agrees with them
                    # instead of just listing rows in raw upload order.
                    _row_dates = {r: get_email_date(data[r]) for r in available_rows}
                    available_rows = sorted(
                        available_rows,
                        key=lambda r: (
                            _row_dates[r] is not None,
                            _row_dates[r] or datetime.min.replace(tzinfo=timezone.utc),
                            r,
                        ),
                        reverse=True,
                    )
                    selected_row = st.selectbox(
                        "Select Row for Deep Dive View — newest first",
                        options=available_rows, 
                        format_func=lambda r: f"Row {r} | {saved_bulk_results[r]['Verdict']} | {saved_bulk_results[r].get('Subject', 'No Subject')}"
                    )

                    raw = data[selected_row].replace("\\n", "\n").encode("utf-8")
                    case_name = f"{uploaded.name} (Row {selected_row})"
                    dd_current_hash = hashlib.sha256(raw).hexdigest()
                    dd_result = analyze_bytes(raw, case_name, 0)
                    _corr_cases[dd_current_hash] = dd_result
                    dd_cases = [r for r in _corr_cases.values() if "error" not in r]
                    if dd_current_hash not in {r.get("_evidence_hash") for r in dd_cases}:
                        _tagged = dict(dd_result)
                        _tagged["_evidence_hash"] = dd_current_hash
                        dd_cases.append(_tagged)
                    _render_technical_logs_block(dd_cases, raw, case_name, dd_result, dd_current_hash)

                    # --- DEEP DIVE MESSAGE CONTENT ---
                    dd_res = st.session_state["bulk_scan_cases"][selected_row]
                    dd_p = dd_res.get("parsed", {})

                    st.markdown("##### Extracted Message Content")
                    st.text_area("Deep Dive Content", dd_p.get('body_text', 'No body text extracted.')[:4000], height=180, disabled=True, label_visibility="collapsed", key=f"dd_body_{selected_row}")

                with col_dock:
                    with st.container(border=True, key="bulk_command_dock"):
                        st.markdown('<div class="right-dock-title">THREAT SUMMARY — ROW {}</div>'.format(selected_row), unsafe_allow_html=True)

                        # Pinned right under the header, same as the main
                        # Dashboard sidebar, rather than after three other
                        # sections below.
                        _render_copilot_panel(dd_cases, raw, case_name, dd_result, dd_current_hash)

                        # Scoped to the row currently loaded in Deep Dive above
                        # (dd_result / dd_p), not the batch aggregate -- this
                        # is what fills the dock instead of leaving the column
                        # short and empty next to the taller left-hand pane.
                        dd_m = dd_result.get("ml", {}) or {}
                        dd_h = dd_result.get("headers", {}) or {}
                        dd_verdict = dd_result.get("verdict", {}) or {}
                        dd_geo = dd_result.get("geo", {}) or {}
                        dd_origin = dd_geo.get("origin", {}) or {}
                        dd_auth_pass = sum(1 for mech in ("spf", "dkim", "dmarc") if dd_h.get(mech) == "pass")
                        dd_anomaly_count = len(dd_h.get("anomalies", []) or [])

                        st.markdown('<div class="panel-card-head"><span>THREAT</span></div>', unsafe_allow_html=True)
                        with st.container(key="dd_dock_metrics_body"):
                            kc1, kc2 = st.columns(2, gap="small")
                            kc1.metric("Threat Score", f"{float(dd_result.get('score', 0)):.1f}", str(dd_result.get('level', '?')).upper())
                            kc2.metric("ML Phishing", f"{float(dd_m.get('prob', 0)):.1%}")
                            kc3, kc4 = st.columns(2, gap="small")
                            kc3.metric("Auth Pass", f"{dd_auth_pass}/3")
                            kc4.metric("Anomalies", dd_anomaly_count)

                        st.markdown('<div class="panel-card-head panel-card-head-violet" style="margin-top:12px;"><span>INVESTIGATION SUMMARY</span></div>', unsafe_allow_html=True)
                        st.markdown(
                            f"""<div class="panel-card-body panel-card-body-violet">
                                <b>From:</b> {dd_p.get('from_addr','Unknown')}<br>
                                <b>Subject:</b> {dd_p.get('subject','No Subject')}<br>
                                <b>Date:</b> {dd_p.get('date','Unknown')}<br>
                                <b>Origin IP:</b> {dd_origin.get('ip','Unknown')}<br>
                                <b>Infrastructure:</b> {dd_origin.get('infra_label','Unknown')}<br>
                                <b>Attachments:</b> {len(dd_p.get('attachments', []) or [])}<br>
                                <b>Links:</b> {len((dd_result.get('iocs',{}) or {}).get('urls', []) or [])}<br>
                                <b>Verdict:</b> {str(dd_result.get('level','UNKNOWN')).upper()}
                            </div>""",
                            unsafe_allow_html=True,
                        )

                        st.markdown('<div class="panel-card-head panel-card-head-amber" style="margin-top:12px;"><span>TOP THREAT SIGNAL BREAKDOWN</span></div>', unsafe_allow_html=True)
                        dd_contributions = dd_verdict.get("contributions", []) or []
                        colors = ["#ff4757", "#ff9f43", "#2fd8ff", "#35d399", "#a389f4", "#f47ab0"]
                        if dd_contributions:
                            for i, c in enumerate(dd_contributions[:6]):
                                pct = c.get("strength", 0.0) * 100
                                st.markdown(
                                    f"""<div class="threattype-row">
                                        <span style="min-width:120px;font-size:11px;">{c.get('label','-')}</span>
                                        <div class="bar-track"><div class="bar-fill" style="width:{pct:.0f}%;background:{colors[i % len(colors)]};"></div></div>
                                        <span class="pct">{pct:.0f}%</span>
                                    </div>""",
                                    unsafe_allow_html=True,
                                )
                        else:
                            st.caption("No scored signals for this row.")
            else:
                row_index = 0
                raw = data[row_index].replace("\\n", "\n").encode("utf-8")
                case_name = f"{uploaded.name} (Row {row_index})"
        else:
            raw = uploaded.getvalue()
            case_name = uploaded.name
            _single_upload_key = hashlib.sha256(raw).hexdigest()
            if st.session_state.get("single_upload_key") != _single_upload_key:
                st.session_state["single_upload_key"] = _single_upload_key
                st.session_state.pop("forensic_report_source", None)

    # Remember what's currently loaded so every other tab can keep using it
    # without re-showing this acquisition UI (cleared automatically the
    # moment a new file/mailbox message is loaded above, since this runs
    # again right after that and overwrites the cache).
    st.session_state["_evidence_cache"] = {
        "raw": raw,
        "case_name": case_name,
        "uploaded_name": uploaded.name if uploaded is not None else None,
        "csv_data": data,
        "csv_scan_key": csv_scan_key,
    }
else:
    _ev_cache = st.session_state.get("_evidence_cache") or {}
    raw = _ev_cache.get("raw")
    case_name = _ev_cache.get("case_name", "")
    data = _ev_cache.get("csv_data") or []
    csv_scan_key = _ev_cache.get("csv_scan_key")
    _cached_upload_name = _ev_cache.get("uploaded_name")
    if _cached_upload_name:
        class _EvidenceRef:
            """Stands in for the real `uploaded` file object outside the
            Dashboard tab -- just enough (`.name`) for the other panels'
            CSV-vs-single-file checks. The real bytes aren't needed again
            here since `raw` above already holds the resolved evidence."""
            def __init__(self, name):
                self.name = name
        uploaded = _EvidenceRef(_cached_upload_name)

    # BUG FIX: a batch pipeline run (_run_batch_pipeline -- e.g. Synapse
    # Copilot's "track my last 10/20 emails") stages
    # `_pending_active_panel = "Forensic Report"` and reruns straight there.
    # If this is the very first evidence loaded all session -- nobody has
    # opened Dashboard and loaded a single file/mailbox message yet --
    # `_evidence_cache` above is still empty, `raw` stays None, and this
    # branch fell straight through to "No evidence loaded yet" below even
    # though a batch had just finished analyzing 10/20 real emails. It only
    # ever "worked" after separately clicking Dashboard, because that click
    # happened to populate `_evidence_cache` as a side effect of rendering
    # its own UI, not because it did anything with the batch itself. Falling
    # back to the batch's own first item here removes that dependency on an
    # unrelated click, for every acquisition mode the pipeline can be
    # launched from (Live IMAP or a CSV upload), not just the Live-IMAP-only
    # case the Dashboard block above already handles for itself.
    if (
        (not isinstance(raw, (bytes, bytearray)) or not raw)
        and st.session_state.get("forensic_report_source") == "pipeline"
        and st.session_state.get("pipeline_batch_items")
    ):
        _pipeline_fallback_item = st.session_state["pipeline_batch_items"][0]
        raw = bytes(_pipeline_fallback_item["_raw"])
        _fallback_source = (st.session_state.get("pipeline_batch_result") or {}).get("source", "Batch")
        case_name = f"{_fallback_source}: Batch item #{_pipeline_fallback_item.get('position', 1)}"

    if not isinstance(raw, (bytes, bytearray)) or not raw:
        # Settings and About don't depend on any evidence -- show them as
        # normal even before a mailbox is connected or a file is uploaded.
        if active_panel == "Settings":
            panel(_settings, "Settings")
            st.stop()
        if active_panel == "About":
            panel(_about, "About")
            st.stop()
        st.info("No evidence loaded yet. Open the **Dashboard** tab to upload a file, connect a mailbox, or pick a CSV row first.")
        st.stop()

if not isinstance(raw, (bytes, bytearray)) or not raw:
    st.error("No valid raw email evidence was received. Please reconnect to Live IMAP and select a valid message.")
    st.stop()

# --- GLOBAL EVIDENCE EXTRACTION (Runs for both single file or selected CSV row) ---
raw = bytes(raw)
analysis_nonce = int(st.session_state.get("live_rescan_nonce", 0)) if "Live IMAP" in case_name else 0
result = analyze_bytes(raw, case_name, analysis_nonce)
parsed, headers, iocs, geo = result["parsed"], result["headers"], result["iocs"], result["geo"]
current_evidence_hash = hashlib.sha256(raw).hexdigest()

# Tag _evidence_hash onto `result` itself (not just use it as the dict key)
# -- every other place that writes into _corr_cases does this, but this
# central one (which runs for every single loaded/analyzed email) didn't.
# Without it, every "is the current email already in this list?" check
# elsewhere (the Origin & Route single-email picker, the correlation graph
# picker, etc.) always found no match on r.get("_evidence_hash") and
# appended a second, duplicate entry for the exact same email -- which is
# why the picker showed the same message twice instead of your other
# loaded emails.
result["_evidence_hash"] = current_evidence_hash
_corr_cases[current_evidence_hash] = result
while len(_corr_cases) > 60:
    _corr_cases.pop(next(iter(_corr_cases)))

# True exactly when the bulk-scan dock (Threat Summary +
# Synapse Copilot, see the CSV branch above) is on screen this run --
# _dashboard() uses this to skip rendering its own copilot instance so
# the widget's keys are never instantiated twice in one run.
_bulk_dock_active = (
    uploaded is not None
    and str(getattr(uploaded, "name", "") or "").lower().endswith(".csv")
    and st.session_state.get("bulk_scan_results") is not None
)

# --------------------------------------------------------------------------
# THREAT MEMORY (REPEAT OFFENDER) & VERDICT BANNER & METRICS
# --------------------------------------------------------------------------
geo = result.get("geo", {}) or {}
current_ip = (geo.get("origin", {}) or {}).get("ip", "Unknown")
current_country = (geo.get("origin", {}) or {}).get("country", "Unknown")
evidence_memory_key = current_evidence_hash

# A freshly (re-)uploaded CSV still needs SOME valid `raw`/`result` below --
# other panels and the "jump to Forensic Report" pipeline buttons depend on
# it -- so row 0 is quietly resolved further up as a placeholder. But nobody
# asked for that row to be scanned yet, so it must not be logged into the
# threat-memory database or displayed as if it were a real result.
_csv_awaiting_scan = bool(
    uploaded is not None
    and str(getattr(uploaded, "name", "") or "").lower().endswith(".csv")
    and st.session_state.get("bulk_scan_results") is None
)

if not _csv_awaiting_scan:
    if st.session_state.get("memory_logged_for") != evidence_memory_key:
        init_db()
        log_threat(current_ip, current_country, result["score"], result["level"].upper())
        st.session_state["memory_logged_for"] = evidence_memory_key
        st.session_state["memory_history"] = check_history(current_ip)

    past_attacks, highest_past_score = st.session_state.get("memory_history", (0, 0))

    if active_panel == "Dashboard" and past_attacks > 1:
        st.error(f" **REPEAT OFFENDER DETECTED!** This IP ({current_ip}) is in our threat database. They have attacked your network {past_attacks - 1} times previously with a max threat score of {highest_past_score:.0f}/100. This is a persistent campaign.")

    # Slim one-line status strip replaces the old full-width verdict banner and
    # 5-metric row — the full detail now lives once, in the Dashboard's right pane.
    st.caption(
        f"**{case_name}** · Verdict **{result['level'].upper()}** ({result['score']:.0f}/100) · "
        f"ML phishing {result['ml']['prob']:.0%} · "
        f"Auth {sum(1 for m in ('spf','dkim','dmarc') if headers[m]=='pass')}/3 · "
        f"Anomalies {len(headers['anomalies'])} · "
        f"Origin {(geo['origin'].get('country_code') or geo['origin'].get('country','?'))}"
    )
elif active_panel == "Dashboard":
    st.caption(f" **{uploaded.name}** loaded — choose a scan option above to begin forensic analysis.")

st.divider()

# NAV_OPTIONS / active_panel are already set — the pill bar now renders once,
# at the very top of the page, replacing the old 7-button top nav row.

# --------------------------------------------------------------------------
# Dashboard - new landing overview. Reuses the exact same `result`, `geo`,
# `parsed`, `_corr_cases` and correlate.py calls the other tabs already use;
# no new analysis logic, just a different view of the same data.
# --------------------------------------------------------------------------
if active_panel == "Dashboard":
    def _dashboard():
        sel_m = result.get("ml", {}) or {}
        sel_h = result.get("headers", {}) or {}
        sel_p = result.get("parsed", {}) or {}
        sel_verdict = result.get("verdict", {}) or {}
        origin = geo.get("origin", {}) or {}

        auth_pass = sum(1 for mech in ("spf", "dkim", "dmarc") if sel_h.get(mech) == "pass")
        anomaly_count = len(sel_h.get("anomalies", []) or [])

        cases = [r for r in _corr_cases.values() if "error" not in r]
        current_case = dict(result)
        current_case["_evidence_hash"] = current_evidence_hash
        if current_evidence_hash not in {r.get("_evidence_hash") for r in cases}:
            cases.append(current_case)

        # ================= CENTER (tabbed map/graph) + RIGHT (summary sidebar) =================
        # The summary panel is a genuine right-hand dock the analyst can
        # open/close, not a column that's simply always there --
        # st.session_state remembers the choice across reruns.
        #
        # Toggling it never leaves an empty gap: when closed, only a
        # single full-width container is rendered below (no hidden second
        # column reserving its width), and the sole way back in is a tab
        # pinned with position:fixed (see .st-key-right_dock_reopen) --
        # fixed elements claim no layout space, so the page is exactly as
        # full-width as if the panel never existed at all.
        #
        # When the bulk-scan dock (Threat Summary + Synapse Copilot) is
        # already on screen further up the page for CSV mode, this sidebar
        # would just be the exact same THREAT SUMMARY content rendered a
        # second time next to the map -- skip it entirely rather than
        # reopen-toggle it, and let the map/graph tabs run full width.
        if _bulk_dock_active:
            col_center = st.container()
            col_right = None
        else:
            st.session_state.setdefault("right_panel_open", True)
            panel_open = st.session_state["right_panel_open"]

            if panel_open:
                col_center, col_right = st.columns([2.1, 1])
            else:
                col_center = st.container()
                col_right = None
                with st.container(key="right_dock_reopen"):
                    if st.button(
                        "☰ Summary",
                        key="toggle_right_summary_closed",
                        help="Show the threat summary sidebar",
                    ):
                        st.session_state["right_panel_open"] = True
                        st.rerun()

        if col_right is not None:
            with col_right:
                with st.container(border=True, key="right_summary_pane"):
                    _dock_h_l, _dock_h_r = st.columns([4.2, 1])
                    with _dock_h_l:
                        st.markdown('<div class="right-dock-title">THREAT SUMMARY</div>', unsafe_allow_html=True)
                    with _dock_h_r:
                        if st.button(
                            "✕",
                            key="toggle_right_summary_open",
                            help="Hide this sidebar",
                            use_container_width=True,
                        ):
                            st.session_state["right_panel_open"] = False
                            st.rerun()

                    # Pinned right under the header, not at the bottom of the
                    # dock — this is the most-used part of the sidebar (it's
                    # how a full multi-email AI + semantic report gets
                    # triggered now), so it shouldn't need scrolling past
                    # three other sections to reach.
                    _render_copilot_panel(cases, raw, case_name, result, current_evidence_hash)

                    st.markdown('<div class="panel-card-head"><span>KEY METRICS</span></div>', unsafe_allow_html=True)
                    with st.container(key="right_dock_metrics_body"):
                        rc1, rc2 = st.columns(2, gap="small")
                        rc1.metric("Threat Score", f"{float(result.get('score',0)):.1f}", str(result.get('level','?')).upper())
                        rc2.metric("ML Phishing", f"{float(sel_m.get('prob',0)):.1%}")
                        rc3, rc4 = st.columns(2, gap="small")
                        rc3.metric("Auth Pass", f"{auth_pass}/3")
                        rc4.metric("Anomalies", anomaly_count)

                    st.markdown('<div class="panel-card-head panel-card-head-violet" style="margin-top:12px;"><span>INVESTIGATION SUMMARY</span></div>', unsafe_allow_html=True)
                    st.markdown(
                        f"""<div class="panel-card-body panel-card-body-violet">
                            <b>From:</b> {sel_p.get('from_addr','Unknown')}<br>
                            <b>Subject:</b> {sel_p.get('subject','No Subject')}<br>
                            <b>Date:</b> {sel_p.get('date','Unknown')}<br>
                            <b>Origin IP:</b> {origin.get('ip','Unknown')}<br>
                            <b>Infrastructure:</b> {origin.get('infra_label','Unknown')}<br>
                            <b>Attachments:</b> {len(sel_p.get('attachments', []) or [])}<br>
                            <b>Links:</b> {len((result.get('iocs',{}) or {}).get('urls', []) or [])}<br>
                            <b>Verdict:</b> {str(result.get('level','UNKNOWN')).upper()}
                        </div>""",
                        unsafe_allow_html=True,
                    )

                    st.markdown('<div class="panel-card-head panel-card-head-amber" style="margin-top:12px;"><span>TOP THREAT SIGNAL BREAKDOWN</span></div>', unsafe_allow_html=True)
                    contributions = sel_verdict.get("contributions", []) or []
                    colors = ["#ff4757", "#ff9f43", "#2fd8ff", "#35d399", "#a389f4", "#f47ab0"]
                    for i, c in enumerate(contributions[:6]):
                        pct = c.get("strength", 0.0) * 100
                        st.markdown(
                            f"""<div class="threattype-row">
                                <span style="min-width:120px;font-size:11px;">{c.get('label','-')}</span>
                                <div class="bar-track"><div class="bar-fill" style="width:{pct:.0f}%;background:{colors[i % len(colors)]};"></div></div>
                                <span class="pct">{pct:.0f}%</span>
                            </div>""",
                            unsafe_allow_html=True,
                        )

                    # col_right only ever exists when the bulk-scan dock is
                    # NOT active (see above), so the copilot above is never a
                    # second instance of the one in that dock.

        with col_center:
            st.markdown(
                """<div class="dash-section-title">
                    <span class="dash-section-dot"></span>
                    <span>Origin &amp; Correlation</span>
                    <span class="dash-section-sub">— geolocation map and infrastructure graph for this case set</span>
                </div>""",
                unsafe_allow_html=True,
            )
            # Map and correlation graph each render full-width, stacked --
            # side-by-side columns were squeezing both into half-width
            # panels, which is what forced aggressive label truncation and
            # made the correlation graph's nodes/labels crowd together.
            # Full width on every device (including narrow windows, where
            # Streamlit's columns used to squash rather than reflow) with
            # room for labels to read cleanly.
            with st.container(border=True, key="dash_map_card"):
                # Always the email that is currently open -- no toggle here.
                # The all-emails / single-email switch lives on Origin & Route.
                _dash_geo = result.get("geo", {}) or {}
                _dash_origin = _dash_geo.get("origin", {}) or {}
                st.markdown(f"""<div class="panel-card-head panel-card-head-green"><span>GLOBE-SCAN: IP GEOLOCATION MAP</span>
                    <span>{html.escape(str(_dash_origin.get('ip', 'Unknown')))}</span></div>""", unsafe_allow_html=True)
                _dash_pts = _case_hop_points(result)
                if _dash_pts:
                    _dash_coords = [[h["lat"], h["lon"]] for h in _dash_pts]
                    dash_map = _new_map(_dash_coords[-1], zoom_start=2)
                    _dash_spots = {}
                    for i, h in enumerate(_dash_pts, 1):
                        is_origin = (h.get("infra") in ("tor", "vpn", "proxy")) or (i == len(_dash_pts))
                        sp = _dash_spots.setdefault(_loc_key(h), {"h": h, "hops": [], "origin": False})
                        sp["hops"].append(i)
                        sp["origin"] = sp["origin"] or is_origin
                    for sp in _dash_spots.values():
                        h = sp["h"]
                        hop_txt = ", ".join(str(x) for x in sp["hops"])
                        _pop = (
                            f'<div class="ps-pop"><div class="ps-h">Hop {hop_txt}</div>'
                            f'<div class="ps-sub">IP {html.escape(str(h.get("ip", "")))}</div>'
                            f'<div class="ps-row">{html.escape(str(h.get("city", "")))} {html.escape(str(h.get("country", "")))}<br>'
                            f'<span style="color:#aab9d0;">{html.escape(str(h.get("infra_label", "")))}</span></div></div>'
                        )
                        _pin_marker(
                            h["lat"], h["lon"], "#ff4757" if sp["origin"] else "#2fd8ff",
                            str(sp["hops"][0]),
                            _pop, tooltip=f"Hop {hop_txt} · {h.get('ip', '')}", big=sp["origin"],
                            chips=([(x, "#ff4757" if sp["origin"] else "#2fd8ff") for x in sp["hops"]] if len(sp["hops"]) > 1 else None),
                            chips_caption="Hops",
                        ).add_to(dash_map)
                    if len(_dash_coords) > 1:
                        folium.PolyLine(_dash_coords, color="#2fd8ff", weight=8, opacity=0.14).add_to(dash_map)
                        folium.PolyLine(_dash_coords, color="#2fd8ff", weight=2.5, opacity=0.9, dash_array="7 9").add_to(dash_map)
                        try:
                            dash_map.fit_bounds(_dash_coords, max_zoom=4)
                        except Exception:
                            pass
                    st_folium(
                        dash_map, width="stretch", height=380, returned_objects=[],
                        key="dash_cur_map_" + hashlib.md5(str(case_name).encode("utf-8", "ignore")).hexdigest()[:10],
                    )
                    _dash_loc = ", ".join(p for p in [_dash_origin.get("city"), _dash_origin.get("country")] if p)
                    st.caption(
                        f"Current email origin: {_dash_loc or 'location unknown'}"
                        + (f" · {_dash_origin.get('infra_label')}" if _dash_origin.get("infra_label") else "")
                        + ". See Origin & Route to compare up to 10 emails or pick another one. Imagery © Esri."
                    )
                else:
                    st.info("No geolocatable hop for this email yet.")

            with st.container(border=True, key="dash_graph_card"):
                st.markdown(f"""<div class="panel-card-head panel-card-head-violet"><span>NETWORK INFRASTRUCTURE CORRELATION GRAPH</span>
                    <span>CURRENT EMAIL</span></div>""", unsafe_allow_html=True)
                # A fixed seed here keeps this small preview stable between
                # reruns; the full, shuffleable, interactive version lives
                # on the dedicated Correlation panel.
                _dash_cur_case = dict(result)
                _dash_cur_case["_evidence_hash"] = current_evidence_hash
                G = _build_correlation_graph([_dash_cur_case], seed=42)
                _corr_fig = correlate.graph_figure(G, height=560)
                # Full-width now (not squeezed into a half-width column), so
                # labels can run longer before needing to be cut off.
                _CORR_LABEL_MAX = 40

                def _corr_truncate(s):
                    s = "" if s is None else str(s)
                    return s if len(s) <= _CORR_LABEL_MAX else s[: _CORR_LABEL_MAX - 1].rstrip() + "…"

                def _corr_shrink_trace(tr):
                    if "text" in (tr.mode or "") and tr.text is not None:
                        if isinstance(tr.text, (list, tuple)):
                            tr.text = [_corr_truncate(t) for t in tr.text]
                        else:
                            tr.text = _corr_truncate(tr.text)
                        tr.update(cliponaxis=False, textfont=dict(size=11))

                _corr_fig.for_each_trace(_corr_shrink_trace)
                _corr_fig.for_each_annotation(lambda a: a.update(text=_corr_truncate(a.text)) if a.text else None)

                # Spreads nodes outward from the plot's centroid so labels
                # and severity halos don't crowd into each other -- now with
                # a lighter factor since full width already gives everything
                # more room than the old half-width column did.
                def _corr_spread(fig, factor=1.25):
                    _xs = [v for tr in fig.data for v in (tr.x or []) if v is not None]
                    _ys = [v for tr in fig.data for v in (tr.y or []) if v is not None]
                    if not _xs or not _ys:
                        return
                    _cx, _cy = sum(_xs) / len(_xs), sum(_ys) / len(_ys)
                    for tr in fig.data:
                        if tr.x is not None:
                            tr.x = [(_cx + (v - _cx) * factor) if v is not None else v for v in tr.x]
                        if tr.y is not None:
                            tr.y = [(_cy + (v - _cy) * factor) if v is not None else v for v in tr.y]
                    if fig.layout.annotations:
                        for _ann in fig.layout.annotations:
                            _upd = {}
                            if _ann.x is not None:
                                _upd["x"] = _cx + (_ann.x - _cx) * factor
                            if _ann.y is not None:
                                _upd["y"] = _cy + (_ann.y - _cy) * factor
                            if _upd:
                                _ann.update(**_upd)

                _corr_spread(_corr_fig)
                _corr_fig.update_layout(margin=dict(l=24, r=24, t=10, b=10))
                st.plotly_chart(_corr_fig, width="stretch")
                st.caption("Connections of the current email. Compare up to 10 emails, or pick another one, on **Correlation Graph** in the sidebar.")

        # ================= BOTTOM (technical logs, antivirus, AI copilot) =================
        # In CSV mode this section already rendered earlier (between the Deep
        # Dive selector and the message content box) — don't show it twice.
        #
        # Full-width below BOTH columns (not confined to col_center's ~68%)
        # -- by this point the THREAT SUMMARY dock has already finished
        # rendering above, so there's no more "blank gap" risk from the dock
        # running taller than this section; keeping it width-capped to
        # col_center just wasted the space to the right where the dock had
        # already ended, which is what this table needs to stretch into.
        if not (uploaded is not None and uploaded.name.lower().endswith(".csv")):
            _render_technical_logs_block(cases, raw, case_name, result, current_evidence_hash)

    if _csv_awaiting_scan:
        st.info("The threat summary, origin map, and correlation graph will appear here once you run a scan above.")
    else:
        panel(_dashboard, "Dashboard")

    # --------------------------------------------------------------------------
    # ANALYST FEEDBACK SECTION -- deliberately last on the Dashboard panel,
    # below the Origin & Routing Map / Correlation Graph panels, so an analyst
    # reviewing a case sees the full evidence (table, message content, map,
    # correlation graph) before being asked to weigh in on it.
    # --------------------------------------------------------------------------
    st.divider()
    st.markdown("""
    <div class="feedback-panel">
        <div class="feedback-title">Analyst Feedback</div>
        <div class="feedback-subtitle">
            Validate the detection to improve future model decisions.
        </div>
    </div>
    """, unsafe_allow_html=True)

    feedback_hash = hashlib.sha256(raw).hexdigest()
    review_count = get_feedback_history_count(feedback_hash)

    if review_count > 0:
        st.caption(f" Previously reviewed {review_count} time{'s' if review_count != 1 else ''}.")

    current_feedback_key = feedback_hash
    if st.session_state.get("feedback_email") != current_feedback_key:
        st.session_state["feedback_email"] = current_feedback_key
        st.session_state["feedback_action"] = None

    fb1, fb2 = st.columns(2, gap="medium")
    feedback_message = None
    feedback_type = None

    with fb1:
        if st.button("Confirm Threat", key="confirm_threat", type="primary", use_container_width=True):
            add_feedback(feedback_hash, "phish", parsed.get("full_text", ""))
            training_result = maybe_retrain_from_feedback()
            if training_result["status"] == "trained":
                get_model.clear()
                analyze_bytes.clear()
                get_sample_results.clear()
                feedback_message = "Threat confirmed. Adaptive model validated and accepted."
            elif training_result["status"] == "rejected":
                feedback_message = f"Threat confirmed and saved. Adaptive candidate was not promoted because validation regressed from {training_result.get('baseline_accuracy', 0):.1%} to {training_result.get('candidate_accuracy', 0):.1%}; existing model was kept."
            else:
                feedback_message = "Threat confirmed and stored for future learning."
            feedback_type = "success"

    with fb2:
        if st.button("✕  False Positive", key="false_positive", type="secondary", use_container_width=True):
            add_feedback(feedback_hash, "legit", parsed.get("full_text", ""))
            training_result = maybe_retrain_from_feedback()
            if training_result["status"] == "trained":
                get_model.clear()
                analyze_bytes.clear()
                get_sample_results.clear()
                feedback_message = "False positive saved. Adaptive model validated and accepted."
            elif training_result["status"] == "rejected":
                feedback_message = f"False positive saved. Adaptive candidate was not promoted because validation regressed from {training_result.get('baseline_accuracy', 0):.1%} to {training_result.get('candidate_accuracy', 0):.1%}; existing model was kept."
            else:
                feedback_message = "False-positive feedback stored for future learning."
            feedback_type = "info"

    if feedback_message:
        show_feedback_typing(feedback_message, feedback_type)

    feedback_count = get_feedback_count()
    adaptive_status = get_adaptive_status()
    is_adaptive = adaptive_status.get("status") == "trained"

    if is_adaptive:
        model_detail = f"Learned from {adaptive_status.get('feedback_samples', 0)} verified analyst samples."
    else:
        model_detail = f"{feedback_count} / 20 verified samples collected."

    with st.container(border=True):
        left, right = st.columns([2.2, 1])
        with left:
            st.markdown("### AI Learning Status")
            st.caption("Analyst-verified feedback is used for controlled model adaptation.")
        with right:
            if is_adaptive:
                st.success("ADAPTIVE MODEL")
            else:
                st.info("BASE MODEL")
            st.caption(model_detail)

    if headers["bec"]["is_bec"] and headers["auth_fail_score"] == 0:
        st.warning("**This message passes SPF, DKIM and DMARC and is still fraud.** It was sent from a genuine mailbox impersonating an executive, so authentication proves the account is real - not that the request is honest. Payload-based filters see nothing to block.")


# --------------------------------------------------------------------------
# 0. AI Threat Analysis (Qwen) - now the FIRST module in the workflow.
#    - CSV evidence: scans the newest 10 or 20 emails and produces one
#      combined campaign summary.
#    - Single evidence (file upload / Live IMAP): runs a single-email
#      Qwen assessment on the message currently loaded.
# --------------------------------------------------------------------------
if active_panel == "AI Threat Analysis":
    def _ai_threat_analysis():
        st.markdown(
            """<div class="ai-console-head">
                <div class="ai-console-status"><span class="ai-pulse"></span>LOCAL QWEN INFERENCE NODE // READY</div>
                <div class="ai-console-title">AI Threat Analysis</div>
                <div class="ai-console-sub">Evidence-bound local LLM assessment · no external API calls</div>
                <div class="ai-console-track"><span></span></div>
            </div>""",
            unsafe_allow_html=True,
        )

        is_csv_mode = uploaded is not None and uploaded.name.lower().endswith(".csv") and data

        if is_csv_mode:
            # ---------------- BULK / CAMPAIGN MODE ----------------
            st.caption(
                "Qwen scans the newest selected emails (max 20) from this CSV and produces ONE full "
                "campaign summary across all of them. Emails are sorted by their Date header; if a "
                "date cannot be read, CSV row order is used as the fallback."
            )

            qwen_count = st.radio(
                "Number of recent emails to scan (max 20)",
                [10, 20],
                horizontal=True,
                key="qwen_recent_count",
            )

            recent_candidates = []
            for idx, email_text in enumerate(data):
                recent_candidates.append({
                    "row": idx,
                    "text": email_text,
                    "date": get_email_date(email_text),
                })

            recent_candidates.sort(
                key=lambda x: (
                    x["date"] is not None,
                    x["date"] if x["date"] is not None else datetime.min.replace(tzinfo=timezone.utc),
                    x["row"]
                ),
                reverse=True
            )
            selected_recent = recent_candidates[:qwen_count]
            st.info(f" **{len(selected_recent)}** newest emails selected from **{len(data)}** total CSV records.")

            preview_rows = []
            for position, item in enumerate(selected_recent, start=1):
                date_text = item["date"].astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if item["date"] is not None else "Date unavailable — CSV order used"
                preview_rows.append({"#": position, "CSV Row": item["row"], "Email Date": date_text})
            _render_polished_table(pd.DataFrame(preview_rows))

            if st.button("Run AI Scan (Full Campaign Summary)", type="primary", use_container_width=True, key="run_qwen_recent_batch"):
                batch_items = []
                progress = st.progress(0, text="Preparing recent email forensic evidence...")

                for position, item in enumerate(selected_recent, start=1):
                    row_raw = item["text"].replace("\\n", "\n").encode("utf-8")
                    with st.spinner(f"Running forensic engine: {position}/{len(selected_recent)}"):
                        row_result = analyze_bytes(row_raw, f"{uploaded.name} (Row {item['row']})")
                    date_text = item["date"].astimezone().isoformat() if item["date"] is not None else "Unknown"
                    batch_items.append({
                        "position": position,
                        "row": item["row"],
                        "date": date_text,
                        "result": row_result,
                        "_raw": row_raw
                    })
                    progress.progress(position / len(selected_recent), text=f"Prepared forensic evidence {position}/{len(selected_recent)}")

                progress.empty()
                qwen_progress = st.progress(0, text="Qwen AI analysis: 0%")

                def _qwen_batch_progress(percent, message):
                    qwen_progress.progress(
                        max(0.0, min(1.0, percent / 100.0)),
                        text=f"Qwen AI analysis: {int(percent)}% · {message}",
                    )

                batch_ai_result = analyze_batch_with_ollama(batch_items, timeout=600, progress_callback=_qwen_batch_progress)
                qwen_progress.progress(1.0, text="Qwen AI analysis: 100% · Complete")

                st.session_state["qwen_batch_result"] = {
                    "csv_hash": csv_scan_key,
                    "count": qwen_count,
                    "result": batch_ai_result,
                }
                st.session_state["qwen_batch_items"] = batch_items

            saved_batch = st.session_state.get("qwen_batch_result")
            if saved_batch and saved_batch.get("csv_hash") == csv_scan_key:
                b_res = saved_batch.get("result", {})

                if b_res.get("ok"):
                    _sec(f"Full Campaign Summary ({saved_batch.get('count')} Emails Assessed)", tone="batch")
                    cleaned_summary = _clean_ai_display(b_res.get("analysis", ""))
                    cleaned_summary = _annotate_email_labels(cleaned_summary, st.session_state.get("qwen_batch_items") or [])
                    st.markdown(
                        f"""<div class="ai-report-frame">
                            <div class="ai-report-bar">
                                <span>QWEN // MULTI-EMAIL CAMPAIGN ASSESSMENT</span>
                                <span class="ai-report-chip">{saved_batch.get('count')} EMAILS EVALUATED</span>
                            </div>
                            <div class="ai-report-body">{_ai_markdown_to_html(cleaned_summary)}</div>
                        </div>""",
                        unsafe_allow_html=True,
                    )

                    _sec("Download Multi-Email Forensic Intelligence", tone="batch")

                    # BUG FIX: this used to offer only one download -- the AI
                    # campaign summary -- with a caption redirecting anyone
                    # who wanted an actual AI + machine combined report to go
                    # open a different email one at a time in the Forensic
                    # Report module. That's not what "combined report" means
                    # for a batch of 10 or 20 emails someone just scanned
                    # together. Every batch item already carries its full
                    # analyze_bytes() result and raw bytes (see batch_items
                    # above), so the same build_report() the single-email
                    # Forensic Report module uses can build a real per-email
                    # machine section for every email in this batch here too
                    # -- no separate module trip required.
                    _batch_items_for_dl = st.session_state.get("qwen_batch_items") or []
                    _batch_machine_sections = []
                    for _bi in _batch_items_for_dl:
                        _bi_result = _bi.get("result")
                        _bi_header = f"### Email #{_bi.get('position')} (CSV Row {_bi.get('row')})"
                        if not _bi_result or "error" in _bi_result:
                            _batch_machine_sections.append(
                                f"{_bi_header}\n\n_Machine report unavailable for this email "
                                f"({_bi_result.get('error') if _bi_result else 'no result'})._"
                            )
                            continue
                        try:
                            _batch_machine_sections.append(
                                f"{_bi_header}\n\n"
                                + build_report(_bi_result, _bi.get("_raw"), analyst="ALGORITHMISTIC automated triage")
                            )
                        except Exception as e:
                            _batch_machine_sections.append(
                                f"{_bi_header}\n\n_Machine report could not be generated ({e})._"
                            )
                    _batch_machine_body = "\n\n---\n\n".join(_batch_machine_sections) or \
                        "_No per-email machine results available for this batch._"

                    ai_only_batch_md = (
                        f"# ALGORITHMISTIC - MULTI-EMAIL CAMPAIGN ASSESSMENT\n\n"
                        f"**Total Emails Assessed:** {saved_batch.get('count')}\n\n"
                        f"## AI Campaign Summary\n\n{cleaned_summary}"
                    )
                    machine_only_batch_md = (
                        f"# ALGORITHMISTIC - MULTI-EMAIL MACHINE FORENSIC REPORT\n\n"
                        f"**Total Emails Assessed:** {saved_batch.get('count')}\n\n---\n\n"
                        f"{_batch_machine_body}"
                    )
                    combined_batch_md = (
                        f"# ALGORITHMISTIC - MULTI-EMAIL COMBINED FORENSIC + AI REPORT\n\n"
                        f"**Total Emails Assessed:** {saved_batch.get('count')}\n\n"
                        f"## AI Campaign Summary\n\n{cleaned_summary}\n\n---\n\n"
                        f"## Per-Email Machine Forensic Reports\n\n{_batch_machine_body}"
                    )

                    _count_tag = saved_batch.get('count')
                    bdl1, bdl2, bdl3 = st.columns(3)
                    with bdl1:
                        st.download_button(
                            label="AI Summary Only (.md)",
                            data=ai_only_batch_md.encode("utf-8"),
                            file_name=f"ai_campaign_summary_{_count_tag}_emails.md",
                            mime="text/markdown",
                            use_container_width=True,
                            key="dl_ai_campaign_md",
                        )
                    with bdl2:
                        st.download_button(
                            label="Machine Results Only (.md)",
                            data=machine_only_batch_md.encode("utf-8"),
                            file_name=f"machine_report_{_count_tag}_emails.md",
                            mime="text/markdown",
                            use_container_width=True,
                            key="dl_machine_campaign_md",
                        )
                    with bdl3:
                        st.download_button(
                            label="Combined Report (.md)",
                            data=combined_batch_md.encode("utf-8"),
                            file_name=f"combined_forensic_report_{_count_tag}_emails.md",
                            mime="text/markdown",
                            use_container_width=True,
                            key="dl_combined_campaign_md",
                        )
                    st.caption(
                        f"Combined Report and Machine Results Only include a full forensic "
                        f"breakdown for all {_count_tag} emails in this batch, not just the AI summary."
                    )
                else:
                    st.error(f"AI Batch Analysis Error: {b_res.get('error', 'Unknown Error')}")
        else:
            # ---------------- SINGLE-EMAIL MODE ----------------
            st.caption(
                "Qwen runs a full evidence-bound assessment of the single message currently loaded "
                "(uploaded .eml/.txt file or the selected Live IMAP message)."
            )
            st.markdown(f"**Evidence:** `{case_name}`  ·  **Verdict:** `{str(result.get('level','UNKNOWN')).upper()}`  ·  **Score:** `{float(result.get('score',0)):.1f}/100`")

            single_reports = st.session_state.setdefault("single_ai_reports", {})
            run_clicked = st.button("Run AI Scan (Single Email)", type="primary", use_container_width=True, key="run_qwen_single")

            if run_clicked:
                ai_progress = st.progress(0, text="Qwen AI analysis: 0%")

                def _qwen_single_progress(percent, message):
                    ai_progress.progress(
                        max(0.0, min(1.0, percent / 100.0)),
                        text=f"Qwen AI analysis: {int(percent)}% · {message}",
                    )

                single_ai_result = analyze_with_ollama(result, timeout=600, progress_callback=_qwen_single_progress)
                ai_progress.progress(1.0, text="Qwen AI analysis: 100% · Complete")
                single_reports[current_evidence_hash] = single_ai_result
                st.session_state["single_ai_reports"] = single_reports

            saved_single = single_reports.get(current_evidence_hash)
            if saved_single:
                if saved_single.get("ok"):
                    cleaned_single = _clean_ai_display(saved_single.get("analysis", ""))
                    st.markdown(
                        f"""<div class="ai-report-frame">
                            <div class="ai-report-bar">
                                <span>QWEN // SINGLE-EMAIL THREAT ASSESSMENT</span>
                                <span class="ai-report-chip">{case_name[:40]}</span>
                            </div>
                            <div class="ai-report-body">{_ai_markdown_to_html(cleaned_single)}</div>
                        </div>""",
                        unsafe_allow_html=True,
                    )

                    _sec("Download AI Threat Report", tone="ai")
                    single_markdown_report = (
                        f"# ALGORITHMISTIC - AI THREAT ASSESSMENT\n\n"
                        f"**Evidence:** {case_name}\n\n"
                        f"**Verdict:** {str(result.get('level','UNKNOWN')).upper()}  ·  "
                        f"**Score:** {float(result.get('score',0)):.1f}/100\n\n"
                        f"## AI Assessment\n\n{cleaned_single}"
                    )
                    st.download_button(
                        label="Download AI Assessment (.md)",
                        data=single_markdown_report.encode("utf-8"),
                        file_name="ai_threat_assessment.md",
                        mime="text/markdown",
                        use_container_width=True,
                        key="dl_ai_single_md",
                    )
                    st.caption("For the combined AI + machine dossier with all three download options, open the **Forensic Report** module.")
                else:
                    st.error(f"AI Analysis Error: {saved_single.get('error', 'Unknown Error')}")
            elif not run_clicked:
                st.info("Click **Run AI Scan** to send this message's forensic evidence to the local Qwen model.")

    panel(_ai_threat_analysis, "AI Threat Analysis")

# --------------------------------------------------------------------------
# 1. Classification
# --------------------------------------------------------------------------
if active_panel == "Classification":
    def _classification():
        _banner("CLASSIFICATION", "Threat Classification",
                "How the risk score was built and why the model flagged this email", "SELECTED EMAIL", "rose")
        left, right = st.columns([1, 1])
        with left:
            _sec("Risk score composition", tone="rose")
            contributions = [c for c in result["verdict"]["contributions"]]
            fig = go.Figure(go.Bar(
                x=[c["points"] for c in contributions],
                y=[c["label"] for c in contributions],
                orientation="h",
                marker=dict(color=[
                    "#b71c1c" if c["points"] >= c["weight"] * 0.6
                    else "#e65100" if c["points"] > 0 else "#cfd8dc"
                    for c in contributions]),
                text=["{:.0f} / {}".format(c["points"], c["weight"]) for c in contributions],
                textposition="outside",
                hovertemplate="%{y}<br>%{x:.1f} points<extra></extra>",
            ))
            fig.update_layout(
                height=300, margin=dict(l=10, r=40, t=10, b=10),
                xaxis_title="points contributed (weights total 100)",
                yaxis=dict(autorange="reversed"),
                plot_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig, width='stretch')
            st.caption("Every point is attributable to a named detector - the score is a weighted sum, not a black box.")

        with right:
            _sec("Why the model flagged this", tone="rose")
            st.metric("Phishing probability", "{:.1%}".format(result["ml"]["prob"]), result["ml"]["label"])
            if result["ml"]["top_terms"]:
                terms = result["ml"]["top_terms"]
                fig_t = go.Figure(go.Bar(
                    x=[w for _, w in terms][::-1],
                    y=[t for t, _ in terms][::-1],
                    orientation="h", marker_color="#5c6bc0",
                    hovertemplate="%{y}<br>contribution %{x:.3f}<extra></extra>",
                ))
                fig_t.update_layout(height=260, margin=dict(l=10, r=10, t=10, b=10),
                                    xaxis_title="contribution toward 'phishing'",
                                    plot_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig_t, width='stretch')
                st.caption("Logistic-regression coefficients, so the exact words driving the decision are readable.")
            else:
                st.success("No term in this message pushed the score toward phishing.")

        st.divider()
        _sec("Message", tone="rose")
        c1, c2 = st.columns([1, 1])
        c1.text_input("From", parsed.get("from_addr", ""), disabled=True)
        c2.text_input("Subject", parsed.get("subject", ""), disabled=True)
        st.text_area("Body as analysed", parsed.get("body_text", "")[:4000], height=240, disabled=True)

    panel(_classification, "Classification")

# --------------------------------------------------------------------------
# 2. Headers & authentication
# --------------------------------------------------------------------------
if active_panel == "Headers & Auth":
    def _headers():
        _banner("HEADERS & AUTH", "Header Authentication & Identity",
                "Sender authentication results and identity-field anomalies", "SELECTED EMAIL", "sky")
        _sec("SPF / DKIM / DMARC", tone="sky")
        cols = st.columns(3)
        for col, mech in zip(cols, ("spf", "dkim", "dmarc")):
            value = headers[mech]
            col.markdown(
                """<div style="background:{c};padding:12px;border-radius:8px;
                text-align:center;color:#fff;"><div style="font-size:12px;
                opacity:.85;">{m}</div><div style="font-size:22px;
                font-weight:700;">{v}</div></div>""".format(
                    c=AUTH_COLOR.get(value, "#78909c"), m=mech.upper(), v=value.upper()),
                unsafe_allow_html=True)
        st.caption("Verdicts stamped by the receiving server at delivery. We re-read them rather than re-running DNS, because published records may have changed since the message arrived.")

        st.divider()
        _sec("Identity anomalies", tone="sky")
        if headers["anomalies"]:
            for a in headers["anomalies"]:
                st.markdown(
                    """<div style="border-left:4px solid {c};padding:8px 14px;
                    margin-bottom:8px;background:rgba(120,120,120,.08);">
                    <b>{t}</b><br><span style="font-size:13px;opacity:.85;">{d}
                    </span></div>""".format(c=SEV_COLOR.get(a["severity"], "#666"), t=a["title"], d=a["detail"]),
                    unsafe_allow_html=True)
        else:
            st.success("No anomalies. Sender identity is internally consistent.")

        if headers["bec"]["is_bec"]:
            st.divider()
            _sec("Business Email Compromise assessment", tone="sky")
            bec = headers["bec"]
            st.progress(min(1.0, bec["score"]), text="BEC pattern strength {:.0%}".format(bec["score"]))
            b1, b2 = st.columns(2)
            b1.write("**Payment language**")
            b1.write(", ".join("`{}`".format(w) for w in bec["payment_words"]) or "none")
            b1.write("**Urgency language**")
            b1.write(", ".join("`{}`".format(w) for w in bec["urgency_words"]) or "none")
            b2.write("**Claims executive identity:** {}".format("yes" if bec["exec_claim"] else "no"))
            b2.write("**Consumer mailbox sender:** {}".format("yes" if bec["freemail_sender"] else "no"))
            b2.write("**No link/attachment to scan:** {}".format("yes" if bec["no_links"] else "no"))

        st.divider()
        _sec("Identity fields", tone="sky")
        _render_polished_table(pd.DataFrame([
            {"Header": label, "Value": parsed.get(key) or "(absent)"}
            for label, key in (
                ("From display name", "from_display"),
                ("From address", "from_addr"),
                ("Reply-To", "reply_to"),
                ("Return-Path", "return_path"),
                ("To", "to"),
                ("Date", "date"),
                ("Message-ID", "message_id"),
                ("X-Mailer", "x_mailer"),
            )]))

        with st.expander("Raw Received chain (oldest hop first)"):
            for i, hop in enumerate(parsed.get("received_chain", []), 1):
                st.code("{}. {}".format(i, hop), language=None)

    panel(_headers, "Headers & Auth")

# --------------------------------------------------------------------------
# 3. Origin & route
# --------------------------------------------------------------------------
if active_panel == "Origin & Route":
    def _geo():
        _banner("ORIGIN & ROUTE", "Where the message actually came from",
                "Trace the sending infrastructure hop by hop \u2014 compare up to 10 emails or drill into one", "ALL OR ONE", "teal")

        # Pull in every other browsed-but-not-yet-opened Live IMAP message
        # that's already been prefetched, so the map/picker below have all
        # of them, not just whichever one is currently loaded -- see
        # _ensure_live_cases_from_prefetch for why this is machine-analysis
        # only (fast) rather than the full AI pipeline.
        _ensure_live_cases_from_prefetch()

        # Every loaded email at a glance (capped so the map stays readable),
        # or one email's full hop chain picked from a dropdown -- same
        # toggle as the Dashboard preview map, so either view is a click
        # away instead of only ever seeing whichever message is loaded.
        cases = [r for r in _corr_cases.values() if "error" not in r]
        current_case = dict(result)
        current_case["_evidence_hash"] = current_evidence_hash
        if current_evidence_hash not in {r.get("_evidence_hash") for r in cases}:
            cases.append(current_case)

        _sec("Interactive Visual Hop Map", "Satellite view of every hop", "teal")
        _geo_map_mode = st.radio(
            "Map view", [_MAP_MODE_ALL, _MAP_MODE_ONE], horizontal=True, key="geo_map_mode_v2",
        )

        # The summary strip below (Origin IP / Infrastructure / VPN Masking /
        # Network Trust) always describes whichever email the map is showing.
        # In "by email" mode that's whatever the dropdown has selected, which
        # can be a different message than the one loaded elsewhere in the app
        # -- so this strip is computed from that same selection instead of
        # always reading the originally loaded email. (Previously it only
        # ever read the loaded email, so switching the dropdown moved the
        # map but left this strip showing the old message.)
        _active_case = result
        if _geo_map_mode == _MAP_MODE_ONE:
            _active_case = _pick_case_for_map(cases, result, case_name, key="geo_map_email_pick", source_rows=data)

        _active_parsed = _active_case.get("parsed", {}) or {}
        _active_geo = _active_case.get("geo", {}) or {}
        origin = _active_geo.get("origin", {}) or {}

        st.info(_active_geo.get("summary", "No routing data."))

        # Network-Trust: geolocate.py already classifies infra (tor/vpn/proxy/
        # datacenter/residential) -- this compares today's origin against
        # *this sender's own mailing history*. A VPN is unremarkable for a
        # sender who always uses one; a trusted sender suddenly routing
        # through one they've never used before is the real signal, and it's
        # the one thing IP/infra classification alone can never catch.
        _nt = assess_network_trust(
            _active_parsed.get("from_addr", ""),
            origin.get("ip", ""),
            origin.get("infra_label", ""),
            origin.get("country", ""),
        )

        g1, g2, g3, g4 = st.columns(4)
        g1.metric("Origin IP", origin.get("ip") or "unknown")
        g2.metric("Location", ", ".join(p for p in [origin.get("city"), origin.get("country")] if p) or "Unknown")
        g3.metric("Infrastructure", origin.get("infra_label", "Unattributed"))
        g4.metric("Hops traced", len(_active_geo.get("hops", [])))

        # VPN Masking / Network Trust / Tor Exit Confirmation get their own
        # row below, in bordered containers with wrapping markdown text
        # rather than st.metric -- squeezed into a 6-up metric row their
        # labels ("Detected — VPN", "New network for this sender") got
        # clipped to "Detect..." since st.metric never wraps. A full-width
        # row fixes that.
        vpn_box, trust_box, tor_box = st.columns(3)
        with vpn_box:
            with st.container(border=True):
                st.caption("VPN Masking")
                # Direct answer to "is VPN/proxy/Tor masking present on this
                # message at all" -- independent of whether that's normal
                # for this sender. Kept separate from Network Trust, which
                # answers the different question of whether it's *new*.
                if _nt.get("is_anonymizing"):
                    st.markdown(f" **Detected — {_nt.get('infra_display', origin.get('infra_label', 'Unknown'))}**")
                else:
                    st.markdown(" **Not detected**")
        with trust_box:
            with st.container(border=True):
                st.caption("Network Trust")
                st.markdown(f"**{_nt['badge']}**")
        with tor_box:
            with st.container(border=True):
                st.caption("Tor Exit Confirmation")
                # Separate signal from VPN Masking above: that box is the
                # `infra` keyword heuristic (ISP/org string guess). This one
                # is tor_check.py's confirmed-list lookup -- an IP actually
                # published on one or more of its cached Tor lists (Tor
                # Project official, community exit mirror, community full
                # node list), cited by name. These can disagree with the
                # heuristic above: a VPS-hosted exit can be confirmed here
                # while the ISP-name guess misses it entirely (ISP just
                # says "OVH SAS").
                if origin.get("tor_exit_confirmed"):
                    _tor_srcs = origin.get("tor_exit_sources", [])
                    st.markdown(" **Confirmed exit node**")
                    st.caption("Source: " + "; ".join(_tor_srcs) if _tor_srcs else "Source: unknown")
                else:
                    st.markdown(" **Not on published exit lists**")

        if _nt["level"] == "alert":
            st.error(
                "**Sender network anomaly** — " + " ".join(_nt["reasons"]) +
                "We can't unmask a VPN/Tor operator, but a trusted sender suddenly routing "
                "through anonymizing infrastructure for the first time is itself the red flag."
            )
        elif _nt["level"] == "warning":
            st.warning("**Sender network anomaly** — " + " ".join(_nt["reasons"]))
        else:
            st.caption("Network Trust: " + " ".join(_nt["reasons"]))

        _table_geo = _active_geo
        if _geo_map_mode == _MAP_MODE_ALL:
            _render_all_hops_map(cases, key_prefix="geo", height=560, source_rows=data)
        else:
            hops = [h for h in _table_geo.get("hops", []) if h.get("lat") is not None]

            if hops:
                start_lat = hops[0]["lat"] if hops else 20.0
                start_lon = hops[0]["lon"] if hops else 0.0

                m = _new_map([start_lat, start_lon], zoom_start=3)
                coordinates = []

                _spots = {}
                for i, h in enumerate(hops, 1):
                    coordinates.append([h["lat"], h["lon"]])
                    is_origin = (h["infra"] in ("tor", "vpn", "proxy")) or (i == len(hops))
                    sp = _spots.setdefault(_loc_key(h), {"h": h, "hops": [], "origin": False})
                    sp["hops"].append(i)
                    sp["origin"] = sp["origin"] or is_origin
                for sp in _spots.values():
                    h = sp["h"]
                    hop_txt = ", ".join(str(x) for x in sp["hops"])
                    _pop = (
                        f'<div class="ps-pop"><div class="ps-h">Hop {hop_txt}</div>'
                        f'<div class="ps-sub">IP {html.escape(str(h.get("ip", "")))}</div>'
                        f'<div class="ps-row">{html.escape(str(h.get("city", "")))}, {html.escape(str(h.get("country", "")))}<br>'
                        f'<span style="color:#aab9d0;">{html.escape(str(h.get("infra_label", "")))}</span></div></div>'
                    )
                    _pin_marker(
                        h["lat"], h["lon"], "#ff4757" if sp["origin"] else "#2fd8ff",
                        str(sp["hops"][0]),
                        _pop, tooltip=f"Hop {hop_txt} · {h.get('ip', '')}", big=sp["origin"],
                        chips=([(x, "#ff4757" if sp["origin"] else "#2fd8ff") for x in sp["hops"]] if len(sp["hops"]) > 1 else None),
                        chips_caption="Hops",
                    ).add_to(m)

                if len(coordinates) == 1:
                    hq_coords = [22.5726, 88.3639]
                    coordinates.append(hq_coords)
                    _pin_marker(
                        hq_coords[0], hq_coords[1], "#35d399", "HQ",
                        '<div class="ps-pop"><div class="ps-h">Target datacenter (HQ)</div></div>',
                        tooltip="Target datacenter (HQ)",
                    ).add_to(m)

                if len(coordinates) > 1:
                    from folium.plugins import AntPath
                    import math
                    for step in range(len(coordinates) - 1):
                        lat1, lon1 = coordinates[step][0], coordinates[step][1]
                        lat2, lon2 = coordinates[step+1][0], coordinates[step+1][1]
                        arc_points = []
                        mid_lat = (lat1 + lat2) / 2.0
                        mid_lon = (lon1 + lon2) / 2.0
                        distance = math.sqrt((lat2 - lat1)**2 + (lon2 - lon1)**2)
                        mid_lat += distance * 0.25

                        for frame in range(51):
                            t = frame / 50.0
                            lat = (1-t)**2 * lat1 + 2*(1-t)*t * mid_lat + t**2 * lat2
                            lon = (1-t)**2 * lon1 + 2*(1-t)*t * mid_lon + t**2 * lon2
                            arc_points.append([lat, lon])

                        AntPath(locations=arc_points, color="#ff4757", pulse_color="#ffffff", weight=3, opacity=0.8, delay=800, dash_array=[15, 30]).add_to(m)

                if len(coordinates) > 1:
                    try:
                        m.fit_bounds(coordinates, max_zoom=5)
                    except Exception:
                        pass
                with st.container(key="geo_single_map_frame"):
                    st_folium(m, width="stretch", height=560, returned_objects=[], key="geo_single_map")
                st.caption(
                    "Pins are numbered by hop (hop 1 = earliest external sender). Red = origin or anonymising "
                    "infrastructure; hops that share a location are merged into one pin whose pill lists those hop numbers. Imagery © Esri."
                )
            else:
                st.warning("No hop in this email could be geolocated, so there is nothing to plot. Recorded as unresolved rather than guessed.")

        # ------------------------------------------------------------------
        # Bulk infrastructure scan (all loaded emails) -- now an always-open
        # section right under the map (it used to sit in a collapsed expander
        # further down, which made it hard to find). One panel, two
        # tabs, rather than two separate expanders stacked on top of each
        # other. Both tabs check every origin + hop IP across every case
        # loaded this session (_corr_cases) in a single pass:
        #   - VPN / Datacenter: network_trust.check_vpn_or_datacenter
        #     against a CIDR list you supply (scan_cases_for_vpn) -- an
        #     offline fallback/second-opinion independent of geolocate.py's
        #     live infra classification above.
        #   - Tor Exit Nodes: tor_check.scan_cases_for_tor against the
        #     Tor Project's official exit list + community mirror cached
        #     in tor_exit_nodes, re-checked live so it also catches cases
        #     traced before the most recent Tor list refresh.
        # ------------------------------------------------------------------
        with st.container(border=True, key="bulk_infra_scan"):
            st.markdown(
                '<div class="infra-scan-head">'
                '<div class="infra-scan-eyebrow">VPN &middot; Datacenter &middot; Tor</div>'
                '<div class="infra-scan-title">Bulk Infrastructure Scan</div>'
                '<div class="infra-scan-sub">Checks every origin and hop IP across all loaded emails against '
                'VPN / datacenter ranges and Tor exit lists, in one pass. Pick a tab below, then press Scan.</div>'
                '</div>',
                unsafe_allow_html=True,
            )
            _bulk_infra_view = st.radio(
                "Bulk infrastructure scan view", ["VPN / Datacenter", "Tor Exit Nodes"],
                horizontal=True, label_visibility="collapsed", key="bulk_infra_scan_radio",
            )

            if _bulk_infra_view == "VPN / Datacenter":
                st.caption(
                    "Checks every origin + hop IP across every email currently loaded "
                    "(this session's cases) against VPN / datacenter CIDR ranges. One "
                    "click fetches the latest ranges from X4BNet, then scans -- no "
                    "separate 'refresh first' step."
                )

                _run_scan = st.button(
                    "Scan All Loaded Emails", key="run_vpn_bulk_scan",
                    type="primary", use_container_width=True,
                )

                # Advanced/manual controls are tucked away by default -- the
                # button above is the whole workflow for everyone who doesn't
                # need to override it. Defaults match the old hidden default
                # exactly, so behaviour for anyone who never opens this is
                # unchanged.
                with st.expander("Advanced: manual CSV / offline mode"):
                    _vpn_csv_path = st.text_input(
                        "Path to CIDR-range CSV (columns: cidr,provider,category)",
                        value="data/vpn_ranges.csv",
                        key="vpn_csv_path",
                    )
                    _vpn_skip_live = st.checkbox(
                        "Skip the live X4BNet fetch -- scan against this file as-is",
                        key="vpn_skip_live_fetch",
                        disabled=not FETCH_VPN_RANGES_AVAILABLE,
                        help="Use this on an offline/air-gapped machine, or to pin the "
                             "scan to a ranges file you built or edited yourself." if FETCH_VPN_RANGES_AVAILABLE
                             else "fetch_vpn_ranges.py wasn't found next to app.py -- the live fetch is "
                                  "unavailable, so scans already use this file as-is.",
                    )

                if _run_scan:
                    _vpn_fetch_ok = False
                    _vpn_fetched_n = 0
                    _do_live_fetch = FETCH_VPN_RANGES_AVAILABLE and not st.session_state.get("vpn_skip_live_fetch")

                    if _do_live_fetch:
                        try:
                            with st.spinner("Fetching live VPN + datacenter ranges from X4BNet..."):
                                _fetched_rows = []
                                for _cat in ("vpn", "datacenter"):
                                    _fetched_rows.extend(_fetch_vpn_category(_cat, include_ipv6=False))
                        except Exception as e:
                            st.warning(
                                f"Live fetch failed ({e}) -- falling back to the last-saved ranges "
                                f"file at `{_vpn_csv_path}` (never wiped by a fetch that didn't happen)."
                            )
                        else:
                            if not _fetched_rows:
                                st.warning("Live fetch returned no ranges -- falling back to the last-saved file.")
                            else:
                                _sp_root = os.path.dirname(os.path.abspath(__file__))
                                _sp_data = os.path.realpath(os.path.join(_sp_root, "data"))
                                _resolved_csv_path = os.path.realpath(os.path.join(_sp_root, _vpn_csv_path))
                                if not _resolved_csv_path.startswith(_sp_data + os.sep):
                                    st.error("For safety, the ranges file must be inside the data/ folder.")
                                    st.stop()
                                _out_dir = os.path.dirname(_resolved_csv_path)
                                if _out_dir:
                                    os.makedirs(_out_dir, exist_ok=True)
                                with open(_resolved_csv_path, "w", newline="", encoding="utf-8") as _f:
                                    _writer = csv.writer(_f)
                                    _writer.writerow(["cidr", "provider", "category"])
                                    _writer.writerows(_fetched_rows)
                                _vpn_fetch_ok = True
                                _vpn_fetched_n = len(_fetched_rows)
                    elif not FETCH_VPN_RANGES_AVAILABLE:
                        st.caption("Live fetch unavailable (fetch_vpn_ranges.py not found) -- scanning against the local file.")

                    try:
                        _vpn_ranges = load_vpn_ranges(_vpn_csv_path)
                    except (FileNotFoundError, OSError) as e:
                        st.error(f"Couldn't read `{_vpn_csv_path}`: {e}")
                    except Exception as e:
                        st.error(f"Couldn't parse `{_vpn_csv_path}` as a ranges CSV: {e}")
                    else:
                        if not _vpn_ranges:
                            st.warning("That file loaded but contained no valid CIDR rows.")
                        else:
                            _live_class = "" if _vpn_fetch_ok else "stale"
                            _live_text = (
                                f"Live &middot; {_vpn_fetched_n} ranges fetched just now from X4BNet"
                                if _vpn_fetch_ok else
                                f"Cached &middot; scanning against {len(_vpn_ranges)} previously-saved range(s) at "
                                f"<code>{html.escape(_vpn_csv_path)}</code>"
                            )
                            st.markdown(
                                f'<div class="infra-scan-livebar {_live_class}"><span class="dot"></span>{_live_text}</div>',
                                unsafe_allow_html=True,
                            )

                            _vpn_cases = [r for r in _corr_cases.values() if "error" not in r]
                            _vpn_current = dict(result)
                            _vpn_current["_evidence_hash"] = current_evidence_hash
                            if current_evidence_hash not in {r.get("_evidence_hash") for r in _vpn_cases}:
                                _vpn_cases.append(_vpn_current)

                            _vpn_rows = scan_cases_for_vpn(_vpn_cases, _vpn_ranges)
                            if not _vpn_rows:
                                st.info("No IPs to check yet -- load some emails first.")
                            else:
                                _vpn_df = pd.DataFrame(_vpn_rows)
                                _flagged_n = int(_vpn_df["flagged"].sum())
                                st.metric("Flagged IPs", f"{_flagged_n} / {len(_vpn_df)}")
                                _render_polished_table(_vpn_df.sort_values("flagged", ascending=False))
                st.caption(
                    "Ranges come from [X4BNet/lists\\_vpn](https://github.com/X4BNet/lists_vpn) "
                    "(public, auto-updated, no signup) -- refetched automatically on every scan "
                    "unless 'Skip the live fetch' is checked above."
                )

            if _bulk_infra_view == "Tor Exit Nodes":
                st.caption(
                    "Checks every origin + hop IP across every email currently loaded "
                    "(this session's cases) against three lists -- the Tor Project's "
                    "official exit list, a community exit-node mirror, and that "
                    "mirror's full Tor node list. One click force-refreshes all three, "
                    "then scans -- no separate 'refresh first' step."
                )

                _run_tor_scan = st.button(
                    "Scan All Loaded Emails", key="run_tor_bulk_scan",
                    type="primary", use_container_width=True,
                )

                with st.expander("Advanced: skip live refresh"):
                    _tor_skip_live = st.checkbox(
                        "Skip the live Tor-list refresh -- scan against whatever's already cached",
                        key="tor_skip_live_fetch",
                        help="Use this offline, or when you already refreshed moments ago and want "
                             "to re-scan instantly without hitting the network again.",
                    )

                if _run_tor_scan:
                    if not st.session_state.get("tor_skip_live_fetch"):
                        with st.spinner("Refreshing Tor exit-node lists from the Tor Project and community mirrors..."):
                            _tor_results = tor_check.update_tor_exit_list()
                        _tor_failed = [k for k, v in _tor_results.items() if v is None]
                        if _tor_failed:
                            _fail_labels = [tor_check.SOURCES[k][1] for k in _tor_failed]
                            # Asymmetric by design (see tor_check.py): a source
                            # that fails keeps whatever it had before rather
                            # than going blank, so detection only ever gets
                            # weaker, never wrong.
                            st.markdown(
                                '<div class="infra-scan-livebar stale"><span class="dot"></span>'
                                'Refreshed what we could -- kept previous cached data for: '
                                f'{html.escape("; ".join(_fail_labels))}</div>',
                                unsafe_allow_html=True,
                            )
                        else:
                            st.markdown(
                                '<div class="infra-scan-livebar"><span class="dot"></span>'
                                'Live &middot; all sources refreshed just now &mdash; '
                                + html.escape(", ".join(f"{tor_check.SOURCES[k][1]}: {v} IPs" for k, v in _tor_results.items()))
                                + '</div>',
                                unsafe_allow_html=True,
                            )
                    else:
                        st.markdown(
                            '<div class="infra-scan-livebar stale"><span class="dot"></span>'
                            'Cached &middot; scanning against whatever is already cached (live refresh skipped)</div>',
                            unsafe_allow_html=True,
                        )

                    _tor_scan_cases = [r for r in _corr_cases.values() if "error" not in r]
                    _tor_scan_current = dict(result)
                    _tor_scan_current["_evidence_hash"] = current_evidence_hash
                    if current_evidence_hash not in {r.get("_evidence_hash") for r in _tor_scan_cases}:
                        _tor_scan_cases.append(_tor_scan_current)

                    _tor_scan_rows = tor_check.scan_cases_for_tor(_tor_scan_cases)
                    if not _tor_scan_rows:
                        st.info("No IPs to check yet -- load some emails first.")
                    else:
                        _tor_scan_df = pd.DataFrame(_tor_scan_rows)
                        _tor_flagged_n = int(_tor_scan_df["flagged"].sum())
                        st.metric("Confirmed Tor IPs", f"{_tor_flagged_n} / {len(_tor_scan_df)}")
                        if _tor_flagged_n:
                            st.warning(
                                f"{_tor_flagged_n} IP(s) across loaded emails matched a "
                                "published Tor list."
                            )
                        _render_polished_table(_tor_scan_df.sort_values("flagged", ascending=False))
                st.caption(
                    "Source-by-source counts and last-sync times are in the "
                    "'Tor Exit-Node List Status' panel below."
                )

        # Routing chain / anonymised caution follow whichever email the map
        # above is showing (the currently loaded one, unless "by email" was
        # used to pick a different one) -- "all senders" mode has no single
        # chain to show, so these keep describing the currently loaded message.
        if _table_geo.get("hops"):
            _sec("Routing chain", tone="teal")
            _render_polished_table(pd.DataFrame([{
                "#": h.get("hop_index"),
                "IP": h["ip"],
                "City": h.get("city") or "-",
                "Country": h.get("country") or "Unknown",
                "Network": h.get("isp") or "-",
                "Infrastructure": h.get("infra_label", "-"),
                "Tor Exit": "Confirmed" if h.get("tor_exit_confirmed") else "-",
                "Source": h.get("source", "-"),
            } for h in _table_geo["hops"]]))

        if _table_geo.get("anonymised"):
            st.warning("**Attribution caution** - the earliest hop is anonymising infrastructure. The location identifies the relay, not the operator. Naming the sender would need relay logs, which Tor deliberately does not keep.")

        # Confirmed-exit-list check is independent of the "anonymised" flag
        # above (which is driven by the `infra` heuristic), so it's called
        # out on its own -- this is the case where a VPS-hosted exit slips
        # past the ISP-name guess but is still on a published exit list.
        if origin.get("tor_exit_confirmed") and not _table_geo.get("anonymised"):
            st.info(
                "**Tor exit confirmed, separately from the infrastructure guess above** — "
                "the origin IP `{}` is on a published Tor exit-node list ({}), even though "
                "its ISP/org string didn't trip the keyword heuristic. Same attribution "
                "caution applies: this identifies the relay, not the operator.".format(
                    origin.get("ip", "unknown"), "; ".join(origin.get("tor_exit_sources", []))
                )
            )

        # ------------------------------------------------------------------
        # Tor exit-node list status (read-only) -- the Tor Exit
        # Confirmation signal above is only as fresh as tor_exit_nodes in
        # the DB. maybe_update_tor_list() (called automatically inside
        # geolocate.trace()) is throttled to once per 30 min per source.
        # The fetch-now button lives in the "Tor Exit Nodes" tab of the
        # Bulk Infrastructure Scan panel above (next to Scan all loaded
        # emails) -- this panel is just the status readout, so there's one
        # fetch control, not two.
        # ------------------------------------------------------------------
        with st.expander("Tor Exit-Node List Status"):
            st.caption(
                "Three independently-tracked sources back the Tor Exit "
                "Confirmation signal above: the Tor Project's own official "
                "exit list, an hourly-updated community exit-node mirror, "
                "and that same mirror's full Tor node list. Each refreshes "
                "automatically at most once every 30 minutes as emails are "
                "analyzed -- use 'Fetch Tor lists now' in the Bulk "
                "Infrastructure Scan panel above to force an immediate "
                "refresh instead of waiting, or to populate this table for "
                "the first time."
            )

            _tor_status = tor_check.tor_list_status()
            _render_polished_table(pd.DataFrame([
                {
                    "Source": info["label"],
                    "IPs cached": info["count"],
                    "Last sync": info["last_sync"] or "Never",
                    "Last error": info["last_error"] or "-",
                }
                for info in _tor_status["sources"].values()
            ]))
            st.caption(f"{_tor_status['total_distinct_ips']} distinct IP(s) cached across all sources.")

        with st.expander("How origin tracing works, and its limits"):
            st.markdown(
                "- Mail servers **prepend** `Received` headers, so the **last** one in the file is the **earliest** hop. We reverse the chain and take the first globally routable IP.\n"
                "- Private, loopback and reserved ranges are skipped - they are internal relays and say nothing about the origin.\n"
                "- Lookup order is bundled cache, then a local MaxMind GeoLite2 database if you drop one at `data/GeoLite2-City.mmdb`, then 'unresolved'. **No live API is ever called**, so the demo cannot fail on conference wifi and gives identical output every run.\n"
                "- Headers **below the first trusted hop can be forged**. Only hops added by servers you control are dependable evidence.\n"
                "- Infrastructure classes: {}\n"
                "- **Tor Exit Confirmation** is a separate, independent check from the infrastructure "
                "class above: it looks the origin IP up against three cached Tor lists -- the Tor "
                "Project's own published exit list, a community exit-node mirror, and that mirror's "
                "full Tor node list (see `tor_check.py`) -- rather than guessing from the ISP/org "
                "name string. It can confirm exits the ISP-name heuristic misses (e.g. Tor hosted on a "
                "plain VPS provider), and it's purely informational -- it does not change the risk score.\n"
                "- **VPN Masking** answers one question only: is *this* message routed through anonymizing "
                "infrastructure (VPN/Tor/proxy) at all. It says nothing about whether that's unusual.\n"
                "- **Network Trust** answers the other question: is that *normal for this sender*. We can "
                "never de-anonymize a VPN/Tor/proxy operator — that needs the provider's private logs — so "
                "instead we track which network each sender has mailed from before and flag it when a message "
                "breaks that pattern, whether or not anonymizing infrastructure is involved. A sender who "
                "always mails through a VPN will show VPN Masking: Detected with Network Trust: Consistent — "
                "that's not a contradiction, it's the point."
                .format(", ".join(sorted(set(INFRA_LABEL.values())))))

    panel(_geo, "Origin & Route")

    def _geo_semantic():
        st.markdown("---")
        _sec("Find Similar Senders", tone="teal")
        st.caption(
            "Looks for other loaded emails whose sending infrastructure behaves like this "
            "one -- same kind of hosting, same region, same anonymizing pattern -- even when "
            "the IP address or domain is completely different. Useful for spotting the same "
            "campaign reused under a different address. (Technical name: semantic origin "
            "correlation via Nomic/Cohere embeddings.)"
        )

        if not _nomic_ready():
            st.warning(
                "This feature isn't available right now: locally, either Ollama isn't "
                "running or `nomic-embed-text` hasn't been pulled; run `ollama pull "
                "nomic-embed-text` and make sure Ollama is running. For the cloud "
                "fallback instead, set SIH26106_COHERE_API_KEY. Then reopen this panel."
            )
            return

        origin = geo.get("origin", {}) or {}
        description = _sem_describe_origin(geo)

        # Slider, capped at the "Strong" band ceiling (85%) instead of the
        # original 95% -- dragging it above 85% is what silently produced
        # zero matches for almost any real data (nothing scores "above
        # Strong") and looked like the feature was broken. Capping the top
        # end means wherever you drag it, it stays inside a range that can
        # actually return something.
        _sem_min = st.slider(
            "Minimum match score", float(_SEM_MIN_SIMILARITY), float(_SEM_STRONG), _SEM_RELATED, 0.05,
            format="%.2f", key="nomic_min_score_v2",
            help=f"Matches scoring below this are hidden as noise. Weak \u2265 {_SEM_MIN_SIMILARITY:.0%}, "
                 f"Related \u2265 {_SEM_RELATED:.0%}, Strong \u2265 {_SEM_STRONG:.0%}.",
        )

        _run_all = st.button(
            "Find Similar Origins", key="run_nomic_embed", use_container_width=True, type="primary",
            help="Compares this email's origin against every other email loaded this session, indexing anything not already compared.",
        )

        if _run_all:
            _pair_map = {h: (r.get("geo") or {}) for h, r in _corr_cases.items() if isinstance(r, dict) and "error" not in r}
            _pair_map[current_evidence_hash] = geo
            _sem_index_many(list(_pair_map.items()), label="Comparing this origin against every loaded email...")
            st.session_state["nomic_last_hash"] = current_evidence_hash
            st.success(f"Compared against {max(len(_pair_map) - 1, 0)} other loaded email(s).")

        _indexed_now = current_evidence_hash in st.session_state.get("_sem_indexed", {})
        if st.session_state.get("nomic_last_hash") == current_evidence_hash or _indexed_now:
            matches = _sem_find(current_evidence_hash, origin, top_k=8, min_score=_sem_min)
            if matches:
                st.markdown("##### Closest previously analyzed origins (by meaning)")
                st.markdown(_sem_headline(matches))
                _render_polished_table(pd.DataFrame(_sem_rows(matches)))
            else:
                st.info(
                    _sem_none_text(_sem_min) + " Try loading more emails first, or choose "
                    "'Show everything, even weak leads' above."
                )
            with st.expander("How this scoring works"):
                st.caption(_SEM_METHOD_NOTE)
                st.text(description)

    panel(_geo_semantic, "Semantic Origin Correlation")

# --------------------------------------------------------------------------
# 4. Indicators of compromise
# --------------------------------------------------------------------------
if active_panel == "Indicators":
    def _iocs():
        _banner("INDICATORS", "Indicators of Compromise",
                "URLs, domains, addresses and wallets extracted from the evidence", "SELECTED EMAIL", "gold")
        urls = iocs.get("urls", [])
        counts = iocs.get("counts", {})

        local_memory_matches = sum(
            1 for u in urls if isinstance(u, dict) and u.get("intel_source") == "Local memory"
        )

        s1, s2, s3 = st.columns(3)
        s1.metric("Total URLs", len(urls))
        s2.metric("Suspicious", counts.get("suspicious", 0))
        s3.metric("Local Memory", local_memory_matches)

        st.divider()
        _sec("Extracted Indicators", tone="gold")
        st.caption("URLs, domains, email addresses, wallets and suspicious indicators extracted from the evidence.")

        indicator_data = [
            ("URLs", counts.get("urls", 0)),
            ("Suspicious", counts.get("suspicious", 0)),
            ("Domains", counts.get("domains", 0)),
            ("Emails", counts.get("emails", 0)),
            ("Wallets", counts.get("wallets", 0)),
        ]

        cols = st.columns(5)
        for col, (label, value) in zip(cols, indicator_data):
            with col:
                with st.container(border=True):
                    st.markdown(f"**{label}**")
                    st.markdown(f"## {value}")

        if urls:
            st.divider()
            _sec("URL Intelligence", tone="gold")
            st.caption("Reputation and heuristic signals attached to extracted URLs.")
            for idx, u in enumerate(urls, 1):
                risk = float(u.get("risk", 0))
                suspicious = bool(u.get("suspicious"))
                state = "SUSPICIOUS" if suspicious else "NO HIGH-RISK SIGNAL"
                st.markdown(
                    f"""
                    **#{idx} — {u.get("url", "-")}**

                    Host: `{u.get("host") or "-"}`  
                    Status: **{state}**  
                    Risk: **{risk:.0%}**
                    """
                )
                if u.get("intel_source") == "Local memory":
                    st.info("Local memory")
                if u.get("flags"):
                    for flag in u["flags"]:
                        st.caption(f"• {flag}")
        else:
            st.info("No URLs in the body. For BEC this can be expected because the threat may rely on identity and intent rather than links.")

        for label, values in (("Domains", iocs.get("domains", [])), ("IPs in body", iocs.get("ips", [])), ("Email addresses", iocs.get("emails", [])), ("Crypto wallets", iocs.get("wallets", []))):
            if values:
                st.markdown(f"**{label}:**")
                st.write(", ".join(f"`{v}`" for v in values))

        if parsed.get("attachments"):
            st.divider()
            _sec("Attachments", tone="gold")
            _render_polished_table(pd.DataFrame([{
                "Filename": a.get("filename", "-"),
                "Bytes": a.get("size", 0),
                "Dangerous type": "yes" if a.get("risky") else "no",
            } for a in parsed["attachments"]]))

        with st.expander("How look-alike domains are detected"):
            st.markdown("Each hostname label is compared using edit distance against the internal brand list.")

    panel(_iocs, "Indicators")

# --------------------------------------------------------------------------
# 5. Correlation across all cases
# --------------------------------------------------------------------------
if active_panel == "Correlation":
    def _graph():
        _banner("CORRELATION", "Campaign Correlation & Attribution",
                "Correlate analyzed messages through shared infrastructure, indicators and identity signals",
                "ACROSS EMAILS", "plum")

        saved_bulk_cases = st.session_state.get("bulk_scan_cases")
        saved_bulk_hash = st.session_state.get("bulk_scan_cases_hash")
        current_csv_hash = csv_scan_key if (uploaded is not None and uploaded.name.lower().endswith(".csv")) else None

        if saved_bulk_cases and current_csv_hash == saved_bulk_hash:
            cases = [r for r in saved_bulk_cases if "error" not in r]
        else:
            # Same auto-index as Origin & Route: pulls in every other
            # already-prefetched Live IMAP message, not just whichever one
            # is currently loaded, without requiring "Full Report" first.
            _ensure_live_cases_from_prefetch()
            cases = [r for r in _corr_cases.values() if "error" not in r]

        current_evidence_case = dict(result)
        current_evidence_case["_evidence_hash"] = current_evidence_hash
        case_keys = {r.get("_evidence_hash") for r in cases}
        if current_evidence_hash not in case_keys:
            cases.append(current_evidence_case)

        # Full-campaign correlation (every analyzed case, no sampling) drives
        # these metrics and the shared-infrastructure table below - only the
        # picture further down gets thinned out for readability, nothing
        # here is ever left out because of that.
        G_full = correlate.build_graph(cases)
        shared = correlate.shared_indicators(G_full)

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Cases Analyzed", len(cases))
        m2.metric("Infrastructure Nodes", G_full.number_of_nodes())
        m3.metric("Correlation Links", G_full.number_of_edges())
        m4.metric("Shared Indicators", len(shared))

        possible_pairs = len(cases) * (len(cases) - 1) // 2
        shared_pair_hits = sum(len(item.get("cases", [])) * (len(item.get("cases", [])) - 1) // 2 for item in shared)
        correlation_strength = 100.0 * shared_pair_hits / possible_pairs if possible_pairs > 0 else 0.0
        m5.metric("Correlation Strength", f"{correlation_strength:.0f}%")
        st.divider()

        current_level = str(result.get("level", "unknown")).upper()
        current_score = float(result.get("score", 0))
        top_driver = result.get("verdict", {}).get("top_driver", "-")

        st.markdown(
            f'<div style="display:flex;justify-content:space-between;align-items:center;gap:20px;padding:16px 18px;border:1px solid #263244;border-radius:10px;background:rgba(15,23,42,.62);margin-bottom:20px;">'
            f'<div><div style="font-size:10px;color:#6f7e93;text-transform:uppercase;letter-spacing:1px;">Current Investigation</div>'
            f'<div style="margin-top:5px;color:#e5edf7;font-size:15px;font-weight:750;">{case_name}</div>'
            f'<div style="margin-top:4px;color:#8795a8;font-size:12px;">Primary signal: {top_driver}</div></div>'
            f'<div style="text-align:right;min-width:120px;"><div style="color:#00d2ff;font-size:11px;font-weight:800;letter-spacing:1px;">CURRENT VERDICT</div>'
            f'<div style="margin-top:3px;color:#f1f5f9;font-size:22px;font-weight:800;">{current_level}</div>'
            f'<div style="color:#8b98aa;font-size:12px;">Risk score {current_score:.0f}/100</div></div></div>',
            unsafe_allow_html=True
        )

        _sec(
            "Infrastructure Correlation Map",
            "Solid lines are shared indicators straight from the evidence. Dashed lines are AI-inferred semantic matches. Click a node to trace its connections.",
            tone="batch",
        )

        # Same switch as Origin & Route: the 10 most recent emails together,
        # or one email picked from the dropdown. (The metrics and the shared-
        # infrastructure table further down always cover every case.)
        _corr_mode = st.radio(
            "Graph view", [_MAP_MODE_ALL, _MAP_MODE_ONE], horizontal=True, key="corr_graph_mode",
        )
        if _corr_mode == _MAP_MODE_ONE:
            graph_cases = [_pick_case_for_map(cases, result, case_name, key="corr_graph_email_pick", source_rows=data)]
        else:
            graph_cases = [
                c for _, c in sorted(
                    enumerate(cases),
                    key=lambda pair: _case_recency_key(pair[1], pair[0], data),
                    reverse=True,
                )
            ][:10]

        graph_scope = hashlib.sha256(
            "|".join([_corr_mode] + sorted(
                f"{r.get('_evidence_hash') or ''}:{r.get('name') or ''}" for r in graph_cases
            )).encode()
        ).hexdigest()[:12]
        if st.session_state.get("corr_graph_scope") != graph_scope:
            st.session_state["corr_graph_scope"] = graph_scope
            st.session_state.pop("corr_graph_highlight", None)
            st.session_state["corr_graph_key_nonce"] = st.session_state.get("corr_graph_key_nonce", 0) + 1

        use_semantic = st.checkbox(
            "AI-inferred semantic links", value=False, key="corr_graph_semantic",
            help="Runs a similarity search per case shown to surface origins that resemble each other even with no shared indicator. Slower - opt in.",
        )

        highlight_node = st.session_state.get("corr_graph_highlight")
        seed = 42
        cases_to_show = len(graph_cases)
        # Cache miss (new data/settings) is the only time this actually
        # does the expensive layout work, so the spinner only shows then.
        if use_semantic:
            with st.spinner("Searching for semantically similar origins..."):
                fig, G_view, semantic_failed, sampled, shown_count, total_count = _cached_correlation_view(
                    graph_scope, graph_cases, cases_to_show, seed, use_semantic, highlight_node,
                )
        else:
            fig, G_view, semantic_failed, sampled, shown_count, total_count = _cached_correlation_view(
                graph_scope, graph_cases, cases_to_show, seed, use_semantic, highlight_node,
            )
        if semantic_failed:
            st.caption("AI semantic similarity search isn't available right now - showing indicator-based links only.")
        if _corr_mode == _MAP_MODE_ONE:
            st.caption("Showing the connections of the selected email.")
        elif len(cases) > len(graph_cases):
            st.caption(f"Showing the {len(graph_cases)} most recent of {len(cases)} analyzed emails.")

        widget_key = "corr_graph_widget_{}".format(st.session_state.get("corr_graph_key_nonce", 0))
        click_event = None
        try:
            click_event = st.plotly_chart(
                fig, width="stretch", on_select="rerun", selection_mode="points", key=widget_key,
            )
        except Exception:
            # Older Streamlit builds without click-selection support -
            # fall back to a plain, still-fully-styled, non-clickable chart.
            st.plotly_chart(fig, width="stretch", key=widget_key + "_static")

        if click_event is not None:
            try:
                sel = click_event.get("selection") if hasattr(click_event, "get") else getattr(click_event, "selection", None)
                pts = (sel.get("points") if hasattr(sel, "get") else getattr(sel, "points", None)) or []
                clicked = None
                if pts:
                    pt = pts[0]
                    clicked = pt.get("customdata") if hasattr(pt, "get") else getattr(pt, "customdata", None)
                if clicked and clicked != highlight_node and clicked in G_view:
                    st.session_state["corr_graph_highlight"] = clicked
                    st.rerun()
            except Exception:
                pass

        if highlight_node and highlight_node in G_view:
            hl_label = G_view.nodes[highlight_node].get("label", highlight_node)
            neighbors = sorted(set(G_view.predecessors(highlight_node)) | set(G_view.successors(highlight_node)))
            neighbor_labels = ", ".join(G_view.nodes[n].get("label", n) for n in neighbors) or "nothing else in this sample"
            hl1, hl2 = st.columns([5, 1])
            with hl1:
                st.caption(f" **{hl_label}** connects to: {neighbor_labels}")
            with hl2:
                if st.button("✕ Clear", key="corr_graph_clear_highlight", use_container_width=True):
                    st.session_state.pop("corr_graph_highlight", None)
                    st.session_state["corr_graph_key_nonce"] = st.session_state.get("corr_graph_key_nonce", 0) + 1
                    st.rerun()

        if shared:
            st.markdown(
                '<div style="margin-top:14px;font-size:16px;font-weight:750;color:#e5edf7;">Shared Infrastructure</div>'
                '<div style="margin-top:4px;margin-bottom:10px;font-size:12px;color:#7f8da3;">Indicators connecting multiple analyzed messages.</div>',
                unsafe_allow_html=True
            )
            shared_rows = [{"Indicator": item.get("indicator", "-"), "Type": item.get("kind", "-"), "Cases": ", ".join(item.get("cases", []))} for item in shared]
            _render_polished_table(pd.DataFrame(shared_rows))
        else:
            st.markdown(
                '<div style="margin-top:14px;padding:14px 16px;border:1px solid #263244;border-radius:9px;background:rgba(30,64,175,.10);">'
                '<div style="color:#60a5fa;font-size:13px;font-weight:700;">No shared infrastructure detected</div>'
                '<div style="margin-top:4px;color:#8b98aa;font-size:12px;line-height:1.5;">The analyzed messages currently appear independent.</div></div>',
                unsafe_allow_html=True
            )

        st.markdown(
            '<div style="margin-top:24px;font-size:16px;font-weight:750;color:#e5edf7;">Case Intelligence</div>'
            '<div style="margin-top:4px;margin-bottom:10px;font-size:12px;color:#7f8da3;">Consolidated view of the analyzed evidence set.</div>',
            unsafe_allow_html=True
        )

        rows = [{
            "Case": r.get("name", "-"),
            "Score": round(float(r.get("score", 0)), 1),
            "Verdict": str(r.get("level", "unknown")).upper(),
            "ML": "{:.0%}".format(r.get("ml", {}).get("prob", 0)),
            "SPF": r.get("headers", {}).get("spf", "-"),
            "DKIM": r.get("headers", {}).get("dkim", "-"),
            "DMARC": r.get("headers", {}).get("dmarc", "-"),
            "Origin IP": r.get("geo", {}).get("origin", {}).get("ip", "-"),
            "Country": r.get("geo", {}).get("origin", {}).get("country", "-")
        } for r in cases]
        _render_polished_table(pd.DataFrame(rows))
        st.caption("Correlation is an investigative linkage signal, not proof of common ownership.")

    panel(_graph, "Correlation")


# --------------------------------------------------------------------------
# New sidebar destinations that don't map onto an existing tab. Each reuses
# real data already sitting in tracker.py / threat_feed.py / config.py --
# nothing here is fabricated or newly computed analysis.
# --------------------------------------------------------------------------
if active_panel == "Threat History":
    def _threat_history():
        _banner("THREAT HISTORY", "Threat History", "Every message this workbench has scored", "ALL ANALYZED", "batch")
        st.caption("Every message this workbench has scored, pulled from the local threat_memory.db (attackers table).")
        try:
            conn = get_connection()
            hist_df = pd.read_sql_query(
                "SELECT date, ip, country, score, verdict FROM attackers ORDER BY date DESC LIMIT 200", conn
            )
            conn.close()
        except Exception:
            hist_df = pd.DataFrame(columns=["date", "ip", "country", "score", "verdict"])

        if hist_df.empty:
            st.info("No history yet - analyze an email to start building this record.")
            return

        m1, m2, m3 = st.columns(3)
        m1.metric("Total Logged", len(hist_df))
        m2.metric("Critical / High", int((hist_df["verdict"].isin(["CRITICAL", "HIGH"])).sum()))
        m3.metric("Average Score", f"{hist_df['score'].mean():.1f}")
        _hist_view = hist_df.rename(columns={"date": "Date", "ip": "IP", "country": "Country", "score": "Threat Score", "verdict": "Verdict"})
        _render_email_results_table(_hist_view, height=360)

    panel(_threat_history, "Threat History")

if active_panel == "URLHaus Feed":
    def _urlhaus_feed():
        _banner("THREAT INTEL", "URLHaus Threat Intelligence Feed", "Malicious-URL feed cached locally", "LIVE FEED", "intel")
        st.caption("abuse.ch URLHaus malicious-URL feed, cached locally in threat_memory.db so lookups stay offline between syncs. Auto-syncs whenever this tab is opened (throttled to once every 30 minutes) -- use the button below to force an immediate sync.")

        # Auto-sync just from visiting this panel, so you don't have to
        # remember to click the button. maybe_update_urlhaus_feed() is
        # throttled internally (via its own cache-file timestamp) to at
        # most once every FEED_UPDATE_INTERVAL, so revisiting this tab
        # repeatedly won't hammer the feed -- most visits just check the
        # timestamp and return immediately without any network call.
        with st.spinner("Checking for URLHaus feed updates..."):
            _auto_imported = threat_feed.maybe_update_urlhaus_feed()
        if _auto_imported:
            st.success(f"Auto-synced {_auto_imported} new indicators.")
        elif getattr(threat_feed, "LAST_URLHAUS_SYNC_ATTEMPTED", False) and getattr(threat_feed, "LAST_URLHAUS_ERROR", None):
            # LAST_URLHAUS_SYNC_ATTEMPTED is only True when the 30-minute
            # throttle window had actually elapsed and a real sync just
            # ran (and failed) -- this won't show on visits where the
            # sync was skipped because it's still within the window.
            st.caption(f"Last auto-sync attempt failed: {getattr(threat_feed, 'LAST_URLHAUS_ERROR', None)}")

        try:
            conn = get_connection(shared=True)
            c = conn.cursor()
            c.execute("SELECT last_sync FROM intel_sync WHERE source = 'urlhaus'")
            row = c.fetchone()
            c.execute("SELECT COUNT(*) FROM threat_intel WHERE source = 'URLhaus' OR source = 'urlhaus'")
            feed_count = c.fetchone()[0] or 0
            conn.close()
        except Exception:
            row, feed_count = None, 0

        m1, m2 = st.columns(2)
        m1.metric("Indicators Cached Locally", feed_count)
        m2.metric("Last Sync", row[0] if row and row[0] else "Never")

        if st.button("Sync URLHaus Feed Now", key="urlhaus_sync_btn"):
            with st.spinner("Fetching the recent URLHaus feed..."):
                imported = threat_feed.update_urlhaus_feed()
            if imported:
                st.success(f"Imported {imported} indicators.")
                st.rerun()
            else:
                st.warning("No indicators imported - check network access, or the feed may be temporarily unavailable.")
                _err = getattr(threat_feed, "LAST_URLHAUS_ERROR", None)
                if _err:
                    st.caption(f"Details: {_err}")

    panel(_urlhaus_feed, "URLHaus Feed")

if active_panel == "Antivirus":
    def _antivirus():
        _banner("SCANNER", "Antivirus (ClamAV)", "Scan attachments and files for known malware", "FILE SCAN", "lime")
        av_up = _clamd_up_cached()
        _av_backend = _antivirus_backend_cached()
        if av_up and _av_backend == "cloud":
            st.success("Antivirus scanning available via VirusTotal (cloud fallback) - local ClamAV daemon not reachable.")
            st.caption("Every attachment below was hashed and checked/scanned against VirusTotal's multi-engine service.")
        elif av_up:
            st.success(f" ClamAV connected - {clamd_version() or 'clamd daemon'}")
            st.caption("Every attachment below was streamed to your local clamd daemon in memory (zINSTREAM) - a real signature scan, not a heuristic.")
        else:
            st.warning(
                "Could not reach the clamd daemon at the configured host/port, and no "
                "SIH26106_VT_API_KEY is set for the cloud fallback - falling back to the "
                "app's own risky-extension check. Confirm clamd is running (or set "
                "SIH26106_CLAMD_HOST / SIH26106_CLAMD_PORT), or set SIH26106_VT_API_KEY."
            )

        cases = list(_corr_cases.values()) + [result]
        total_files, threats_found, rows = 0, 0, []
        for r in cases:
            for att in (r.get("parsed", {}) or {}).get("attachments", []) or []:
                total_files += 1
                if av_up:
                    outcome = _scan_bytes_cached(att.get("data") or b"")
                    infected = bool(outcome.get("infected"))
                    status = "INFECTED" if infected else ("Scan error" if not outcome.get("ok") else "Clean")
                    detail = outcome.get("signature") or ("-" if outcome.get("ok") else outcome.get("error"))
                else:
                    infected = bool(att.get("risky"))
                    status = "Risky extension" if infected else "Clean"
                    detail = "-"
                if infected:
                    threats_found += 1
                rows.append({
                    "Case": r.get("name", "-"),
                    "Filename": att.get("filename", "-"),
                    "Size (bytes)": att.get("size", 0),
                    "Status": status,
                    "Detail": detail,
                })

        m1, m2, m3 = st.columns(3)
        m1.metric("Files Scanned", total_files)
        m2.metric("Threats Found", threats_found)
        m3.metric("Clean", total_files - threats_found)

        if rows:
            _render_polished_table(pd.DataFrame(rows))
        else:
            st.info("No attachments found across the currently analyzed emails.")

    panel(_antivirus, "Antivirus")

if active_panel == "Settings":
    panel(_settings, "Settings")

if active_panel == "About":
    panel(_about, "About")


# --------------------------------------------------------------------------
# 6. Unified forensic report (RICH MARKDOWN DETAILED MACHINE UI)
if active_panel == "Forensic Report":
    
    # Full-width layout, same as every other module (was a centered 1:8:1
    # column strip that left wide empty margins on both sides).
    d_center = st.container()
    
    with d_center:
        st.subheader("Complete Forensic Investigation Dossier")
        st.caption("Select an email number to view the highly detailed machine forensic analysis and AI threat report together.")

        pipeline_active = (
            st.session_state.get("forensic_report_source") == "pipeline"
            and bool(st.session_state.get("pipeline_batch_items"))
        )

        if pipeline_active:
            pipeline_result = st.session_state.get("pipeline_batch_result") or {}
            report_items = list(st.session_state.get("pipeline_batch_items") or [])
        elif uploaded is not None and uploaded.name.lower().endswith(".csv") and data:
            saved_batch = st.session_state.get("qwen_batch_result") or {}
            saved_items = st.session_state.get("qwen_batch_items") or []

            if saved_batch.get("csv_hash") == csv_scan_key and saved_batch.get("count") == 20 and saved_items:
                report_items = list(saved_items)
            else:
                recent = []
                for idx, email_text in enumerate(data):
                    recent.append({"row": idx, "text": email_text, "date": get_email_date(email_text)})
                recent.sort(
                    key=lambda x: (
                        x["date"] is not None,
                        x["date"] if x["date"] is not None else datetime.min.replace(tzinfo=timezone.utc),
                        x["row"],
                    ),
                    reverse=True,
                )
                report_items = []
                for position, item in enumerate(recent[:20], start=1):
                    row_raw = item["text"].replace("\\n", "\n").encode("utf-8")
                    report_items.append({
                        "position": position,
                        "row": item["row"],
                        "date": item["date"].astimezone().isoformat() if item["date"] else "Unknown",
                        "result": analyze_bytes(row_raw, f"{uploaded.name} (Row {item['row']})"),
                        "_raw": row_raw,
                    })
        else:
            report_items = [{
                "position": 1,
                "row": None,
                "date": parsed.get("date") or "Unknown",
                "result": result,
                "_raw": raw,
            }]

        report_items = [item for item in report_items if isinstance(item.get("result"), dict) and "error" not in item.get("result", {})]

        if not report_items:
            st.warning("No analyzed evidence is available for the report.")
            st.stop()

        if pipeline_active:
            st.markdown('<div id="joint-report-anchor"></div>', unsafe_allow_html=True)
            if st.session_state.pop("_scroll_to_joint_report", False):
                # Lands the user on the report itself instead of wherever the
                # page happened to be scrolled to (e.g. this same panel's
                # per-email dossier section further down) right after a
                # fresh Full Report run. Streamlit components render in an
                # iframe, so we reach the parent document to scroll it.
                components.html(
                    """
                    <script>
                    setTimeout(function() {
                        var el = window.parent.document.getElementById('joint-report-anchor');
                        if (el) { el.scrollIntoView({behavior: 'smooth', block: 'start'}); }
                    }, 250);
                    </script>
                    """,
                    height=0,
                )
            _n_joint = pipeline_result.get('count', len(report_items))
            _banner(
                "PART 1", f"Batch Report \u2014 All {_n_joint} Emails",
                sub=f"Source: {pipeline_result.get('source', '')}",
                scope="Covers all emails", tone="batch",
            )
            st.caption("Machine analysis + AI threat analysis + semantic origin correlation, combined across the batch. Drill into any single email below, or grab everything at once.")

            _ai_res = pipeline_result.get("result", {}) or {}
            _joint_ai_text = ""
            if _ai_res.get("ok"):
                _joint_ai_text = _clean_ai_display(_ai_res.get("analysis", ""))
                _joint_ai_text = _annotate_email_labels(_joint_ai_text, report_items)
                st.markdown(
                    f"""<div class="ai-report-frame">
                        <div class="ai-report-bar">
                            <span>AI // MULTI-EMAIL CAMPAIGN ASSESSMENT</span>
                            <span class="ai-report-chip">{pipeline_result.get('count', len(report_items))} EMAILS EVALUATED</span>
                        </div>
                        <div class="ai-report-body">{_ai_markdown_to_html(_joint_ai_text)}</div>
                    </div>""",
                    unsafe_allow_html=True,
                )
            else:
                st.error(f"AI batch analysis error: {_ai_res.get('error', 'Unknown error')}")

            _semantic_lines = pipeline_result.get("semantic_summary") or []
            _semantic_all = pipeline_result.get("semantic_matches_all") or {}
            with st.expander("Semantic origin correlation", expanded=bool(_semantic_lines)):
                if _semantic_lines:
                    for _line in _semantic_lines:
                        st.markdown(f"- {_line}")
                    _sem_table_rows = []
                    for _pos, _ms in sorted(_semantic_all.items()):
                        for _r in _sem_rows(_ms):
                            _sem_table_rows.append({"Email #": _pos, **_r})
                    if _sem_table_rows:
                        _render_polished_table(pd.DataFrame(_sem_table_rows))
                else:
                    st.caption("No semantically related origins were found for this batch.")
                st.caption(_SEM_METHOD_NOTE)

            # Campaign correlation across everything analyzed so far this
            # session, computed the exact same way the dedicated Correlation
            # panel does it (shared infrastructure/indicators via correlate.py)
            # so the "Correlated" column below means the same thing it does
            # everywhere else in the app.
            _corr_case_list = [r for r in _corr_cases.values() if "error" not in r]
            try:
                _corr_shared = correlate.shared_indicators(correlate.build_graph(_corr_case_list))
            except Exception:
                _corr_shared = []
            _corr_count_by_name = {}
            for _s in _corr_shared:
                for _cn in _s.get("cases", []):
                    _corr_count_by_name[_cn] = _corr_count_by_name.get(_cn, 0) + 1

            _semantic_matches = pipeline_result.get("semantic_matches") or {}

            _machine_rows = []
            for _it in report_items:
                _r = _it["result"]
                _p = _r.get("parsed", {}) or {}
                _h = _r.get("headers", {}) or {}
                _m = _r.get("ml", {}) or {}
                _i = _r.get("iocs", {}) or {}
                _g = (_r.get("geo", {}) or {}).get("origin", {}) or {}
                _case_name = _r.get("name", "-")
                _sem = _semantic_matches.get(_it["position"])
                _corr_hits = _corr_count_by_name.get(_case_name, 0)
                _machine_rows.append({
                    "#": _it["position"],
                    "Verdict": str(_r.get("level", "UNKNOWN")).upper(),
                    "Score": round(float(_r.get("score", 0)), 1),
                    "Classifier": f"{str(_m.get('label', 'unknown')).upper()} ({float(_m.get('prob', 0)):.0%})",
                    "From": _p.get("from_addr", "Unknown"),
                    "Subject": _p.get("subject", "No Subject"),
                    "SPF": str(_h.get("spf", "-")).upper(),
                    "DKIM": str(_h.get("dkim", "-")).upper(),
                    "DMARC": str(_h.get("dmarc", "-")).upper(),
                    "Origin IP": _g.get("ip", "Unknown"),
                    "Country": _g.get("country", "Unknown"),
                    "IOCs": f"{_i.get('counts', {}).get('suspicious', 0)}/{len(_i.get('urls', []))} links",
                    "Semantic Match": (
                        f"{_sem_norm(_sem)['band']} {_sem_norm(_sem)['score']:.0%} · {_sem.get('infra_label') or _sem.get('ip') or 'related origin'}"
                        if _sem else "-"
                    ),
                    "Correlated": f"Yes ({_corr_hits})" if _corr_hits else "No",
                })
            _render_polished_table(pd.DataFrame(_machine_rows))

            _machine_table_lines = [
                "| # | Verdict | Score | Classifier | From | Subject | SPF | DKIM | DMARC | Origin IP | Country | IOCs | Semantic Match | Correlated |",
                "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
            ]
            for _row in _machine_rows:
                _machine_table_lines.append(
                    f"| {_row['#']} | {_row['Verdict']} | {_row['Score']} | {_row['Classifier']} | {_row['From']} | "
                    f"{_row['Subject']} | {_row['SPF']} | {_row['DKIM']} | {_row['DMARC']} | {_row['Origin IP']} | "
                    f"{_row['Country']} | {_row['IOCs']} | {_row['Semantic Match']} | {_row['Correlated']} |"
                )
            _machine_table_md = "\n".join(_machine_table_lines)

            _sem_md_parts = [
                "\n".join(f"- {_l}" for _l in _semantic_lines) if _semantic_lines else "_No related origins found._"
            ]
            _sem_detail_md = [f"### Email #{_pos}\n\n" + _sem_md_table(_ms) for _pos, _ms in sorted(_semantic_all.items())]
            if _sem_detail_md:
                _sem_md_parts.append("\n\n".join(_sem_detail_md))
            _sem_md_parts.append("_" + _SEM_METHOD_NOTE + "_")
            _semantic_md = "\n\n".join(_sem_md_parts)

            _joint_md = (
                f"# ALGORITHMISTIC - JOINT FORENSIC REPORT ({pipeline_result.get('count', len(report_items))} EMAILS)\n\n"
                f"**Source:** {pipeline_result.get('source', '')}\n\n"
                "## AI Campaign Summary\n\n" + (_joint_ai_text or "_AI analysis unavailable._") + "\n\n"
                "## Semantic Origin Correlation\n\n" + _semantic_md + "\n\n"
                "## Machine Analysis Summary\n\n" + _machine_table_md + "\n"
            )

            st.download_button(
                label="Download Joint Report — All Emails (.md)",
                data=_joint_md.encode("utf-8"),
                file_name=f"joint_forensic_report_{pipeline_result.get('count', len(report_items))}_emails.md",
                mime="text/markdown",
                use_container_width=True,
                type="primary",
                key="dl_joint_pipeline_report",
            )

        st.markdown(
            '<div class="part-sep"><span>' + ('END OF BATCH REPORT' if pipeline_active else 'EMAIL DEEP DIVE') + '</span></div>'
            + _banner_html(
                'PART 2' if pipeline_active else 'SINGLE EMAIL',
                'Single-Email Deep Dive',
                sub='Everything below this point is about ONE email only. Choose which one:',
                scope='One email', tone='single',
            ),
            unsafe_allow_html=True,
        )

        sel_pos = st.selectbox(
            "Select Email Number to Inspect",
            key="single_email_select",
            options=list(range(1, len(report_items) + 1)),
            format_func=lambda num: f"Email #{num} | Row {report_items[num-1].get('row', 'Single File')} | {str(report_items[num-1]['result'].get('level','UNKNOWN')).upper()}"
        )

        sel_item = report_items[sel_pos - 1]
        sel_res = sel_item["result"]
        sel_raw = sel_item.get("_raw", raw)
        sel_hash = hashlib.sha256(sel_raw).hexdigest()
        
        sel_p = sel_res.get("parsed", {})
        sel_h = sel_res.get("headers", {})
        sel_m = sel_res.get("ml", {})
        sel_i = sel_res.get("iocs", {})
        sel_g = sel_res.get("geo", {})
        sel_lvl = str(sel_res.get("level", "UNKNOWN")).upper()
        sel_score = float(sel_res.get("score", 0))

        _dh_col = _LEVEL_MARKER_COLORS.get(sel_lvl, "#8b96a5")
        st.markdown(
            '<div class="dossier-head"><div class="dh-title">Dossier: Email #' + str(sel_pos)
            + ' <span class="dh-of">of ' + str(len(report_items)) + '</span></div>'
            '<span class="dh-pill" style="color:' + _dh_col + ';border-color:' + _dh_col + '66;background:' + _dh_col + '1a;">'
            + html.escape(sel_lvl) + ' \u00b7 ' + f"{sel_score:.1f}" + '</span></div>',
            unsafe_allow_html=True,
        )

        # --- SHOW HIGHLY DETAILED MACHINE REPORT UI USING DATAFRAMES ---
        _sec("Machine Forensic Analysis", tone="single")
        st.caption("Deep technical telemetry extracted deterministically. Select the email above to populate.")
        
        with st.container(border=True):
            st.markdown("##### 1. Threat & Classification Telemetry")
            _render_polished_table(pd.DataFrame([{
                "Risk Score": f"{sel_score:.1f}/100",
                "Verdict": sel_lvl,
                "Primary Driver": sel_res.get('verdict', {}).get('top_driver', 'None'),
                "ML Phishing Probability": f"{float(sel_m.get('prob', 0)):.1%}",
                "ML Label": str(sel_m.get("label", "unknown")).upper()
            }]))

            st.markdown("##### 2. Extracted Message Content")
            st.text_area("Dossier Message Content", sel_p.get("body_text", "No body text extracted.")[:4000], height=180, disabled=True, label_visibility="collapsed", key=f"dossier_body_{sel_pos}")

            st.markdown("##### 3. Authentication & Header Intelligence")
            _render_polished_table(pd.DataFrame([{
                "SPF": str(sel_h.get('spf', 'None')).upper(),
                "DKIM": str(sel_h.get('dkim', 'None')).upper(),
                "DMARC": str(sel_h.get('dmarc', 'None')).upper(),
                "BEC Impersonation": 'DETECTED' if sel_h.get('bec', {}).get('is_bec', False) else 'NO',
                "Header Anomalies": len(sel_h.get('anomalies', []))
            }]))
            
            if sel_h.get('anomalies'):
                st.markdown("###### Header Anomalies Detail")
                anomalies_df = pd.DataFrame(sel_h['anomalies'])
                _render_polished_table(anomalies_df[['severity', 'title', 'detail']])

            st.markdown("##### 4. Origin & Network Routing")
            sel_nt = assess_network_trust(
                sel_p.get("from_addr", ""),
                sel_g.get('origin', {}).get('ip', ''),
                sel_g.get('origin', {}).get('infra_label', ''),
                sel_g.get('origin', {}).get('country', ''),
            )
            _render_polished_table(pd.DataFrame([{
                "Origin IP": sel_g.get('origin', {}).get('ip', 'Unknown'),
                "Country": sel_g.get('origin', {}).get('country', 'Unknown'),
                "Infrastructure": sel_g.get('origin', {}).get('infra_label', 'Unknown'),
                "Total Hops Traced": len(sel_g.get('hops', [])),
                "VPN Masking": f"Detected — {sel_nt.get('infra_display', sel_g.get('origin', {}).get('infra_label', 'Unknown'))}" if sel_nt.get("is_anonymizing") else "Not detected",
                "Tor Exit Confirmed": "Yes — " + "; ".join(sel_g.get('origin', {}).get('tor_exit_sources', [])) if sel_g.get('origin', {}).get('tor_exit_confirmed') else "No",
                "Network Trust": sel_nt["badge"],
            }]))
            if sel_nt["level"] != "ok" or sel_nt["is_new_sender"]:
                st.caption("Network Trust — " + " ".join(sel_nt["reasons"]))

            st.markdown("##### 5. Payload & Indicators of Compromise (IOCs)")
            _render_polished_table(pd.DataFrame([{
                "Total Links": len(sel_i.get('urls', [])),
                "Suspicious Links": sel_i.get('counts', {}).get('suspicious', 0),
                "Extracted Domains": len(sel_i.get('domains', [])),
                "Extracted Emails": len(sel_i.get('emails', []))
            }]))

            st.markdown("##### 6. Campaign Correlation & Semantic Origin Match")
            # Same methodology as the dedicated Correlation panel: shared
            # infrastructure/indicators across every case analyzed so far
            # this session, via correlate.py.
            _dossier_cases = [r for r in _corr_cases.values() if "error" not in r]
            _dossier_self = dict(sel_res)
            _dossier_self["_evidence_hash"] = sel_hash
            _dossier_keys = {r.get("_evidence_hash") for r in _dossier_cases}
            if sel_hash not in _dossier_keys:
                _dossier_cases.append(_dossier_self)
            try:
                _dossier_shared = correlate.shared_indicators(correlate.build_graph(_dossier_cases))
            except Exception:
                _dossier_shared = []
            _sel_case_name = sel_res.get("name", f"Email #{sel_pos}")
            _dossier_links = [s for s in _dossier_shared if _sel_case_name in s.get("cases", [])]
            if _dossier_links:
                _render_polished_table(pd.DataFrame([{
                    "Indicator": s.get("indicator", "-"),
                    "Type": s.get("kind", "-"),
                    "Also Seen In": ", ".join(c for c in s.get("cases", []) if c != _sel_case_name) or "-",
                } for s in _dossier_links]))
            else:
                st.caption("No shared infrastructure/indicators with other analyzed cases this session.")

            _sem_ready = _nomic_ready()
            _sem_matches = []
            _sem_origin = (sel_g or {}).get("origin", {}) or {}
            if _sem_ready:
                # Index every email in this report (plus this one) so the
                # comparison pool exists without anyone having to run the
                # Nomic panel first; already-indexed emails are skipped.
                _sem_pairs = [
                    (hashlib.sha256(_it["_raw"]).hexdigest(), (_it["result"].get("geo") or {}))
                    for _it in report_items if _it.get("_raw")
                ]
                _sem_pairs.append((sel_hash, sel_g or {}))
                _sem_index_many(_sem_pairs)
                _sem_matches = _sem_find(sel_hash, _sem_origin, top_k=5)
            if _sem_matches:
                st.markdown(_sem_headline(_sem_matches))
                _render_polished_table(pd.DataFrame(_sem_rows(_sem_matches)))
            elif _sem_ready:
                st.caption(_sem_none_text())
            else:
                st.caption("Semantic origin comparison unavailable — Ollama / nomic-embed-text isn't reachable right now.")
            st.caption(_SEM_METHOD_NOTE)

            st.caption(f"SHA-256 Cryptographic Evidence Hash: `{sel_hash}`")

        # --- BUILD RICH MARKDOWN STRING WITH TABLES ---
        m_urls_list = [f"| `{u.get('url')}` | {float(u.get('risk', 0)):.0%} |" for u in sel_i.get('urls', [])]
        m_urls = "| Extracted URL | Risk Score |\n|---|---|\n" + "\n".join(m_urls_list) if m_urls_list else "None detected"
        
        m_anoms_list = [f"| **{a.get('severity', '').upper()}** | {a.get('title')} | {a.get('detail')} |" for a in sel_h.get('anomalies', [])]
        m_anoms = "| Severity | Title | Detail |\n|---|---|---|\n" + "\n".join(m_anoms_list) if m_anoms_list else "None"

        m_corr_list = [
            f"| `{s.get('indicator', '-')}` | {s.get('kind', '-')} | {', '.join(c for c in s.get('cases', []) if c != _sel_case_name) or '-'} |"
            for s in _dossier_links
        ]
        m_corr = "| Indicator | Type | Also Seen In |\n|---|---|---|\n" + "\n".join(m_corr_list) if m_corr_list else "No shared infrastructure/indicators with other analyzed cases this session."

        if _sem_matches:
            m_sem = (
                _sem_headline(_sem_matches) + "\n\n" + _sem_md_table(_sem_matches)
                + "\n\n**Origin profile analysed:**\n\n```text\n" + _sem_describe_origin(sel_g or {}) + "\n```\n\n_"
                + _SEM_METHOD_NOTE + "_"
            )
        elif _sem_ready:
            m_sem = _sem_none_text() + "\n\n_" + _SEM_METHOD_NOTE + "_"
        else:
            m_sem = "Semantic origin comparison was unavailable when this report was generated (Ollama / nomic-embed-text not reachable)."

        machine_md = f"""# ALGORITHMISTIC - DIGITAL FORENSIC EVIDENCE REPORT

## 1. EVIDENCE IDENTIFIERS
| Property | Value |
|---|---|
| **Email Number** | #{sel_pos} |
| **Source Row** | {sel_item.get('row', 'Single File')} |
| **Evidence SHA-256** | `{sel_hash}` |
| **Date** | {sel_item.get('date')} |

## 2. THREAT CLASSIFICATION
| Property | Value |
|---|---|
| **Verdict** | {sel_lvl} |
| **Threat Score** | {sel_score:.1f}/100 |
| **Primary Driver** | {sel_res.get('verdict', {}).get('top_driver', 'None')} |
| **ML Phishing Prob** | {float(sel_m.get('prob', 0)):.1%} |

## 3. MESSAGE HEADERS & CONTENT
| Property | Value |
|---|---|
| **From** | `{sel_p.get('from_addr')}` |
| **Reply-To** | `{str(sel_p.get('reply_to') or 'None')}` |
| **Subject** | `{str(sel_p.get('subject') or 'No Subject')}` |
| **SPF** | {str(sel_h.get('spf', 'None')).upper()} |
| **DKIM** | {str(sel_h.get('dkim', 'None')).upper()} |
| **DMARC** | {str(sel_h.get('dmarc', 'None')).upper()} |
| **Origin IP** | `{sel_g.get('origin', {}).get('ip', 'Unknown')}` |
| **Origin Country** | {sel_g.get('origin', {}).get('country', 'Unknown')} |
| **Infrastructure** | {sel_g.get('origin', {}).get('infra_label', 'Unknown')} |
| **VPN Masking** | {f"Detected — {sel_nt.get('infra_display', sel_g.get('origin', {}).get('infra_label', 'Unknown'))}" if sel_nt.get('is_anonymizing') else "Not detected"} |
| **Tor Exit Confirmed** | {("Yes — " + "; ".join(sel_g.get('origin', {}).get('tor_exit_sources', []))) if sel_g.get('origin', {}).get('tor_exit_confirmed') else "No"} |
| **Network Trust** | {sel_nt['badge']} |
| **Network Trust Notes** | {'; '.join(sel_nt['reasons'])} |

### Extracted Body Snippet:
```text
{str(sel_p.get('body_text', 'No body text extracted'))[:1000]}
```

## 4. HEADER ANOMALIES
{m_anoms}

## 5. INDICATORS OF COMPROMISE (URLs)
{m_urls}

## 6. CAMPAIGN CORRELATION & SEMANTIC ORIGIN MATCH
### Shared infrastructure/indicators
{m_corr}

### Semantically similar origins
{m_sem}
"""

        # --------------------------------------------------------------------
        # AI THREAT REPORT FOR THIS SPECIFIC EMAIL (generated on demand,
        # cached per evidence hash so it survives navigation/reruns).
        # --------------------------------------------------------------------
        st.divider()
        _sec("AI Threat Report", tone="ai")
        st.caption("Evidence-bound local Qwen assessment for this specific email. Generate it here if it hasn't run yet.")

        single_reports = st.session_state.setdefault("single_ai_reports", {})
        saved_ai_for_email = single_reports.get(sel_hash)

        if saved_ai_for_email is None:
            if st.button("Generate AI Report For This Email", use_container_width=True, key=f"gen_ai_dossier_{sel_pos}"):
                ai_dossier_progress = st.progress(0, text="Qwen AI analysis: 0%")

                def _ai_dossier_progress(percent, message):
                    ai_dossier_progress.progress(
                        max(0.0, min(1.0, percent / 100.0)),
                        text=f"Qwen AI analysis: {int(percent)}% · {message}",
                    )

                saved_ai_for_email = analyze_with_ollama(
                    sel_res, timeout=600, progress_callback=_ai_dossier_progress, network_trust=sel_nt
                )
                single_reports[sel_hash] = saved_ai_for_email
                st.session_state["single_ai_reports"] = single_reports
                st.rerun()
            else:
                st.info("No AI report has been generated for this email yet.")

        ai_markdown_body = ""
        if saved_ai_for_email is not None:
            if saved_ai_for_email.get("ok"):
                cleaned_ai = _clean_ai_display(saved_ai_for_email.get("analysis", ""))
                ai_markdown_body = cleaned_ai
                st.markdown(
                    f"""<div class="ai-report-frame">
                        <div class="ai-report-bar">
                            <span>QWEN // SINGLE-EMAIL THREAT ASSESSMENT</span>
                            <span class="ai-report-chip">EMAIL #{sel_pos}</span>
                        </div>
                        <div class="ai-report-body">{_ai_markdown_to_html(cleaned_ai)}</div>
                    </div>""",
                    unsafe_allow_html=True,
                )
            else:
                st.error(f"AI Analysis Error: {saved_ai_for_email.get('error', 'Unknown Error')}")

        ai_md = f"""# ALGORITHMISTIC - AI THREAT ASSESSMENT

**Email Number:** #{sel_pos}
**Evidence SHA-256:** `{sel_hash}`

## AI Assessment

{ai_markdown_body if ai_markdown_body else "_No AI report has been generated for this email yet._"}
"""

        combined_md = machine_md + "\n\n---\n\n" + ai_md

        # --------------------------------------------------------------------
        # THREE DOWNLOAD OPTIONS: AI only, Machine only, Combined
        # --------------------------------------------------------------------
        st.divider()
        _sec("Download Forensic Report", tone="single")
        st.caption("Choose which report to export for Email #{}.".format(sel_pos))

        # BUG FIX: "Combined Report" used to have no `disabled` guard, so
        # clicking it before generating the AI section silently downloaded a
        # file that was the machine report plus a placeholder line saying no
        # AI report existed yet -- indistinguishable, in practice, from just
        # downloading the machine-only report. It now matches the "AI Result
        # Only" button's existing behaviour: disabled with a clear reason
        # until there's real AI content to combine, so a "Combined Report"
        # download is guaranteed to actually contain both sections.
        if not ai_markdown_body:
            st.caption("Generate the AI Threat Report above first to unlock a true combined download.")

        with st.container(key="forensic_download_row"):
            dl1, dl2, dl3 = st.columns(3)
            with dl1:
                st.download_button(
                    label="AI Result Only (.md)",
                    data=ai_md.encode("utf-8"),
                    file_name=f"ai_report_email_{sel_pos}.md",
                    mime="text/markdown",
                    use_container_width=True,
                    disabled=not ai_markdown_body,
                    key=f"dl_ai_only_{sel_pos}",
                    help="Requires an AI report to be generated for this email first." if not ai_markdown_body else None,
                )
            with dl2:
                st.download_button(
                    label="Machine Result Only (.md)",
                    data=machine_md.encode("utf-8"),
                    file_name=f"machine_report_email_{sel_pos}.md",
                    mime="text/markdown",
                    use_container_width=True,
                    key=f"dl_machine_only_{sel_pos}",
                )
            with dl3:
                st.download_button(
                    label="Combined Report (.md)",
                    data=combined_md.encode("utf-8"),
                    file_name=f"combined_forensic_report_email_{sel_pos}.md",
                    mime="text/markdown",
                    use_container_width=True,
                    disabled=not ai_markdown_body,
                    key=f"dl_combined_{sel_pos}",
                    help="Requires an AI report to be generated for this email first — otherwise this would just be the machine report again." if not ai_markdown_body else None,
                )