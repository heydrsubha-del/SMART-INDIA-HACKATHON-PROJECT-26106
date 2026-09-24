"""SIH26106 - AI-Powered Email Threat Detection, GeoLocation & Forensic
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
import html
import re
import textwrap

import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

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
from nomic_embed import nomic_available, describe_origin, embed_text, save_origin_embedding, find_similar_origins
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
    None (never raises) if no cache file exists yet or it's unreadable."""
    try:
        with open(_GOOGLE_EMAIL_CACHE_PATH, "r", encoding="utf-8") as f:
            return (json.load(f) or {}).get("email") or None
    except Exception:
        return None


def _save_cached_google_email(email: str):
    """Best-effort write; failing to persist just means we'll re-resolve
    the email next time instead of breaking anything."""
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

from tracker import (
    init_db,
    log_threat,
    check_history,
    add_feedback,
    get_feedback_history_count,
    get_connection,
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
from antivirus_scan import clamd_available, clamd_version, scan_bytes

@st.cache_data(ttl=20, show_spinner=False)
def _clamd_up_cached():
    """clamd_available() opens a real TCP socket -- st.tabs renders every
    tab's body on every rerun (only visibility is toggled client-side), so
    without this the antivirus tab would re-probe clamd on every single
    interaction anywhere in the app, even the map tab. A 20s cache keeps the
    same live check without hammering the daemon."""
    return clamd_available(timeout=2)

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
    """nomic_available() pings Ollama, so cache the answer briefly -- the
    Forensic Report reruns on every widget click."""
    now = time.time()
    cached = st.session_state.get("_nomic_ready_cache")
    if cached and now - cached[0] < 30:
        return cached[1]
    try:
        ok = bool(nomic_available())
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
    page_title="AI-Powered Email Threat Detection, GeoLocation & Forensic | SIH26106",
    page_icon="\U0001F6E1",
    layout="wide",
    initial_sidebar_state="expanded"
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
if GOOGLE_OAUTH_READY:
    _oauth_code = st.query_params.get("code")
    _oauth_state = st.query_params.get("state")
    _oauth_error = st.query_params.get("error")
    if _oauth_error:
        st.query_params.clear()
        st.session_state["_google_oauth_error"] = _oauth_error
    elif _oauth_code:
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
        --bg: #05070a;
        --panel: #0d121c;
        --panel-2: #111826;
        --panel-3: #0a0e15;
        --line: #1c2431;
        --line-strong: #2a3444;
        --text: #eef2f8;
        --muted: #93a0b3;
        --cyan: #5470ff;
        /* Secondary accent family -- gives AI/assistant surfaces (the Qwen
           dossiers, the AI console, the copilot panel) their own color
           identity instead of reusing the primary action blue everywhere. */
        --violet: #8c7bf0;
        /* Tertiary accent family -- reserved for brand/navigation chrome
           (sidebar, masthead) so the app reads as deliberately multi-toned
           rather than one blue skin repeated on every surface. */
        --teal: #22c7ac;
        --green: #2fce87;
        --amber: #f2a93c;
        --red: #ef5a5a;
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
        --glow-violet: 0 0 0 1px rgba(84,112,255,.30), 0 6px 16px rgba(0,0,0,.24);
        /* Signature brand accent: one flat, professional blue for every
           primary action / active state, instead of a two-hue gradient --
           gives the app a single deliberate identity color. */
        --brand-gradient: linear-gradient(90deg,#5470ff,#5470ff);
        /* Action-button tokens -- the whole button family (primary = teal
           action key, secondary = graphite key) is tinted from here, so the
           look can be re-colored in one place without touching any rule. */
        --act-1-top:#2bd5b4; --act-1-bot:#17a58b; --act-1-border:rgba(94,236,210,.55); --act-1-text:#03110e;
        --act-1-top-hover:#3ae0c0; --act-1-bot-hover:#1db89c; --act-1-border-hover:rgba(140,248,226,.85);
        --act-2-top:#161d2a; --act-2-bot:#0e141e; --act-2-border:#2a3444; --act-2-text:#dbe4ef;
        --act-2-top-hover:#1b2432; --act-2-bot-hover:#111a26; --act-2-border-hover:rgba(34,199,172,.65);
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
        box-shadow: 0 0 0 3px rgba(84,112,255,.14) !important;
        outline: none !important;
    }
    .stApp input:invalid, .stApp select:invalid, .stApp textarea:invalid,
    .stApp input:required:invalid {
        box-shadow: none !important;
    }

    /* Quality-floor: a visible, on-brand focus ring everywhere, so keyboard
       navigation is never invisible -- this replaces the browser default
       rather than removing it. */
    *:focus-visible {outline:2px solid var(--cyan) !important; outline-offset:2px !important;}

    /* Slim, on-theme scrollbars instead of the default OS chrome. */
    ::-webkit-scrollbar {width:10px; height:10px;}
    ::-webkit-scrollbar-track {background:#081420;}
    ::-webkit-scrollbar-thumb {background:#1f3f58; border-radius:8px; border:2px solid #081420;}
    ::-webkit-scrollbar-thumb:hover {background:#2c5877;}
    * {scrollbar-color:#1f3f58 #081420; scrollbar-width:thin;}


    #MainMenu, footer {display:none !important;}
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
        box-shadow:0 0 0 1px rgba(84,112,255,.25), 0 8px 22px rgba(0,0,0,.4) !important;
        transition:transform .15s var(--ease), box-shadow .15s var(--ease) !important;
    }
    [data-testid="collapsedControl"]:hover {
        transform:scale(1.04) !important;
        box-shadow:0 0 0 1px rgba(84,112,255,.4), 0 10px 26px rgba(0,0,0,.45) !important;
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
            radial-gradient(circle at 12% -8%, rgba(84,112,255,.05), transparent 28%),
            radial-gradient(circle at 92% 0%, rgba(19,139,181,.045), transparent 26%),
            radial-gradient(circle at 55% 105%, rgba(84,112,255,.025), transparent 32%),
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
    .stage-card-success {border-left-color:var(--green) !important;}
    .stage-card-success:hover {border-color:#22453a !important;}
    .stage-label {
        position:relative; z-index:1;
        display:inline-flex !important; align-items:center !important;
        color:var(--cyan) !important; font-size:10px !important; font-weight:800 !important;
        letter-spacing:1.5px !important; text-transform:uppercase !important;
        background:rgba(84,112,255,.08) !important; border:1px solid rgba(84,112,255,.22) !important;
        border-radius:20px !important; padding:3px 10px !important;
    }
    .stage-card-success .stage-label {color:var(--green) !important; background:rgba(47,206,135,.10) !important; border-color:rgba(47,206,135,.28) !important;}
    .stage-title {position:relative; z-index:1; color:#ebf6ff !important; font-size:16px !important; font-weight:750 !important; margin-top:7px !important;}
    .stage-help {position:relative; z-index:1; color:#8299b2 !important; font-size:12px !important; margin-top:3px !important; line-height:1.45 !important;}

    /* ------------------------------------------------------------------
       BUTTON SYSTEM -- one restrained, enterprise-grade look for every
       action button in the workspace (st.button, download buttons and
       form-submit buttons).
         * Primary   : solid teal action key with dark ink text. Teal is the
                       app's existing brand-chrome color, so the CTA reads as
                       part of the product instead of a stock blue fill.
         * Secondary : graphite key from the same family as the panels --
                       hairline border, teal edge on hover.
       Colors come from the --act-* tokens in :root.
       ------------------------------------------------------------------ */
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) > button {
        min-height:44px !important;
        border-radius:10px !important;
        background:linear-gradient(180deg,var(--act-2-top) 0%,var(--act-2-bot) 100%) !important;
        color:var(--act-2-text) !important;
        border:1px solid var(--act-2-border) !important;
        font-weight:700 !important;
        box-shadow:0 1px 2px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.045) !important;
        transition:background .18s var(--ease), border-color .18s var(--ease), box-shadow .18s var(--ease), color .18s var(--ease), transform .1s var(--ease) !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) > button:hover {
        border-color:var(--act-2-border-hover) !important;
        background:linear-gradient(180deg,var(--act-2-top-hover) 0%,var(--act-2-bot-hover) 100%) !important;
        color:#ffffff !important;
        box-shadow:0 0 0 1px rgba(34,199,172,.14), 0 8px 20px rgba(0,0,0,.32), inset 0 1px 0 rgba(255,255,255,.06) !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) > button:active {transform:translateY(1px) !important; transition-duration:.08s !important;}
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) > button:focus-visible {outline:2px solid rgba(34,199,172,.55) !important; outline-offset:2px !important;}
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) > button[kind^="primary"] {
        background:linear-gradient(180deg,var(--act-1-top) 0%,var(--act-1-bot) 100%) !important;
        color:var(--act-1-text) !important;
        border:1px solid var(--act-1-border) !important;
        box-shadow:0 1px 2px rgba(0,0,0,.4), 0 6px 18px rgba(34,199,172,.14), inset 0 1px 0 rgba(255,255,255,.22) !important;
    }
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) > button[kind^="primary"]:hover {
        background:linear-gradient(180deg,var(--act-1-top-hover) 0%,var(--act-1-bot-hover) 100%) !important;
        border-color:var(--act-1-border-hover) !important;
        color:var(--act-1-text) !important;
        box-shadow:0 0 0 1px rgba(34,199,172,.30), 0 10px 26px rgba(34,199,172,.22), inset 0 1px 0 rgba(255,255,255,.28) !important;
    }
    /* Disabled keys: dimmed and inert, so they never look clickable. */
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) > button:disabled {opacity:.4 !important; filter:saturate(.55) !important; pointer-events:none !important; box-shadow:none !important;}

    /* Google-branded "Sign in with Google" link-button. Plain HTML/CSS
       (not a Streamlit widget) so it renders identically across Streamlit
       versions -- it needs to be a real <a> so clicking it navigates the
       browser straight to Google, rather than a server-side st.button. */
    .google-signin-btn {
        display:flex !important;
        align-items:center !important;
        justify-content:center !important;
        width:100% !important;
        min-height:42px !important;
        box-sizing:border-box !important;
        background:#ffffff !important;
        color:#3c4043 !important;
        border:1px solid #dadce0 !important;
        border-radius:8px !important;
        font-family:Inter,"Segoe UI",Arial,sans-serif !important;
        font-weight:600 !important;
        font-size:14px !important;
        text-decoration:none !important;
        box-shadow:0 1px 3px rgba(0,0,0,.2) !important;
        padding:10px 16px 10px 44px !important;
        background-repeat:no-repeat !important;
        background-position:14px center !important;
        background-size:20px 20px !important;
        background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cpath fill='%23FFC107' d='M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z'/%3E%3Cpath fill='%23FF3D00' d='M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4c-7.682 0-14.344 4.337-17.694 10.691z'/%3E%3Cpath fill='%234CAF50' d='M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238C29.211 35.091 26.715 36 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z'/%3E%3Cpath fill='%231976D2' d='M43.611 20.083H42V20H24v8h11.303c-.792 2.237-2.231 4.166-4.087 5.571l6.19 5.238C40.463 35.751 44 30.5 44 24c0-1.341-.138-2.65-.389-3.917z'/%3E%3C/svg%3E") !important;
        transition:box-shadow .15s ease, border-color .15s ease !important;
    }
    .google-signin-btn:hover {
        box-shadow:0 2px 8px rgba(0,0,0,.3) !important;
        border-color:#c6c9cc !important;
        color:#3c4043 !important;
    }

    .stTextInput input, .stNumberInput input, textarea {
        background:linear-gradient(180deg,#0d2035,#091729) !important;
        color:#eaf2fa !important;
        border:1px solid #2f5478 !important;
        border-radius:10px !important;
        box-shadow:inset 0 1px 3px rgba(0,0,0,.35) !important;
        transition:border-color .15s var(--ease), box-shadow .15s var(--ease) !important;
    }
    .stTextInput input:hover, .stNumberInput input:hover, textarea:hover {border-color:#3d6790 !important;}
    .stTextInput input:focus, .stNumberInput input:focus, textarea:focus {
        border-color:var(--cyan) !important;
        box-shadow:0 0 0 3px rgba(84,112,255,.14), inset 0 1px 3px rgba(0,0,0,.3) !important;
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
        border:1px solid #2f5478 !important;
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
        border:1px solid #2f5478 !important;
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
    .stMultiSelect [data-baseweb="select"]:hover > div {border-color:#3d6790 !important;}
    .stSelectbox [data-baseweb="select"]:focus-within > div,
    .stMultiSelect [data-baseweb="select"]:focus-within > div {
        border-color:var(--cyan) !important;
        box-shadow:0 0 0 3px rgba(84,112,255,.14), inset 0 1px 3px rgba(0,0,0,.3) !important;
    }
    .stSelectbox svg, .stMultiSelect svg {color:var(--cyan) !important;}
    div[data-baseweb="popover"] ul[role="listbox"] {
        background:#0d1a2b !important;
        border:1px solid #2f5478 !important;
        border-radius:10px !important;
        box-shadow:0 14px 30px rgba(0,0,0,.4) !important;
        padding:4px !important;
    }
    div[data-baseweb="popover"] li[role="option"] {color:#dfeaf4 !important; border-radius:7px !important;}
    div[data-baseweb="popover"] li[role="option"]:hover,
    div[data-baseweb="popover"] li[aria-selected="true"] {background:rgba(84,112,255,.14) !important; color:#ffffff !important;}
    /* Widget labels ("Mail provider", "IMAP server", "Port"...) previously
       rode on Streamlit's plain default text -- a touch brighter, a firm
       weight and tighter line-height reads as deliberate field labelling
       instead of leftover placeholder-grey. */
    [data-testid="stWidgetLabel"] p {
        color:#a9c1d8 !important; font-size:12.5px !important; font-weight:650 !important;
        letter-spacing:.15px !important; margin-bottom:2px !important;
    }
    .stRadio > div {background:#081522 !important; border:1px solid #1b344e !important; border-radius:11px !important; padding:5px !important; gap:4px !important;}
    /* Every st.radio in this app renders horizontal=True and is used as a
       tab/segmented control (main workflow nav, acquisition mode, severity
       filter...) rather than a traditional single-column choice list, so
       each option gets full button-like affordances: pointer cursor, its
       own pill hit-area, and a hover/press/select animation chain that
       shares the same easing as .stButton so switching "tabs" feels like
       the same physical material as the rest of the UI. */
    .stRadio label {
        color:#c9d8e7 !important;
        cursor:pointer !important;
        border-radius:9px !important;
        border:1px solid transparent !important;
        padding:7px 6px !important;
        transition:background .22s var(--ease), border-color .22s var(--ease),
                   box-shadow .22s var(--ease), transform .16s var(--ease), color .18s var(--ease) !important;
    }
    .stRadio label:hover {
        background:rgba(84,112,255,.08) !important;
        border-color:#20415e !important;
        transform:translateY(-1px) !important;
    }
    .stRadio label:active {
        transform:translateY(0) scale(.97) !important;
        transition-duration:.08s !important;
    }
    /* Segmented-control feel: the checked pill gets a filled gradient
       (the same one .stButton's primary action uses, for one consistent
       "button" language across the app) instead of just a colored dot, so
       the active workflow step reads at a glance and selecting it feels
       like pressing a real button rather than flipping a bare radio. */
    .stRadio label[data-baseweb="radio"]:has(input:checked),
    .stRadio div[role="radiogroup"] label:has(input:checked) {
        background:var(--brand-gradient) !important;
        border-color:#8b7bd8 !important;
        box-shadow:var(--glow-violet) !important;
        transform:translateY(-1px) !important;
    }
    .stRadio label:has(input:checked):hover {transform:translateY(-1px) !important;}
    .stRadio label:has(input:checked):active {transform:translateY(-1px) scale(.97) !important;}
    .stRadio label:has(input:checked) div:first-child {border-color:#eaf8ff !important;}
    .stRadio label:has(input:checked) p {color:#ffffff !important; font-weight:800 !important;}
    .stFileUploader {background:#091625 !important; border:1px dashed #315878 !important; border-radius:12px !important;}
    .stFileUploader section {background:transparent !important;}

    div[data-testid="stMetric"] {
        background:linear-gradient(180deg,#102238,#0c1b2d) !important;
        border:1px solid #213c59 !important;
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
        border:1px solid #1d3651 !important;
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
    [data-testid="stExpander"] {background:#0b1828 !important; border:1px solid #1e3954 !important; border-radius:var(--r-md) !important; transition:border-color .15s var(--ease) !important;}
    [data-testid="stExpander"]:hover {border-color:#2c5877 !important;}
    .stTabs [data-baseweb="tab-list"] {gap:5px !important; background:#071321 !important; border:1px solid #18324b !important; padding:5px !important; border-radius:var(--r-md) !important;}
    .stTabs [data-baseweb="tab"] {
        color:#8197af !important; border-radius:8px !important; padding:9px 15px !important;
        cursor:pointer !important;
        transition:background .2s var(--ease), color .18s var(--ease),
                   box-shadow .2s var(--ease), transform .16s var(--ease) !important;
    }
    .stTabs [data-baseweb="tab"]:hover {color:#c9e4f4 !important; background:rgba(84,112,255,.08) !important; transform:translateY(-1px) !important;}
    .stTabs [data-baseweb="tab"]:active {transform:translateY(0) scale(.97) !important; transition-duration:.08s !important;}
    .stTabs [aria-selected="true"] {
        color:#eff9ff !important;
        background:linear-gradient(90deg, #14304a, #102b43) !important;
        box-shadow:inset 0 0 0 1px rgba(84,112,255,.28), 0 6px 14px rgba(0,0,0,.22) !important;
        transform:translateY(-1px) !important;
    }
    /* A thin accent underline that fades/slides in on the selected tab
       instead of just appearing -- present (invisible) on every tab so
       switching never shifts row height, only the active one lights up. */
    .stTabs [data-baseweb="tab"]::after {
        content:""; display:block; height:2px; margin-top:7px; border-radius:2px;
        background:linear-gradient(90deg, transparent, var(--cyan), var(--violet), transparent);
        opacity:0; transform:scaleX(.4);
        transition:opacity .25s var(--ease), transform .25s var(--ease);
    }
    .stTabs [aria-selected="true"]::after {opacity:1; transform:scaleX(1);}
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
        border-bottom:2px solid rgba(84,112,255,.35);
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
    table.polished-table tbody tr:hover {background:rgba(84,112,255,.10);}
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
            radial-gradient(circle at 15% 0%, rgba(84,112,255,.035), transparent 26%),
            radial-gradient(circle at 100% 15%, rgba(84,112,255,.03), transparent 30%),
            var(--bg) !important;
        background-size: auto !important;
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
        height:2.75rem !important;
        min-height:2.75rem !important;
        padding-top:0 !important;
        padding-bottom:0 !important;
    }
    [data-testid="stSidebarUserContent"] {
        padding-top:0.5rem !important;
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
    :is(.stButton, .stDownloadButton, .stFormSubmitButton) > button {border-radius:var(--r-md) !important; text-transform:uppercase; letter-spacing:.6px;}
    .stTabs [data-baseweb="tab-list"] {border-radius:var(--r-md) !important;}
    .stTabs [data-baseweb="tab"] {border-radius:var(--r-sm) !important; text-transform:uppercase; font-size:10px !important; letter-spacing:.6px;}

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
        background:rgba(34,199,172,.05) !important;
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
        background:rgba(34,199,172,.12);
        border:1px solid rgba(34,199,172,.32);
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
        box-shadow:0 0 0 3px rgba(84,112,255,.14) !important;
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
        position:relative; flex:1 1 300px; display:flex; align-items:center; gap:16px;
        background:var(--panel); border:1px solid var(--line); border-radius:var(--r-lg);
        padding:19px 20px; box-shadow:none;
        transition:border-color .18s var(--ease), background .18s var(--ease), box-shadow .18s var(--ease), transform .18s var(--ease);
    }
    .mode-card-icon {
        flex:0 0 44px; width:44px; height:44px; border-radius:var(--r-md);
        display:flex; align-items:center; justify-content:center; font-size:19px;
    }
    .mode-card-icon-blue {
        background:rgba(84,112,255,.14); border:1px solid rgba(84,112,255,.34); color:#93a7ff;
    }
    .mode-card-icon-neutral {
        background:rgba(34,199,172,.14); border:1px solid rgba(34,199,172,.34); color:#7fd8c4;
    }
    .mode-card-title {color:#eef5ff; font-size:14.5px; font-weight:750; line-height:1.3;}
    .mode-card-sub {color:#8299b2; font-size:12px; margin-top:2px; line-height:1.4;}
    .mode-card:hover {border-color:var(--line-strong); background:var(--panel-2); transform:translateY(-1px);}
    @keyframes modeCardSelect {
        0%   {transform:scale(.97); box-shadow:0 0 0 0 rgba(84,112,255,.0);}
        55%  {transform:scale(1.012);}
        100% {transform:scale(1); box-shadow:0 0 0 1px rgba(84,112,255,.34);}
    }
    @keyframes modeCardIconPop {
        0%   {transform:scale(.75) rotate(-6deg);}
        60%  {transform:scale(1.1) rotate(3deg);}
        100% {transform:scale(1) rotate(0deg);}
    }
    .mode-card-active {
        border-color:var(--cyan) !important; background:var(--panel-2) !important;
        box-shadow:0 0 0 1px rgba(84,112,255,.34) !important;
        animation:modeCardSelect .4s var(--ease);
    }
    .mode-card-active .mode-card-icon {animation:modeCardIconPop .45s var(--ease);}
    @media (prefers-reduced-motion: reduce) {
        .mode-card-active, .mode-card-active .mode-card-icon {animation:none !important;}
    }
    .st-key-acq_pick_live, .st-key-acq_pick_upload {
        margin-top:-78px !important; position:relative !important; z-index:5 !important;
    }
    .st-key-acq_pick_live button, .st-key-acq_pick_upload button {
        height:78px !important; width:100% !important; min-height:0 !important;
        background:transparent !important; border:none !important; box-shadow:none !important;
        color:transparent !important; cursor:pointer !important; outline:none !important;
    }
    /* The generic .stButton > button:hover / :active rules elsewhere in this
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
        box-shadow:inset 0 0 18px rgba(84,112,255,.03) !important;
    }
    .feedback-icon { font-weight:900 !important; margin-right:9px !important; }
    .feedback-cursor { animation:feedbackBlink .8s steps(1) infinite; }
    @keyframes feedbackBlink { 0%,49%{opacity:1} 50%,100%{opacity:0} }

    .ai-console-head {
        position:relative; overflow:hidden; margin:6px 0 14px 0; padding:18px 20px 16px;
        border:1px solid #3d3168; border-left:3px solid var(--violet); border-radius:var(--r-lg);
        background:linear-gradient(180deg,#101f33 0%,#0c1a2a 100%);
        box-shadow:inset 0 0 26px rgba(84,112,255,.05),0 14px 34px rgba(0,0,0,.20);
    }
    .ai-console-status {font:800 9px/1.3 monospace; letter-spacing:1.4px; color:#9584b8; text-transform:uppercase;}
    .ai-pulse {display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 12px rgba(47,206,135,.8);margin-right:7px;}
    .ai-console-title {margin-top:7px;color:#f1fbff;font-size:27px;font-weight:850;letter-spacing:.3px;}
    .ai-console-sub {margin-top:5px;color:#8f83ac;font:800 10px/1.5 monospace;letter-spacing:1px;}
    .ai-console-track {margin-top:13px;height:2px;background:#241c3c;position:relative;overflow:hidden;}
    .ai-console-track span {display:block;width:36%;height:100%;background:linear-gradient(90deg,transparent,var(--violet),transparent);animation:aiSweep 2.8s linear infinite;}
    @keyframes aiSweep {0%{transform:translateX(-120%)}100%{transform:translateX(330%)}}
    .ai-report-frame {border:1px solid #3d3168;border-radius:var(--r-lg);overflow:hidden;background:linear-gradient(180deg,#0f0c1e,#0a0816);box-shadow:inset 0 0 30px rgba(84,112,255,.05),0 12px 28px rgba(0,0,0,.2);}
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
    .st-key-topnav::after {
        content:""; position:absolute; left:12px; right:12px; bottom:0; height:2px;
        background:linear-gradient(90deg,#5470ff 0%,rgba(84,112,255,.12) 60%,transparent 100%);
        border-radius:2px; pointer-events:none;
    }
    .st-key-topnav .stRadio > div {
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
        scrollbar-color:rgba(84,112,255,.4) transparent !important;
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
        background:rgba(84,112,255,.4) !important; border-radius:6px !important;
        transition:background .25s ease !important;
    }
    .st-key-topnav .stRadio > div::-webkit-scrollbar-thumb:hover {background:rgba(84,112,255,.7) !important;}

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

    /* Active tab: one flat, confident blue fill -- no gradient, no lift,
       no glow ring -- so the current section reads as a solid selected
       pill (clean product tab-bar) rather than a lit-up SCADA control. */
    .st-key-topnav .stRadio label:has(input:checked) {
        background:#5470ff !important;
        border-color:#5470ff !important;
        box-shadow:0 2px 8px rgba(84,112,255,.35) !important;
    }
    .st-key-topnav .stRadio label:has(input:checked) p {
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
        display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:14px;
        background:linear-gradient(180deg,#101f33 0%,#0c1a2a 100%);
        border:1px solid #24506a; border-radius:var(--r-lg);
        padding:14px 20px; margin-bottom:12px;
        box-shadow:0 10px 26px rgba(0,0,0,.25);
    }
    .topbar-brand {display:flex; align-items:center; gap:12px;}
    .topbar-logo {font-size:30px;}
    .topbar-kicker {font-size:10px; font-weight:800; letter-spacing:1.4px; color:var(--teal); text-transform:uppercase; margin-bottom:3px;}
    .topbar-title {font-size:23px; font-weight:900; letter-spacing:.2px; color:#f2f8ff; line-height:1.25;}
    .topbar-subtitle {font-size:11.5px; color:#93abc3; line-height:1.5; margin-top:4px;}
    .topbar-status-wrap {display:flex; flex-direction:column; align-items:flex-end; gap:7px;}
    .topbar-status-pill {
        display:flex; align-items:center; gap:8px; font-size:11.5px; color:#c9f5df; white-space:nowrap;
        background:rgba(47,206,135,.09); border:1px solid rgba(47,206,135,.28); border-radius:999px;
        padding:5px 13px;
    }
    .topbar-status-dot {width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 10px rgba(47,206,135,.8);display:inline-block; animation:sbPulse 2.2s ease-in-out infinite;}
    .topbar-status-online {color:#c9f5df; font-weight:650;}
    .topbar-status-time {font-size:10.5px; color:#5b7690; letter-spacing:.3px; white-space:nowrap;}

    /* ============ SIDEBAR — full redesign ============
       A shared "breathing" pulse keyframe for every live-status dot in the
       sidebar (brand session dot, system-status dot) so they read as one
       consistent "this is live" language rather than a static icon. */
    @keyframes sbPulse {0%,100%{opacity:1; box-shadow:0 0 6px rgba(47,206,135,.6);} 50%{opacity:.55; box-shadow:0 0 14px rgba(47,206,135,.9);}}

    .sidebar-brand-v2 {padding:10px 6px 16px; border-bottom:1px solid #1c3a53; margin-bottom:10px;}
    .brand-row {display:flex; align-items:center; gap:10px;}
    .brand-mark {
        width:34px; height:34px; flex:0 0 34px; border-radius:var(--r-md);
        display:flex; align-items:center; justify-content:center; font-size:17px;
        background:linear-gradient(180deg,#12233a,#0d1c2c); border:1px solid #24445f;
        box-shadow:0 0 0 1px rgba(91,157,249,.18), 0 6px 14px rgba(0,0,0,.3), inset 0 1px 0 rgba(255,255,255,.06);
    }
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
        letter-spacing:1.6px !important; text-transform:uppercase !important; margin:18px 4px 7px !important;
    }
    .sidebar-group-label .grp-index {
        color:var(--teal); font:900 9px/1 "Consolas","Cascadia Code",monospace; letter-spacing:0;
        border:1px solid #1a3a5c; border-radius:6px; padding:1.5px 4px; background:#0a1826;
    }
    .sidebar-group-label:after {content:""; flex:1; height:1px; background:linear-gradient(90deg,#1c3a52,transparent);}

    [data-testid="stSidebar"] .stButton > button {
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
    [data-testid="stSidebar"] .stButton > button > div {
        width:100% !important; display:flex !important; justify-content:flex-start !important;
    }
    [data-testid="stSidebar"] .stButton > button p {
        text-align:left !important; width:100% !important;
    }
    /* A left accent bar as a pseudo-element (not a border) so it animates
       in/out on hover/select without ever nudging the row's own layout. */
    [data-testid="stSidebar"] .stButton > button::before {
        content:""; position:absolute; left:0; top:7px; bottom:7px; width:3px; border-radius:2px;
        background:var(--teal); opacity:0; transform:scaleY(.3);
        transition:opacity .2s var(--ease), transform .2s var(--ease);
    }
    [data-testid="stSidebar"] .stButton > button:hover {
        background:rgba(91,157,249,.12) !important; border-color:#1e3a5c !important; color:#eaf6ff !important;
        padding-left:18px !important;
    }
    [data-testid="stSidebar"] .stButton > button:hover::before {opacity:.5; transform:scaleY(.7);}
    [data-testid="stSidebar"] .stButton > button:active {transform:scale(.985) !important; transition-duration:.08s !important;}
    [data-testid="stSidebar"] .stButton > button[kind="primary"] {
        background:linear-gradient(90deg,rgba(91,157,249,.20),rgba(91,157,249,.02)) !important;
        border:1px solid #1e3a5c !important;
        color:#eefaff !important; box-shadow:inset 0 0 0 1px rgba(91,157,249,.10) !important;
        padding-left:18px !important;
    }
    [data-testid="stSidebar"] .stButton > button[kind="primary"]::before {
        opacity:1 !important; transform:scaleY(1) !important; box-shadow:0 0 8px rgba(91,157,249,.65);
    }
    /* System-status widget: a small two-tile "health" card instead of a
       plain list of rows, with its own pulse dot and hover lift so it
       reads as a live product widget, not a static footer. */
    .sidebar-status-card-v2 {
        margin-top:16px; padding:13px 13px 11px; border:1px solid #1b465a; position:relative; overflow:hidden;
        background:linear-gradient(180deg,#101f33 0%,#0c1a2a 100%); border-radius:var(--r-lg);
        box-shadow:0 8px 20px rgba(0,0,0,.2), inset 0 0 20px rgba(84,112,255,.02);
        transition:border-color .2s var(--ease), box-shadow .2s var(--ease);
    }
    .sidebar-status-card-v2:hover {border-color:#2c5877; box-shadow:0 10px 24px rgba(0,0,0,.26), inset 0 0 26px rgba(84,112,255,.04);}
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
       dock scrolls internally before you ever reach the Copilot panel. */
    .panel-card-head {
        display:flex; justify-content:space-between; align-items:center;
        padding:9px 13px; border:1px solid #193a50; border-bottom:none;
        background:#0a1d2b; border-radius:var(--r-lg) var(--r-lg) 0 0;
        color:#5fdfff; font:800 10.5px/1.2 monospace; letter-spacing:1px;
    }
    .panel-card-body {border:1px solid #193a50; border-top:none; border-radius:0 0 var(--r-lg) var(--r-lg); padding:12px; background:#081522;}

    .threattype-row {display:flex; align-items:center; gap:10px; margin:9px 0; font-size:12px; color:#c9d8e7;}
    .threattype-row .bar-track {flex:1; height:7px; border-radius:5px; background:#0d1f30; overflow:hidden;}
    .threattype-row .bar-fill {height:100%; border-radius:5px;}
    .threattype-row .pct {width:38px; text-align:right; color:#8fa5bd; font-size:11px;}

    .copilot-header {display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;}
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
    .scan-compact-status {display:flex; align-items:center; gap:8px; font:700 12px/1.4 monospace; color:#c9d8e7; padding:6px 2px;}

    /* Copilot panel container -- a real st.container(border=True, key=...)
       styled to match the .copilot-header/.copilot-msg family above it, so
       native widgets (buttons, the command input) sit genuinely inside the
       box instead of an HTML div spliced across separate st.markdown calls. */
    .st-key-copilot_panel {
        border:1px solid #223c58 !important; border-top:none !important;
        border-radius:0 0 var(--r-lg) var(--r-lg) !important;
        background:linear-gradient(180deg,#0d1c2c,#091623) !important;
        padding:12px 14px 14px 14px !important;
    }
    .st-key-copilot_quick_actions .stButton > button {
        font-size:10.5px !important; padding:6px 6px !important; min-height:34px !important;
        white-space:normal !important; line-height:1.2 !important;
    }
    .st-key-copilot_command_row .stTextInput input {
        background:#0a1826 !important; border-color:#1c3a52 !important; font-size:12.5px !important;
    }
    .st-key-copilot_command_row .stFormSubmitButton > button {
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

with st.sidebar:
    st.markdown(
        """<div class="sidebar-brand-v2">
            <div class="brand-row">
                <div class="brand-mark"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 5-3.2 8.5-7 10-3.8-1.5-7-5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4.5"/></svg></div>
                <div class="brand-text">
                    <div class="name">SIH26106</div>
                    <div class="role">Forensic Intelligence Platform</div>
                </div>
            </div>
            <div class="brand-meta"><span class="brand-dot"></span>Active Session</div>
        </div>""",
        unsafe_allow_html=True,
    )

    def _nav_group(label):
        """Section header for a run of sidebar nav buttons: a small
        auto-incrementing index tag + label + a gradient rule filling the
        rest of the row (see .sidebar-group-label), so groups read as
        labelled dividers rather than floating caption text."""
        _nav_group._n = getattr(_nav_group, "_n", 0) + 1
        st.markdown(
            f'<div class="sidebar-group-label"><span class="grp-index">{_nav_group._n:02d}</span>{label}</div>',
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

    _nav_group("Threat Operations")
    _nav_button(
        "Upload Email(s)", "Dashboard", force_mode=_UPLOAD_MODE, key="nav_upload",
        active_when=_on_dashboard and _mode_now == _UPLOAD_MODE,
    )
    _nav_button(
        "Live Email Scan (IMAP)", "Dashboard", force_mode=_LIVE_MODE, key="nav_live",
        active_when=_on_dashboard and _mode_now == _LIVE_MODE,
    )
    _nav_button("AI Copilot", "AI Threat Analysis", key="nav_ai_copilot_side")
    _nav_button(
        "Nomic AI", "Origin & Route", key="nav_nomic_side",
        active_when=_on_origin_route and _origin_focus == "nomic",
        on_click_set={"origin_route_focus": "nomic"},
    )

    _nav_group("Visualization")
    _nav_button(
        "Global Threat Map", "Origin & Route", key="nav_map_side",
        active_when=_on_origin_route and _origin_focus == "map",
        on_click_set={"origin_route_focus": "map"},
    )
    _nav_button("Correlation Graph", "Correlation", key="nav_graph_side")
    _nav_button("Analytics", "Classification", key="nav_analytics_side")

    _nav_group("Intelligence")
    _nav_button("Threat History", "Threat History", key="nav_history_side")
    _nav_button("IOC Lookup", "Indicators", key="nav_ioc_side")
    _nav_button("URLHaus Feed", "URLHaus Feed", key="nav_urlhaus_side")

    _nav_group("Security")
    _nav_button("Antivirus (ClamAV)", "Antivirus", key="nav_av_side")

    _nav_group("System")
    _nav_button("Settings", "Settings", key="nav_settings_side")
    _nav_button("ℹ About", "About", key="nav_about_side")

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

st.markdown(
    f"""<div class="topbar-shell">
      <div class="topbar-brand">
        <div class="topbar-logo"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 5-3.2 8.5-7 10-3.8-1.5-7-5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4.5"/></svg></div>
        <div>
          <div class="topbar-kicker">SIH26106 · Forensic Intelligence Platform</div>
          <div class="topbar-title">AI-Powered Email Threat Detection &amp; Forensic Intelligence</div>
          <div class="topbar-subtitle">Evidence acquisition · header authentication · IOC intelligence · origin tracing · campaign correlation · local AI assessment</div>
        </div>
      </div>
      <div class="topbar-status-wrap">
        <div class="topbar-status-pill">
          <span class="topbar-status-dot"></span>
          <span class="topbar-status-online">System operational</span>
        </div>
        <div class="topbar-status-time">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
      </div>
    </div>""",
    unsafe_allow_html=True,
)

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
st.markdown('<div class="nav-caption">FORENSIC WORKFLOW / ACTIVE MODULE</div>', unsafe_allow_html=True)
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
    st.subheader("About SIH26106")
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
_MAP_MODE_ALL = "All senders (up to 10)"
_MAP_MODE_ONE = "By email"

_TILE_LAYERS = (
    ("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
     "Esri World Imagery", "Satellite"),
    ("https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}",
     "Esri World Terrain", "Terrain"),
)

_LEVEL_MARKER_COLORS = {
    "CRITICAL": "#ff4757", "HIGH": "#ff9f43", "MEDIUM": "#f5c542", "LOW": "#2fd8ff",
}


def _add_base_tiles(m):
    for tiles, attr, name in _TILE_LAYERS:
        folium.TileLayer(tiles=tiles, attr=attr, name=name, control=True).add_to(m)


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


def _render_all_senders_map(cases, key_prefix, height=430, max_markers=10):
    """One marker per email's origin, most-recent-first, capped at
    max_markers so the map never turns into unreadable clutter."""
    all_points = [pt for pt in (_case_origin_point(c) for c in cases) if pt]
    points = all_points[-max_markers:]
    if not points:
        st.info("No geolocatable origins across the loaded emails yet.")
        return
    m = folium.Map(location=[points[0]["lat"], points[0]["lon"]], zoom_start=2, tiles=None)
    _add_base_tiles(m)
    for pt in points:
        color = _LEVEL_MARKER_COLORS.get(pt["level"], "#2fd8ff")
        popup = (
            f"<b>{pt['sender']}</b><br>{pt['case_name']}<br>"
            f"IP: {pt['ip']}<br>{pt['city']} {pt['country']}<br>"
            f"Infra: {pt['infra_label']}<br>Verdict: {pt['level']}"
        )
        folium.CircleMarker(
            location=[pt["lat"], pt["lon"]], radius=8, color=color,
            fill=True, fill_opacity=0.85, popup=folium.Popup(popup, max_width=280),
        ).add_to(m)
    folium.LayerControl(collapsed=False).add_to(m)
    st_folium(m, width="stretch", height=height, returned_objects=[], key=f"{key_prefix}_all_senders_map")
    st.caption(
        f"Showing {len(points)} of {len(all_points)} geolocatable sender origins "
        f"(most recent {max_markers} max). Marker color = verdict severity."
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
    if nomic_available():
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

def _display_email_table(df):
    """Presentation-only helper: adds a progress-bar column config for Threat
    Score. Never mutates the caller's dataframe or the underlying analysis
    data -- purely how the existing 'Row #, Email, Origin IP, Country, Threat
    Score, Verdict, Subject' table is *displayed*."""
    view = df.copy()
    if "Verdict" in view.columns:
        view["Verdict"] = view["Verdict"].apply(lambda v: str(v))
    col_config = {}
    if "Threat Score" in view.columns:
        col_config["Threat Score"] = st.column_config.ProgressColumn(
            "Threat Score", min_value=0, max_value=100, format="%.1f"
        )
    if "Row #" in view.columns:
        col_config["Row #"] = st.column_config.NumberColumn("Row #", width="small")
    return view, col_config


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
        if st.session_state.get("live_mailbox_config"):
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
        elif _is_csv_source:
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
        '<div class="panel-card-head" style="margin-top:14px;">'
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
    with _mc_live:
        st.markdown(
            f"""<div class="mode-card {'mode-card-active' if input_mode == _LIVE_OPT else ''}">
                <div class="mode-card-icon mode-card-icon-blue"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z"/></svg></div>
                <div>
                    <div class="mode-card-title">Live IMAP mailbox interceptor</div>
                    <div class="mode-card-sub">Read-only, connects directly to the mailbox</div>
                </div>
            </div>""",
            unsafe_allow_html=True,
        )
        if st.button("Use live IMAP mailbox interceptor", key="acq_pick_live", use_container_width=True):
            st.session_state["input_mode_radio"] = _LIVE_OPT
            st.rerun()
    with _mc_upload:
        st.markdown(
            f"""<div class="mode-card {'mode-card-active' if input_mode == _UPLOAD_OPT else ''}">
                <div class="mode-card-icon mode-card-icon-neutral"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5z"/><path d="M14 3v5h5"/><path d="M12 12.5v5.5M9.2 15.2h5.6"/></svg></div>
                <div>
                    <div class="mode-card-title">Evidence file upload</div>
                    <div class="mode-card-sub">.eml, .txt, .csv batch import</div>
                </div>
            </div>""",
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
                """<div class="acq-panel"><div class="acq-label">EVIDENCE ACQUISITION</div>
                <div class="acq-help">Drop a suspicious EML, TXT or CSV evidence set into the secure analysis intake.</div></div>""",
                unsafe_allow_html=True,
            )
            _up_l, _up_c, _up_r = st.columns([1, 3, 1])
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
                st.info("SYSTEM READY · Awaiting evidence acquisition. Supported: EML / TXT / CSV · Maximum 200 MB per file.")
                st.stop()
    elif "Live IMAP Mailbox Interceptor" in input_mode:
        st.markdown("### Live Mailbox Interceptor")
        st.caption("Read-only mailbox access. Complete the workflow from top to bottom: connect → browse → select → acquire evidence.")

        mailbox_loaded = bool(st.session_state.get("live_mailbox_messages"))
        if "show_imap_connection_form" not in st.session_state:
            st.session_state["show_imap_connection_form"] = not mailbox_loaded
        show_connection_form = st.session_state["show_imap_connection_form"]

        if mailbox_loaded and not show_connection_form:
            _cfg_summary = st.session_state.get("live_mailbox_config", {}) or {}
            st.markdown(f"""
            <div class="stage-card stage-card-success">
              <div class="stage-label">MAILBOX CONNECTED</div>
              <div class="stage-title">{html.escape(str(_cfg_summary.get("user", "")))} &middot; folder: {html.escape(str(_cfg_summary.get("folder", "INBOX")))}</div>
              <div class="stage-help">{len(st.session_state.get("live_mailbox_messages", []))} message headers loaded from {html.escape(str(_cfg_summary.get("host", "")))}. Connection details are hidden while you work &mdash; use the buttons below to change them.</div>
            </div>
            """, unsafe_allow_html=True)

            # Standalone quick-launch: just the "run the full pipeline on the
            # last 10 emails" action (none of the copilot chat's other
            # shortcuts, history, or text box) sitting right here beside the
            # mailbox controls -- so it's visible the moment the mailbox
            # connects, with nothing to scroll to, select, or open in the
            # sidebar first.
            _cc1, _cc2, _cc3 = st.columns([2, 1, 1])
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
                if st.button("Change mailbox / Reconnect", use_container_width=True, key="imap_show_form_btn"):
                    st.session_state["show_imap_connection_form"] = True
                    st.rerun()
            with _cc3:
                if st.button("Disconnect mailbox", use_container_width=True, key="imap_disconnect_btn"):
                    for _k in [
                        "live_mailbox_messages", "live_mailbox_config", "live_selected_uid",
                        "live_selected_raw", "live_rescan_nonce", "forensic_report_source",
                        "pipeline_batch_result", "pipeline_batch_items",
                    ]:
                        st.session_state.pop(_k, None)
                    st.session_state["show_imap_connection_form"] = True
                    st.rerun()
            st.caption(
                "The Full Report button runs machine analysis, AI threat analysis and semantic "
                "origin correlation on the 10 newest messages, then opens the Forensic Report "
                "ready to download — no need to pick a message below."
            )
            imap_host = _cfg_summary.get("host", "")
            imap_port = _cfg_summary.get("port", 993)
            imap_user = _cfg_summary.get("user", "")
            imap_credential = _cfg_summary.get("credential", "")
            folder = _cfg_summary.get("folder", "INBOX")
            browse_count = st.session_state.get("imap_browse_count", 10)
            auth_mode = _cfg_summary.get("auth_mode", "App Password / Password")
        else:
            st.markdown("""
            <div class="stage-card">
              <div class="stage-label">01 · Mail server</div>
              <div class="stage-title">Choose provider and connection endpoint</div>
              <div class="stage-help">Provider defaults are supplied automatically. Custom IMAP servers remain supported.</div>
            </div>
            """, unsafe_allow_html=True)
            provider = st.selectbox("Mail provider", list(PROVIDERS.keys()), key="imap_provider")
            provider_defaults = PROVIDERS[provider]
            imap_host = st.text_input("IMAP server", provider_defaults["host"], key=f"imap_host_{provider}")
            imap_port = st.number_input("Port", min_value=1, max_value=65535, value=int(provider_defaults["port"]), step=1, key=f"imap_port_{provider}")

            # Gmail + already signed in (this session, or restored from the
            # token cache after a restart) but no address on file yet ->
            # resolve it now, once, before the Email address field below is
            # created, so the field opens pre-filled instead of asking the
            # user to retype an address Google already gave us.
            if provider == "Gmail" and GOOGLE_OAUTH_READY and oauth_available() and not st.session_state.get("imap_user"):
                _cached_tok = st.session_state.get("google_oauth_token") or get_cached_access_token()
                if _cached_tok and not st.session_state.get("_google_email_autofill_tried"):
                    st.session_state["_google_email_autofill_tried"] = True
                    _resolved_email = _load_cached_google_email() or _fetch_google_email_from_token(_cached_tok)
                    if _resolved_email:
                        st.session_state["imap_user"] = _resolved_email
                        _save_cached_google_email(_resolved_email)

            st.markdown("""
            <div class="stage-card">
              <div class="stage-label">02 · Authentication</div>
              <div class="stage-title">Sign in to the mailbox</div>
              <div class="stage-help">Gmail signs in with your Google account. Other providers use an app password or OAuth2 token.</div>
            </div>
            """, unsafe_allow_html=True)
            imap_user = st.text_input("Email address", placeholder="you@example.com", key="imap_user")

            imap_credential = ""
            auth_mode = "App Password / Password"

            if provider == "Gmail":
                if GOOGLE_OAUTH_READY and oauth_available():
                    cached_token = st.session_state.get("google_oauth_token") or get_cached_access_token()
                    if cached_token:
                        st.session_state["google_oauth_token"] = cached_token
                        auth_mode = "OAuth2 Access Token"
                        imap_credential = cached_token
                        st.success("Signed in with Google.")
                        if st.button("Sign out of Google", key="google_signout_btn"):
                            clear_saved_token()
                            st.session_state.pop("google_oauth_token", None)
                            st.session_state.pop("imap_user", None)
                            st.session_state.pop("_google_email_autofill_tried", None)
                            try:
                                os.remove(_GOOGLE_EMAIL_CACHE_PATH)
                            except OSError:
                                pass
                            st.rerun()
                    else:
                        # The ?code=/?error= redirect from Google is handled
                        # once, at the very top of the script (see the
                        # callback block right after st.set_page_config) --
                        # by the time this section renders, that's already
                        # been consumed. Only a leftover error (if sign-in
                        # failed) surfaces here.
                        _pending_oauth_error = st.session_state.pop("_google_oauth_error", None)
                        if _pending_oauth_error:
                            st.error(f"Google sign-in didn't complete: {_pending_oauth_error}")
                            st.caption("The sign-in link may have expired or already been used. Click 'Sign in with Google' again below.")

                        issue = client_secret_issue()
                        if issue:
                            st.warning(f"Google Sign-In isn't configured correctly: {issue}")
                        else:
                            with st.expander("Redirect URL setup (only needed once per environment)"):
                                st.caption(
                                    "Must exactly match a redirect URI registered on the Google OAuth client, "
                                    "and be the URL this app is actually reachable at right now (e.g. "
                                    "`http://localhost:8501` when testing locally, or your deployed https:// URL)."
                                )
                                redirect_override = st.text_input(
                                    "App URL (redirect URI)",
                                    value=google_redirect_uri(),
                                    key="google_redirect_uri_input",
                                )
                                if redirect_override.strip():
                                    os.environ["SIH26106_GOOGLE_REDIRECT_URI"] = redirect_override.strip().rstrip("/")

                            try:
                                auth_url, _state = get_authorization_url(email_hint=imap_user)
                                st.markdown(
                                    f'<a href="{html.escape(auth_url)}" target="_self" class="google-signin-btn">Sign in with Google</a>',
                                    unsafe_allow_html=True,
                                )
                                st.caption("Opens Google's sign-in page. After you approve access, Google sends you back here automatically.")
                            except Exception as e:
                                st.error(f"Google sign-in failed to start: {e}")

                        with st.expander("Use an app password instead"):
                            manual_cred = st.text_input("App password", type="password", key="gmail_app_password")
                            if manual_cred:
                                imap_credential = manual_cred
                else:
                    if not GOOGLE_OAUTH_READY:
                        st.warning("Google Sign-In isn't available: google_Oauth.py failed to import. Run `pip install google-auth google-auth-oauthlib` and restart the app.")
                    else:
                        st.warning("Google Sign-In needs setup: add a `client_secret.json` OAuth Desktop credential next to app.py, then restart the app.")
                    imap_credential = st.text_input("App password / access token", type="password", key=f"imap_credential_{provider}")
            else:
                auth_mode = st.selectbox("Authentication", ["App Password / Password", "OAuth2 Access Token"], key="imap_auth_mode")
                imap_credential = st.text_input("App password / access token", type="password", key=f"imap_credential_{provider}")

            if provider == "Outlook / Microsoft 365" and auth_mode == "App Password / Password":
                st.warning("Microsoft 365 commonly requires OAuth2 for IMAP. Switch to OAuth2 if password authentication is rejected.")

            st.markdown("""
            <div class="stage-card">
              <div class="stage-label">03 · Mail scope</div>
              <div class="stage-title">Define the folder and browsing window</div>
              <div class="stage-help">Only headers are loaded during browsing. The complete raw message is fetched after selection.</div>
            </div>
            """, unsafe_allow_html=True)
            folder = st.text_input("Mailbox folder", "INBOX", key="imap_folder")
            browse_count = st.selectbox("Messages to browse", [10, 25, 50, 100], index=0, key="imap_browse_count")
            connect_clicked = st.button("Connect & Load Mailbox", type="primary", use_container_width=True, key="connect_imap")

            if connect_clicked:
                if not imap_user or not imap_credential or not imap_host:
                    st.error("Enter the mailbox address, server and authentication credential first.")
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
            st.markdown("""
            <div class="stage-card">
              <div class="stage-label">04 · Message selection</div>
              <div class="stage-title">Review metadata and select the evidence item</div>
              <div class="stage-help">Keep the mailbox lightweight: raw RFC-5322 content is not fetched until you load one message.</div>
            </div>
            """, unsafe_allow_html=True)

            display_rows = []
            for item in mailbox_messages:
                dt = item.get("date_dt")
                if dt is not None:
                    try:
                        date_text = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        date_text = str(item.get("date") or "Unknown")
                else:
                    date_text = str(item.get("date") or "Unknown")
                display_rows.append({
                    "UID": item.get("uid", ""),
                    "Date": date_text,
                    "From": item.get("from", "Unknown sender"),
                    "Subject": item.get("subject", "No Subject"),
                })

            labels = [
                f"{i + 1}. {x.get('date', 'Unknown')} | {x.get('from', 'Unknown sender')} | {x.get('subject', 'No Subject')}"
                for i, x in enumerate(mailbox_messages)
            ]

            # Clicking a row here selects it the same way picking it from
            # the "Message to investigate" dropdown below does, instead of
            # the table and the dropdown being two disconnected controls
            # that just happen to sit next to each other. Streamlit hands
            # back the currently-selected row on *every* rerun, not just the
            # run where the click happened -- so this only pushes into the
            # dropdown's own state when the clicked row has actually
            # changed since last time. Without that guard, picking a
            # message from the dropdown directly would get silently
            # snapped back to whatever row was clicked earlier.
            _table_event = st.dataframe(
                pd.DataFrame(display_rows),
                width="stretch",
                hide_index=True,
                on_select="rerun",
                selection_mode="single-row",
                key="imap_message_table",
            )
            st.caption("Click a row above to load it into **Message to investigate** below.")
            try:
                _clicked_rows = list(_table_event.selection.rows)
            except Exception:
                _clicked_rows = []
            if _clicked_rows and _clicked_rows[0] < len(labels):
                _clicked_row = _clicked_rows[0]
                if st.session_state.get("_imap_table_last_clicked_row") != _clicked_row:
                    st.session_state["_imap_table_last_clicked_row"] = _clicked_row
                    st.session_state["imap_message_selector"] = labels[_clicked_row]

            selected_label = st.selectbox("Message to investigate", labels, key="imap_message_selector")
            selected_index = labels.index(selected_label)
            selected_meta = mailbox_messages[selected_index]
            selected_uid = str(selected_meta.get("uid", ""))

            st.markdown("""
            <div class="stage-card">
              <div class="stage-label">05 · Evidence acquisition</div>
              <div class="stage-title">Fetch the full message and begin forensic analysis</div>
              <div class="stage-help">The selected UID is retrieved and passed to the same forensic pipeline used for uploaded evidence.</div>
            </div>
            """, unsafe_allow_html=True)

            load_clicked = st.button("Load & Scan Selected Message", type="primary", use_container_width=True, key="load_imap_message")
            rescan_clicked = st.button("Rescan Selected Message", use_container_width=True, key="rescan_imap_message")

            if load_clicked or rescan_clicked:
                cfg = st.session_state.get("live_mailbox_config", {})
                credential = cfg.get("credential") or imap_credential
                if not cfg or not credential:
                    st.error("Reconnect to the mailbox before selecting a message.")
                    st.stop()
                try:
                    with st.spinner("Fetching the complete RFC-5322 message securely..."):
                        selected_raw = fetch_message_by_uid(
                            cfg["host"], cfg["user"], credential, selected_uid,
                            folder=cfg["folder"], port=cfg["port"], auth_mode=cfg["auth_mode"],
                        )
                    if not isinstance(selected_raw, bytes) or not selected_raw:
                        raise RuntimeError("The server returned an empty raw message.")
                    st.session_state["live_selected_uid"] = selected_uid
                    st.session_state["live_selected_raw"] = selected_raw
                    if rescan_clicked:
                        st.session_state["live_rescan_nonce"] = int(st.session_state.get("live_rescan_nonce", 0)) + 1
                    st.success("Message acquired.")
                    fetch_ok = True
                except Exception as exc:
                    st.error(f"Could not retrieve the selected message: {exc}")
                    st.session_state["live_selected_raw"] = None
                    fetch_ok = False

                if fetch_ok:
                    # Deliberately stay on Dashboard instead of jumping to
                    # Forensic Report — this run falls straight through to the
                    # same Dashboard rendering a plain file upload gets,
                    # Threat Summary + Synapse Copilot sidebar included. A
                    # full AI + semantic report across several messages is
                    # now a separate, deliberate action: ask the Copilot
                    # below to "track my last N emails" once it's on screen.
                    st.rerun()

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
                    "**Load & Scan Selected Message** if you want to inspect one email individually instead."
                )
                return _raw, _case_name

            if st.session_state.get("live_selected_uid") == selected_uid:
                candidate_raw = st.session_state.get("live_selected_raw")
                if isinstance(candidate_raw, (bytes, bytearray)) and candidate_raw:
                    raw = bytes(candidate_raw)
                    case_name = f"Live IMAP: {selected_meta.get('subject') or 'No Subject'}"
                    st.info(f"Selected evidence: {selected_meta.get('subject') or 'No Subject'} · UID {selected_uid} · {len(raw):,} raw bytes")
                elif pipeline_ready:
                    raw, case_name = _use_pipeline_fallback_message()
                else:
                    st.warning("Select Load & Scan Selected Message to fetch this message.")
                    st.stop()
            elif pipeline_ready:
                raw, case_name = _use_pipeline_fallback_message()
            else:
                st.info("Choose a mailbox message and load it for forensic analysis.")
                st.stop()
        else:
            st.info("Connect to Gmail, Yahoo, Outlook/Microsoft 365, or a custom IMAP server to browse messages.")
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

        st.write("")
        st.markdown("#### Technical Logs & Antivirus")
        tab_logs, tab_av = st.tabs(["Email Results", "Antivirus Scan"])

        with tab_logs:
            st.caption(
                "Want a full multi-email report? Ask the ** Synapse Copilot** in the sidebar to "
                "*\"track my last 10 emails\"* — machine + AI + semantic analysis across your recent "
                "mail, ending on a downloadable Forensic Report."
            )
            st.divider()

            _is_current_csv = uploaded is not None and uploaded.name.lower().endswith(".csv")
            unified_table = st.session_state.get("unified_email_table") if _is_current_csv else None
            if unified_table is not None and not unified_table.empty:
                _view, _cfg = _display_email_table(unified_table)
                st.dataframe(_view, width="stretch", hide_index=True, height=280, column_config=_cfg)
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
                _view, _cfg = _display_email_table(pd.DataFrame(log_rows))
                st.dataframe(_view, width="stretch", hide_index=True, height=280, column_config=_cfg)

        with tab_av:
            av_up = _clamd_up_cached()
            if av_up:
                st.success(f" ClamAV connected - {clamd_version() or 'clamd daemon'}")
            else:
                st.warning("ClamAV daemon not reachable right now - showing the built-in risky-extension check instead.")
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

                if st.button(
                    "Analyze 10 Most Recent Emails — Full Report",
                    type="primary", use_container_width=True, key="csv_pipeline_btn",
                ):
                    _pipeline_items = _collect_recent_csv_items(data, uploaded.name, 10)
                    _run_batch_pipeline(_pipeline_items, uploaded.name)
                st.caption("Runs machine analysis, AI threat analysis and semantic origin correlation on the 10 newest rows, then opens the Forensic Report ready to download.")

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

                saved_bulk_results = st.session_state.get("bulk_scan_results")

            if saved_bulk_results is not None:
                # Compact, single-line completion status (same pattern as the
                # Live IMAP "Mailbox connected" confirmation) instead of a
                # lingering progress bar + separate success banner, paired
                # with compact secondary actions instead of the full intro
                # block once there's something to show.
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
                        kc1, kc2 = st.columns(2)
                        kc1.metric("Threat Score", f"{float(dd_result.get('score', 0)):.1f}", str(dd_result.get('level', '?')).upper())
                        kc2.metric("ML Phishing", f"{float(dd_m.get('prob', 0)):.1%}")
                        kc3, kc4 = st.columns(2)
                        kc3.metric("Auth Pass", f"{dd_auth_pass}/3")
                        kc4.metric("Anomalies", dd_anomaly_count)

                        st.markdown('<div class="panel-card-head" style="margin-top:12px;"><span>INVESTIGATION SUMMARY</span></div>', unsafe_allow_html=True)
                        st.markdown(
                            f"""<div class="panel-card-body">
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

                        st.markdown('<div class="panel-card-head" style="margin-top:12px;"><span>TOP THREAT SIGNAL BREAKDOWN</span></div>', unsafe_allow_html=True)
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

                    st.markdown('<div class="panel-card-head" style="margin-top:12px;"><span>KEY METRICS</span></div>', unsafe_allow_html=True)
                    rc1, rc2 = st.columns(2)
                    rc1.metric("Threat Score", f"{float(result.get('score',0)):.1f}", str(result.get('level','?')).upper())
                    rc2.metric("ML Phishing", f"{float(sel_m.get('prob',0)):.1%}")
                    rc3, rc4 = st.columns(2)
                    rc3.metric("Auth Pass", f"{auth_pass}/3")
                    rc4.metric("Anomalies", anomaly_count)

                    st.markdown('<div class="panel-card-head" style="margin-top:12px;"><span>INVESTIGATION SUMMARY</span></div>', unsafe_allow_html=True)
                    st.markdown(
                        f"""<div class="panel-card-body">
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

                    st.markdown('<div class="panel-card-head" style="margin-top:12px;"><span>TOP THREAT SIGNAL BREAKDOWN</span></div>', unsafe_allow_html=True)
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
            st.caption("MIDDLE PREVIEW PANE")
            # Map and correlation graph render side by side in one row
            # instead of stacked or behind a tab switch -- both are visible
            # at once, no extra click needed either way.
            with st.container(border=True):
                map_col, graph_col = st.columns(2, gap="medium")
                with map_col:
                    _dash_map_mode = st.radio(
                        "Map view", [_MAP_MODE_ALL, _MAP_MODE_ONE], horizontal=True,
                        key="dash_map_mode", label_visibility="collapsed",
                    )
                    if _dash_map_mode == _MAP_MODE_ALL:
                        st.markdown("""<div class="panel-card-head"><span>GLOBE-SCAN: IP GEOLOCATION MAP</span>
                            <span>All senders</span></div>""", unsafe_allow_html=True)
                        _render_all_senders_map(cases, key_prefix="dash", height=430)
                    else:
                        _dash_sel_case = _pick_case_for_map(cases, result, case_name, key="dash_map_email_pick", source_rows=data)
                        _dash_sel_geo = _dash_sel_case.get("geo", {}) or {}
                        _dash_sel_origin = _dash_sel_geo.get("origin", {}) or {}
                        st.markdown(f"""<div class="panel-card-head"><span>GLOBE-SCAN: IP GEOLOCATION MAP</span>
                            <span>{_dash_sel_origin.get('ip','Unknown')}</span></div>""", unsafe_allow_html=True)
                        hops = [h for h in _dash_sel_geo.get("hops", []) if h.get("lat") is not None]
                        if hops:
                            dash_map = folium.Map(location=[hops[0]["lat"], hops[0]["lon"]], zoom_start=2, tiles=None)
                            _add_base_tiles(dash_map)
                            for i, h in enumerate(hops, 1):
                                is_origin = (h.get("infra") in ("tor", "vpn", "proxy")) or (i == len(hops))
                                folium.CircleMarker(
                                    location=[h["lat"], h["lon"]], radius=7,
                                    color="#ff4757" if is_origin else "#2fd8ff",
                                    fill=True, fill_opacity=0.85,
                                    popup=f"{h['ip']} · {h.get('city','')} {h.get('country','')}",
                                ).add_to(dash_map)
                            folium.LayerControl(collapsed=False).add_to(dash_map)
                            st_folium(dash_map, width="stretch", height=430, returned_objects=[], key="dash_single_map")
                        else:
                            st.info("No geolocatable hop for this email yet.")

                with graph_col:
                    st.markdown(f"""<div class="panel-card-head"><span>NETWORK INFRASTRUCTURE CORRELATION GRAPH</span>
                        <span>{len(cases)} CASES</span></div>""", unsafe_allow_html=True)
                    # A fixed seed here keeps this small preview stable between
                    # reruns; the full, shuffleable, interactive version lives
                    # on the dedicated Correlation panel.
                    G = _build_correlation_graph(cases, max_cases=20, seed=42)
                    st.plotly_chart(correlate.graph_figure(G, height=430), width="stretch")
                    if G.graph.get("sampled"):
                        st.caption(f"Preview sample: {G.graph['case_count']} of {G.graph['total_case_count']} cases. Full interactive view: ** Correlation Graph** in the sidebar.")
                    else:
                        st.caption("Shared-indicator detail and case table: ** Correlation Graph** in the sidebar.")

        # ================= BOTTOM (technical logs, antivirus, AI copilot) =================
        # In CSV mode this section already rendered earlier (between the Deep
        # Dive selector and the message content box) — don't show it twice.
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
                    st.markdown(f"#### Full Campaign Summary ({saved_batch.get('count')} Emails Assessed)")
                    cleaned_summary = _clean_ai_display(b_res.get("analysis", ""))
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

                    st.markdown("#### Download Multi-Email Forensic Intelligence")

                    batch_markdown_report = (
                        f"# SIH26106 - MULTI-EMAIL CAMPAIGN ASSESSMENT\n\n"
                        f"**Total Emails Assessed:** {saved_batch.get('count')}\n\n"
                        f"## AI Campaign Summary\n\n{cleaned_summary}"
                    )

                    st.download_button(
                        label="Download Campaign Summary (.md)",
                        data=batch_markdown_report.encode("utf-8"),
                        file_name=f"ai_campaign_summary_{saved_batch.get('count')}_emails.md",
                        mime="text/markdown",
                        use_container_width=True,
                        key="dl_ai_campaign_md",
                    )
                    st.caption("For a per-email combined AI + machine dossier with all three download options, open the **Forensic Report** module.")
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

                    st.markdown("#### Download AI Threat Report")
                    single_markdown_report = (
                        f"# SIH26106 - AI THREAT ASSESSMENT\n\n"
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
        left, right = st.columns([1, 1])
        with left:
            st.subheader("Risk score composition")
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
            st.subheader("Why the model flagged this")
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
        st.subheader("Message")
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
        st.subheader("SPF / DKIM / DMARC")
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
        st.subheader("Identity anomalies")
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
            st.subheader("Business Email Compromise assessment")
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
        st.subheader("Identity fields")
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
        st.subheader("Where the message actually came from")

        # Every loaded email at a glance (capped so the map stays readable),
        # or one email's full hop chain picked from a dropdown -- same
        # toggle as the Dashboard preview map, so either view is a click
        # away instead of only ever seeing whichever message is loaded.
        cases = [r for r in _corr_cases.values() if "error" not in r]
        current_case = dict(result)
        current_case["_evidence_hash"] = current_evidence_hash
        if current_evidence_hash not in {r.get("_evidence_hash") for r in cases}:
            cases.append(current_case)

        st.markdown("### Interactive Visual Hop Map (Folium)")
        _geo_map_mode = st.radio(
            "Map view", [_MAP_MODE_ALL, _MAP_MODE_ONE], horizontal=True, key="geo_map_mode",
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
            _render_all_senders_map(cases, key_prefix="geo", height=500)
        else:
            hops = [h for h in _table_geo.get("hops", []) if h.get("lat") is not None]

            if hops:
                start_lat = hops[0]["lat"] if hops else 20.0
                start_lon = hops[0]["lon"] if hops else 0.0

                m = folium.Map(location=[start_lat, start_lon], zoom_start=2, tiles=None)
                _add_base_tiles(m)
                coordinates = []

                for i, h in enumerate(hops, 1):
                    lat, lon = h["lat"], h["lon"]
                    coords = [lat, lon]
                    coordinates.append(coords)

                    is_origin = (h["infra"] in ("tor", "vpn", "proxy")) or (i == len(hops))
                    color = "red" if is_origin else "blue"
                    popup_text = f"<b>Hop {i}</b><br>IP: {h['ip']}<br>Loc: {h.get('city', '')}, {h.get('country', '')}<br>Infra: {h.get('infra_label', '')}"

                    folium.Marker(
                        location=coords, popup=folium.Popup(popup_text, max_width=300), icon=folium.Icon(color=color, icon="info-sign")
                    ).add_to(m)

                if len(coordinates) == 1:
                    hq_coords = [22.5726, 88.3639]
                    coordinates.append(hq_coords)
                    folium.CircleMarker(location=hq_coords, radius=5, color="#35d399", fill=True, fill_color="#35d399", fill_opacity=0.9, popup="Target Datacenter (HQ)").add_to(m)

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

                folium.LayerControl(collapsed=False).add_to(m)
                left, center, right = st.columns([1, 8, 1])
                with center:
                    st_folium(m, width="stretch", height=500, returned_objects=[], key="geo_single_map")
                st.caption("Hop 1 is the earliest external sender. Red markers indicate origin or anonymizing infrastructure. Arcs jump dynamically to the HQ target. Use the layer control (top-right of the map) to switch between satellite and terrain view.")
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
            _bulk_vpn_tab, _bulk_tor_tab = st.tabs(["VPN / Datacenter", "Tor Exit Nodes"])

            with _bulk_vpn_tab:
                st.caption(
                    "Checks every origin + hop IP across every email currently loaded "
                    "(this session's cases) against a local CIDR list, in one pass -- "
                    "no live API, no per-email calls."
                )
                _vpn_csv_path = st.text_input(
                    "Path to CIDR-range CSV (columns: cidr,provider,category)",
                    value="data/vpn_ranges.csv",
                    key="vpn_csv_path",
                )

                # This CSV doesn't ship with the project and nothing builds it
                # automatically -- the panel used to just error until someone
                # ran fetch_vpn_ranges.py by hand from a terminal. This button
                # does the same fetch in-app instead, so there's no separate
                # script to remember to run first.
                _fetch_col, _scan_col = st.columns(2)
                with _fetch_col:
                    if st.button(
                        "Fetch ranges now (X4BNet, needs internet)",
                        key="fetch_vpn_ranges_btn",
                        use_container_width=True,
                        disabled=not FETCH_VPN_RANGES_AVAILABLE,
                        help=None if FETCH_VPN_RANGES_AVAILABLE
                             else "fetch_vpn_ranges.py wasn't found next to app.py.",
                    ):
                        try:
                            with st.spinner("Fetching VPN + datacenter CIDR lists from X4BNet..."):
                                _fetched_rows = []
                                for _cat in ("vpn", "datacenter"):
                                    _fetched_rows.extend(_fetch_vpn_category(_cat, include_ipv6=False))
                        except Exception as e:
                            st.error(
                                f"Fetch failed ({e}). Check your internet connection, or build the "
                                "CSV yourself from one of the sources noted below."
                            )
                        else:
                            if not _fetched_rows:
                                st.warning("Fetch completed but returned no ranges — nothing written.")
                            else:
                                _sp_root = os.path.dirname(os.path.abspath(__file__))
                                _sp_data = os.path.realpath(os.path.join(_sp_root, "data"))
                                _vpn_csv_path = os.path.realpath(os.path.join(_sp_root, _vpn_csv_path))
                                if not _vpn_csv_path.startswith(_sp_data + os.sep):
                                    st.error("For safety, the ranges file must be inside the data/ folder.")
                                    st.stop()
                                _out_dir = os.path.dirname(_vpn_csv_path)
                                if _out_dir:
                                    os.makedirs(_out_dir, exist_ok=True)
                                with open(_vpn_csv_path, "w", newline="", encoding="utf-8") as _f:
                                    _writer = csv.writer(_f)
                                    _writer.writerow(["cidr", "provider", "category"])
                                    _writer.writerows(_fetched_rows)
                                st.success(
                                    f"Wrote {len(_fetched_rows)} ranges to `{_vpn_csv_path}`. "
                                    "Click 'Scan all loaded emails' to use it."
                                )
                with _scan_col:
                    _run_scan = st.button("Scan all loaded emails", key="run_vpn_bulk_scan", type="primary", use_container_width=True)
                if _run_scan:
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
                st.markdown(
                    "**Where the range list comes from, and whether you need a key:** "
                    "`load_vpn_ranges()` reads a local CSV — it never calls a live API, so no "
                    "account or API key is required. You supply the CSV yourself, built from a "
                    "free public source such as [X4BNet/lists\\_vpn](https://github.com/X4BNet/lists_vpn) "
                    "(VPN + datacenter CIDRs, auto-updated, no signup), IP2Location LITE (free tier, "
                    "email signup for a download token), or the cloud providers' own published ranges "
                    "(AWS/GCP/Azure/DigitalOcean/OVH, all public, no key). Reformat whichever source you "
                    "pick into `cidr,provider,category` columns and point the field above at that file."
                )

            with _bulk_tor_tab:
                st.caption(
                    "Checks every origin + hop IP across every email currently loaded "
                    "(this session's cases) against three cached lists -- the Tor "
                    "Project's official exit list, a community exit-node mirror, and "
                    "that same mirror's full Tor node list -- in one pass, no per-email "
                    "lookups."
                )

                # Same left/right layout as the VPN tab: fetch on the left,
                # scan on the right -- one row, not stacked. This replaces
                # the separate fetch button that used to live only in the
                # "Tor Exit-Node List Status" panel below, so there's a
                # single place to refresh before scanning, not two.
                _tor_fetch_col, _tor_scan_col = st.columns(2)
                with _tor_fetch_col:
                    if st.button(
                        "Fetch Tor lists now (needs internet)",
                        key="fetch_tor_list_btn",
                        use_container_width=True,
                    ):
                        with st.spinner("Fetching from the Tor Project and community mirrors..."):
                            _tor_results = tor_check.update_tor_exit_list()
                        _tor_failed = [k for k, v in _tor_results.items() if v is None]
                        if _tor_failed:
                            _fail_labels = [tor_check.SOURCES[k][1] for k in _tor_failed]
                            # Asymmetric by design (see tor_check.py): a source
                            # that fails keeps whatever it had before rather
                            # than going blank, so detection only ever gets
                            # weaker, never wrong.
                            st.warning(
                                "Refreshed what we could. This source failed and kept its "
                                "previous cached data rather than being wiped: " +
                                "; ".join(_fail_labels)
                            )
                        else:
                            st.success(
                                "Refreshed all sources — " +
                                ", ".join(f"{tor_check.SOURCES[k][1]}: {v} IPs" for k, v in _tor_results.items())
                            )
                        st.rerun()
                with _tor_scan_col:
                    _run_tor_scan = st.button("Scan all loaded emails", key="run_tor_bulk_scan", type="primary", use_container_width=True)
                if _run_tor_scan:
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
                    "' Tor Exit-Node List Status' panel below."
                )

        # Routing chain / anonymised caution follow whichever email the map
        # above is showing (the currently loaded one, unless "by email" was
        # used to pick a different one) -- "all senders" mode has no single
        # chain to show, so these keep describing the currently loaded message.
        if _table_geo.get("hops"):
            st.subheader("Routing chain")
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
        st.subheader("Semantic Origin Correlation (Nomic Embeddings)")
        st.caption(
            "Uses the local nomic-embed-text model, served by Ollama, to compare this "
            "message's origin/routing profile against previously analyzed emails by "
            "MEANING rather than exact match - so differently-hosted infrastructure "
            "that behaves the same way can still surface as related, even with no "
            "shared IP or domain."
        )

        if not nomic_available():
            st.warning(
                "Nomic embeddings unavailable right now: either Ollama isn't running, "
                "or the `nomic-embed-text` model hasn't been pulled yet. Run "
                "`ollama pull nomic-embed-text`, make sure Ollama is running, then "
                "reopen this panel."
            )
            return

        origin = geo.get("origin", {}) or {}
        description = _sem_describe_origin(geo)

        with st.expander("Text sent to the embedding model"):
            st.text(description)

        _sem_min = st.slider(
            "Minimum match score", 0.30, 0.95, float(_SEM_MIN_SIMILARITY), 0.05,
            format="%.2f", key="nomic_min_score",
            help="Matches scoring below this are hidden as noise. Raise it for fewer, stronger matches; lower it to explore weak leads.",
        )

        _run_col, _idx_col = st.columns(2)
        with _run_col:
            _run_embed = st.button("Run Semantic Origin Analysis", key="run_nomic_embed", use_container_width=True, type="primary")
        with _idx_col:
            _run_index = st.button(
                "Index all loaded emails", key="index_all_nomic", use_container_width=True,
                help="Embeds the origin profile of every email loaded this session, so this email has more to be compared against.",
            )

        if _run_embed:
            with st.spinner("Embedding this origin profile with nomic-embed-text..."):
                _ok, _err = _sem_index(current_evidence_hash, geo, force=True)
            if not _ok:
                st.error(_err)
            else:
                st.session_state["nomic_last_hash"] = current_evidence_hash
                st.success("Embedding stored. Comparing against previously analyzed origins below.")

        if _run_index:
            _pair_map = {h: (r.get("geo") or {}) for h, r in _corr_cases.items() if isinstance(r, dict) and "error" not in r}
            _pair_map[current_evidence_hash] = geo
            _n_new = _sem_index_many(list(_pair_map.items()), label="Indexing every loaded email's origin profile...")
            st.session_state["nomic_last_hash"] = current_evidence_hash
            st.success(f"Indexed {_n_new} new origin profile(s); {len(_pair_map)} loaded email(s) are now searchable.")

        _indexed_now = current_evidence_hash in st.session_state.get("_sem_indexed", {})
        if st.session_state.get("nomic_last_hash") == current_evidence_hash or _indexed_now:
            matches = _sem_find(current_evidence_hash, origin, top_k=8, min_score=_sem_min)
            if matches:
                st.markdown("##### Closest previously analyzed origins (by meaning)")
                st.markdown(_sem_headline(matches))
                _render_polished_table(pd.DataFrame(_sem_rows(matches)))
            else:
                st.info(
                    _sem_none_text(_sem_min) + " Use 'Index all loaded emails', run this on more emails, "
                    "or lower the minimum match score."
                )
            st.caption(_SEM_METHOD_NOTE)

    panel(_geo_semantic, "Semantic Origin Correlation")

# --------------------------------------------------------------------------
# 4. Indicators of compromise
# --------------------------------------------------------------------------
if active_panel == "Indicators":
    def _iocs():
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
        st.markdown("## Extracted Indicators")
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
            st.markdown("### URL Intelligence")
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
            st.subheader("Attachments")
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
        st.markdown(
            '<div style="padding:4px 0 14px 0;">'
            '<div style="font-size:28px;font-weight:800;letter-spacing:.2px;color:#e8f1ff;">'
            'Campaign Correlation & Attribution</div>'
            '<div style="margin-top:5px;font-size:13px;color:#7f8da3;line-height:1.5;">'
            'Correlate analyzed messages through shared infrastructure, indicators and identity signals.</div>'
            '</div>', unsafe_allow_html=True
        )

        saved_bulk_cases = st.session_state.get("bulk_scan_cases")
        saved_bulk_hash = st.session_state.get("bulk_scan_cases_hash")
        current_csv_hash = csv_scan_key if (uploaded is not None and uploaded.name.lower().endswith(".csv")) else None

        if saved_bulk_cases and current_csv_hash == saved_bulk_hash:
            cases = [r for r in saved_bulk_cases if "error" not in r]
        else:
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

        st.markdown(
            '<div style="font-size:15px;font-weight:750;color:#e5edf7;margin-bottom:4px;">◉ Infrastructure Correlation Map</div>'
            '<div style="font-size:12px;color:#7f8da3;margin-bottom:10px;">Solid lines are shared indicators straight from the evidence. Dashed lines are AI-inferred semantic matches. Click a node to trace its connections.</div>',
            unsafe_allow_html=True
        )

        # Keep the picture legible: large campaigns are thinned to a random,
        # manageable sample (the metrics/table above always cover every
        # case regardless). The sample and any node highlight stay put
        # across unrelated reruns, and only change when the case set
        # changes or the analyst explicitly asks.
        graph_scope = hashlib.sha256(
            "|".join(sorted(r.get("_evidence_hash", "") for r in cases)).encode()
        ).hexdigest()[:12]
        if st.session_state.get("corr_graph_scope") != graph_scope:
            st.session_state["corr_graph_scope"] = graph_scope
            st.session_state["corr_graph_seed"] = random.randint(0, 2**31 - 1)
            st.session_state.pop("corr_graph_highlight", None)
            st.session_state.pop("corr_graph_max_cases", None)
            st.session_state["corr_graph_key_nonce"] = st.session_state.get("corr_graph_key_nonce", 0) + 1

        ctrl1, ctrl2, ctrl3 = st.columns([2.2, 2, 1.2])
        with ctrl1:
            if len(cases) > 5:
                cases_to_show = st.slider(
                    "Cases shown in graph", min_value=5,
                    max_value=min(len(cases), 50), value=min(20, len(cases)),
                    key="corr_graph_max_cases",
                    help="Larger campaigns are thinned to a random sample so the picture stays readable.",
                )
            else:
                cases_to_show = len(cases)
        with ctrl2:
            use_semantic = st.checkbox(
                "AI-inferred semantic links", value=False, key="corr_graph_semantic",
                help="Runs a similarity search per case shown to surface origins that resemble each other even with no shared indicator. Slower - opt in.",
            )
        with ctrl3:
            if st.button("Shuffle", use_container_width=True, key="corr_graph_shuffle"):
                st.session_state["corr_graph_seed"] = random.randint(0, 2**31 - 1)
                st.session_state.pop("corr_graph_highlight", None)
                st.session_state["corr_graph_key_nonce"] = st.session_state.get("corr_graph_key_nonce", 0) + 1
                st.rerun()

        highlight_node = st.session_state.get("corr_graph_highlight")
        seed = st.session_state["corr_graph_seed"]
        # Cache miss (new data/settings) is the only time this actually
        # does the expensive layout work, so the spinner only shows then.
        if use_semantic:
            with st.spinner("Searching for semantically similar origins..."):
                fig, G_view, semantic_failed, sampled, shown_count, total_count = _cached_correlation_view(
                    graph_scope, cases, cases_to_show, seed, use_semantic, highlight_node,
                )
        else:
            fig, G_view, semantic_failed, sampled, shown_count, total_count = _cached_correlation_view(
                graph_scope, cases, cases_to_show, seed, use_semantic, highlight_node,
            )
        if semantic_failed:
            st.caption("AI semantic similarity search isn't available right now - showing indicator-based links only.")
        if sampled:
            st.caption(f"Showing a random {shown_count} of {total_count} analyzed cases - shuffle for a different sample.")

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
        st.subheader("Threat History")
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
        _view, _cfg = _display_email_table(_hist_view)
        st.dataframe(_view, width="stretch", hide_index=True, column_config=_cfg)

    panel(_threat_history, "Threat History")

if active_panel == "URLHaus Feed":
    def _urlhaus_feed():
        st.subheader("URLHaus Threat Intelligence Feed")
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
            conn = get_connection()
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
        st.subheader("Antivirus (ClamAV)")
        av_up = _clamd_up_cached()
        if av_up:
            st.success(f" ClamAV connected - {clamd_version() or 'clamd daemon'}")
            st.caption("Every attachment below was streamed to your local clamd daemon in memory (zINSTREAM) - a real signature scan, not a heuristic.")
        else:
            st.warning(
                "Could not reach the clamd daemon at the configured host/port - falling back to the "
                "app's own risky-extension check. Confirm clamd is running, or set "
                "SIH26106_CLAMD_HOST / SIH26106_CLAMD_PORT if it isn't on 127.0.0.1:3310."
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
    
    # Define a custom center layout constraint here, isolating it safely
    d_spacer_l, d_center, d_spacer_r = st.columns([1, 8, 1])
    
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
            st.markdown("---")
            st.markdown(f"#### Joint Report — {pipeline_result.get('count', len(report_items))} Emails ({pipeline_result.get('source', '')})")
            st.caption("Machine analysis + AI threat analysis + semantic origin correlation, combined across the batch. Drill into any single email below, or grab everything at once.")

            _ai_res = pipeline_result.get("result", {}) or {}
            _joint_ai_text = ""
            if _ai_res.get("ok"):
                _joint_ai_text = _clean_ai_display(_ai_res.get("analysis", ""))
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
                f"# SIH26106 - JOINT FORENSIC REPORT ({pipeline_result.get('count', len(report_items))} EMAILS)\n\n"
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
            st.divider()

        sel_pos = st.selectbox(
            "Select Email Number to Inspect",
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

        st.markdown(f"### Dossier: Email #{sel_pos}")

        # --- SHOW HIGHLY DETAILED MACHINE REPORT UI USING DATAFRAMES ---
        st.markdown("#### Machine Forensic Analysis")
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

        machine_md = f"""# SIH26106 - DIGITAL FORENSIC EVIDENCE REPORT

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
        st.markdown("#### AI Threat Report")
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

        ai_md = f"""# SIH26106 - AI THREAT ASSESSMENT

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
        st.markdown("#### Download Forensic Report")
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