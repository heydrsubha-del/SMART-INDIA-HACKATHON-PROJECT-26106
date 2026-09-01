"""SIH26106 - AI-Powered Email Threat Detection, GeoLocation & Forensic
Intelligence Platform.

Run:   streamlit run app.py

"""
import os
import traceback
import hashlib
import time
import textwrap
import csv
import io
import sys

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from tracker import (
    init_db,
    log_threat,
    check_history,
    add_feedback,
    import_urlhaus_recent,
    get_feedback_history_count,
)

import folium
from streamlit_folium import st_folium

import config as C
import correlate
from analyzer import analyze_all_samples, analyze_email, list_samples
from classifier import (
    cached_metrics,
    load_or_train,
    maybe_retrain_from_feedback,
    get_adaptive_status,
    get_feedback_count,
)
from geolocate import INFRA_LABEL
from report import build_report, evidence_hash

st.set_page_config(
    page_title="AI-Powered Email Threat Detection, GeoLocation & Forensic | SIH26106",
    page_icon="\U0001F6E1",
    layout="wide",
    initial_sidebar_state="expanded"
)
uploaded = None

# --------------------------------------------------------------------------
# Threat Intelligence / API Access
# --------------------------------------------------------------------------

with st.sidebar:
    st.markdown(
        """
        <div style="
            padding: 4px 2px 12px 2px;
        ">
            <div style="
                font-size:18px;
                font-weight:800;
                color:#e8f1ff;
                letter-spacing:.4px;
            ">
                🌐 Threat Intelligence
            </div>
            <div style="
                font-size:11px;
                color:#7f8da3;
                margin-top:4px;
                line-height:1.4;
            ">
                External intelligence is stored locally so normal
                email analysis remains fast.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div style="
            font-size:13px;
            font-weight:700;
            color:#b9c6d8;
            margin:2px 0 8px 0;
        ">
            🔐 API ACCESS
        </div>
        """,
        unsafe_allow_html=True
    )

    # Prefer a secure Streamlit secret for deployment/demo.
    try:
        configured_key = st.secrets.get("URLHAUS_AUTH_KEY", "")
    except Exception:
        configured_key = ""

    # Session-only fallback for local development.
    if configured_key:
        urlhaus_key = configured_key
        key_source = "Secure secret"
    else:
        urlhaus_key = st.text_input(
            "URLhaus Auth-Key",
            type="password",
            key="urlhaus_auth_key",
            placeholder="Enter Auth-Key",
            help="Used only for the current Streamlit session."
        )
        key_source = "Session only"

    # Connection status
    if urlhaus_key:
        status_html = """
        <div style="
            display:flex;
            align-items:center;
            gap:8px;
            padding:9px 11px;
            margin:8px 0 10px 0;
            border:1px solid rgba(34,197,94,.28);
            border-radius:8px;
            background:rgba(34,197,94,.08);
        ">
            <span style="
                width:8px;
                height:8px;
                border-radius:50%;
                background:#22c55e;
                display:inline-block;
                box-shadow:0 0 8px rgba(34,197,94,.55);
            "></span>
            <span style="
                color:#86efac;
                font-size:12px;
                font-weight:700;
            ">
                API CONFIGURED
            </span>
        </div>
        """
    else:
        status_html = """
        <div style="
            display:flex;
            align-items:center;
            gap:8px;
            padding:9px 11px;
            margin:8px 0 10px 0;
            border:1px solid rgba(234,179,8,.25);
            border-radius:8px;
            background:rgba(234,179,8,.07);
        ">
            <span style="
                width:8px;
                height:8px;
                border-radius:50%;
                background:#eab308;
                display:inline-block;
            "></span>
            <span style="
                color:#fde68a;
                font-size:12px;
                font-weight:700;
            ">
                API NOT CONFIGURED
            </span>
        </div>
        """

    st.markdown(
    textwrap.dedent(status_html).strip(),
    unsafe_allow_html=True
)

    st.caption(f"Key storage: {key_source}")

    st.divider()

    # Update intelligence
    if st.button(
        "↻  Update Threat Intelligence",
        key="update_urlhaus",
        use_container_width=True
    ):
        if not urlhaus_key:
            st.warning("Enter a URLhaus Auth-Key first.")
        else:
            with st.spinner("Synchronizing threat intelligence..."):
                try:
                    intel_result = import_urlhaus_recent(urlhaus_key)

                    status = intel_result.get("status", "error")
                    message = intel_result.get(
                        "message",
                        "Threat-intelligence update completed."
                    )

                    if status == "updated":
                        st.success(message)
                        st.session_state["intel_last_status"] = "Updated"

                    elif status == "cached":
                        st.info(message)
                        st.session_state["intel_last_status"] = "Cached"

                    else:
                        st.error(message)
                        st.session_state["intel_last_status"] = "Failed"

                except Exception as exc:
                    st.error(
                        f"Threat-intelligence update failed: {exc}"
                    )
                    st.session_state["intel_last_status"] = "Failed"

        last_status = st.session_state.get(
            "intel_last_status",
            "Not synchronized this session"
        )

        # Feed status card
        st.markdown("### 🌐 Intelligence Feed")

        with st.container(border=True):
            st.markdown("**URLhaus**")

            status_icon = {
                "Updated": "🟢",
                "Cached": "🔵",
                "Failed": "🔴",
            }.get(last_status, "🟡")

            st.caption(
                f"{status_icon} Status: {last_status}"
            )


# --------------------------------------------------------------------------
# CUSTOM ENTERPRISE SOC UI STYLING
# --------------------------------------------------------------------------

st.markdown(
    """
    <style>

    /* ---------------------------------------------------------
       Streamlit chrome
       --------------------------------------------------------- */
    #MainMenu {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }

    /* Keep header visible so sidebar controls work normally. */

    /* ---------------------------------------------------------
       Application background
       --------------------------------------------------------- */
    .stApp {
        background:
            radial-gradient(
                circle at top right,
                rgba(0, 210, 255, 0.045),
                transparent 30%
            ),
            #0b0f19;
        color: #e0e6ed;
    }

    /* ---------------------------------------------------------
       Main title
       --------------------------------------------------------- */
    h1 {
        font-family:
            'Consolas',
            'Courier New',
            monospace !important;
        color: #00d2ff !important;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        text-align: center;
        text-shadow: 0 0 15px rgba(0, 210, 255, 0.25);
        margin-bottom: 0 !important;
    }

    /* ---------------------------------------------------------
       File uploader
       --------------------------------------------------------- */
    .stFileUploader {
        border: 1px dashed rgba(0, 210, 255, 0.55) !important;
        border-radius: 10px;
        background: rgba(17, 24, 39, 0.65) !important;
        padding: 12px;
        transition: border-color .2s ease, box-shadow .2s ease;
    }

    .stFileUploader:hover {
        border-color: rgba(0, 210, 255, 0.9) !important;
        box-shadow: 0 0 18px rgba(0, 210, 255, 0.08);
    }

    /* ---------------------------------------------------------
       Buttons
       Don't force every button red.
       --------------------------------------------------------- */
    .stButton > button {
        border-radius: 8px;
        font-weight: 700;
        letter-spacing: .35px;
        min-height: 40px;
        transition:
            transform .15s ease,
            box-shadow .15s ease,
            border-color .15s ease;
    }

    .stButton > button:hover {
        transform: translateY(-1px);
    }

    /* ---------------------------------------------------------
       Inputs
       --------------------------------------------------------- */
    .stTextInput input,
    .stNumberInput input {
        background: #111827 !important;
        color: #e5edf7 !important;
        border: 1px solid #2b3748 !important;
        border-radius: 8px !important;
    }

    .stTextInput input:focus,
    .stNumberInput input:focus {
        border-color: #00d2ff !important;
        box-shadow: 0 0 0 1px rgba(0, 210, 255, 0.18) !important;
    }

    /* ---------------------------------------------------------
       Expanders
       --------------------------------------------------------- */
    .streamlit-expanderHeader {
        background: #111827 !important;
        color: #dbe7f5 !important;
        font-weight: 700;
        border-radius: 7px;
    }

    /* =========================================================
       ANALYST FEEDBACK TYPING EFFECT
       ========================================================= */
    .feedback-typing-text {
        font-weight: 500;
    }

    .typing-cursor {
        display: inline-block;
        width: 2px;
        height: 1em;
        margin-left: 4px;
        vertical-align: -2px;
        background: currentColor;
        animation: blink .7s infinite;
    }

    @keyframes blink {
        0%, 49% {
            opacity: 1;
        }

        50%, 100% {
            opacity: 0;
        }
    }

    </style>
    """,
    unsafe_allow_html=True
)

def show_feedback_typing(message, message_type="success"):
    """Display a realistic terminal-style typing animation."""
    
    placeholder = st.empty()

    icon = "✅" if message_type == "success" else "ℹ️"

    # Start with the icon and empty cursor
    placeholder.markdown(
        f"""
        <div class="feedback-result {'feedback-result-success' if message_type == 'success' else 'feedback-result-info'}">
            <span class="feedback-result-icon">{icon}</span>
            <span class="feedback-typing-text">|</span>
        </div>
        """,
        unsafe_allow_html=True
    )

    typed = ""

    for char in message:
        typed += char

        placeholder.markdown(
            f"""
            <div class="feedback-result {'feedback-result-success' if message_type == 'success' else 'feedback-result-info'}">
                <span class="feedback-result-icon">{icon}</span>
                <span class="feedback-typing-text">{typed}<span class="typing-cursor">|</span></span>
            </div>
            """,
            unsafe_allow_html=True
        )

        time.sleep(0.025)

    # Final state without cursor
    placeholder.markdown(
        f"""
        <div class="feedback-result {'feedback-result-success' if message_type == 'success' else 'feedback-result-info'}">
            <span class="feedback-result-icon">{icon}</span>
            <span class="feedback-typing-text">{message}</span>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown("""
<style>
.feedback-panel {
    background: rgba(17, 24, 39, 0.72);
    border: 1px solid #263244;
    border-radius: 12px;
    padding: 18px 20px;
    margin: 8px 0 14px 0;
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.18);
}

.feedback-title {
    color: #e5edf7;
    font-size: 20px;
    font-weight: 700;
    letter-spacing: 0.3px;
}

.feedback-subtitle {
    color: #8b98aa;
    font-size: 13px;
    margin-top: 4px;
}

/* Confirm Threat */
div[data-testid="stBaseButton-primary"] button {
    min-height: 48px !important;
    border-radius: 8px !important;
    border: 1px solid #238636 !important;
    background: linear-gradient(180deg, #1f8f4c 0%, #176b3b 100%) !important;
    color: #ffffff !important;
    font-weight: 700 !important;
    font-size: 14px !important;
    letter-spacing: 0.3px;
    box-shadow: 0 4px 16px rgba(35, 134, 54, 0.20) !important;
    transition: all 0.18s ease !important;
}

/* Confirm Threat hover */
div[data-testid="stBaseButton-primary"] button:hover {
    transform: translateY(-1px);
    border-color: #2ea043 !important;
    box-shadow: 0 7px 22px rgba(35, 134, 54, 0.30) !important;
}

/* False Positive */
div[data-testid="stBaseButton-secondary"] button {
    min-height: 48px !important;
    border-radius: 8px !important;
    border: 1px solid #8b2c3b !important;
    background: linear-gradient(180deg, #7f2635 0%, #5c1d29 100%) !important;
    color: #ffffff !important;
    font-weight: 700 !important;
    font-size: 14px !important;
    letter-spacing: 0.3px;
    box-shadow: 0 4px 16px rgba(185, 28, 28, 0.16) !important;
    transition: all 0.18s ease !important;
}

/* False Positive hover */
div[data-testid="stBaseButton-secondary"] button:hover {
    transform: translateY(-1px);
    border-color: #b23a4d !important;
    box-shadow: 0 7px 22px rgba(185, 28, 28, 0.26) !important;
}

/* Feedback success/info messages */
div[data-testid="stAlert"] {
    border-radius: 8px !important;
    margin-top: 10px !important;
}

/* =========================================================
   FEEDBACK RESULT PANEL
   ========================================================= */

.feedback-typing {
    display: inline-block;
    white-space: nowrap;
    overflow: hidden;
    width: 0;
    animation:
        feedbackTyping 1.6s steps(45, end) forwards,
        feedbackCursor 0.7s step-end infinite;
    border-right: 2px solid currentColor;
}

@keyframes feedbackTyping {
    from {
        width: 0;
    }
    to {
        width: 100%;
    }
}

@keyframes feedbackCursor {
    50% {
        border-color: transparent;
    }
}

.feedback-result {
    width: 100%;
    box-sizing: border-box;
    margin-top: 14px;
    padding: 17px 20px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 15px;
    font-weight: 600;
    letter-spacing: 0.2px;
    min-height: 54px;
}

.feedback-result-success {
    background: rgba(22, 101, 52, 0.28);
    border: 1px solid rgba(46, 160, 67, 0.45);
    color: #4ade80;
}

.feedback-result-info {
    background: rgba(30, 64, 175, 0.25);
    border: 1px solid rgba(59, 130, 246, 0.35);
    color: #60a5fa;
}

.feedback-result-icon {
    font-size: 18px;
    flex-shrink: 0;
}

.feedback-typing-text {
    font-family: "Consolas", "Courier New", monospace;
}

.typing-cursor {
    display: inline-block;
    margin-left: 2px;
    animation: typingBlink 0.7s steps(1) infinite;
}

@keyframes typingBlink {
    0%, 50% {
        opacity: 1;
    }
    51%, 100% {
        opacity: 0;
    }
}

</style>
""", unsafe_allow_html=True)                  

SEV_COLOR = {"high": "#b71c1c", "medium": "#f9a825", "low": "#78909c",
             "info": "#546e7a"}
AUTH_COLOR = {"pass": "#2e7d32", "fail": "#b71c1c", "softfail": "#e65100",
              "none": "#78909c", "neutral": "#78909c"}


# --------------------------------------------------------------------------
# Cached heavy work - the model trains once per session, not once per click.
# --------------------------------------------------------------------------
@st.cache_resource(show_spinner="Loading phishing model...")

def get_model(model_version=0):
    """
    Load the current model once.

    model_version changes only when the model file changes,
    allowing Streamlit to reuse the model across normal reruns.
    """
    return load_or_train()


@st.cache_data(show_spinner="Analysing shipped samples...")
def get_sample_results():
    return analyze_all_samples(get_model())


@st.cache_data(show_spinner="Analysing message...")
def analyze_bytes(raw, name):
    return analyze_email(raw, name, get_model())


def panel(fn, label):
    """Render one section, showing the error inline instead of killing the app."""
    try:
        fn()
    except Exception:
        st.error("The **{}** panel failed. Everything else still works.".format(label))
        with st.expander("Technical detail"):
            st.code(traceback.format_exc())


st.markdown("<h1 style='font-family: \"Orbitron\", sans-serif; font-size: 48px !important; color: #00d2ff; text-transform: uppercase; text-align: center; text-shadow: 0 0 20px rgba(0,210,255,0.6); line-height: 1.1; margin-bottom: 0px;'>AI-Powered Email Threat Detection, GeoLocation & Forensic</h1>", unsafe_allow_html=True)
st.markdown("<p style='font-family: \"Rajdhani\", sans-serif; text-align: center; color: #6b7280; font-size: 16px; margin-top: 5px; letter-spacing: 1px;'>SIH26106 | ADVANCED PERSISTENT THREAT MONITORING</p>", unsafe_allow_html=True)
st.write("")

# High-tech toggle between File Upload and Live Interceptor
input_mode = st.radio("Select Threat Acquisition Mode", ["📁 Evidence File Upload (.eml, .txt, .csv)", "⚡ Live IMAP Mailbox Interceptor"], horizontal=True)

raw = None
case_name = ""
uploaded = None

if "Evidence File Upload" in input_mode:
    uploaded = st.file_uploader("📂 Drop evidence file below", type=["eml", "txt", "csv"])
    if not uploaded:
        st.info("👋 Upload a suspicious email or bulk CSV dataset above to begin deep forensic analysis.")
        st.stop()
elif "Live IMAP Mailbox Interceptor" in input_mode:
    # --- LIVE IMAP MODE ---
    st.markdown("### ⚡ Live Mailbox Interceptor")
    col1, col2, col3 = st.columns(3)
    imap_host = col1.text_input("IMAP Server", "imap.gmail.com")
    imap_user = col2.text_input(
        "Email Address",
        placeholder="you@example.com"
    )
    imap_pass = col3.text_input("App Password / Token", type="password")

    if st.button("🔌 Connect & Scan Live Inbox"):
        if not imap_pass:
            st.warning("Please enter your mailbox app password or token.")
            st.stop()
        else:
            from live_scanner import fetch_live_emails
            with st.spinner("Intercepting unread traffic from mail server..."):
                live_msgs = fetch_live_emails(imap_host, imap_user, imap_pass)

            if live_msgs:
                st.session_state['live_msgs'] = live_msgs
            else:
                st.info("No unread messages found in the live inbox.")
                st.stop()

    if 'live_msgs' in st.session_state and st.session_state['live_msgs']:
        st.success(f"Intercepted {len(st.session_state['live_msgs'])} live emails!")
        selected_live = st.selectbox(
            "Select Intercepted Message to Analyze",
            st.session_state['live_msgs'],
            format_func=lambda x: f"From: {x['from']} | Subject: {x['subject']}"
        )
        raw = selected_live['raw_bytes']
        case_name = f"Live IMAP: {selected_live['subject']}"
    else:
        st.info("👋 Enter your IMAP credentials above and click connect to load live messages.")
        st.stop()
else:
    st.info("Please select a threat acquisition mode.")
    st.stop()

@st.cache_data(show_spinner=False)
def parse_email_csv(file_bytes):
    # Allow large email fields inside CSV files.
    # Important for datasets containing full raw emails/headers.
    csv.field_size_limit(50 * 1024 * 1024)  # 50 MB per field

    text = file_bytes.decode(
        "utf-8-sig",
        errors="replace"
    )

    reader = csv.DictReader(
        io.StringIO(text, newline="")
    )

    if not reader.fieldnames:
        return []

    fields = [
        str(f).strip()
        for f in reader.fieldnames
        if f is not None
    ]

    preferred = [
        "raw_email",
        "raw_message",
        "email",
        "email_text",
        "message",
        "body",
        "content",
        "text",
    ]

    selected = None

    for wanted in preferred:
        for field in fields:

            normalized = (
                field.lower()
                .strip()
                .replace(" ", "_")
                .replace("-", "_")
            )

            if normalized == wanted:
                selected = field
                break

        if selected:
            break

    data = []

    for row in reader:

        if selected:
            value = row.get(
                selected,
                ""
            )

        else:
            # Fallback: select the largest textual field.
            values = [
                str(v or "")
                for v in row.values()
            ]

            value = max(
                values,
                key=len,
                default=""
            )

        value = str(value or "")

        if value.strip():
            data.append(value)

    return data

# --- File Processing ---

if uploaded is not None:

    if uploaded.name.endswith(".csv"):

        # ---------------------------------------------------------------
        # SAFE CSV PARSING
        # ---------------------------------------------------------------
        data = parse_email_csv(
            uploaded.getvalue()
        )
        csv_scan_key = hashlib.sha256(
            uploaded.getvalue()
        ).hexdigest()

        if st.session_state.get("bulk_scan_file_key") != csv_scan_key:
            st.session_state["bulk_scan_file_key"] = csv_scan_key
            st.session_state["bulk_scan_results"] = None
            st.session_state["bulk_scan_map"] = None
            st.session_state["bulk_scan_mapped_points"] = 0

        if not data:
            st.error(
                "No email messages could be extracted from this CSV."
            )
            st.stop()

        # ---------------------------------------------------------------
        # PROMINENT BULK THREAT SCANNER
        # ---------------------------------------------------------------

        st.markdown("## 🌍 Bulk Threat Scanner")

        st.caption(
            "Analyze the entire CSV dataset, trace globally resolvable "
            "infrastructure, visualize routing paths and generate a "
            "forensic report."
        )

        b1, b2, b3, b4 = st.columns(4)

        with b1:
            st.info("🛰️ Satellite Map")

        with b2:
            st.info("📍 Global IP Tracking")

        with b3:
            st.warning("⚡ Live Route Arcs")

        with b4:
            st.success("📄 Forensic Report")

        st.info(
            f"📦 **{len(data):,}** email records loaded from "
            f"**{uploaded.name}**"
        )

        if st.button(
            "🚀 RUN GLOBAL IP SCAN",
            key="run_global_ip_scan",
            use_container_width=True
        ):
            st.info(
                f"📦 **{len(data):,}** email records loaded from "
                f"**{uploaded.name}**"
            )

            # ---------------------------------------------------------------
            # MAIN SCAN BUTTON
            # ---------------------------------------------------------------
            progress_bar = st.progress(
                0,
                text="Initiating Threat Scan... 0%"
            )

            bulk_results = []

            # -----------------------------------------------------------
            # GLOBAL SATELLITE MAP
            # -----------------------------------------------------------
            global_map = folium.Map(
                location=[20.0, 0.0],
                zoom_start=2,
                tiles=(
                    "https://server.arcgisonline.com/"
                    "ArcGIS/rest/services/World_Imagery/"
                    "MapServer/tile/{z}/{y}/{x}"
                ),
                attr="Esri World Imagery"
            )

            mapped_points = 0

            # -----------------------------------------------------------
            # ANALYZE EVERY EMAIL
            # -----------------------------------------------------------
            update_every = max(
    1,
    min(
        10,
        len(data) // 20
    )
)
            for i, text in enumerate(data):

                row_raw = (
                    text
                    .replace("\\n", "\n")
                    .encode("utf-8")
                )

                res = analyze_bytes(
                    row_raw,
                    f"Row {i}"
                )

                # -------------------------------------------------------
                # ORIGIN INFORMATION
                # -------------------------------------------------------
                origin = (
                    res
                    .get("geo", {})
                    .get("origin", {})
                )

                ip = origin.get("ip") or "Unknown"
                country = origin.get("country") or "Unknown"
                score = res.get("score", 0)

                # -------------------------------------------------------
                # ALL GEOLOCATED HOPS
                # -------------------------------------------------------
                hops = (
                    res
                    .get("geo", {})
                    .get("hops", [])
                )

                route_coords = []

                for h in hops:

                    h_lat = h.get("lat")
                    h_lon = h.get("lon")
                    h_ip = h.get("ip")

                    if h_lat is not None and h_lon is not None:

                        route_coords.append(
                            [h_lat, h_lon]
                        )

                        is_origin = (
                            h_ip == ip
                        )

                        marker_color = (
                            "red"
                            if is_origin
                            else "#00bfff"
                        )

                        radius = (
                            6
                            if is_origin
                            else 3
                        )

                        folium.CircleMarker(
                            location=[
                                h_lat,
                                h_lon
                            ],
                            radius=radius,
                            color=marker_color,
                            fill=True,
                            fill_color=marker_color,
                            fill_opacity=0.7,
                            popup=(
                                f"Row {i}<br>"
                                f"IP: {h_ip}<br>"
                                f"{'Origin' if is_origin else 'Relay'} "
                                f"({h.get('country', 'Unknown')})"
                            )
                        ).add_to(global_map)

                        mapped_points += 1

                # -------------------------------------------------------
                # HQ TARGET WHEN ONLY ONE GEOLOCATED HOP EXISTS
                # -------------------------------------------------------
                if len(route_coords) == 1:

                    hq_coords = [
                        22.5726,
                        88.3639
                    ]

                    route_coords.append(
                        hq_coords
                    )

                    folium.CircleMarker(
                        location=hq_coords,
                        radius=5,
                        color="#00ff00",
                        fill=True,
                        fill_opacity=0.9,
                        popup="Target Datacenter (HQ)"
                    ).add_to(global_map)

                # -------------------------------------------------------
                # ANIMATED ROUTE ARCS
                # -------------------------------------------------------
                if len(route_coords) > 1:

                    from folium.plugins import AntPath
                    import math

                    line_color = (
                        "red"
                        if score > 50
                        else "#00bfff"
                    )

                    for step in range(
                        len(route_coords) - 1
                    ):

                        lat1 = route_coords[step][0]
                        lon1 = route_coords[step][1]

                        lat2 = route_coords[step + 1][0]
                        lon2 = route_coords[step + 1][1]

                        arc_points = []

                        mid_lat = (
                            lat1 + lat2
                        ) / 2.0

                        mid_lon = (
                            lon1 + lon2
                        ) / 2.0

                        distance = math.sqrt(
                            (lat2 - lat1) ** 2
                            +
                            (lon2 - lon1) ** 2
                        )

                        mid_lat += (
                            distance * 0.25
                        )

                        for frame in range(51):

                            t = frame / 50.0

                            lat = (
                                (1 - t) ** 2 * lat1
                                +
                                2 * (1 - t) * t
                                * mid_lat
                                +
                                t ** 2 * lat2
                            )

                            lon = (
                                (1 - t) ** 2 * lon1
                                +
                                2 * (1 - t) * t
                                * mid_lon
                                +
                                t ** 2 * lon2
                            )

                            arc_points.append(
                                [lat, lon]
                            )

                        AntPath(
                            locations=arc_points,
                            color=line_color,
                            pulse_color="#ffffff",
                            weight=3,
                            opacity=0.8,
                            delay=800,
                            dash_array=[15, 30]
                        ).add_to(global_map)

                # -------------------------------------------------------
                # REPORT DATA
                # -------------------------------------------------------
                bulk_results.append({
                    "Row ID": i,
                    "Origin IP": ip,
                    "Country": country,
                    "Threat Score": round(
                        score,
                        1
                    ),
                    "Verdict": (
                        res
                        .get("level", "unknown")
                        .upper()
                    )
                })

                # -------------------------------------------------------
                # PROGRESS
                # -------------------------------------------------------
                if (
                    (i + 1) % update_every == 0
                    or i + 1 == len(data)
                ):

                    current_pct = int(
                        ((i + 1) / len(data))
                        * 100
                    )

                    progress_bar.progress(
                        (i + 1) / len(data),
                        text=(
                            f"Analyzing Evidence... "
                            f"{current_pct}% "
                            f"({i + 1:,} of "
                            f"{len(data):,} processed)"
                        )
                    )

            # -----------------------------------------------------------
            # SCAN COMPLETE
            # -----------------------------------------------------------

            st.session_state["bulk_scan_results"] = bulk_results
            st.session_state["bulk_scan_map"] = global_map
            st.session_state["bulk_scan_mapped_points"] = mapped_points

            st.success(
                f"✅ Bulk Scan Complete! "
                f"Tracked {mapped_points:,} geolocated "
                f"IPs globally."
            )

            # -----------------------------------------------------------
            # GLOBAL MAP
            # -----------------------------------------------------------
            if mapped_points > 0:

                st.markdown(
                    "### 🛰️ Global Threat Infrastructure Map"
                )

                st.caption(
                    "Satellite view with geolocated hops, "
                    "origin markers and animated routing paths."
                )

                st_folium(
                    global_map,
                    width=1000,
                    height=550,
                    returned_objects=[]
                )

            else:

                st.warning(
                    "No globally geolocatable hops were found "
                    "in the analyzed dataset."
                )

            
                   # PERSISTED BULK SCAN RESULTS
        # Keeps previous scan visible after feedback or other reruns.
        # ---------------------------------------------------------------

        saved_bulk_results = st.session_state.get(
            "bulk_scan_results"
        )

        saved_bulk_map = st.session_state.get(
            "bulk_scan_map"
        )

        saved_mapped_points = st.session_state.get(
            "bulk_scan_mapped_points",
            0
        )

        if saved_bulk_results is not None:

            st.divider()

            st.markdown(
                "### 📊 Global Threat Scan Results"
            )

            st.caption(
                "Previous global scan retained for this uploaded dataset."
            )

            df_saved = pd.DataFrame(
                saved_bulk_results
            )

            st.dataframe(
                df_saved,
                use_container_width=True,
                hide_index=True
            )

            if (
                saved_bulk_map is not None
                and saved_mapped_points > 0
            ):
                st.markdown(
                    "### 🛰️ Global Threat Infrastructure Map"
                )

                st_folium(
                    saved_bulk_map,
                    width=1000,
                    height=550,
                    returned_objects=[]
                )

            st.download_button(
                "📥 Download Global IP Forensic Report (CSV)",
                df_saved.to_csv(index=False).encode("utf-8"),
                "global_ip_tracking_report.csv",
                "text/csv",
                use_container_width=True,
                key="download_saved_global_ip_report"
            )

    # ---------------------------------------------------------------
    # DEEP DIVE
    # ---------------------------------------------------------------
    st.divider()

    st.subheader(
        "🔍 Deep Dive Analysis"
    )

    row_index = st.number_input(
        f"Select Row for Detailed View "
        f"(0 to {len(data) - 1})",
        min_value=0,
        max_value=len(data) - 1,
        value=0,
        key="csv_row_selector"
    )

    email_string = data[row_index]

    raw = (
        email_string
        .replace("\\n", "\n")
        .encode("utf-8")
    )

    case_name = (
        f"{uploaded.name} (Row {row_index})"
    )

else:

    # ---------------------------------------------------------------
    # STANDARD EML / TXT
    # ---------------------------------------------------------------
    if uploaded is not None:
        raw = uploaded.getvalue()
        case_name = uploaded.name

result = analyze_bytes(raw, case_name)
parsed, headers, iocs, geo = (result["parsed"], result["headers"],
                              result["iocs"], result["geo"])

# ---> NEW: AI MEMORY BANK TRIGGER <---
# --------------------------------------------------------------------------
# Threat memory - write/check only once per analyzed evidence item
# --------------------------------------------------------------------------

current_ip = geo["origin"].get("ip", "Unknown")
current_country = geo["origin"].get("country", "Unknown")

evidence_memory_key = hashlib.sha256(raw).hexdigest()

if st.session_state.get("memory_logged_for") != evidence_memory_key:
    init_db()

    log_threat(
        current_ip,
        current_country,
        result["score"],
        result["level"].upper(),
    )

    st.session_state["memory_logged_for"] = evidence_memory_key

    # Cache the history result for this evidence item.
    st.session_state["memory_history"] = check_history(current_ip)

past_attacks, highest_past_score = st.session_state.get(
    "memory_history",
    (0, 0),
)

if past_attacks > 1: # Greater than 1 because we just logged the current one!
    st.error(f"🚨 **REPEAT OFFENDER DETECTED!** This IP ({current_ip}) is in our threat database. They have attacked your network {past_attacks - 1} times previously with a max threat score of {highest_past_score:.0f}/100. This is a persistent campaign.")

# --------------------------------------------------------------------------
# Header + verdict banner
# --------------------------------------------------------------------------
st.markdown(
    """<div style="background:{c};padding:16px 22px;border-radius:10px;color:#fff;
    display:flex;justify-content:space-between;align-items:center;">
    <div><div style="font-size:13px;opacity:.85;letter-spacing:.5px;">VERDICT</div>
    <div style="font-size:30px;font-weight:700;line-height:1.15;">{lvl}</div>
    <div style="font-size:13px;opacity:.9;">{name}</div></div>
    <div style="text-align:right;"><div style="font-size:44px;font-weight:700;
    line-height:1;">{s:.0f}<span style="font-size:19px;opacity:.8;">/100</span></div>
    <div style="font-size:12px;opacity:.9;">driver: {d}</div></div></div>""".format(
        c=result["color"], lvl=result["level"].upper(), name=case_name,
        s=result["score"], d=result["verdict"].get("top_driver", "-")),
    unsafe_allow_html=True)
st.write("")

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("ML phishing probability", "{:.0%}".format(result["ml"]["prob"]))
k2.metric("Authentication",
          "{}/3 pass".format(sum(1 for m in ("spf", "dkim", "dmarc")
                                 if headers[m] == "pass")))
k3.metric("Header anomalies", len(headers["anomalies"]))
k4.metric("Suspicious links", "{}/{}".format(iocs["counts"]["suspicious"],
                                             iocs["counts"]["urls"]))
k5.metric("Origin", (geo["origin"].get("country_code")
                     or geo["origin"].get("country", "?")))

# --------------------------------------------------------------------------
# Analyst feedback
# --------------------------------------------------------------------------
st.divider()

st.markdown("""
<div class="feedback-panel">
    <div class="feedback-title">🧠 Analyst Feedback</div>
    <div class="feedback-subtitle">
        Validate the detection to improve future model decisions.
    </div>
</div>
""", unsafe_allow_html=True)

feedback_hash = hashlib.sha256(raw).hexdigest()

review_count = get_feedback_history_count(feedback_hash)

if review_count > 0:
    st.caption(
        f"🗂️ Previously reviewed {review_count} time"
        f"{'s' if review_count != 1 else ''}."
    )

# Reset the visible feedback message whenever a different email is loaded.
current_feedback_key = feedback_hash

if st.session_state.get("feedback_email") != current_feedback_key:
    st.session_state["feedback_email"] = current_feedback_key
    st.session_state["feedback_action"] = None

fb1, fb2 = st.columns(2, gap="medium")

feedback_message = None
feedback_type = None

with fb1:
    if st.button(
        "✅  Confirm Threat",
        key="confirm_threat",
        type="primary",
        use_container_width=True
    ):
        add_feedback(
            feedback_hash,
            "phish",
            parsed.get("full_text", "")
        )

        training_result = maybe_retrain_from_feedback()

        if training_result["status"] == "trained":
            get_model.clear()
            analyze_bytes.clear()
            get_sample_results.clear()

            feedback_message = (
                "Threat confirmed. Adaptive model validated and accepted."
            )
        elif training_result["status"] == "rejected":
            feedback_message = (
                "Threat confirmed. Adaptive model rejected because validation "
                "accuracy decreased; existing model was kept."
            )
        else:
            feedback_message = (
                "Threat confirmed and stored for future learning."
            )

        feedback_type = "success"


with fb2:
    if st.button(
        "✕  False Positive",
        key="false_positive",
        type="secondary",
        use_container_width=True
    ):
        add_feedback(
            feedback_hash,
            "legit",
            parsed.get("full_text", "")
        )

        training_result = maybe_retrain_from_feedback()

        if training_result["status"] == "trained":
            get_model.clear()
            analyze_bytes.clear()
            get_sample_results.clear()

            feedback_message = (
                "False positive saved. Adaptive model validated and accepted."
            )
        elif training_result["status"] == "rejected":
            feedback_message = (
                "False positive saved. Adaptive model rejected because validation "
                "accuracy decreased; existing model was kept."
            )
        else:
            feedback_message = (
                "False-positive feedback stored for future learning."
            )

        feedback_type = "info"


# --------------------------------------------------------------------------
# Feedback result - full width
# --------------------------------------------------------------------------
if feedback_message:
    show_feedback_typing(
        feedback_message,
        feedback_type
    )
# --------------------------------------------------------------------------
# AI Learning Status
# --------------------------------------------------------------------------

feedback_count = get_feedback_count()
adaptive_status = get_adaptive_status()

is_adaptive = adaptive_status.get("status") == "trained"

if is_adaptive:
    model_detail = (
        f"Learned from "
        f"{adaptive_status.get('feedback_samples', 0)} "
        f"verified analyst samples."
    )
else:
    model_detail = f"{feedback_count} / 20 verified samples collected."

with st.container(border=True):
    left, right = st.columns([2.2, 1])

    with left:
        st.markdown("### 🧠 AI Learning Status")
        st.caption(
            "Analyst-verified feedback is used for controlled model adaptation."
        )

    with right:
        if is_adaptive:
            st.success("ADAPTIVE MODEL")
        else:
            st.info("BASE MODEL")

        st.caption(model_detail)

if headers["bec"]["is_bec"] and headers["auth_fail_score"] == 0:
    st.warning("**This message passes SPF, DKIM and DMARC and is still fraud.** "
               "It was sent from a genuine mailbox impersonating an executive, "
               "so authentication proves the account is real - not that the "
               "request is honest. Payload-based filters see nothing to block.")

st.divider()

tab_class, tab_head, tab_geo, tab_ioc, tab_graph, tab_report = st.tabs([
    "Classification", "Headers & Auth", "Origin & Route", "Indicators",
    "Correlation", "Forensic Report",
])

# --------------------------------------------------------------------------
# 1. Classification
# --------------------------------------------------------------------------
with tab_class:
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
                text=["{:.0f} / {}".format(c["points"], c["weight"])
                      for c in contributions],
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
            st.caption("Every point is attributable to a named detector - the "
                       "score is a weighted sum, not a black box.")

        with right:
            st.subheader("Why the model flagged this")
            st.metric("Phishing probability", "{:.1%}".format(result["ml"]["prob"]),
                      result["ml"]["label"])
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
                st.caption("Logistic-regression coefficients, so the exact words "
                           "driving the decision are readable.")
            else:
                st.success("No term in this message pushed the score toward "
                           "phishing.")

        st.divider()
        st.subheader("Message")
        c1, c2 = st.columns([1, 1])
        c1.text_input("From", parsed.get("from_addr", ""), disabled=True)
        c2.text_input("Subject", parsed.get("subject", ""), disabled=True)
        st.text_area("Body as analysed", parsed.get("body_text", "")[:4000],
                     height=240, disabled=True)

    panel(_classification, "Classification")

# --------------------------------------------------------------------------
# 2. Headers & authentication
# --------------------------------------------------------------------------
with tab_head:
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
                    c=AUTH_COLOR.get(value, "#78909c"), m=mech.upper(),
                    v=value.upper()),
                unsafe_allow_html=True)
        st.caption("Verdicts stamped by the receiving server at delivery. We "
                   "re-read them rather than re-running DNS, because published "
                   "records may have changed since the message arrived.")

        st.divider()
        st.subheader("Identity anomalies")
        if headers["anomalies"]:
            for a in headers["anomalies"]:
                st.markdown(
                    """<div style="border-left:4px solid {c};padding:8px 14px;
                    margin-bottom:8px;background:rgba(120,120,120,.08);">
                    <b>{t}</b><br><span style="font-size:13px;opacity:.85;">{d}
                    </span></div>""".format(c=SEV_COLOR.get(a["severity"], "#666"),
                                            t=a["title"], d=a["detail"]),
                    unsafe_allow_html=True)
        else:
            st.success("No anomalies. Sender identity is internally consistent.")

        if headers["bec"]["is_bec"]:
            st.divider()
            st.subheader("Business Email Compromise assessment")
            bec = headers["bec"]
            st.progress(min(1.0, bec["score"]),
                        text="BEC pattern strength {:.0%}".format(bec["score"]))
            b1, b2 = st.columns(2)
            b1.write("**Payment language**")
            b1.write(", ".join("`{}`".format(w) for w in bec["payment_words"])
                     or "none")
            b1.write("**Urgency language**")
            b1.write(", ".join("`{}`".format(w) for w in bec["urgency_words"])
                     or "none")
            b2.write("**Claims executive identity:** {}".format(
                "yes" if bec["exec_claim"] else "no"))
            b2.write("**Consumer mailbox sender:** {}".format(
                "yes" if bec["freemail_sender"] else "no"))
            b2.write("**No link/attachment to scan:** {}".format(
                "yes" if bec["no_links"] else "no"))

        st.divider()
        st.subheader("Identity fields")
        st.dataframe(pd.DataFrame([
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
            )]), width='stretch', hide_index=True)

        with st.expander("Raw Received chain (oldest hop first)"):
            for i, hop in enumerate(parsed.get("received_chain", []), 1):
                st.code("{}. {}".format(i, hop), language=None)

    panel(_headers, "Headers & Auth")
# --------------------------------------------------------------------------
# 3. Origin & route
# --------------------------------------------------------------------------
with tab_geo:
    def _geo():
        st.subheader("Where the message actually came from")
        origin = geo["origin"]
        st.info(geo.get("summary", "No routing data."))

        g1, g2, g3, g4 = st.columns(4)
        g1.metric("Origin IP", origin.get("ip") or "unknown")
        g2.metric("Location", ", ".join(
            p for p in [origin.get("city"), origin.get("country")] if p) or "Unknown")
        g3.metric("Infrastructure", origin.get("infra_label", "Unattributed"))
        g4.metric("Hops traced", len(geo.get("hops", [])))

        hops = [h for h in geo.get("hops", []) if h.get("lat") is not None]
        
        if hops:
            st.markdown("### 🗺️ Interactive Visual Hop Map (Folium)")
            
            # ---> 1. Interactive UI Toggle Switch for Satellite View <---
            use_satellite = st.toggle("🛰️ Enable Satellite View", value=True)
            
            if use_satellite:
                map_tiles = "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"
                map_attr = "Esri World Imagery"
            else:
                map_tiles = "OpenStreetMap"
                map_attr = "OpenStreetMap contributors"
            
            # Start map centered roughly on the first hop, or center of the world
            start_lat = hops[0]["lat"] if hops else 20.0
            start_lon = hops[0]["lon"] if hops else 0.0
            
            m = folium.Map(location=[start_lat, start_lon], zoom_start=2, tiles=map_tiles, attr=map_attr)
            
            coordinates = []
            
            # Plot each hop
            for i, h in enumerate(hops, 1):
                lat, lon = h["lat"], h["lon"]
                coords = [lat, lon]
                coordinates.append(coords)
                
                is_origin = (h["infra"] in ("tor", "vpn", "proxy")) or (i == len(hops))
                color = "red" if is_origin else "blue"
                
                popup_text = f"<b>Hop {i}</b><br>IP: {h['ip']}<br>Loc: {h.get('city', '')}, {h.get('country', '')}<br>Infra: {h.get('infra_label', '')}"
                
                folium.Marker(
                    location=coords,
                    popup=folium.Popup(popup_text, max_width=300),
                    icon=folium.Icon(color=color, icon="info-sign")
                ).add_to(m)

            # ---> 2. Automatic HQ Target Pin & Jumping Arcs for .eml files <---
            if len(coordinates) == 1:
                hq_coords = [22.5726, 88.3639] # Kolkata HQ Datacenter
                coordinates.append(hq_coords)
                folium.CircleMarker(
                    location=hq_coords, radius=5, color="#00ff00",
                    fill=True, fill_opacity=0.9, popup="Target Datacenter (HQ)"
                ).add_to(m)

            if len(coordinates) > 1:
                from folium.plugins import AntPath
                import math
                
                for step in range(len(coordinates) - 1):
                    lat1, lon1 = coordinates[step][0], coordinates[step][1]
                    lat2, lon2 = coordinates[step+1][0], coordinates[step+1][1]
                    
                    # Bezier Curve Math for the Jumping Arc
                    arc_points = []
                    mid_lat = (lat1 + lat2) / 2.0
                    mid_lon = (lon1 + lon2) / 2.0
                    distance = math.sqrt((lat2 - lat1)**2 + (lon2 - lon1)**2)
                    mid_lat += distance * 0.25 # Jump height
                    
                    for frame in range(51):
                        t = frame / 50.0
                        lat = (1-t)**2 * lat1 + 2*(1-t)*t * mid_lat + t**2 * lat2
                        lon = (1-t)**2 * lon1 + 2*(1-t)*t * mid_lon + t**2 * lon2
                        arc_points.append([lat, lon])
                        
                    AntPath(
                        locations=arc_points,
                        color="red",
                        pulse_color="#ffffff",
                        weight=3,
                        opacity=0.8,
                        delay=800,
                        dash_array=[15, 30]
                    ).add_to(m)

            # Render it in Streamlit
            st_folium(m, width=800, height=450, returned_objects=[])
            
            st.caption("Hop 1 is the earliest external sender. Red markers indicate origin or anonymizing infrastructure. Arcs jump dynamically to the HQ target.")
        else:
            st.warning("No hop in this message could be geolocated, so there is "
                       "nothing to plot. Recorded as unresolved rather than "
                       "guessed.")

        if geo.get("hops"):
            st.subheader("Routing chain")
            st.dataframe(pd.DataFrame([{
                "#": h.get("hop_index"),
                "IP": h["ip"],
                "City": h.get("city") or "-",
                "Country": h.get("country") or "Unknown",
                "Network": h.get("isp") or "-",
                "Infrastructure": h.get("infra_label", "-"),
                "Source": h.get("source", "-"),
            } for h in geo["hops"]]), width='stretch', hide_index=True)

        if geo.get("anonymised"):
            st.warning("**Attribution caution** - the earliest hop is anonymising "
                       "infrastructure. The location identifies the relay, not the "
                       "operator. Naming the sender would need relay logs, which "
                       "Tor deliberately does not keep.")

        with st.expander("How origin tracing works, and its limits"):
            st.markdown(
                "- Mail servers **prepend** `Received` headers, so the **last** "
                "one in the file is the **earliest** hop. We reverse the chain "
                "and take the first globally routable IP.\n"
                "- Private, loopback and reserved ranges are skipped - they are "
                "internal relays and say nothing about the origin.\n"
                "- Lookup order is bundled cache, then a local MaxMind GeoLite2 "
                "database if you drop one at `data/GeoLite2-City.mmdb`, then "
                "'unresolved'. **No live API is ever called**, so the demo cannot "
                "fail on conference wifi and gives identical output every run.\n"
                "- Headers **below the first trusted hop can be forged**. Only "
                "hops added by servers you control are dependable evidence.\n"
                "- Infrastructure classes: {}".format(
                    ", ".join(sorted(set(INFRA_LABEL.values())))))

    panel(_geo, "Origin & Route")
# --------------------------------------------------------------------------
# 4. Indicators of compromise
# --------------------------------------------------------------------------

with tab_ioc:
    def _iocs():

        urls = iocs.get("urls", [])
        counts = iocs.get("counts", {})

        urlhaus_matches = sum(
            1
            for u in urls
            if isinstance(u, dict) and u.get("external_intel")
        )

        local_memory_matches = sum(
            1
            for u in urls
            if isinstance(u, dict)
            and u.get("intel_source") == "Local memory"
        )

        s1, s2, s3, s4 = st.columns(4)

        s1.metric("Total URLs", len(urls))
        s2.metric("Suspicious", counts.get("suspicious", 0))
        s3.metric("URLhaus Matches", urlhaus_matches)
        s4.metric("Local Memory", local_memory_matches)

        st.divider()

        st.markdown("## Extracted Indicators")
        st.caption(
            "URLs, domains, email addresses, wallets and suspicious "
            "indicators extracted from the evidence."
        )

        indicator_data = [
            ("🌐", "URLs", counts.get("urls", 0)),
            ("⚠️", "Suspicious", counts.get("suspicious", 0)),
            ("🔗", "Domains", counts.get("domains", 0)),
            ("✉️", "Emails", counts.get("emails", 0)),
            ("₿", "Wallets", counts.get("wallets", 0)),
        ]

        cols = st.columns(5)

        for col, (icon, label, value) in zip(
            cols,
            indicator_data
        ):
            with col:
                with st.container(border=True):
                    st.markdown(f"**{icon} {label}**")
                    st.markdown(f"## {value}")

        if urls:
            st.divider()

            st.markdown("### URL Intelligence")
            st.caption(
                "Reputation and heuristic signals attached to extracted URLs."
            )

            for idx, u in enumerate(urls, 1):

                risk = float(u.get("risk", 0))
                suspicious = bool(u.get("suspicious"))

                state = (
                    "SUSPICIOUS"
                    if suspicious
                    else "NO HIGH-RISK SIGNAL"
                )

                st.markdown(
                    f"""
                    **#{idx} — {u.get("url", "-")}**

                    Host: `{u.get("host") or "-"}`  
                    Status: **{state}**  
                    Risk: **{risk:.0%}**
                    """
                )

                if u.get("external_intel"):
                    st.info("🌐 URLhaus verified")

                elif u.get("intel_source") == "Local memory":
                    st.info("🧠 Local memory")

                if u.get("flags"):
                    for flag in u["flags"]:
                        st.caption(f"• {flag}")

        else:
            st.info(
                "No URLs in the body. For BEC this can be expected because "
                "the threat may rely on identity and intent rather than links."
            )

        # Other observables
        for label, values in (
            ("Domains", iocs.get("domains", [])),
            ("IPs in body", iocs.get("ips", [])),
            ("Email addresses", iocs.get("emails", [])),
            ("Crypto wallets", iocs.get("wallets", [])),
        ):
            if values:
                st.markdown(f"**{label}:**")
                st.write(", ".join(f"`{v}`" for v in values))

        # Attachments
        if parsed.get("attachments"):
            st.divider()
            st.subheader("Attachments")

            st.dataframe(
                pd.DataFrame([
                    {
                        "Filename": a.get("filename", "-"),
                        "Bytes": a.get("size", 0),
                        "Dangerous type": (
                            "yes" if a.get("risky") else "no"
                        ),
                    }
                    for a in parsed["attachments"]
                ]),
                width="stretch",
                hide_index=True
            )

        with st.expander("How look-alike domains are detected"):
            st.markdown(
                "Each hostname label is compared using edit distance "
                "against the internal brand list."
            )

    panel(_iocs, "Indicators")

# --------------------------------------------------------------------------
# 5. Correlation across all cases
# --------------------------------------------------------------------------
with tab_graph:
    def _graph():

        # ---------------------------------------------------------------
        # CAMPAIGN CORRELATION HEADER
        # ---------------------------------------------------------------
        st.markdown(
            '<div style="padding:4px 0 14px 0;">'
            '<div style="font-size:28px;font-weight:800;letter-spacing:.2px;color:#e8f1ff;">'
            'Campaign Correlation & Attribution'
            '</div>'
            '<div style="margin-top:5px;font-size:13px;color:#7f8da3;line-height:1.5;">'
            'Correlate analyzed messages through shared infrastructure, '
            'indicators and identity signals.'
            '</div>'
            '</div>',
            unsafe_allow_html=True
        )

        # ---------------------------------------------------------------
        # BUILD CASE SET
        # ---------------------------------------------------------------
        sample_results = [
            r for r in get_sample_results()
            if "error" not in r
        ]

        cases = list(sample_results)

        if result["name"] not in [c["name"] for c in cases]:
            cases.append(result)

        # ---------------------------------------------------------------
        # CORRELATION GRAPH
        # ---------------------------------------------------------------
        G = correlate.build_graph(cases)
        shared = correlate.shared_indicators(G)

        # ---------------------------------------------------------------
        # EXECUTIVE METRICS
        # ---------------------------------------------------------------
        m1, m2, m3, m4 = st.columns(4)

        m1.metric("Cases Analyzed", len(cases))
        m2.metric("Infrastructure Nodes", G.number_of_nodes())
        m3.metric("Correlation Links", G.number_of_edges())
        m4.metric("Shared Indicators", len(shared))

        st.divider()

        # ---------------------------------------------------------------
        # CURRENT INVESTIGATION CARD
        # ---------------------------------------------------------------
        current_level = str(
            result.get("level", "unknown")
        ).upper()

        current_score = float(
            result.get("score", 0)
        )

        top_driver = result.get(
            "verdict", {}
        ).get(
            "top_driver",
            "-"
        )

        current_card = (
            '<div style="'
            'display:flex;'
            'justify-content:space-between;'
            'align-items:center;'
            'gap:20px;'
            'padding:16px 18px;'
            'border:1px solid #263244;'
            'border-radius:10px;'
            'background:rgba(15,23,42,.62);'
            'margin-bottom:20px;'
            '">'
            '<div>'
            '<div style="font-size:10px;color:#6f7e93;'
            'text-transform:uppercase;letter-spacing:1px;">'
            'Current Investigation'
            '</div>'
            f'<div style="margin-top:5px;color:#e5edf7;'
            f'font-size:15px;font-weight:750;">{case_name}</div>'
            f'<div style="margin-top:4px;color:#8795a8;'
            f'font-size:12px;">Primary signal: {top_driver}</div>'
            '</div>'
            '<div style="text-align:right;min-width:120px;">'
            '<div style="color:#00d2ff;font-size:11px;'
            'font-weight:800;letter-spacing:1px;">'
            'CURRENT VERDICT'
            '</div>'
            f'<div style="margin-top:3px;color:#f1f5f9;'
            f'font-size:22px;font-weight:800;">{current_level}</div>'
            f'<div style="color:#8b98aa;font-size:12px;">'
            f'Risk score {current_score:.0f}/100</div>'
            '</div>'
            '</div>'
        )

        st.markdown(
            current_card,
            unsafe_allow_html=True
        )

        # ---------------------------------------------------------------
        # GRAPH HEADER
        # ---------------------------------------------------------------
        st.markdown(
            '<div style="font-size:15px;font-weight:750;'
            'color:#e5edf7;margin-bottom:4px;">'
            '◉ Infrastructure Correlation Map'
            '</div>'
            '<div style="font-size:12px;color:#7f8da3;margin-bottom:10px;">'
            'Shared IPs, domains and other indicators can reveal '
            'relationships between otherwise separate messages.'
            '</div>',
            unsafe_allow_html=True
        )

        # ---------------------------------------------------------------
        # GRAPH
        # ---------------------------------------------------------------
        st.plotly_chart(
            correlate.graph_figure(G),
            width="stretch"
        )

        # ---------------------------------------------------------------
        # SHARED INFRASTRUCTURE
        # ---------------------------------------------------------------
        if shared:

            st.markdown(
                '<div style="margin-top:14px;font-size:16px;'
                'font-weight:750;color:#e5edf7;">'
                '🔗 Shared Infrastructure'
                '</div>'
                '<div style="margin-top:4px;margin-bottom:10px;'
                'font-size:12px;color:#7f8da3;">'
                'Indicators connecting multiple analyzed messages.'
                '</div>',
                unsafe_allow_html=True
            )

            shared_rows = []

            for item in shared:
                shared_rows.append({
                    "Indicator": item.get("indicator", "-"),
                    "Type": item.get("kind", "-"),
                    "Cases": ", ".join(
                        item.get("cases", [])
                    )
                })

            st.dataframe(
                pd.DataFrame(shared_rows),
                width="stretch",
                hide_index=True
            )

        else:

            st.markdown(
                '<div style="margin-top:14px;padding:14px 16px;'
                'border:1px solid #263244;border-radius:9px;'
                'background:rgba(30,64,175,.10);">'
                '<div style="color:#60a5fa;font-size:13px;font-weight:700;">'
                'No shared infrastructure detected'
                '</div>'
                '<div style="margin-top:4px;color:#8b98aa;font-size:12px;'
                'line-height:1.5;">'
                'The analyzed messages currently appear independent.'
                '</div>'
                '</div>',
                unsafe_allow_html=True
            )

        # ---------------------------------------------------------------
        # CASE INTELLIGENCE
        # ---------------------------------------------------------------
        st.markdown(
            '<div style="margin-top:24px;font-size:16px;'
            'font-weight:750;color:#e5edf7;">'
            '📋 Case Intelligence'
            '</div>'
            '<div style="margin-top:4px;margin-bottom:10px;'
            'font-size:12px;color:#7f8da3;">'
            'Consolidated view of the analyzed evidence set.'
            '</div>',
            unsafe_allow_html=True
        )

        rows = []

        for r in cases:

            rows.append({
                "Case": r.get("name", "-"),
                "Score": round(
                    float(r.get("score", 0)),
                    1
                ),
                "Verdict": str(
                    r.get("level", "unknown")
                ).upper(),
                "ML": "{:.0%}".format(
                    r.get("ml", {}).get("prob", 0)
                ),
                "SPF": r.get(
                    "headers", {}
                ).get("spf", "-"),
                "DKIM": r.get(
                    "headers", {}
                ).get("dkim", "-"),
                "DMARC": r.get(
                    "headers", {}
                ).get("dmarc", "-"),
                "Origin IP": r.get(
                    "geo", {}
                ).get(
                    "origin", {}
                ).get("ip", "-"),
                "Country": r.get(
                    "geo", {}
                ).get(
                    "origin", {}
                ).get("country", "-")
            })

        st.dataframe(
            pd.DataFrame(rows),
            width="stretch",
            hide_index=True
        )

        st.caption(
            "Correlation is an investigative linkage signal, "
            "not proof of common ownership."
        )

    panel(_graph, "Correlation")

# --------------------------------------------------------------------------
# 6. Forensic report
# --------------------------------------------------------------------------
with tab_report:
    def _report():
        st.subheader("Exportable forensic report")
        st.caption("Investigator-facing document: verdict, evidence, scoring "
                   "breakdown, recommended actions, and an explicit limitations "
                   "section.")

        markdown = build_report(result, raw)
        r1, r2 = st.columns([1, 1])
        r1.download_button("Download report (Markdown)", markdown,
                           file_name="forensic_report_{}.md".format(
                               case_name.replace(".eml", "")),
                           mime="text/markdown", width='stretch')
        r2.code("SHA-256  {}".format(evidence_hash(raw)), language=None)
        st.caption("The hash is the integrity anchor - any reviewer can confirm "
                   "the exhibit was not altered during analysis.")

        st.divider()
        st.markdown(markdown)

    panel(_report, "Forensic Report")

# --------------------------------------------------------------------------
st.divider()
with st.expander("Scope, honesty notes and what we would add next"):
    st.markdown(
        "**What is real here**\n"
        "- Full RFC-5322 parsing, `Received`-chain reconstruction, and "
        "SPF/DKIM/DMARC extraction from real header syntax.\n"
        "- A genuinely trained classifier (TF-IDF + logistic regression) scored "
        "on **held-out templates**, with per-word explanations.\n"
        "- Look-alike domain detection by edit distance; BEC detection by "
        "identity and intent rather than payload.\n"
        "- Weighted, fully attributable risk scoring and a court-shaped report "
        "with an evidence hash.\n\n"
        "**What is simulated, and why**\n"
        "- The training corpus is **synthetic** (seeded, reproducible). Public "
        "phishing corpora are large and licence-encumbered; the loader reads a "
        "plain `text,label` CSV, so a real corpus drops straight in.\n"
        "- Because synthetic text is cleaner than reality, the reported accuracy "
        "is a **sanity check, not a real-world figure**.\n"
        "- Geolocation comes from a bundled cache, with optional local MaxMind "
        "GeoLite2 support. **No live API calls anywhere** - deliberate, so the "
        "demo is deterministic and cannot fail on venue wifi.\n\n"
        "**Deliberately out of scope**\n"
        "- Live WHOIS/DNS/VirusTotal enrichment: rate-limited and network-"
        "dependent, the two most common causes of a dead demo. Every hook needed "
        "to add them exists in `ioc_extract.py`.\n"
        "- Attachment sandboxing, and IMAP/Exchange ingestion for continuous "
        "monitoring.\n\n"
        "**Next steps**: swap in a real labelled corpus, add live enrichment "
        "behind a cache with a timeout, ingest from a live mailbox, and persist "
        "cases so the correlation graph grows across a whole campaign.")
