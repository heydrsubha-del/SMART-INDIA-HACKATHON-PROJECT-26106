"""Streamlit panel for the agentic investigation (explicit start, read-only)."""
import re

import streamlit as st

import investigation_agent as ia

_MD = re.compile(r"([\\`*_{}\[\]()#+!|<>~])")


_AGENT_CSS = """<style>
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) {position:relative; overflow:hidden; border-radius:20px !important; border:1px solid rgba(255,255,255,.09) !important;
 background:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px) 0 0/100% 26px, linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px) 0 0/26px 100%, radial-gradient(70% 150% at 100% 0%,rgba(167,139,250,.18),transparent 60%), radial-gradient(60% 120% at 0% 100%,rgba(52,211,153,.10),transparent 60%), linear-gradient(180deg,#0f1622,#0a0f17) !important;
 box-shadow:0 26px 54px -28px #000, inset 0 1px 0 rgba(255,255,255,.08) !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x)::before {content:''; position:absolute; left:0; top:0; bottom:0; width:4px; background:linear-gradient(180deg,#38bdf8,#a78bfa 55%,#34d399); box-shadow:0 0 20px #38bdf8; z-index:3;}
.ag-con {display:flex; flex-wrap:wrap; gap:10px 8px; align-items:center; margin:2px 0 4px;}
.ag-con .ag-eye {flex:1 1 100%; display:flex; align-items:center; gap:9px; font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.22em; color:#a78bfa;}
.ag-con .ag-eye i {width:7px; height:7px; border-radius:50%; background:#34d399; box-shadow:0 0 0 3px rgba(52,211,153,.2),0 0 10px #34d399; animation:agp 2s infinite;}
.ag-con .ag-eye b {padding:3px 8px; border-radius:5px; color:#f59e0b; background:rgba(245,158,11,.1); border:1px solid rgba(245,158,11,.35); letter-spacing:.16em;}
@keyframes agp {50% {opacity:.35;}}
.ag-con p {flex:1 1 100%; margin:2px 0 6px; font:400 13px/1.5 Inter,'Segoe UI',sans-serif; color:#9fb0c6;}
.ag-chip {display:inline-flex; align-items:center; gap:7px; padding:6px 12px; border-radius:8px; font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.14em; color:var(--c); background:color-mix(in srgb,var(--c) 11%,transparent); border:1px solid color-mix(in srgb,var(--c) 40%,transparent);}
.ag-chip::before {content:''; width:6px; height:6px; border-radius:50%; background:var(--c); box-shadow:0 0 8px var(--c);}
.ag-prof {display:flex; flex-wrap:wrap; align-items:stretch; gap:14px; margin:6px 0 4px; padding:16px 18px; border-radius:16px; border:1px solid rgba(255,255,255,.08); background:linear-gradient(135deg,rgba(255,255,255,.045),rgba(255,255,255,.01));}
.ag-prof .ag-h {flex:1 1 100%; font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.2em; color:#7d8aa0; display:flex; gap:8px; flex-wrap:wrap; align-items:center;}
.ag-gauge {flex:1 1 170px; display:flex; align-items:center; gap:14px; padding:12px 14px; border-radius:14px; background:#0a1018; border:1px solid color-mix(in srgb,var(--c) 35%,transparent); box-shadow:0 12px 26px -18px var(--c);}
.ag-ring {width:58px; height:58px; border-radius:50%; display:grid; place-items:center; background:conic-gradient(var(--c) calc(var(--p)*1%),rgba(255,255,255,.08) 0); box-shadow:0 0 22px -6px var(--c);}
.ag-ring div {width:44px; height:44px; border-radius:50%; background:#0a1018; display:grid; place-items:center; font:800 15px Inter,sans-serif; color:#fff;}
.ag-gauge span {display:block; font:700 10px ui-monospace,Consolas,monospace; letter-spacing:.16em; color:color-mix(in srgb,var(--c) 65%,#fff);}
.ag-gauge small {display:block; margin-top:5px; font:500 11.5px Inter,sans-serif; color:#8fa0b6;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label {padding:14px 20px !important; border-radius:14px !important; border:1px solid rgba(255,255,255,.1) !important; background:rgba(255,255,255,.035) !important; transition:all .18s ease;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label:hover {transform:translateY(-2px); border-color:rgba(167,139,250,.6) !important; box-shadow:0 10px 24px -12px #a78bfa !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label:has(input:checked) {border-color:rgba(52,211,153,.65) !important; background:linear-gradient(135deg,rgba(52,211,153,.2),rgba(52,211,153,.03)) !important; box-shadow:0 0 0 3px rgba(52,211,153,.08), 0 12px 28px -14px #34d399 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_lim_calls_"] {--ac:#a78bfa;} html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_lim_iters_"] {--ac:#38bdf8;} html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_lim_secs_"] {--ac:#34d399;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_lim_"] {position:relative; border-radius:16px !important; overflow:hidden; border:1px solid color-mix(in srgb,var(--ac) 45%,transparent) !important;
 background:radial-gradient(100% 140% at 0% 0%,color-mix(in srgb,var(--ac) 22%,transparent),transparent 65%), linear-gradient(180deg,#0e1520,#0a1018) !important; box-shadow:0 16px 32px -18px var(--ac) !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_lim_"]::before {content:''; position:absolute; left:0; right:0; top:0; height:3px; background:linear-gradient(90deg,var(--ac),transparent 85%);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"] {background:linear-gradient(135deg,#8b5cf6,#38bdf8) !important; border:0 !important; box-shadow:0 14px 30px -12px #8b5cf6, inset 0 1px 0 rgba(255,255,255,.3) !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_g_"] {position:relative; padding:12px 14px !important; border-radius:16px !important; background:#0a1018 !important; border:1px solid rgba(255,255,255,.1) !important; box-shadow:0 14px 30px -18px #000 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_g_calls_"] {border-color:rgba(167,139,250,.5) !important; box-shadow:0 14px 30px -16px #a78bfa !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_g_iters_"] {border-color:rgba(56,189,248,.5) !important; box-shadow:0 14px 30px -16px #38bdf8 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_g_secs_"] {border-color:rgba(52,211,153,.5) !important; box-shadow:0 14px 30px -16px #34d399 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_g_"] .ag-gauge {border:0; box-shadow:none; background:none; padding:0;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_g_"] [data-testid="stButton"] button {min-width:38px !important; width:38px !important; height:38px !important; min-height:38px !important; padding:0 !important; border-radius:10px !important; font:800 18px/1 Inter,sans-serif !important; background:#111a26 !important; border:1px solid rgba(255,255,255,.14) !important; color:#fff !important; box-shadow:none !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_g_"] [data-testid="stButton"] button:hover {border-color:#a78bfa !important; background:#1a2434 !important;}
html body .stApp .st-key-ai_step_agent [class*="st-key-agent_g_"] [data-testid="stButton"] button::before,
html body .stApp .st-key-ai_step_agent [class*="st-key-agent_g_"] [data-testid="stButton"] button::after {content:none !important; display:none !important; background:none !important;}
html body .stApp .st-key-ai_step_agent [class*="st-key-agent_g_"] [data-testid="stButton"] button p {display:block !important; font-size:20px !important; line-height:1 !important; margin:0 !important; color:#fff !important; visibility:visible !important;}
html body .stApp .st-key-ai_step_agent [class*="st-key-agent_lim_"],
html body .stApp .st-key-ai_step_agent [class*="st-key-agent_g_"] {border-radius:4px !important; border:1px solid rgba(245,158,11,.35) !important; border-left:4px solid var(--ac,#f59e0b) !important; background:repeating-linear-gradient(0deg,rgba(255,255,255,.02) 0 1px,transparent 1px 22px),#0b1118 !important;}
.ag-gauge span::before {content:'FILE \00b7 '; opacity:.55;}
.ag-gauge span {text-transform:uppercase; letter-spacing:.22em;}
.ag-ring {border-radius:6px; background:none; border:2px solid var(--c); box-shadow:none;}
.ag-ring div {border-radius:3px; width:46px; height:46px; font-family:ui-monospace,Consolas,monospace;}
</style>"""


def _t(v):
    """Escape email-derived text so it cannot render as markdown/HTML."""
    return _MD.sub(r"\\\1", ia.clean(v, 300))


def render_investigation_panel(result, raw, cases, conns_factory, key, download_fn=None):
    store = st.session_state.setdefault("agent_investigations", {})
    key = str(key)
    st.markdown(_AGENT_CSS + '<div class="ag-con"><div class="ag-eye"><i></i>AGENTIC INVESTIGATION<b>MISSION BRIEF</b></div>'
                '<p>Read-only. Uses this app\'s existing analysis tools, a strict tool allowlist and hard limits. '
                'It never changes the scanner\'s score, sends mail or submits intelligence.</p>'
                '<span class="ag-chip" style="--c:#34d399">READ-ONLY</span><span class="ag-chip" style="--c:#38bdf8">TOOL ALLOWLIST</span>'
                '<span class="ag-chip" style="--c:#a78bfa">SCORE UNCHANGED</span><span class="ag-chip" style="--c:#f59e0b">NO OUTBOUND MAIL</span></div>',
                unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1.container(key="agent_opt_ai_" + key):
      use_ai = st.checkbox("AI-assisted planning and proposed findings", value=True, key="agent_ai_" + key,
                         help="Uses the app's configured provider (local Ollama/Qwen or the Groq backend). "
                              "Sends only a short evidence digest, never the email body.")
    with c2.container(key="agent_opt_net_" + key):
      net = st.checkbox("Allow public DNS/RDAP lookups", value=False, key="agent_net_" + key,
                      help="Sends only domain names found in this email to public DNS-over-HTTPS and RDAP services.")
    def _step(k, d, lo, hi):
        st.session_state[k] = max(lo, min(hi, int(st.session_state.get(k, lo)) + d))
    _lim = {}
    with st.expander("Limits", expanded=False):
        _cols = st.columns(3)
        for _col, (_n, _lab, _sub, _lo, _hi, _df, _c) in zip(_cols, (
                ("calls", "TOOL CALLS", "hard cap per run", 1, 15, 10, "#a78bfa"),
                ("iters", "ITERATIONS", "planning loops", 1, 15, 10, "#38bdf8"),
                ("secs", "SECONDS", "wall-clock budget", 10, 300, 90, "#34d399"))):
            _k = "agent_" + _n + "_" + key
            st.session_state.setdefault(_k, _df)
            _stp = 1 if _n != "secs" else 10
            with _col.container(key="agent_g_" + _n + "_" + key):
                _m, _x, _y = st.columns([5, 1.3, 1.3], vertical_alignment="center")
                _v = int(st.session_state[_k])
                _m.markdown('<div class="ag-gauge" style="--c:' + _c + ';--p:' + str(_v * 100 // _hi) + '"><div class="ag-ring"><div>' + str(_v)
                            + '</div></div><div><span>MAX ' + _lab + '</span><small>' + _sub + '</small></div></div>', unsafe_allow_html=True)
                _x.button("\u2212", key="agent_dn_" + _n + "_" + key, on_click=_step, args=(_k, -_stp, _lo, _hi))
                _y.button("+", key="agent_up_" + _n + "_" + key, on_click=_step, args=(_k, _stp, _lo, _hi))
            _lim[_n] = int(st.session_state[_k])
    calls, iters, secs = _lim["calls"], _lim["iters"], _lim["secs"]
    st.markdown('<div class="ag-prof"><div class="ag-h">RUN PROFILE'
                '<span class="ag-chip" style="--c:' + ('#34d399' if use_ai else '#8b96a5') + '">' + ('AI-ASSISTED' if use_ai else 'DETERMINISTIC') + '</span>'
                '<span class="ag-chip" style="--c:' + ('#f59e0b' if net else '#8b96a5') + '">' + ('PUBLIC DNS/RDAP ON' if net else 'OFFLINE LOOKUPS') + '</span></div></div>',
                unsafe_allow_html=True)
    if st.button("Start investigation", type="primary", key="agent_go_" + key):
        log = st.empty()
        seen = []
        with st.spinner("Investigating..."):
            def _p(n, tool):
                seen.append(f"{n}. {tool}")
                log.caption("Running: " + " → ".join(seen))
            store[key] = ia.investigate(result, cases=cases, conns_factory=conns_factory, allow_network=net, use_ai=use_ai,
                                        limits=ia.Limits(max_iterations=iters, max_tool_calls=calls, max_seconds=secs), progress=_p)
        log.empty()
    inv = store.get(key)
    if not inv:
        st.info("Click **Start investigation** to run a bounded, evidence-attributed investigation of this email.")
        return
    m = st.columns(4)
    m[0].metric("Status", inv["status"])
    m[1].metric("Tool calls", f"{len(inv['evidence'])}/{inv['limits']['max_tool_calls']}")
    m[2].metric("Time", f"{inv['seconds']}s")
    m[3].metric("Mode", "AI" if inv["mode"] == "ai" else "Deterministic")
    st.caption(f"Stopped: {inv['stop_reason'] or '-'} · Scanner score unchanged: {inv['score_snapshot']['score']} ({inv['score_snapshot']['level']})")
    if inv.get("mode_note"):
        st.warning(_t(inv["mode_note"]))
    if inv.get("narrative"):
        st.markdown("**Summary (generated from tool findings)**")
        st.markdown(_t(inv["narrative"]))
    st.markdown("**Action log**")
    st.dataframe([{"#": s["n"], "tool": s["tool"], "argument": s["args"].get("indicator", "-"), "chosen by": s["source"],
                   "result": s.get("status"), "evidence": s.get("evidence_id", "-"), "why": s["reason"]} for s in inv["steps"]], hide_index=True)
    _desc = {"verified": "Facts confirmed by a tool result.", "suspicious": "Signals that raise risk; review before acting.",
             "uncertain": "What could not be checked; treat the verdict with caution."}
    for kind, title in (("suspicious", "Suspicious signals"), ("uncertain", "Missing evidence / uncertainty")):
        items = [f for f in inv["findings"] if f["kind"] == kind]
        st.markdown(f"**{title} ({len(items)})** - {_desc[kind]}")
        for f in items:
            st.markdown(f"- {_t(f['statement'])} `[{','.join(f['evidence_ids'])}]`")
        if not items:
            st.caption("None recorded.")
    for kind, title in (("verified", "Verified facts"),):
        items = [f for f in inv["findings"] if f["kind"] == kind]
        with st.expander(f"{title} ({len(items)}) - {_desc[kind]}", expanded=False):
            for f in items:
                st.markdown(f"- {_t(f['statement'])} `[{','.join(f['evidence_ids'])}]`")
            if not items:
                st.caption("None recorded.")
    for e in inv["evidence"]:
        if e.get("records"):
            with st.expander(f"Supporting records: {e['id']} · {e['args'].get('indicator', '-')} ({len(e['records'])} shown) - raw stored rows", expanded=False):
                st.caption("Stored values as found. 'historical' = seen before only; 'suspicious'/'confirmed' require stored evidence in the record.")
                st.dataframe(e["records"], hide_index=True)
    report_md = ia.render_report(inv, result, raw)
    if download_fn is not None:     # app's premium download (HTML report + Word), same as the AI assessment
        download_fn(label="Download Investigation Report", markdown=report_md, file_name="agentic_investigation_report.md",
                    key="agent_dl_" + key, help="Full forensic report with the agentic investigation (HTML, or Word)")
    else:
        st.download_button("Download report (.md)", report_md, file_name="agentic_investigation_report.md",
                           mime="text/markdown", key="agent_dl_md_" + key)