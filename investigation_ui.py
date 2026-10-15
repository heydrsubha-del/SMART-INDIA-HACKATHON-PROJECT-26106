"""Streamlit panel for the agentic investigation (explicit start, read-only)."""
import re

import streamlit as st

import investigation_agent as ia

_MD = re.compile(r"([\\`*_{}\[\]()#+!|<>~])")


_P = "html body .stApp" + ".stApp" * 22 + " .st-key-ai_step_agent" + ":not(#_x)" * 22
_SVG = ("url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='@D' "
        "stroke='%23e2e8f0' stroke-width='2.6' stroke-linecap='round' fill='none'/%3E%3C/svg%3E\")")
_AGENT_CSS = """<style>
@P {border-radius:16px !important; border:1px solid rgba(255,255,255,.08) !important; background:#0d131c !important; box-shadow:none !important; padding:6px 8px !important;}
@P::before, @P::after {content:none !important; display:none !important;}
.ag-con {display:block; margin:0 0 6px;}
.ag-eye {display:flex; align-items:center; gap:8px; margin-bottom:8px; font:600 11px/1 ui-monospace,Consolas,monospace; letter-spacing:.18em; color:#8b98ab;}
.ag-eye i {width:6px; height:6px; border-radius:50%; background:#34d399;}
.ag-con p {margin:0 0 12px; max-width:78ch; font:400 13.5px/1.55 Inter,'Segoe UI',sans-serif; color:#9fb0c6;}
.ag-tags {display:flex; flex-wrap:wrap; gap:8px;}
.ag-tag {display:inline-flex; align-items:center; gap:6px; padding:5px 11px; border-radius:999px; font:500 11.5px/1 Inter,'Segoe UI',sans-serif; color:#a9b6c8; background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08);}
.ag-tag::before {content:''; width:5px; height:5px; border-radius:50%; background:#34d399;}
.ag-gauge {display:flex; align-items:center; gap:12px; flex-wrap:nowrap; margin:0; padding:0;}
.ag-ring {flex:none; width:46px; height:46px; border-radius:50%; display:grid; place-items:center; background:conic-gradient(var(--c) calc(var(--p)*1%),rgba(255,255,255,.09) 0);}
.ag-ring div {width:34px; height:34px; border-radius:50%; background:#0b1119; display:grid; place-items:center; font:700 13px Inter,sans-serif; color:#fff;}
.ag-gauge span {display:block; font:600 10px ui-monospace,Consolas,monospace; letter-spacing:.14em; color:#cbd5e1;}
.ag-gauge small {display:block; margin-top:3px; font:400 11px Inter,sans-serif; color:#7d8aa0;}
@P [class*="st-key-agent_opt_"], @P [class*="st-key-agent_opt_"] > div, @P [class*="st-key-agent_opt_"] [data-testid="stVerticalBlock"], @P [class*="st-key-agent_opt_"] [data-testid="stElementContainer"], @P [class*="st-key-agent_opt_"] [data-testid="stCheckbox"] {border:0 !important; background:none !important; box-shadow:none !important; outline:0 !important; padding:0 !important; margin:0 !important; border-radius:0 !important;}
@P [data-testid="stCheckbox"] label {padding:10px 14px !important; border-radius:10px !important; background:rgba(255,255,255,.03) !important; border:1px solid rgba(255,255,255,.12) !important; box-shadow:none !important; width:100%; transform:none !important; transition:border-color .15s;}
@P [data-testid="stCheckbox"] label:hover {border-color:rgba(255,255,255,.28) !important; box-shadow:none !important; transform:none !important;}
@P [data-testid="stCheckbox"] label:has(input:checked) {background:rgba(52,211,153,.07) !important; border-color:rgba(52,211,153,.45) !important; box-shadow:none !important;}
@P [data-testid="stHorizontalBlock"]:has([class*="st-key-agent_opt_"]) {gap:12px !important; margin:4px 0 8px !important;}
@P [class*="st-key-agent_g_"] {padding:12px 14px !important; border-radius:12px !important; background:#0b1119 !important; border:1px solid rgba(255,255,255,.08) !important; box-shadow:none !important;}
@P [class*="st-key-agent_g_"] [data-testid="stVerticalBlock"] {gap:0 !important;}
@P [class*="st-key-agent_g_"] [data-testid="stElementContainer"], @P [class*="st-key-agent_g_"] [data-testid="stMarkdownContainer"] {margin:0 !important; padding:0 !important; width:auto !important;}
@P [class*="st-key-agent_g_"] [data-testid="stHorizontalBlock"] {gap:6px !important; flex-wrap:nowrap !important; align-items:center !important; min-height:46px !important;}
@P [class*="st-key-agent_g_"] [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:nth-child(1) {flex:1 1 auto !important; min-width:0 !important; width:auto !important;}
@P [class*="st-key-agent_g_"] [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:nth-child(n+2) {flex:0 0 30px !important; width:30px !important; min-width:30px !important;}
@P [class*="st-key-agent_g_calls_"] {--bc:#a78bfa;}
@P [class*="st-key-agent_g_iters_"] {--bc:#38bdf8;}
@P [class*="st-key-agent_g_secs_"] {--bc:#34d399;}
@P [class*="st-key-agent_g_"] [data-testid="stButton"] button::before, @P [class*="st-key-agent_g_"] [data-testid="stButton"] button::after {content:none !important; display:none !important;}
@P [class*="st-key-agent_g_"] [data-testid="stButton"] button > * {display:none !important;}
@P [class*="st-key-agent_g_"] [data-testid="stButton"] button {width:30px !important; min-width:30px !important; height:30px !important; min-height:30px !important; padding:0 !important; border-radius:50% !important; background-color:rgba(255,255,255,.05) !important; background-repeat:no-repeat !important; background-position:center !important; background-size:14px 14px !important; border:1px solid rgba(255,255,255,.14) !important; box-shadow:none !important; transition:background-color .15s, border-color .15s;}
@P [class*="st-key-agent_g_"] [data-testid="stButton"] button:hover {background-color:rgba(255,255,255,.12) !important; border-color:rgba(255,255,255,.3) !important;}
@P [class*="st-key-agent_dn_"] button {background-image:@MINUS !important;}
@P [class*="st-key-agent_up_"] button {background-image:@PLUS !important;}
@P [data-testid="stButton"] button[kind="primary"] {background:linear-gradient(135deg,#6d5ef0,#3b9be8) !important; border:0 !important; box-shadow:none !important;}
</style>""".replace("@P", _P).replace("@MINUS", _SVG.replace("@D", "M6 12h12")).replace("@PLUS", _SVG.replace("@D", "M6 12h12M12 6v12"))


def _t(v):
    """Escape email-derived text so it cannot render as markdown/HTML."""
    return _MD.sub(r"\\\1", ia.clean(v, 300))


def render_investigation_panel(result, raw, cases, conns_factory, key, download_fn=None):
    store = st.session_state.setdefault("agent_investigations", {})
    key = str(key)
    st.markdown(_AGENT_CSS + '<div class="ag-con"><div class="ag-eye"><i></i>AGENTIC INVESTIGATION</div>'
                '<p>Runs this app\'s existing analysis tools under a strict allowlist and hard limits. '
                'It never changes the scanner\'s score, sends mail or submits intelligence.</p>'
                '<div class="ag-tags"><span class="ag-tag">Read-only</span><span class="ag-tag">Tool allowlist</span>'
                '<span class="ag-tag">Score unchanged</span><span class="ag-tag">No outbound mail</span></div></div>',
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
    st.caption(("AI-assisted" if use_ai else "Deterministic") + " · " + ("Public DNS/RDAP on" if net else "Offline lookups")
               + f" · up to {calls} tool calls, {iters} iterations, {secs}s")
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