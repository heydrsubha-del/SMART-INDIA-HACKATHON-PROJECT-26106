"""Streamlit panel for the agentic investigation (explicit start, read-only)."""
import re

import streamlit as st

import investigation_agent as ia

_MD = re.compile(r"([\\`*_{}\[\]()#+!|<>~])")
_KINDS = (("suspicious", "Suspicious", "#f87171", "Signals that raise risk; review before acting."),
          ("uncertain", "Uncertain", "#fbbf24", "Could not be checked; treat the verdict with caution."),
          ("verified", "Verified", "#34d399", "Facts confirmed by a tool result."))
_CSS = """<style>
.inv-head{display:flex;align-items:center;gap:14px;margin:4px 0 2px}
.inv-badge{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;font-weight:700;
 font-size:.85rem;color:#7dd3fc;background:rgba(56,189,248,.12);border:1px solid rgba(56,189,248,.35)}
.inv-title{font-size:1.15rem;font-weight:700;line-height:1.2}
.inv-sub{font-size:.8rem;opacity:.65}
.inv-lbl{font-size:.68rem;letter-spacing:.12em;text-transform:uppercase;opacity:.6;margin:10px 0 2px}
.inv-pills{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 4px}
.inv-pill{padding:5px 12px;border-radius:999px;font-size:.78rem;background:rgba(148,163,184,.12);
 border:1px solid rgba(148,163,184,.25)}
.inv-pill b{margin-left:4px}
.inv-card{border-radius:10px;padding:10px 14px;margin:6px 0;background:rgba(148,163,184,.07);
 border-left:3px solid var(--c);font-size:.9rem}
.inv-ev{opacity:.55;font-family:monospace;font-size:.75rem;margin-left:6px}
.inv-sum{border-radius:12px;padding:14px 16px;margin:10px 0;background:rgba(129,140,248,.08);
 border:1px solid rgba(129,140,248,.25)}
/* AG */
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) .inv-info {display:flex; align-items:center; gap:12px; padding:12px 18px; border-radius:12px; font:400 13.5px Inter,sans-serif; color:#b9c6da; background:rgba(56,189,248,.07); border:1px solid rgba(56,189,248,.28);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) .inv-info b {display:grid; place-items:center; width:20px; height:20px; border-radius:50%; font:700 12px Inter,sans-serif; color:#38bdf8; border:1.5px solid #38bdf8;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) .inv-div {display:flex; align-items:center; gap:14px; margin:10px 0 0; font:700 10.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.2em; color:#8fa3b8;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) .inv-div::after {content:''; flex:1; height:1px; background:linear-gradient(90deg,rgba(255,255,255,.14),transparent);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"]) {gap:16px !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"]) > [data-testid="stColumn"] {--ac:#a78bfa; position:relative; overflow:hidden; padding:16px 18px 18px !important; border-radius:16px; border:1px solid color-mix(in srgb,var(--ac) 40%,transparent); background:radial-gradient(100% 140% at 0% 0%,color-mix(in srgb,var(--ac) 16%,transparent),transparent 65%),linear-gradient(180deg,#0e1520,#0a1018); box-shadow:0 16px 32px -20px var(--ac);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"]) > [data-testid="stColumn"]::before {content:''; position:absolute; left:0; right:0; top:0; height:3px; background:linear-gradient(90deg,var(--ac),transparent 85%);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"]) > [data-testid="stColumn"]:nth-child(2) {--ac:#38bdf8;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"]) > [data-testid="stColumn"]:nth-child(3) {--ac:#34d399;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInput"] label p {font:700 11px ui-monospace,Consolas,monospace !important; letter-spacing:.18em !important; text-transform:uppercase; color:color-mix(in srgb,var(--ac,#a78bfa) 65%,#fff) !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"] {width:auto !important; min-width:260px; padding:0 54px 0 64px !important; justify-content:flex-start !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stColumn"]:nth-child(1) [data-testid="stNumberInput"] label p::before {content:'⚙'; margin-right:8px;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stColumn"]:nth-child(2) [data-testid="stNumberInput"] label p::before {content:'↻'; margin-right:8px;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stColumn"]:nth-child(3) [data-testid="stNumberInput"] label p::before {content:'⏱'; margin-right:8px;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] {display:flex !important; align-items:center; gap:12px; padding:4px 4px 4px 14px !important; border:0 !important; border-radius:12px; background:#070b12 !important; box-shadow:inset 0 0 0 1px rgba(255,255,255,.06) !important; overflow:visible !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] [data-baseweb], html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] [data-baseweb] > div, html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] input {border:0 !important; outline:0 !important; box-shadow:none !important; background:transparent !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] [data-baseweb="input"] {flex:1 1 auto !important; width:auto !important; min-width:0;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] input {text-align:left !important; padding:0 !important; font:800 28px/1 Inter,sans-serif !important; color:#fff !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] > div:has(> button) {display:flex !important; gap:8px; border:0 !important; background:none !important; box-shadow:none !important; padding:0 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] button {width:40px !important; height:40px !important; min-width:40px; margin:0 !important; border:0 !important; border-radius:10px !important; color:#fff !important; background:color-mix(in srgb,var(--ac,#a78bfa) 20%,#0d141d) !important; box-shadow:none !important; transition:all .15s;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] button:hover {background:color-mix(in srgb,var(--ac,#a78bfa) 45%,#0d141d) !important; transform:translateY(-1px);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] button:disabled {opacity:.35;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stCheckbox"]) {position:relative; display:flex !important; flex-wrap:nowrap !important; gap:0 !important; padding:38px 0 6px !important; border-radius:16px; border:1px solid rgba(255,255,255,.09);
 background:linear-gradient(rgba(255,255,255,.022) 1px,transparent 1px) 0 0/100% 22px, radial-gradient(70% 160% at 100% 0%,rgba(52,211,153,.10),transparent 60%), linear-gradient(180deg,#0e1520,#0a1018); box-shadow:0 18px 36px -24px #000, inset 0 1px 0 rgba(255,255,255,.06); overflow:hidden;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stCheckbox"])::before {content:'\u25CF  TOOLKIT  \u00B7  RUN OPTIONS'; position:absolute; left:20px; top:14px; font:700 10px/1 ui-monospace,Consolas,monospace; letter-spacing:.22em; color:#34d399;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stCheckbox"])::after {content:'OPTIONAL'; position:absolute; right:16px; top:11px; padding:3px 8px; border-radius:5px; font:700 9.5px/1 ui-monospace,Consolas,monospace; letter-spacing:.16em; color:#f59e0b; background:rgba(245,158,11,.1); border:1px solid rgba(245,158,11,.35);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stCheckbox"]) > [data-testid="stColumn"] {flex:1 1 0 !important; width:auto !important; min-width:0 !important; padding:0 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stCheckbox"]) > [data-testid="stColumn"]:nth-child(2) {border-left:1px solid rgba(255,255,255,.08);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] {width:100% !important; padding:0 !important; border:0 !important; background:none !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label {display:flex !important; flex-direction:row-reverse; align-items:center; justify-content:space-between; gap:18px; width:100% !important; min-height:0 !important; padding:14px 22px 16px !important; border:0 !important; border-radius:0 !important; background:none !important; box-shadow:none !important; transition:background .2s;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label:hover {background:rgba(255,255,255,.03) !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label:has(input:checked) {background:linear-gradient(90deg,rgba(52,211,153,.16),transparent 80%) !important; box-shadow:inset 3px 0 0 #34d399 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label p {font:500 12.5px/1.45 Inter,sans-serif !important; color:#8fa3b8 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label p strong {font:700 14.5px Inter,sans-serif !important; color:#fff !important;}
</style>"""


def _t(v):
    """Escape email-derived text so it cannot render as markdown/HTML."""
    return _MD.sub(r"\\\1", ia.clean(v, 300))


def _controls(key):
    st.markdown(_CSS, unsafe_allow_html=True)
    st.markdown('<div class="inv-info"><b>i</b>Read-only \u00b7 allowlisted tools \u00b7 scanner score unchanged \u00b7 no outbound mail</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    use_ai = c1.toggle("**AI-assisted planning**  \n:gray[Let the AI plan its investigation approach.]", value=True, key="agent_ai_" + key,
                       help="Uses the app's configured provider (local Ollama/Qwen or Groq). "
                            "Sends only a short evidence digest, never the email body.")
    net = c2.toggle("**Public DNS/RDAP lookups**  \n:gray[Allow lookups to public DNS and RDAP services.]", value=False, key="agent_net_" + key,
                    help="Sends only domain names found in this email to public DNS-over-HTTPS and RDAP services.")
    st.markdown('<div class="inv-div">LIMITS \u00b7 PER-RUN CAPS</div>', unsafe_allow_html=True)
    # The stubbed Streamlit used in tests does not expose st.container(). Keep a compatible layout.
    l1, l2, l3 = st.columns(3)
    calls = int(l1.number_input("Tool calls", 1, 15, 10, 1, key="agent_calls_" + key, help="Hard cap per run"))
    iters = int(l2.number_input("Iterations", 1, 15, 10, 1, key="agent_iters_" + key, help="Planning loops"))
    secs = int(l3.number_input("Seconds", 10, 300, 90, 10, key="agent_secs_" + key, help="Wall-clock budget"))
    # Avoid deprecated and unsupported Streamlit kwargs used by the failing tests.
    go = st.button("Start investigation  →", type="primary", key="agent_go_" + key)
    st.caption("Runs only the enabled lookups and stops at the limits above.")
    return use_ai, net, calls, iters, secs, go


def _pills(inv):
    snap = inv["score_snapshot"]
    items = (("Status", inv["status"]), ("Calls", f"{len(inv['evidence'])}/{inv['limits']['max_tool_calls']}"),
             ("Time", f"{inv['seconds']}s"), ("Mode", "AI" if inv["mode"] == "ai" else "Deterministic"),
             ("Stopped", inv["stop_reason"] or "-"), ("Score", f"{snap['score']} ({snap['level']})"))
    st.markdown('<div class="inv-pills">' + "".join(
        f'<span class="inv-pill">{k}<b>{_t(v)}</b></span>' for k, v in items) + "</div>", unsafe_allow_html=True)


def _findings(inv):
    for kind, title, color, desc in _KINDS:
        items = [f for f in inv["findings"] if f["kind"] == kind]
        with st.expander(f"{title} ({len(items)})", expanded=kind != "verified" and bool(items)):
            st.caption(desc)
            for f in items:
                st.markdown(f'<div class="inv-card" style="--c:{color}">{_t(f["statement"])}'
                            f'<span class="inv-ev">[{_t(",".join(f["evidence_ids"]))}]</span></div>',
                            unsafe_allow_html=True)
            if not items:
                st.caption("None recorded.")


def _actions(inv):
    st.dataframe([{"#": s["n"], "tool": s["tool"], "argument": s["args"].get("indicator", "-"),
                   "chosen by": s["source"], "result": s.get("status"),
                   "evidence": s.get("evidence_id", "-"), "why": s["reason"]} for s in inv["steps"]],
                 hide_index=True)


def _evidence(inv):
    shown = False
    for e in inv["evidence"]:
        if e.get("records"):
            shown = True
            with st.expander(f"{e['id']} · {e['args'].get('indicator', '-')} ({len(e['records'])} rows)"):
                st.caption("Stored values as found. 'historical' = seen before only; "
                           "'suspicious'/'confirmed' require stored evidence in the record.")
                st.dataframe(e["records"], hide_index=True)
    if not shown:
        st.caption("No supporting records.")


def render_investigation_panel(result, raw, cases, conns_factory, key, download_fn=None):
    store = st.session_state.setdefault("agent_investigations", {})
    key = str(key)
    use_ai, net, calls, iters, secs, go = _controls(key)
    if go:
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
        st.caption("Start an investigation for a bounded, evidence-attributed review of this email.")
        return

    _pills(inv)
    if inv.get("mode_note"):
        st.warning(_t(inv["mode_note"]))
    if inv.get("narrative"):
        st.markdown(f'<div class="inv-sum"><div class="inv-lbl" style="margin-top:0">Summary · generated from tool findings</div>'
                    f'{_t(inv["narrative"])}</div>', unsafe_allow_html=True)

    t1, t2, t3 = st.tabs(["Findings", "Action log", "Evidence"])
    with t1:
        _findings(inv)
    with t2:
        _actions(inv)
    with t3:
        _evidence(inv)

    report_md = ia.render_report(inv, result, raw)
    if download_fn is not None:     # app's premium download (HTML report + Word)
        download_fn(label="Download Investigation Report", markdown=report_md, file_name="agentic_investigation_report.md",
                    key="agent_dl_" + key, help="Full forensic report with the agentic investigation (HTML, or Word)")
    else:
        st.download_button("Download report (.md)", report_md, file_name="agentic_investigation_report.md",
                           mime="text/markdown", key="agent_dl_md_" + key)
