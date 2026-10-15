"""Streamlit panel for the agentic investigation (explicit start, read-only)."""
import html
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
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] {display:block !important; width:100% !important; padding:0 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] > div, html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] > label, html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] > div > label, html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label {width:100% !important; max-width:none !important; flex:1 1 100% !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label {display:flex !important; flex-direction:row-reverse !important; align-items:center !important; justify-content:space-between !important; gap:16px; padding:8px 22px 14px !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] [data-testid="stWidgetLabel"] {display:flex !important; flex:1 1 auto; align-items:center; justify-content:space-between; gap:12px; width:auto !important; margin:0 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] [data-testid="stWidgetLabel"] > div:first-child {flex:1 1 auto;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stCheckbox"]) > [data-testid="stColumn"] {flex:0 0 auto !important; width:100% !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stCheckbox"]) > [data-testid="stColumn"]:nth-child(n+2) {border-left:0 !important; border-top:1px solid rgba(255,255,255,.06);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stElementContainer"]:has([data-testid="stCheckbox"]), html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_ai_"], html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [class*="st-key-agent_net_"] {width:100% !important; max-width:none !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label {padding:14px 22px !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label p strong {font:600 14px Inter,sans-serif !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stCheckbox"] label p {font:400 12.5px/1.4 Inter,sans-serif !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"]) {position:relative; display:grid !important; grid-template-columns:repeat(3,minmax(0,1fr)); gap:0 !important; padding:44px 0 0 !important; margin:0 0 12px !important; border-radius:14px; border:1px solid rgba(255,255,255,.08); overflow:hidden; background:linear-gradient(rgba(255,255,255,.07),rgba(255,255,255,.07)) 0 42px/100% 1px no-repeat,#0b111a !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"])::before {content:'Limits'; position:absolute; left:22px; top:14px; font:600 13px/1 Inter,sans-serif; color:#e5ecf6;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"])::after {content:'Per-run caps'; position:absolute; right:22px; top:15px; font:400 12px/1 Inter,sans-serif; color:#6f7f95;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"]) > [data-testid="stColumn"] {width:auto !important; min-width:0 !important; flex:none !important; padding:16px 22px 20px !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has([data-testid="stNumberInput"]) > [data-testid="stColumn"]:nth-child(n+2) {border-left:1px solid rgba(255,255,255,.07);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInput"] label p {font:600 11px Inter,sans-serif !important; letter-spacing:.08em !important; text-transform:uppercase; color:#8fa3b8 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] {display:flex !important; align-items:center; justify-content:space-between; gap:12px; padding:0 !important; border:0 !important; background:none !important; box-shadow:none !important; overflow:visible !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] [data-baseweb], html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] [data-baseweb] > div, html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] input {border:0 !important; outline:0 !important; box-shadow:none !important; background:transparent !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] [data-baseweb="input"] {order:1; flex:1 1 auto !important; width:auto !important; min-width:0;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] input {text-align:center !important; padding:0 !important; font:700 30px/1 Inter,sans-serif !important; color:#fff !important; pointer-events:none !important; caret-color:transparent !important; user-select:none !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] > div:has(> button) {display:contents !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] [data-testid="stNumberInputStepDown"] {order:0;} html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] [data-testid="stNumberInputStepUp"] {order:2;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] button {flex:0 0 auto; width:38px !important; height:38px !important; min-width:38px; margin:0 !important; border-radius:50% !important; color:#e5ecf6 !important; background:#121a27 !important; border:1px solid rgba(255,255,255,.1) !important; box-shadow:none !important; transition:all .15s;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] button:hover {background:#1b2536 !important; border-color:#3b4a63 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stNumberInputContainer"] button:disabled {opacity:.3;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"] {width:auto !important; min-width:0 !important; height:44px !important; min-height:44px !important; padding:0 26px !important; justify-content:center !important; border-radius:10px !important; border:1px solid rgba(255,255,255,.14) !important; background:linear-gradient(180deg,#6d70f5,#4f46e5) !important; box-shadow:inset 0 1px 0 rgba(255,255,255,.2), 0 1px 2px rgba(0,0,0,.5) !important; transition:transform .12s ease,filter .12s ease;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"]::before, html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"]::after {display:none !important; content:none !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"] p {font:600 14px Inter,sans-serif !important; letter-spacing:.01em; color:#fff !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"]:hover {filter:brightness(1.1); transform:translateY(-1px);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"]:active {filter:brightness(.94); transform:translateY(0) scale(.98);}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"]:focus-visible {outline:2px solid #a5b4fc !important; outline-offset:2px;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"]:disabled {opacity:.45; filter:grayscale(.4); cursor:not-allowed; transform:none;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stHorizontalBlock"]:has(.inv-run) {align-items:center !important; gap:18px !important; margin-top:4px;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) .inv-run {font:400 12.5px/1.5 Inter,sans-serif; color:#7d8da3;} html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) .inv-run b {color:#c9d5e6; font-weight:600;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-testid="stButton"] button[kind="primary"] p::before {content:'▶' !important; -webkit-mask-image:none !important; mask-image:none !important; animation:none !important; position:static !important; display:inline-block !important; width:auto !important; height:auto !important; transform:none !important; background:none !important; background-color:transparent !important; color:#fff; font-size:10px; margin-right:10px; opacity:.9;}
</style>"""

_RES_CSS = """<style>
.rs-kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border:1px solid rgba(255,255,255,.08);border-radius:14px;background:#0b111a;overflow:hidden;margin:18px 0 12px}
.rs-k{position:relative;padding:14px 18px 20px;border-left:1px solid rgba(255,255,255,.07);min-width:0}
.rs-k:first-child{border-left:0}
.rs-k span{display:block;font:600 10.5px Inter,sans-serif;letter-spacing:.08em;text-transform:uppercase;color:#8fa3b8}
.rs-k b{display:block;margin-top:8px;font:700 20px/1.1 Inter,sans-serif;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rs-k b small{font:500 13px Inter,sans-serif;color:#7d8da3;margin-left:2px}
.rs-k b.ok::before,.rs-k b.warn::before{content:'';display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;vertical-align:middle;background:#34d399}
.rs-k b.warn::before{background:#fbbf24}
.rs-k i{position:absolute;left:18px;right:18px;bottom:9px;height:3px;border-radius:2px;background:rgba(255,255,255,.08)}
.rs-k i::after{content:'';position:absolute;left:0;top:0;bottom:0;width:var(--p);border-radius:2px;background:#38bdf8}
.rs-lvl{display:inline-block;margin-left:8px;padding:2px 8px;border-radius:5px;font:700 10.5px Inter,sans-serif;letter-spacing:.06em;text-transform:uppercase;vertical-align:middle;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent);border:1px solid color-mix(in srgb,var(--c) 35%,transparent)}
.rs-card{border:1px solid rgba(255,255,255,.08);border-radius:14px;background:#0b111a;margin:0 0 12px;overflow:hidden}
.rs-hd{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:13px 20px;border-bottom:1px solid rgba(255,255,255,.07)}
.rs-hd b{font:600 13px Inter,sans-serif;color:#e5ecf6}.rs-hd span{font:400 12px Inter,sans-serif;color:#6f7f95}
.rs-bd{padding:16px 20px;font:400 14px/1.7 Inter,sans-serif;color:#c3cde0}
.rs-grp{border-bottom:1px solid rgba(255,255,255,.07)}.rs-grp:last-child{border-bottom:0}
.rs-grp summary{display:flex;align-items:center;gap:12px;padding:13px 20px;cursor:pointer;list-style:none}
.rs-grp summary::-webkit-details-marker{display:none}
.rs-grp summary:hover{background:rgba(255,255,255,.025)}
.rs-grp summary i{width:8px;height:8px;border-radius:50%;background:var(--c)}
.rs-grp summary .t{font:600 14px Inter,sans-serif;color:#fff}
.rs-grp summary em{font:700 11px Inter,sans-serif;font-style:normal;padding:2px 9px;border-radius:999px;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent)}
.rs-grp summary .d{margin-left:auto;font:400 12px Inter,sans-serif;color:#6f7f95}
.rs-grp summary::after{content:'▸';color:#6f7f95;margin-left:8px}
.rs-grp[open] summary::after{content:'▾'}
.rs-row{display:flex;gap:16px;align-items:flex-start;justify-content:space-between;padding:10px 20px 10px 40px;border-top:1px solid rgba(255,255,255,.05);font:400 13.5px/1.55 Inter,sans-serif;color:#d3dcea}
.rs-ev{display:flex;flex-wrap:wrap;gap:5px;flex:0 0 auto;justify-content:flex-end}
.rs-ev span{padding:2px 7px;border-radius:5px;font:600 11px ui-monospace,Consolas,monospace;color:#8fa3b8;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}
.rs-none{padding:10px 20px 14px 40px;border-top:1px solid rgba(255,255,255,.05);font:400 13px Inter,sans-serif;color:#6f7f95}
@media(max-width:900px){.rs-kpis{grid-template-columns:repeat(3,minmax(0,1fr))}.rs-k:nth-child(4){border-left:0}}
</style>"""


def _h(v, n=300):
    """Escape email-derived text for HTML contexts (no markdown escaping)."""
    return html.escape(str(ia.clean(v, n)))


def _t(v):
    """Escape email-derived text so it cannot render as markdown/HTML."""
    return _MD.sub(r"\\\1", ia.clean(v, 300))


def _controls(key):
    st.markdown(_CSS, unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    use_ai = c1.toggle("**AI-assisted planning**  \n:gray[Let the AI plan its investigation approach.]", value=True, key="agent_ai_" + key,
                       help="Uses the app's configured provider (local Ollama/Qwen or Groq). "
                            "Sends only a short evidence digest, never the email body.")
    net = c2.toggle("**Public DNS/RDAP lookups**  \n:gray[Allow lookups to public DNS and RDAP services.]", value=False, key="agent_net_" + key,
                    help="Sends only domain names found in this email to public DNS-over-HTTPS and RDAP services.")
    # The stubbed Streamlit used in tests does not expose st.container(). Keep a compatible layout.
    l1, l2, l3 = st.columns(3)
    calls = int(l1.number_input("Tool calls", 1, 15, 10, 1, key="agent_calls_" + key, help="Hard cap per run"))
    iters = int(l2.number_input("Iterations", 1, 15, 10, 1, key="agent_iters_" + key, help="Planning loops"))
    secs = int(l3.number_input("Seconds", 10, 300, 90, 10, key="agent_secs_" + key, help="Wall-clock budget"))
    # Avoid deprecated and unsupported Streamlit kwargs used by the failing tests.
    b1, b2 = st.columns([1, 3])
    go = b1.button("Start investigation  →", type="primary", key="agent_go_" + key)
    b2.markdown('<div class="inv-run">Up to <b>' + str(calls) + '</b> tool calls \u00b7 <b>' + str(iters) + '</b> iterations \u00b7 <b>' + str(secs) + 's</b> \u00b7 '
                + ('AI-assisted' if use_ai else 'Deterministic') + (' \u00b7 public DNS/RDAP on' if net else ' \u00b7 offline lookups') + '</div>', unsafe_allow_html=True)
    return use_ai, net, calls, iters, secs, go


def _pills(inv):
    snap = inv["score_snapshot"]
    try:
        sc = f"{float(snap['score']):.1f}"
    except (TypeError, ValueError):
        sc = _h(snap.get("score"), 12)
    lv = str(snap.get("level") or "").strip()
    lc = {"low": "#34d399", "medium": "#fbbf24", "high": "#f87171", "critical": "#f87171"}.get(lv.lower(), "#94a3b8")
    done = str(inv["status"]).lower() == "complete"
    mx = max(1, int(inv["limits"]["max_tool_calls"]))
    pct = max(0, min(100, len(inv["evidence"]) * 100 // mx))
    try:
        tm = f"{float(inv['seconds']):.1f}"
    except (TypeError, ValueError):
        tm = _h(inv["seconds"], 12)
    cells = (
        ("Status", f'<b class="{"ok" if done else "warn"}">{_h(inv["status"], 20).capitalize()}</b>'),
        ("Tool calls", f'<b>{len(inv["evidence"])}<small>/{mx}</small></b><i style="--p:{pct}%"></i>'),
        ("Time", f'<b>{tm}<small>s</small></b>'),
        ("Mode", f'<b>{"AI" if inv["mode"] == "ai" else "Deterministic"}</b>'),
        ("Stopped", f'<b>{_h(inv["stop_reason"] or "-", 40).replace("_", " ")}</b>'),
        ("Scanner score", f'<b>{sc}<small>/100</small><span class="rs-lvl" style="--c:{lc}">{_h(lv, 12)}</span></b>'),
    )
    st.markdown(_RES_CSS + '<div class="rs-kpis">' + "".join(f"<div class=\"rs-k\"><span>{k}</span>{v}</div>" for k, v in cells) + "</div>",
                unsafe_allow_html=True)


def _findings(inv):
    parts = ['<div class="rs-card"><div class="rs-hd"><b>Findings</b><span>Every item cites its evidence ID</span></div>']
    for kind, title, color, desc in _KINDS:
        items = [f for f in inv["findings"] if f["kind"] == kind]
        op = " open" if kind != "verified" and items else ""
        parts.append(f'<details class="rs-grp"{op} style="--c:{color}"><summary><i></i><span class="t">{title}</span><em>{len(items)}</em>'
                     f'<span class="d">{html.escape(desc)}</span></summary>')
        for f in items:
            ev = "".join(f"<span>{_h(e, 20)}</span>" for e in f["evidence_ids"])
            parts.append(f'<div class="rs-row"><div>{_h(f["statement"], 600)}</div><div class="rs-ev">{ev}</div></div>')
        if not items:
            parts.append('<div class="rs-none">None recorded.</div>')
        parts.append("</details>")
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


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
        return

    _pills(inv)
    if inv.get("mode_note"):
        st.warning(_t(inv["mode_note"]))
    if inv.get("narrative"):
        st.markdown('<div class="rs-card"><div class="rs-hd"><b>Summary</b><span>Generated from tool findings</span></div>'
                    f'<div class="rs-bd">{_h(inv["narrative"], 4000)}</div></div>', unsafe_allow_html=True)

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
