"""Streamlit panel for the agentic investigation (explicit start, read-only)."""
import contextlib
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
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-baseweb="tab-list"] {gap:4px !important; border-bottom:1px solid rgba(255,255,255,.08) !important; background:none !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) button[data-baseweb="tab"] {height:auto !important; padding:10px 18px !important; border:0 !important; border-radius:0 !important; background:none !important; box-shadow:none !important; color:#8fa3b8 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) button[data-baseweb="tab"] p {font:600 13.5px Inter,sans-serif !important; color:inherit !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) button[data-baseweb="tab"][aria-selected="true"] {color:#fff !important; box-shadow:inset 0 -2px 0 #6366f1 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) button[data-baseweb="tab"]:hover {color:#e5ecf6 !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-baseweb="tab-highlight"] {background:#6366f1 !important; height:2px !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) [data-baseweb="tab-border"] {display:none !important;}
html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) .rs-sel td, html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) .rs-sel th {user-select:text;} html body .stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp.stApp .st-key-ai_step_agent:not(#_x):not(#_x):not(#_x):not(#_x) .rs-t .ind {min-width:260px;}
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
.rs-tw{overflow-x:auto}.rs-t{width:100%;border-collapse:collapse;font:400 13px/1.5 Inter,sans-serif;color:#d3dcea}
.rs-t th{padding:10px 16px;text-align:left;font:600 10.5px Inter,sans-serif;letter-spacing:.08em;text-transform:uppercase;color:#8fa3b8;background:rgba(255,255,255,.025);border-bottom:1px solid rgba(255,255,255,.07);white-space:nowrap}
.rs-t td{padding:11px 16px;vertical-align:top;border-bottom:1px solid rgba(255,255,255,.05)}.rs-t tr:last-child td{border-bottom:0}.rs-t tbody tr:hover{background:rgba(255,255,255,.025)}
.rs-t .n{color:#6f7f95;width:48px;font-variant-numeric:tabular-nums}.rs-t .tl{font-weight:600;color:#fff;white-space:nowrap}
.rs-t .mo{font:500 12px ui-monospace,Consolas,monospace;color:#b9c6da;word-break:break-all}.rs-t .mu{color:#8fa3b8;white-space:nowrap}.rs-t .wh{color:#9fb0c6;min-width:240px}
.rs-b{display:inline-block;padding:2px 9px;border-radius:999px;font:700 11px Inter,sans-serif;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent);white-space:nowrap}
.rs-ev span{font:600 11.5px Inter,sans-serif !important;color:#b9c6da !important}
.rs-sh{font:600 16px/1.4 Inter,sans-serif;color:#fff}.rs-chips{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.rs-chip{display:inline-flex;align-items:baseline;gap:7px;padding:6px 12px;border-radius:8px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);font:400 12.5px Inter,sans-serif;color:#8fa3b8}.rs-chip b{font:700 15px Inter,sans-serif;color:#fff}
.rs-vd{font:400 13px/1.6 Inter,sans-serif;color:#9fb0c6}.rs-vd b{color:#e5ecf6;font-weight:600}
.rs-raw{margin-top:12px}.rs-raw summary{cursor:pointer;font:500 12px Inter,sans-serif;color:#6f7f95}.rs-raw p{margin:8px 0 0;font:400 12.5px/1.6 Inter,sans-serif;color:#7d8da3}
@media(max-width:900px){.rs-kpis{grid-template-columns:repeat(3,minmax(0,1fr))}.rs-k:nth-child(4){border-left:0}}
</style>"""


def _h(v, n=300):
    """Escape email-derived text for HTML contexts (no markdown escaping)."""
    return html.escape(str(ia.clean(v, n)))

_SCAN_CSS = """<style>
.sc{position:relative;overflow:hidden;border:1px solid rgba(255,255,255,.08);border-radius:14px;background:#0b111a;margin:14px 0}
.sc::before{content:'';position:absolute;inset:0;pointer-events:none;background:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px) 0 0/100% 22px,linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px) 0 0/22px 100%}
.sc::after{content:'';position:absolute;top:0;bottom:0;width:140px;left:-140px;pointer-events:none;background:linear-gradient(90deg,transparent,rgba(56,189,248,.12),transparent);animation:scSweep 2.6s linear infinite}
@keyframes scSweep{to{left:100%}}
.sc-h{position:relative;z-index:1;display:flex;align-items:center;gap:16px;padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.07)}
.sc-radar{position:relative;flex:0 0 auto;width:38px;height:38px;border-radius:50%;border:1px solid rgba(56,189,248,.4);background:radial-gradient(circle,rgba(56,189,248,.16),transparent 70%)}
.sc-radar::before{content:'';position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,rgba(56,189,248,.6),transparent 35%);animation:scSpin 1.4s linear infinite}
.sc-radar::after{content:'';position:absolute;left:50%;top:50%;width:6px;height:6px;margin:-3px;border-radius:50%;background:#38bdf8}
@keyframes scSpin{to{transform:rotate(360deg)}}
.sc-t b{display:block;font:600 14px Inter,sans-serif;color:#fff}.sc-t span{font:400 12px Inter,sans-serif;color:#6f7f95}
.sc-cnt{margin-left:auto;font:600 12px ui-monospace,Consolas,monospace;color:#8fa3b8}
.sc-bar{position:relative;z-index:1;height:3px;background:rgba(255,255,255,.06);overflow:hidden}
.sc-bar i{position:absolute;left:0;top:0;bottom:0;width:var(--p);background:linear-gradient(90deg,#6366f1,#38bdf8);transition:width .4s ease}
.sc-bar::after{content:'';position:absolute;top:0;bottom:0;width:70px;left:-70px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.55),transparent);animation:scSweep 1.3s linear infinite}
.sc-log{position:relative;z-index:1;padding:12px 20px 16px;font:500 12.5px/1.9 ui-monospace,Consolas,monospace;color:#8fa3b8}
.sc-log div{display:flex;gap:12px}.sc-log .ok{color:#34d399}.sc-log .run{color:#38bdf8}.sc-log .n{color:#5b6b82}
.sc-log .cur::after{content:'';display:inline-block;width:7px;height:13px;margin-left:6px;background:#38bdf8;vertical-align:middle;animation:scBlink 1s steps(2) infinite}
@keyframes scBlink{50%{opacity:0}}
@media (prefers-reduced-motion:reduce){.sc::after,.sc-radar::before,.sc-bar::after,.sc-log .cur::after{animation:none}}
</style>"""


def _scan_html(seen, calls):
    pct = min(95, len(seen) * 100 // max(1, int(calls))) if seen else 4
    rows = []
    for i, (n, tool) in enumerate(seen):
        last = i == len(seen) - 1
        rows.append(f'<div class="{"run" if last else ""}"><span class="{"run" if last else "ok"}">{"\u203A" if last else "\u2713"}</span>'
                    f'<span class="n">{int(n):02d}</span><span class="{"cur" if last else ""}">{html.escape(_hum(tool))}</span></div>')
    if not rows:
        rows.append('<div class="run"><span class="run">\u203A</span><span class="cur">Planning investigation</span></div>')
    return (_SCAN_CSS + '<div class="sc"><div class="sc-h"><div class="sc-radar"></div><div class="sc-t"><b>Investigating</b>'
            '<span>Read-only checks \u00b7 results appear when complete</span></div>'
            f'<div class="sc-cnt">{len(seen)} / {int(calls)} CALLS</div></div><div class="sc-bar" style="--p:{pct}%"><i></i></div>'
            f'<div class="sc-log">{"".join(rows)}</div></div>')


def _show(slot, markup):
    try:
        slot.markdown(markup, unsafe_allow_html=True)
    except Exception:
        pass


def _summary(inv):
    k = {x: sum(1 for f in inv["findings"] if f["kind"] == x) for x in ("suspicious", "uncertain", "verified")}
    if k["suspicious"]:
        head = "Suspicious signals found \u2014 review before acting."
    elif k["uncertain"]:
        head = f"No suspicious signals found, but {k['uncertain']} check(s) could not be completed."
    else:
        head = "No suspicious signals found."
    snap = inv["score_snapshot"]
    try:
        sc = f"{float(snap['score']):.1f}"
    except (TypeError, ValueError):
        sc = _h(snap.get("score"), 12)
    chips = "".join(f'<span class="rs-chip"><b>{v}</b>{lab}</span>' for v, lab in (
        (len(inv["evidence"]), "checks run"), (k["verified"], "verified"), (k["suspicious"], "suspicious"), (k["uncertain"], "gaps")))
    raw = (f'<details class="rs-raw"><summary>Show generated text</summary><p>{_h(inv["narrative"], 4000)}</p></details>'
           if inv.get("narrative") else "")
    return ('<div class="rs-card"><div class="rs-hd"><b>Summary</b><span>Generated from tool findings</span></div><div class="rs-bd">'
            f'<div class="rs-sh">{head}</div><div class="rs-chips">{chips}</div>'
            f'<div class="rs-vd">Scanner verdict (unchanged): <b>{_h(snap.get("level"), 12)} \u00b7 {sc}/100</b>. '
            f'Absence of findings is not evidence of safety.</div>{raw}</div></div>')



def _hum(v):
    return str(v or "-").replace("_", " ").strip().capitalize()


def _src(inv):
    m = {}
    for st_ in inv.get("steps", []):
        if st_.get("evidence_id"):
            m[st_["evidence_id"]] = _hum(st_.get("tool"))
    for e in inv.get("evidence", []):
        if e.get("tool"):
            m.setdefault(e.get("id"), _hum(e["tool"]))
    return m


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
    src = _src(inv)
    parts = ['<div class="rs-card"><div class="rs-hd"><b>Findings</b><span>Source = the tool that produced each finding</span></div>']
    for kind, title, color, desc in _KINDS:
        items = [f for f in inv["findings"] if f["kind"] == kind]
        op = " open" if kind != "verified" and items else ""
        parts.append(f'<details class="rs-grp"{op} style="--c:{color}"><summary><i></i><span class="t">{title}</span><em>{len(items)}</em>'
                     f'<span class="d">{html.escape(desc)}</span></summary>')
        for f in items:
            names = list(dict.fromkeys(src.get(e, e) for e in f["evidence_ids"]))
            ev = "".join(f'<span title="Evidence {_h(",".join(f["evidence_ids"]), 60)}">{_h(n, 40)}</span>' for n in names)
            parts.append(f'<div class="rs-row"><div>{_h(f["statement"], 600)}</div><div class="rs-ev">{ev}</div></div>')
        if not items:
            parts.append('<div class="rs-none">None recorded.</div>')
        parts.append("</details>")
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def _actions(inv):
    def badge(v):
        t = str(v or "-").lower()
        c = "#34d399" if any(k in t for k in ("ok", "success", "done", "complete")) else \
            "#f87171" if any(k in t for k in ("fail", "error", "denied", "blocked")) else "#fbbf24"
        return f'<span class="rs-b" style="--c:{c}">{_h(_hum(v), 24)}</span>'
    rows = "".join(
        f'<tr><td class="n">{_h(x["n"], 6)}</td><td class="tl">{_h(_hum(x["tool"]), 60)}</td>'
        f'<td class="mo">{_h(x["args"].get("indicator", "-"), 120)}</td><td>{badge(x.get("status"))}</td>'
        f'<td class="mu">{_h(_hum(x["source"]), 30)}</td><td class="wh">{_h(x["reason"], 400)}</td></tr>' for x in inv["steps"])
    st.markdown(_RES_CSS + f'<div class="rs-card"><div class="rs-hd"><b>Action log</b><span>{len(inv["steps"])} steps run by the agent</span></div>'
                '<div class="rs-tw"><table class="rs-t"><thead><tr><th>Step</th><th>Tool</th><th>Target</th><th>Result</th><th>Chosen by</th><th>Why</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div></div>', unsafe_allow_html=True)


def _evidence(inv):
    src = _src(inv)
    shown = False
    for e in inv["evidence"]:
        recs = e.get("records")
        if not recs:
            continue
        shown = True
        cols = list(recs[0].keys())

        def cell(c, v):
            k = str(c).lower()
            if k == "tier":
                t = str(v).lower()
                col = "#f87171" if t in ("suspicious", "confirmed") else "#94a3b8" if t == "historical" else "#fbbf24"
                return f'<td><span class="rs-b" style="--c:{col}">{_h(v, 24)}</span></td>'
            cls = "mo ind" if "indicator" in k else "wh" if k == "reason" else "n" if k == "#" else ""
            return f'<td class="{cls}">{_h(v, 600)}</td>'
        head = "".join(f"<th>{_h(c, 30)}</th>" for c in cols)
        rows = "".join("<tr>" + "".join(cell(c, r.get(c, "")) for c in cols) + "</tr>" for r in recs)
        title = f"{src.get(e['id'], e['id'])} \u00b7 {e['args'].get('indicator', '-')}"
        st.markdown(_RES_CSS + f'<div class="rs-card"><div class="rs-hd"><b>{_h(title, 160)}</b><span>{len(recs)} rows \u00b7 stored values as found</span></div>'
                    f'<div class="rs-tw"><table class="rs-t rs-sel"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div>'
                    '<div class="rs-bd" style="padding:10px 20px;font-size:12px;color:#6f7f95">\u2018historical\u2019 = seen before only; '
                    '\u2018suspicious\u2019 / \u2018confirmed\u2019 require stored evidence in the record.</div></div>', unsafe_allow_html=True)
        icol = next((c for c in cols if "indicator" in str(c).lower()), None)
        if icol:
            vals = list(dict.fromkeys(str(r.get(icol, "")) for r in recs if r.get(icol)))
            if vals:
                try:
                    st.caption("Copy indicators")
                    st.code("\n".join(vals), language=None)
                except Exception:
                    pass
    if not shown:
        st.caption("No supporting records.")


def render_investigation_panel(result, raw, cases, conns_factory, key, download_fn=None):
    store = st.session_state.setdefault("agent_investigations", {})
    key = str(key)
    use_ai, net, calls, iters, secs, go = _controls(key)
    if go:
        log = st.empty()
        seen = []
        _show(log, _scan_html(seen, calls))
        with contextlib.nullcontext():
            def _p(n, tool):
                seen.append((n, tool))
                _show(log, _scan_html(seen, calls))
            store[key] = ia.investigate(result, cases=cases, conns_factory=conns_factory, allow_network=net, use_ai=use_ai,
                                        limits=ia.Limits(max_iterations=iters, max_tool_calls=calls, max_seconds=secs), progress=_p)
        try:
            log.empty()
        except Exception:
            pass
    inv = store.get(key)
    if not inv:
        return

    _pills(inv)
    if inv.get("mode_note"):
        st.warning(_t(inv["mode_note"]))
    st.markdown(_RES_CSS + _summary(inv), unsafe_allow_html=True)

    _nev = sum(1 for e in inv["evidence"] if e.get("records"))
    t1, t2, t3 = st.tabs([f"Findings ({len(inv['findings'])})", f"Action log ({len(inv['steps'])})", f"Evidence ({_nev})"])
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
