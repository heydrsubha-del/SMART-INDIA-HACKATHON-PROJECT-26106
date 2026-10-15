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
</style>"""


def _t(v):
    """Escape email-derived text so it cannot render as markdown/HTML."""
    return _MD.sub(r"\\\1", ia.clean(v, 300))


def _controls(key):
    st.markdown(_CSS, unsafe_allow_html=True)
    st.caption("Read-only \u00b7 allowlisted tools \u00b7 scanner score unchanged \u00b7 no outbound mail")
    c1, c2 = st.columns(2)
    use_ai = c1.toggle("AI-assisted planning", value=True, key="agent_ai_" + key,
                       help="Uses the app's configured provider (local Ollama/Qwen or Groq). "
                            "Sends only a short evidence digest, never the email body.")
    net = c2.toggle("Public DNS/RDAP lookups", value=False, key="agent_net_" + key,
                    help="Sends only domain names found in this email to public DNS-over-HTTPS and RDAP services.")
    st.markdown('<div class="inv-lbl">Limits · per-run caps</div>', unsafe_allow_html=True)
    with st.container(key="agent_limits_" + key):
        l1, l2, l3 = st.columns(3)
        calls = int(l1.number_input("Tool calls", 1, 15, 10, 1, key="agent_calls_" + key, help="Hard cap per run"))
        iters = int(l2.number_input("Iterations", 1, 15, 10, 1, key="agent_iters_" + key, help="Planning loops"))
        secs = int(l3.number_input("Seconds", 10, 300, 90, 10, key="agent_secs_" + key, help="Wall-clock budget"))
    go = st.button("Start investigation  →", type="primary", use_container_width=True, key="agent_go_" + key)
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
                 hide_index=True, use_container_width=True)


def _evidence(inv):
    shown = False
    for e in inv["evidence"]:
        if e.get("records"):
            shown = True
            with st.expander(f"{e['id']} · {e['args'].get('indicator', '-')} ({len(e['records'])} rows)"):
                st.caption("Stored values as found. 'historical' = seen before only; "
                           "'suspicious'/'confirmed' require stored evidence in the record.")
                st.dataframe(e["records"], hide_index=True, use_container_width=True)
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
