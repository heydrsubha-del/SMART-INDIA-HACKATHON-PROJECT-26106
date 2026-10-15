"""Streamlit panel for the agentic investigation (explicit start, read-only)."""
import re

import streamlit as st

import investigation_agent as ia

_MD = re.compile(r"([\\`*_{}\[\]()#+!|<>~])")


_AGENT_CSS = """<style>
.ag-chips {display:flex; flex-wrap:wrap; gap:8px; margin:0 0 12px;}
.ag-chips span {display:inline-flex; align-items:center; gap:8px; padding:6px 12px; border-radius:999px; font:600 12px/1 Inter,'Segoe UI',sans-serif; color:#dbe4f0; background:rgba(255,255,255,.035); border:1px solid var(--line-strong, rgba(255,255,255,.1));}
.ag-chips em {font:700 9.5px/1 ui-monospace,Consolas,monospace; font-style:normal; letter-spacing:.14em; color:var(--c);}
</style>"""


def _chips(items):
    return '<div class="ag-chips">' + "".join('<span><em style="--c:%s">%s</em>%s</span>' % (c, k, v) for c, k, v in items) + "</div>"


def _t(v):
    """Escape email-derived text so it cannot render as markdown/HTML."""
    return _MD.sub(r"\\\1", ia.clean(v, 300))


def render_investigation_panel(result, raw, cases, conns_factory, key, download_fn=None):
    store = st.session_state.setdefault("agent_investigations", {})
    key = str(key)
    st.markdown(_AGENT_CSS + _chips((("#38bdf8", "ACCESS", "Read-only"), ("#a78bfa", "TOOLS", "Allowlist"),
                                     ("#34d399", "SCORE", "Unchanged"), ("#f59e0b", "MAIL", "None outbound"))), unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    use_ai = c1.toggle("AI-assisted planning and proposed findings", value=True, key="agent_ai_" + key,
                       help="Uses the app's configured provider (local Ollama/Qwen or the Groq backend). "
                            "Sends only a short evidence digest, never the email body.")
    net = c2.toggle("Allow public DNS/RDAP lookups", value=False, key="agent_net_" + key,
                    help="Sends only domain names found in this email to public DNS-over-HTTPS and RDAP services.")
    with st.expander("Limits", expanded=False):
        l1, l2, l3 = st.columns(3)
        calls = int(l1.number_input("Max tool calls", 1, 15, 10, 1, key="agent_calls_" + key, help="Hard cap per run"))
        iters = int(l2.number_input("Max iterations", 1, 15, 10, 1, key="agent_iters_" + key, help="Planning loops"))
        secs = int(l3.number_input("Max seconds", 10, 300, 90, 10, key="agent_secs_" + key, help="Wall-clock budget"))
    st.markdown(_chips((("#34d399", "PLANNER", "AI-assisted" if use_ai else "Deterministic"),
                        ("#f59e0b", "LOOKUPS", "Public DNS/RDAP" if net else "Offline only"),
                        ("#a78bfa", "BUDGET", f"{calls} calls \u00b7 {iters} loops \u00b7 {secs}s"))), unsafe_allow_html=True)
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