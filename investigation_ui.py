"""Streamlit panel for the agentic investigation (explicit start, read-only)."""
import re

import streamlit as st

import investigation_agent as ia

_MD = re.compile(r"([\\`*_{}\[\]()#+!|<>~])")


def _t(v):
    """Escape email-derived text so it cannot render as markdown/HTML."""
    return _MD.sub(r"\\\1", ia.clean(v, 300))


def render_investigation_panel(result, raw, cases, conns_factory, key):
    store = st.session_state.setdefault("agent_investigations", {})
    key = str(key)
    st.markdown("#### Agentic Investigation")
    st.caption("Read-only. Uses this app's existing analysis tools, a strict tool allowlist and hard limits. "
               "It never changes the scanner's score, sends mail or submits intelligence.")
    c1, c2 = st.columns(2)
    use_ai = c1.checkbox("AI-assisted planning and summary", value=True, key="agent_ai_" + key,
                         help="Uses the app's configured provider (local Ollama/Qwen or the Groq backend). "
                              "Sends only a short evidence digest, never the email body.")
    net = c2.checkbox("Allow public DNS/RDAP lookups", value=False, key="agent_net_" + key,
                      help="Sends only domain names found in this email to public DNS-over-HTTPS and RDAP services.")
    with st.expander("Limits", expanded=False):
        a, b, c = st.columns(3)
        calls = a.number_input("Max tool calls", 1, 15, 10, key="agent_calls_" + key)
        iters = b.number_input("Max iterations", 1, 15, 10, key="agent_iters_" + key)
        secs = c.number_input("Max seconds", 10, 300, 90, key="agent_secs_" + key)
    if st.button("Start investigation", type="primary", key="agent_go_" + key, use_container_width=True):
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
                   "result": s.get("status"), "evidence": s.get("evidence_id", "-"), "why": s["reason"]} for s in inv["steps"]],
                 use_container_width=True, hide_index=True)
    for kind, title in (("verified", "Verified facts"), ("suspicious", "Suspicious signals"), ("uncertain", "Missing evidence / uncertainty")):
        items = [f for f in inv["findings"] if f["kind"] == kind]
        with st.expander(f"{title} ({len(items)})", expanded=(kind != "verified")):
            for f in items:
                st.markdown(f"- {_t(f['statement'])} `[{','.join(f['evidence_ids'])}]`")
            if not items:
                st.caption("None recorded.")
    from_md = ia.render_report(inv, result, raw)
    st.download_button("Download forensic report with investigation (.md)", from_md, file_name="agentic_investigation_report.md",
                       mime="text/markdown", key="agent_dl_" + key)
