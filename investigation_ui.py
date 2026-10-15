"""Streamlit panel for the agentic investigation (explicit start, read-only)."""
import re

import streamlit as st

import investigation_agent as ia

_MD = re.compile(r"([\\`*_{}\[\]()#+!|<>~])")
_KINDS = (("suspicious", "Suspicious", "Signals that raise risk; review before acting."),
          ("uncertain", "Uncertain", "Could not be checked; treat the verdict with caution."),
          ("verified", "Verified", "Facts confirmed by a tool result."))


def _t(v):
    """Escape email-derived text so it cannot render as markdown/HTML."""
    return _MD.sub(r"\\\1", ia.clean(v, 300))


def _controls(key):
    with st.container(border=True):
        st.markdown("#### Agentic Investigation")
        st.caption("Optional · read-only · allowlisted tools · score unchanged · no outbound mail")
        c1, c2 = st.columns(2)
        use_ai = c1.toggle("AI-assisted planning", value=True, key="agent_ai_" + key,
                           help="Uses the app's configured provider (local Ollama/Qwen or Groq). "
                                "Sends only a short evidence digest, never the email body.")
        net = c2.toggle("Public DNS/RDAP lookups", value=False, key="agent_net_" + key,
                        help="Sends only domain names found in this email to public DNS-over-HTTPS and RDAP services.")
        l1, l2, l3 = st.columns(3)
        calls = int(l1.number_input("Max tool calls", 1, 15, 10, 1, key="agent_calls_" + key, help="Hard cap per run"))
        iters = int(l2.number_input("Max iterations", 1, 15, 10, 1, key="agent_iters_" + key, help="Planning loops"))
        secs = int(l3.number_input("Max seconds", 10, 300, 90, 10, key="agent_secs_" + key, help="Wall-clock budget"))
        go = st.button("Start investigation", type="primary", use_container_width=True, key="agent_go_" + key)
    return use_ai, net, calls, iters, secs, go


def _findings(inv):
    for kind, title, desc in _KINDS:
        items = [f for f in inv["findings"] if f["kind"] == kind]
        with st.expander(f"{title} ({len(items)})", expanded=kind != "verified" and bool(items)):
            st.caption(desc)
            for f in items:
                st.markdown(f"- {_t(f['statement'])} `[{','.join(f['evidence_ids'])}]`")
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

    m = st.columns(4)
    m[0].metric("Status", inv["status"])
    m[1].metric("Tool calls", f"{len(inv['evidence'])}/{inv['limits']['max_tool_calls']}")
    m[2].metric("Time", f"{inv['seconds']}s")
    m[3].metric("Mode", "AI" if inv["mode"] == "ai" else "Deterministic")
    st.caption(f"Stopped: {inv['stop_reason'] or '-'} · Scanner score unchanged: "
               f"{inv['score_snapshot']['score']} ({inv['score_snapshot']['level']})")
    if inv.get("mode_note"):
        st.warning(_t(inv["mode_note"]))
    if inv.get("narrative"):
        with st.container(border=True):
            st.markdown("**Summary** · generated from tool findings")
            st.markdown(_t(inv["narrative"]))

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
