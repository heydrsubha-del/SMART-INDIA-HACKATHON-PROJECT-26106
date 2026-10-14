"""Small, Streamlit-free helpers for the feedback and analysis UI (unit-testable)."""

FEEDBACK_KEY = "feedback_messages"


def save_then_retrain(add_feedback, retrain, on_trained, saved_msg):
    """Persist one verdict, THEN try retraining. Returns [(kind, text), ...].

    Once add_feedback returns, the row is committed: later failures never say the save failed.
    """
    try:
        add_feedback()
    except Exception:
        return [("error", "Feedback could not be saved. Nothing was recorded; please try again.")]
    out = [("success", saved_msg)]
    try:
        tr = retrain() or {}
    except Exception:
        out.append(("warning", "Retraining failed, so the model was not changed. Your feedback is saved and will be used next time."))
        return out
    status = tr.get("status")
    if status == "trained":
        try:
            on_trained()
        except Exception:
            out.append(("warning", "Adaptive model was trained, but cached results could not be refreshed. Reload the app to see them."))
        out.append(("success", "Adaptive model validated and accepted by the backend."))
    elif status == "rejected":
        out.append(("warning", "Adaptive candidate was not promoted: validation regressed from "
                    f"{tr.get('baseline_accuracy', 0):.1%} to {tr.get('candidate_accuracy', 0):.1%}; existing model kept."))
    else:
        out.append(("info", "The model has not been changed by this action."))
    return out


def set_feedback(state, email_hash, items):
    state[FEEDBACK_KEY] = {"hash": email_hash, "items": list(items)}


def current_feedback(state, email_hash):
    """Messages for this email; stale ones (other email) are cleared."""
    cur = state.get(FEEDBACK_KEY)
    if not cur:
        return []
    if cur.get("hash") != email_hash:
        state.pop(FEEDBACK_KEY, None)
        return []
    return cur.get("items", [])


def section_anchor(anchor_id):
    return f'<div id="{anchor_id}"></div>'


SECTIONS = (("ai-overview", "Overview"), ("ai-assessment", "AI Assessment"),
            ("ai-agentic", "Agentic Investigation"), ("ai-downloads", "Downloads"))


def nav_html():
    links = "".join(f'<a href="#{i}">{t}</a>' for i, t in SECTIONS)
    return f'<nav class="ai-nav" aria-label="Page sections">{links}</nav>'


import html as _html
import re as _re


def verdict_pill_html(level, color):
    """Coloured verdict badge; colour is validated so it cannot inject CSS/HTML."""
    col = color if isinstance(color, str) and _re.fullmatch(r"#[0-9a-fA-F]{3,8}", color) else "#22d3ee"
    txt = _html.escape(str(level or "UNKNOWN").upper())
    return ('<div style="font-size:11px;letter-spacing:.08em;color:#8fa3b8;margin-bottom:4px;">VERDICT</div>'
            f'<span style="display:inline-block;padding:4px 14px;border-radius:999px;font-weight:700;font-size:15px;'
            f'color:{col};background:{col}22;border:1px solid {col}77;">{txt}</span>')
