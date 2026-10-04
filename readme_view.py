"""
readme_view.py: render README.md in Streamlit so it looks like it does on GitHub.

GitHub-only features are converted for Streamlit:
  * raw HTML (div/img/badges)   -> rendered (unsafe_allow_html, trusted file only)
  * <!-- HTML comments -->      -> removed
  * ```mermaid blocks           -> real diagram via Mermaid.js
  * > [!NOTE] / [!TIP] / ...    -> st.info / st.success / st.warning / st.error
  * <details><summary>          -> st.expander
  * heading anchors             -> GitHub-compatible ids, so "#-installation" links work

Usage:
    from readme_view import render_readme
    render_readme()
"""
from __future__ import annotations

import html
import re
from pathlib import Path
from typing import List, Optional, Tuple

import streamlit as st
import streamlit.components.v1 as components

README_PATH = Path(__file__).with_name("README.md")

# (kind, content, extra)
#   kind = "md" | "mermaid" | "alert" | "details"
Segment = Tuple[str, object, Optional[str]]

_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})\s*([\w+-]*)")
_ALERT_RE = re.compile(
    r"^\s*>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$", re.I
)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_SUMMARY_RE = re.compile(r"<summary>(.*?)</summary>", re.S | re.I)
_TAG_RE = re.compile(r"<[^>]+>")

_ALERTS = {
    "NOTE":      ("info",    "ℹ️", "Note"),
    "TIP":       ("success", "💡", "Tip"),
    "IMPORTANT": ("info",    "❗", "Important"),
    "WARNING":   ("warning", "⚠️", "Warning"),
    "CAUTION":   ("error",   "🛑", "Caution"),
}

# Make capsule-render banners taller in Streamlit only (README on GitHub is untouched).
CAPSULE_HEIGHT_SCALE = 1.5   # try 1.3 to 2.0
_CAPSULE_RE = re.compile(
    r"(https://capsule-render\.vercel\.app/api\?[^\"'\s)]*?)height=(\d+)"
)


def _scale_capsule(text: str) -> str:
    def repl(m):
        return f"{m.group(1)}height={int(int(m.group(2)) * CAPSULE_HEIGHT_SCALE)}"
    return _CAPSULE_RE.sub(repl, text)



# ───────────────────────────── helpers ─────────────────────────────
def _github_slug(text: str) -> str:
    """Reproduce GitHub's heading-anchor algorithm.

    '🔐 Security & secrets' -> '-security--secrets'
    """
    text = _TAG_RE.sub("", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)  # drops emoji, punctuation, '&'
    return text.replace(" ", "-")


def _strip_tags(text: str) -> str:
    return html.unescape(_TAG_RE.sub("", text)).strip()


# ───────────────────────────── parser ──────────────────────────────
def _parse(lines: List[str], slugs: dict) -> List[Segment]:
    segments: List[Segment] = []
    buf: List[str] = []
    fence: Optional[str] = None
    i = 0

    def flush() -> None:
        if buf:
            segments.append(("md", "\n".join(buf), None))
            buf.clear()

    while i < len(lines):
        line = lines[i]

        # Inside a normal code fence: copy lines unchanged.
        if fence:
            buf.append(line)
            if line.strip().startswith(fence):
                fence = None
            i += 1
            continue

        # Opening code fence
        m = _FENCE_RE.match(line)
        if m:
            marker, lang = m.group(1), m.group(2).lower()
            if lang == "mermaid":
                body, j = [], i + 1
                while j < len(lines) and not lines[j].strip().startswith(marker):
                    body.append(lines[j])
                    j += 1
                flush()
                segments.append(("mermaid", "\n".join(body), None))
                i = j + 1
                continue
            fence = marker
            buf.append(line)
            i += 1
            continue

        # GitHub alert: > [!NOTE]
        am = _ALERT_RE.match(line)
        if am:
            body, j = [], i + 1
            while j < len(lines) and lines[j].lstrip().startswith(">"):
                body.append(re.sub(r"^\s*>\s?", "", lines[j]))
                j += 1
            flush()
            segments.append(("alert", "\n".join(body).strip(), am.group(1).upper()))
            i = j
            continue

        # <details> ... </details>
        if line.strip().lower().startswith("<details"):
            block, j = [], i
            while j < len(lines):
                block.append(lines[j])
                if "</details>" in lines[j].lower():
                    break
                j += 1
            raw = "\n".join(block)
            sm = _SUMMARY_RE.search(raw)
            title = _strip_tags(sm.group(1)) if sm else "Details"
            inner = _SUMMARY_RE.sub("", raw, count=1)
            inner = re.sub(r"</?details[^>]*>", "", inner, flags=re.I)
            flush()
            segments.append(("details", _parse(inner.splitlines(), slugs), title))
            i = j + 1
            continue

        # Headings: add a GitHub-compatible anchor so in-page links work.
        hm = _HEADING_RE.match(line)
        if hm and "<" not in hm.group(2):
            slug = _github_slug(hm.group(2))
            n = slugs.get(slug, 0)
            slugs[slug] = n + 1
            if n:
                slug = f"{slug}-{n}"
            # Blank lines around the anchor stop the markdown parser
            # from merging the heading into the HTML block.
            buf.extend(["", f'<a id="{slug}"></a>', ""])

        buf.append(line)
        i += 1

    flush()
    return segments


@st.cache_data(show_spinner=False)
def _load(path: str, mtime: float) -> List[Segment]:
    """Parse once and re-parse only when the README file changes (mtime key)."""
    text = Path(path).read_text(encoding="utf-8")
    text = _COMMENT_RE.sub("", text)
    text = _scale_capsule(text) 
    return _parse(text.splitlines(), {})


# ──────────────────────────── renderers ────────────────────────────
def _render_mermaid(source: str, height: int = 420) -> None:
    # Mermaid line breaks are <br/>; turn literal "\n" in labels into one.
    source = source.replace("\\n", "<br/>")
    components.html(
        f"""
        <style>
          body {{ margin:0; background:transparent; }}
          pre.mermaid {{
            margin:0; color:#e6f7ff; font-family:'Fira Code',monospace;
            font-size:12px; white-space:pre-wrap; text-align:center;
          }}
        </style>
        <pre class="mermaid">{html.escape(source)}</pre>
        <script type="module">
          try {{
            const {{ default: mermaid }} = await import(
              "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs"
            );
            mermaid.initialize({{ startOnLoad: false, theme: "dark",
                                  flowchart: {{ useMaxWidth: true }} }});
            await mermaid.run();
          }} catch (e) {{
            /* Offline: the diagram source stays visible as text. */
          }}
        </script>
        """,
        height=height,
        scrolling=True,
    )


def _render(segments: List[Segment], nested: bool = False) -> None:
    for kind, content, extra in segments:
        if kind == "md":
            if str(content).strip():
                st.markdown(content, unsafe_allow_html=True)

        elif kind == "mermaid":
            _render_mermaid(str(content))

        elif kind == "alert":
            fn, icon, label = _ALERTS.get(extra or "NOTE", _ALERTS["NOTE"])
            getattr(st, fn)(f"**{label}**\n\n{content}", icon=icon)

        elif kind == "details":
            if nested:  # Streamlit can't nest expanders
                st.markdown(f"**{extra}**")
                _render(content, nested=True)  # type: ignore[arg-type]
            else:
                with st.expander(extra or "Details"):
                    _render(content, nested=True)  # type: ignore[arg-type]


# ───────────────────────────── public API ──────────────────────────
def render_readme(path: Path | str = README_PATH) -> None:
    """Render README.md on the About page.

    unsafe_allow_html is used ONLY for this trusted, repo-owned file.
    Never pass email bodies or other untrusted input through it.
    """
    p = Path(path)
    if not p.exists():
        st.warning("README.md not found. Keep it in the same folder as app.py.")
        return

    st.markdown('<a id="top"></a>', unsafe_allow_html=True)  # for "⬆ back to top"
    _render(_load(str(p), p.stat().st_mtime))


if __name__ == "__main__":
    # Preview on its own:  streamlit run readme_view.py
    st.set_page_config(page_title="About · Algorithmistic", layout="wide")
    render_readme()
