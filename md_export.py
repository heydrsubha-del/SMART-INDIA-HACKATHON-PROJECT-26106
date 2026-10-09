"""Markdown helpers for report export (standard library only).

md_cell()                 - make any value safe inside a Markdown table cell.
md_to_html_document()     - turn a report's Markdown into a standalone,
                            print-ready HTML page with real rendered tables.
"""
import html
import re

_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")
_SEP_ROW = re.compile(r"\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?")


def md_cell(value):
    """Escape a value for a pipe-table cell: '|' would split the column and a
    newline would end the row, which is what broke tables in downloads."""
    text = "" if value is None else str(value)
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return text.replace("|", "\\|")


def _split_row(line):
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    return [c.strip().replace("\\|", "|") for c in _UNESCAPED_PIPE.split(s)]


def _is_sep(line):
    t = line.strip()
    return "|" in t and bool(_SEP_ROW.fullmatch(t))


def _align(sep_cell):
    c = sep_cell.strip()
    if c.startswith(":") and c.endswith(":"):
        return "center"
    if c.endswith(":"):
        return "right"
    return "left"


def _inline(value):
    value = html.escape(value, quote=False)
    codes = []

    def _stash(m):
        codes.append(m.group(1))
        return "\x00%d\x00" % (len(codes) - 1)

    value = re.sub(r"`([^`]+)`", _stash, value)
    value = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", value)
    value = re.sub(r"__(.+?)__", r"<strong>\1</strong>", value)
    value = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", value)
    value = value.replace("\\|", "|")
    return re.sub(r"\x00(\d+)\x00", lambda m: "<code>%s</code>" % codes[int(m.group(1))], value)


_CSS = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;background:#f3f4f8;color:#1b1f2a;font:15px/1.6 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:1100px;margin:28px auto;padding:34px 40px;background:#fff;border-radius:14px;box-shadow:0 6px 28px rgba(30,30,60,.10)}
h1{font-size:26px;margin:0 0 14px;color:#2b1a6b;border-bottom:3px solid #6d3fd8;padding-bottom:10px}
h2{font-size:20px;margin:30px 0 10px;color:#2b1a6b}
h3{font-size:16px;margin:22px 0 8px;color:#43308a}
h4,h5,h6{font-size:14px;margin:18px 0 6px;color:#43308a}
p{margin:8px 0}
hr{border:0;border-top:1px solid #dcdff0;margin:22px 0}
code{background:#eef0fa;border-radius:4px;padding:1px 5px;font:13px Consolas,Menlo,monospace;word-break:break-all}
pre{background:#f4f5fb;color:#1b1f2a;border:1px solid #dcdff0;border-radius:8px;padding:12px 14px;overflow:auto;max-height:280px;white-space:pre-wrap;word-break:break-word;font-size:13px}
pre code{background:none;color:inherit;padding:0;word-break:break-word}
blockquote{margin:12px 0;padding:8px 16px;border-left:4px solid #6d3fd8;background:#f6f3ff;color:#43308a}
.tw{overflow-x:auto;margin:12px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{background:#2b1a6b;color:#fff;text-align:left;padding:9px 11px;border:1px solid #2b1a6b}
td{padding:8px 11px;border:1px solid #dcdff0;vertical-align:top;word-break:break-word}
tr:nth-child(even) td{background:#f8f9fe}
ul,ol{margin:8px 0 8px 24px;padding:0}
@media print{body{background:#fff}main{box-shadow:none;margin:0;max-width:none;padding:0}.tw{overflow:visible}}
"""


def md_to_html_document(md_text, title="Report"):
    lines = str(md_text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out, para = [], []
    state = {"list": None}

    def flush_para():
        if para:
            out.append("<p>%s</p>" % "<br>".join(_inline(p) for p in para))
            para.clear()

    def close_list():
        if state["list"]:
            out.append("</%s>" % state["list"])
            state["list"] = None

    i = 0
    while i < len(lines):
        raw = lines[i]
        s = raw.strip()

        if s.startswith("```"):
            flush_para()
            close_list()
            i += 1
            block = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>%s</code></pre>" % html.escape("\n".join(block)))
            continue

        if s.startswith("|") and i + 1 < len(lines) and _is_sep(lines[i + 1]):
            flush_para()
            close_list()
            header = _split_row(s)
            aligns = [_align(c) for c in _split_row(lines[i + 1])]
            aligns = (aligns + ["left"] * len(header))[:len(header)]
            i += 2
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = _split_row(lines[i])
                if len(cells) > len(header):  # unescaped '|' in a value: keep the data
                    cells = cells[:len(header) - 1] + [" | ".join(cells[len(header) - 1:])]
                rows.append(cells + [""] * (len(header) - len(cells)))
                i += 1
            th = "".join('<th style="text-align:%s">%s</th>' % (a, _inline(h))
                         for a, h in zip(aligns, header))
            body = "".join(
                "<tr>%s</tr>" % "".join(
                    '<td style="text-align:%s">%s</td>' % (a, _inline(c))
                    for a, c in zip(aligns, r))
                for r in rows)
            out.append('<div class="tw"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>'
                       % (th, body))
            continue

        i += 1
        if not s:
            flush_para()
            close_list()
            continue
        if re.fullmatch(r"[-_*=]{3,}", s):
            flush_para()
            close_list()
            out.append("<hr>")
            continue
        m = re.match(r"^(#{1,6})\s+(.+?)\s*#*$", s)
        if m:
            flush_para()
            close_list()
            lvl = len(m.group(1))
            out.append("<h%d>%s</h%d>" % (lvl, _inline(m.group(2)), lvl))
            continue
        if s.startswith(">"):
            flush_para()
            close_list()
            out.append("<blockquote>%s</blockquote>" % _inline(s.lstrip("> ").strip()))
            continue
        m = re.match(r"^[-*\u2022]\s+(.+)$", s)
        m2 = re.match(r"^\d+[.)]\s+(.+)$", s)
        if m or m2:
            flush_para()
            kind = "ul" if m else "ol"
            if state["list"] != kind:
                close_list()
                out.append("<%s>" % kind)
                state["list"] = kind
            out.append("<li>%s</li>" % _inline((m or m2).group(1)))
            continue
        close_list()
        para.append(s)

    flush_para()
    close_list()
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>%s</title><style>%s</style></head><body><main>%s</main></body></html>"
        % (html.escape(str(title)), _CSS, "\n".join(out))
    )


_WORD_NS = ('<html xmlns:o="urn:schemas-microsoft-com:office:office" '
            'xmlns:w="urn:schemas-microsoft-com:office:word" '
            'xmlns="http://www.w3.org/TR/REC-html40" lang="en">')
_WORD_HEAD = ("<!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View>"
              "<w:Zoom>100</w:Zoom></w:WordDocument></xml><![endif]-->")


def md_to_word_document(md_text, title="Report"):
    """Same report as a Word-openable .doc (HTML-based; Word and LibreOffice
    open it directly with tables intact, no extra libraries needed)."""
    doc = md_to_html_document(md_text, title)
    doc = doc.replace('<html lang="en">', _WORD_NS, 1)
    doc = doc.replace("<head>", "<head>" + _WORD_HEAD, 1)
    # Word ignores most table CSS, so give tables explicit HTML attributes.
    doc = doc.replace("<table>", '<table border="1" cellspacing="0" cellpadding="6" width="100%" '
                      'style="border-collapse:collapse;border:1px solid #b9bedd">')
    doc = doc.replace("<th ", '<th bgcolor="#2b1a6b" ')
    doc = doc.replace("body{margin:0;background:#f3f4f8;", "body{margin:0;background:#ffffff;")
    return doc.replace("<td ", '<td valign="top" ')


_INVISIBLE = re.compile("[\u00ad\u034f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u206f\ufeff]")


def clean_body_snippet(text, limit=1000):
    """Display-only tidy of an email body: drop invisible padding characters
    and collapse runs of blank lines (marketing emails are full of them)."""
    s = _INVISIBLE.sub("", str(text or "")).replace("\xa0", " ").replace("```", "'''")
    lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in s.splitlines()]
    s = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    return s[:limit] or "No body text extracted"


def group_urls(urls, keep=3, example_len=110):
    """Rows for a URL table. Flagged/risky URLs always get their own row.
    Clean URLs from one host are listed individually up to `keep`; beyond that
    they collapse into one row (first link as example + a count), so a
    tracking-heavy newsletter doesn't print dozens of near-identical links."""
    order, groups = [], {}
    for u in urls or []:
        host = u.get("host") or ""
        if host not in groups:
            groups[host] = []
            order.append(host)
        groups[host].append(u)

    def _risk(u):
        try:
            return float(u.get("risk") or 0)
        except (TypeError, ValueError):
            return 0.0

    rows = []
    for host in order:
        flagged, plain = [], []
        for u in groups[host]:
            (flagged if (u.get("suspicious") or u.get("flags") or _risk(u) > 0) else plain).append(u)
        for u in flagged:
            rows.append({"url": u.get("url", ""), "count": 1, "host": host,
                         "risk": _risk(u), "flags": list(u.get("flags") or [])})
        if len(plain) <= keep:
            for u in plain:
                rows.append({"url": u.get("url", ""), "count": 1, "host": host,
                             "risk": _risk(u), "flags": []})
        else:
            url = plain[0].get("url", "")
            if len(url) > example_len:
                url = url[:example_len - 1] + "\u2026"
            rows.append({"url": url, "count": len(plain), "host": host,
                         "risk": max(_risk(u) for u in plain), "flags": []})
    return rows