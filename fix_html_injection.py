"""Escape email-controlled values rendered with st.markdown(..., unsafe_allow_html=True) in app.py.

Usage (repo root):  python fix_html_injection.py [--check]
Exact-match edits only; aborts without writing if any target is missing, so it cannot
corrupt a newer app.py. Preserves line endings. Idempotent."""
import ast, sys

PATH = "app.py"
E = lambda x: "html.escape(str(%s))" % x
EDITS = [
    ("{dd_p.get('from_addr','Unknown')}", "{" + E("dd_p.get('from_addr','Unknown')") + "}"),
    ("{dd_p.get('subject','No Subject')}", "{" + E("dd_p.get('subject','No Subject')") + "}"),
    ("{dd_p.get('date','Unknown')}", "{" + E("dd_p.get('date','Unknown')") + "}"),
    ("{dd_origin.get('ip','Unknown')}", "{" + E("dd_origin.get('ip','Unknown')") + "}"),
    ("{dd_origin.get('infra_label','Unknown')}", "{" + E("dd_origin.get('infra_label','Unknown')") + "}"),
    ("{c.get('label','-')}", "{" + E("c.get('label','-')") + "}"),
    (">{case_name}</div>", ">{" + E("case_name") + "}</div>"),
    ("Primary signal: {top_driver}</div>", "Primary signal: {" + E("top_driver") + "}</div>"),
    (">{current_level}</div>", ">{" + E("current_level") + "}</div>"),
    ('{_msg["content"]}</div>', '{' + E('_msg["content"]') + '}</div>'),
]

def main():
    raw = open(PATH, "rb").read().decode("utf-8")
    out, todo = raw, 0
    for old, new in EDITS:
        if new in out and old not in out.replace(new, ""):
            continue                                   # already fixed
        if out.count(old) != 1:
            sys.exit("ABORTED, nothing written: %r found %d times (expected 1). app.py differs from the audited version." % (old, out.count(old)))
        out = out.replace(old, new); todo += 1
    if "import html" not in out:
        sys.exit("ABORTED: app.py does not import html")
    ast.parse(out)                                     # must still be valid Python
    if "--check" in sys.argv:
        print("would apply %d edit(s)" % todo); return
    if todo:
        open(PATH, "wb").write(out.encode("utf-8"))
    print("applied %d edit(s); %d already fixed" % (todo, len(EDITS) - todo))

main()
