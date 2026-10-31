#!/usr/bin/env python3
"""THROWAWAY fault-injection check for the Algorithmistic extortion / validation UI paths.

Injects one fault at a time, runs the real analyzer -> risk -> report pipeline, then executes the REAL code from
app.py for the Classification panel (`_classification()`) and the Forensic Report/Dossier (warning, telemetry-table
row, Markdown export) and checks what they would show.

    python fault_injection_check.py --repo /path/to/repo                 # all scenarios
    python fault_injection_check.py --repo /path/to/repo --scenario truncated --verbose
    python fault_injection_check.py --list

Needs only the repo's own dependencies; it does NOT need Streamlit (app.py code runs under a recording stub, so this
checks the app's logic, not Streamlit's rendering - use fault_injection_app.py for the real UI).

Isolation (nothing is written to the repo, nothing leaves the machine):
  * bytecode writing is disabled; threat memory (tracker.DB_FILE / SESSION_DIR) is redirected to a temp directory;
  * the ML model is never loaded or trained (a fixed probability is injected), so data/ is not touched;
  * outbound HTTP (requests) and raw socket connects are blocked; community intel is forced off;
  * a before/after snapshot of every file in the repo must be identical, otherwise the run FAILS.
Supabase, production data, deployment settings and user files are never read or written. Exit code 0 = all checks pass.
"""
import argparse
import ast
import builtins
import contextlib
import os
import sys
import tempfile
from unittest import mock

sys.dont_write_bytecode = True

SCENARIOS = ["clean_control", "genuine_sextortion", "detector_failure", "truncated", "malformed_url_score",
             "missing_url_risk"]
FIXED_ML = (0.10, "legit", [("invoice", 0.25), ("payment", 0.12)])      # classifier.predict() contract
INVOICE = "Hello, attached is invoice 4411 for $3,000. Please pay within 7 days. Thanks."
PAD = "Quarterly newsletter content about nothing in particular. " * 3000        # > the detector's scan limit
MISSING_RISK_ENTRY = {"url": "https://missing-risk.example/path"}               # a URL entry with NO "risk" key


def build_email(body, subject="Hello"):
    return ("From: A <anon1@gmail.com>\r\nTo: v@example.com\r\nSubject: %s\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000"
            "\r\nMessage-ID: <1@x>\r\n\r\n%s" % (subject, body)).encode()


def snapshot(repo):
    out = {}
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
                out[os.path.relpath(path, repo)] = (st.st_size, st.st_mtime_ns)
            except OSError:
                pass
    return out


def load_repo(repo):
    """Import the repo modules we need (after putting the repo on sys.path)."""
    repo = os.path.abspath(repo)
    if not os.path.isfile(os.path.join(repo, "app.py")):
        raise SystemExit("--repo must be the repository root (app.py not found in %s)" % repo)
    sys.path.insert(0, repo)
    import analyzer, classifier, community_intel, extortion_detection, geolocate, ioc_extract, md_export, report, tracker
    import requests
    missing = [n for mod, names in ((report, ("extortion_block", "partial_scan_note", "scan_validation_status", "validation_issues")),
                                    (extortion_detection, ("checked", "failure_result")))
               for n in names if not hasattr(mod, n)]
    if missing:
        raise SystemExit("This repository does not contain the extortion-validation changes this check targets "
                         "(missing: %s). Apply the changes to a copy of the repo first." % ", ".join(missing))
    return dict(repo=repo, analyzer=analyzer, classifier=classifier, community_intel=community_intel,
                ED=extortion_detection, geolocate=geolocate, ioc_extract=ioc_extract, md_export=md_export,
                report=report, tracker=tracker, requests=requests)


def isolate(m, stack, tmpdir, block_sockets=True):
    """Apply every isolation patch to the ExitStack `stack` (they stay active until the stack closes)."""
    def blocked(*a, **k):
        raise ConnectionError("blocked by fault-injection isolation")
    p = stack.enter_context
    for mod in (m["classifier"], m["analyzer"]):
        p(mock.patch.object(mod, "predict", return_value=FIXED_ML))
        p(mock.patch.object(mod, "load_or_train", return_value=object()))
    p(mock.patch.object(m["tracker"], "DB_FILE", os.path.join(tmpdir, "threat_memory.db")))
    p(mock.patch.object(m["tracker"], "SESSION_DIR", os.path.join(tmpdir, "sessions")))
    p(mock.patch.object(m["community_intel"], "enabled", return_value=False))
    p(mock.patch("requests.sessions.Session.request", side_effect=blocked))      # blocks requests.get/Session (geolocate, feeds)
    if block_sockets:
        p(mock.patch("socket.socket.connect", side_effect=blocked))
    os.environ.pop(getattr(m["community_intel"], "FLAG_ENV", "SIH26106_COMMUNITY_INTEL"), None)


def apply_fault(m, stack, scenario, mode="check"):
    """Inject ONE fault. Returns the raw email bytes to analyse (check mode) - in 'app' mode the user supplies the email."""
    ED, ioc = m["ED"], m["ioc_extract"]
    real_extract = ioc.extract
    p = stack.enter_context
    if scenario == "detector_failure":
        p(mock.patch.object(ED, "analyze", side_effect=RuntimeError("injected detector failure")))
    elif scenario == "malformed_url_score":
        p(mock.patch.object(ioc, "extract", side_effect=lambda parsed: dict(real_extract(parsed), url_score="abc")))
    elif scenario == "missing_url_risk":
        p(mock.patch.object(ioc, "extract", side_effect=lambda parsed: dict(real_extract(parsed), urls=[MISSING_RISK_ENTRY])))
    elif scenario == "truncated" and mode == "app":
        # any ordinary email becomes "too long": shrink the scan window instead of uploading a huge file
        p(mock.patch.object(ED, "MAX_SCAN_CHARS", 200))
        p(mock.patch.object(ED, "_HEAD_CHARS", 100))
        p(mock.patch.object(ED, "_TAIL_CHARS", 100))
    if mode != "check":
        return None
    if scenario == "truncated":
        return build_email(PAD)
    if scenario == "genuine_sextortion":
        with open(os.path.join(m["repo"], "samples", "sextortion_private_photo.eml"), "rb") as fh:
            return fh.read()
    return build_email(INVOICE)


# ---- stub Streamlit + extraction of the REAL app.py code ------------------------------------------------------
class RecordingStreamlit:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        if name == "columns":
            return lambda spec, *a, **k: [mock.MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]

        def rec(*args, **kwargs):
            self.calls.append((name, " ".join(str(a) for a in args)))
            return mock.MagicMock()
        return rec

    def messages(self, *kinds):
        return [t for n, t in self.calls if n in kinds]


class _Namespace(dict):
    def __missing__(self, key):
        if hasattr(builtins, key):
            raise KeyError(key)
        self[key] = mock.MagicMock()
        return self[key]


def _smallest(tree, lines, needle, kinds):
    best = None
    for node in ast.walk(tree):
        if isinstance(node, kinds) and needle in "\n".join(lines[node.lineno - 1:node.end_lineno]):
            if best is None or (node.end_lineno - node.lineno) < (best.end_lineno - best.lineno):
                best = node
    return best


def parse_app(repo):
    with open(os.path.join(repo, "app.py"), encoding="utf-8") as fh:
        src = fh.read()
    return src, ast.parse(src), src.splitlines()


def run_classification(m, app, result):
    src, tree, lines = app
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_classification")
    import textwrap
    code = textwrap.dedent("\n".join(lines[node.lineno - 1:node.end_lineno]))
    st = RecordingStreamlit()
    ns = _Namespace(st=st, result=result, extortion_block=m["report"].extortion_block,
                    partial_scan_note=m["report"].partial_scan_note)
    exec(compile(code, "app.py::_classification", "exec"), ns)
    ns["_classification"]()
    return st


def run_dossier(m, app, result):
    src, tree, lines = app
    import pandas
    st, captured = RecordingStreamlit(), {}
    ns = _Namespace(st=st, sel_res=result, sel_h=result["headers"], sel_m=result["ml"], sel_p=result["parsed"],
                    sel_score=result["score"], sel_lvl=result["level"].upper(), sel_hash="deadbeef",
                    sel_item={"row": 1, "date": "2024-01-01"}, sel_pos=1, pd=pandas, md_cell=m["md_export"].md_cell,
                    extortion_status=m["report"].extortion_status,
                    scan_validation_status=m["report"].scan_validation_status,
                    validation_issues=m["report"].validation_issues,
                    _render_polished_table=lambda tone=None, df=None, **k: captured.__setitem__("df", df))
    for needle, kinds in (("validation_issues(sel_res)", (ast.If,)),
                          ('"Scan Validation": scan_validation_status(sel_res)', (ast.Expr,)),
                          ("| **Scan Validation** |", (ast.Assign,))):
        node = _smallest(tree, lines, needle, kinds)
        if node is None:
            raise SystemExit("Could not locate the Dossier statement containing %r in app.py "
                             "(is this the version with the Scan Validation row?)" % needle)
        exec(compile(ast.get_source_segment(src, node), "app.py::dossier", "exec"), ns)
    return {"row": captured["df"].iloc[0].to_dict(), "warnings": st.messages("warning"), "md": ns["machine_md"]}


# ---- expectations -------------------------------------------------------------------------------------------------
def expectations(scenario, res, ui, dossier, md):
    row, any_ui = dossier["row"], " ".join(ui.messages("error", "warning", "success"))
    ext, ver = row["Extortion Assessment"], row["Scan Validation"]
    bad = ("No action required", "consistent with legitimate mail")
    c = []
    add = lambda ok, text: c.append((bool(ok), text))
    if scenario == "clean_control":
        add("No action required" in md, "report keeps its normal 'No action required' wording for a clean, fully validated email")
    else:
        add(not any(b in md for b in bad), "report never says 'No action required' / 'consistent with legitimate mail'")
    if scenario == "clean_control":
        add(not ui.messages("error", "warning"), "Classification panel shows no extortion/validation warning")
        add(ext == "No extortion pattern found", "Dossier extortion row: 'No extortion pattern found'")
        add(ver.startswith("Complete"), "Dossier Scan Validation: Complete")
        add(not dossier["warnings"] and "Scan validation" not in md, "no Dossier warning; report has no Scan validation row")
    elif scenario == "genuine_sextortion":
        add(any("Suspected sextortion" in t for t in ui.messages("error")), "Classification panel: error banner 'Suspected sextortion'")
        add(ext.startswith("Suspected sextortion detected"), "Dossier extortion row shows the finding")
        add(ver.startswith("Complete") and not dossier["warnings"], "Dossier Scan Validation: Complete, no warning")
        add("Do not pay or reply" in md, "report recommends 'Do not pay or reply'")
        add(res["level"] in ("High", "Critical"), "verdict is High/Critical")
    elif scenario == "detector_failure":
        add(any("Manual review required" in t and "not a clean result" in t for t in ui.messages("warning")), "Classification panel: 'Manual review required ... not a clean result'")
        add(ext.startswith("Detector failed") and "NOT a clean result" in ext, "Dossier extortion row: Detector failed - NOT a clean result")
        add(ver.startswith("INCOMPLETE") and "extortion detector failed" in ver, "Dossier Scan Validation: INCOMPLETE (detector failed)")
        add(len(dossier["warnings"]) == 1, "Dossier shows one 'Scan validation incomplete' warning")
        add("NOT a clean result" in md and "**manual review required**" in md, "report discloses the failure and requires review")
        add(res["level"] in ("Medium", "High", "Critical"), "verdict held at Medium or above")
    elif scenario == "truncated":
        add(any("Partial scan" in t for t in ui.messages("warning")), "Classification panel: 'Partial scan' warning")
        add("PARTIAL SCAN" in ext, "Dossier extortion row: PARTIAL SCAN")
        add(ver.startswith("INCOMPLETE") and "partial scan" in ver, "Dossier Scan Validation: INCOMPLETE (partial scan)")
        add("**Partial scan.**" in md and "NOT a complete assessment" in md, "report discloses the partial scan")
    elif scenario in ("malformed_url_score", "missing_url_risk"):
        name = "suspicious_url (not numeric)" if scenario == "malformed_url_score" else "suspicious_url_entry[0] (missing)"
        add(any("Risk-input validation failed" in t and name in t for t in ui.messages("warning")), "Classification panel: 'Risk-input validation failed ... %s'" % name)
        add(ext.startswith("No extortion pattern matched, but the scan had invalid risk inputs") and ext != "No extortion pattern found", "Dossier extortion row is NOT 'No extortion pattern found'")
        add(ver.startswith("INCOMPLETE") and name in ver, "Dossier Scan Validation: INCOMPLETE (%s)" % name)
        add(len(dossier["warnings"]) == 1 and name in dossier["warnings"][0], "Dossier warning names the invalid input")
        add("| Scan validation | **INCOMPLETE**" in md and name in md, "report summary table has the Scan validation row")
        add(res["level"] in ("Medium", "High", "Critical") and res["verdict"]["input_validation_failed"], "verdict held at Medium or above; input_validation_failed=True")
        add(res["verdict"]["override_applied"] is False, "no extortion override fabricated")
    return c


def run_scenario(m, app, scenario, tmpdir, verbose):
    with contextlib.ExitStack() as stack:
        isolate(m, stack, tmpdir)
        raw = apply_fault(m, stack, scenario, "check")
        res = m["analyzer"].analyze_email(raw, "fault_%s.eml" % scenario)
        md = m["report"].build_report(res, raw)
        ui = run_classification(m, app, res)
        dossier = run_dossier(m, app, res)
    checks = expectations(scenario, res, ui, dossier, md)
    print("\n=== %s" % scenario)
    print("  verdict      : %s (score %.1f), override=%s, malformed_inputs=%s" % (
        res["level"], res["score"], res["verdict"]["override_applied"], res["verdict"]["malformed_inputs"]))
    for kind in ("error", "warning"):
        for text in ui.messages(kind):
            print("  panel %-7s: %s" % (kind, text.replace("\n", " ")[:140]))
    print("  dossier rows : Extortion Assessment = %s" % dossier["row"]["Extortion Assessment"][:150])
    print("               : Scan Validation      = %s" % dossier["row"]["Scan Validation"][:150])
    for text in dossier["warnings"]:
        print("  dossier warn : %s" % text[:150])
    if verbose:
        print("  --- report excerpt ---")
        print("\n".join("  | " + ln for ln in md.splitlines()[:26]))
    for ok, text in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", text))
    return all(ok for ok, _ in checks)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", default=".", help="repository root (contains app.py); default: current directory")
    ap.add_argument("--scenario", choices=SCENARIOS + ["all"], default="all")
    ap.add_argument("--list", action="store_true", help="list scenarios and exit")
    ap.add_argument("--verbose", action="store_true", help="print the start of each generated report")
    args = ap.parse_args(argv)
    if args.list:
        print("\n".join(SCENARIOS))
        return 0
    m = load_repo(args.repo)
    secrets = os.path.join(m["repo"], ".streamlit", "secrets.toml")
    if os.path.exists(secrets):
        print("NOTE: %s exists. This tool never reads it and blocks network access, but prefer a copy of the repo "
              "without live credentials." % secrets)
    app = parse_app(m["repo"])
    before = snapshot(m["repo"])
    ok = True
    with tempfile.TemporaryDirectory(prefix="fault_injection_") as tmp:
        for scenario in (SCENARIOS if args.scenario == "all" else [args.scenario]):
            ok = run_scenario(m, app, scenario, tmp, args.verbose) and ok
    after = snapshot(m["repo"])
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    print("\n=== isolation: repository files changed during the run: %s" % (changed or "none"))
    ok = ok and not changed
    print("RESULT: %s" % ("ALL CHECKS PASSED" if ok else "FAILURES - see FAIL lines above"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
