"""Regression tests: HTML escaping in app.py, parser/scanner resource limits, shared-intel clamps, auth SQL invariants, config."""
import glob
import io
import os
import re
import unittest
import zipfile
from unittest import mock

import antivirus_scan as AV
import email_parser as EP
import shared_intel_client as SI

ROOT = os.path.dirname(os.path.abspath(__file__))


def _eml(parts=b"", extra=b""):
    return (b"From: a@example.com\nSubject: t\nMIME-Version: 1.0\n" + extra +
            b"Content-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/plain\n\nhello\n" + parts + b"--B--\n")


def _att(name, body):
    return (b"--B\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n"
            b"Content-Disposition: attachment; filename=\"" + name + b"\"\n\n" + __import__("base64").b64encode(body) + b"\n")


class HtmlInjection(unittest.TestCase):
    def test_email_controlled_values_escaped_in_app(self):
        src = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
        for raw in ("{dd_p.get('from_addr','Unknown')}", "{dd_p.get('subject','No Subject')}", "{case_name}</div>",
                    "{dd_origin.get('infra_label','Unknown')}", '{_msg["content"]}</div>'):
            self.assertNotIn(raw, src)
        self.assertIn("html.escape(str(dd_p.get('subject','No Subject')))", src)


class ParserLimits(unittest.TestCase):
    def test_oversize_message_rejected(self):
        with mock.patch.object(EP, "MAX_MESSAGE_BYTES", 1000):
            with self.assertRaises(EP.EmailTooLargeError):
                EP.parse_eml(b"From: a@b.c\n\n" + b"x" * 2000)

    def test_attachment_count_capped(self):
        with mock.patch.object(EP, "MAX_ATTACHMENTS", 3):
            r = EP.parse_eml(_eml(b"".join(_att(b"f%d.txt" % i, b"x") for i in range(10))))
        self.assertEqual(len(r["attachments"]), 4)
        self.assertEqual(r["attachments"][-1]["skipped"], "attachment_count_limit")

    def test_per_attachment_and_aggregate_caps(self):
        with mock.patch.object(EP, "MAX_ATTACHMENT_BYTES", 100), mock.patch.object(EP, "MAX_TOTAL_ATTACHMENT_BYTES", 150):
            r = EP.parse_eml(_eml(_att(b"big.bin", b"x" * 500) + _att(b"a.bin", b"y" * 90) + _att(b"b.bin", b"z" * 90)))
        a = {x["filename"]: x for x in r["attachments"]}
        self.assertEqual(a["big.bin"]["skipped"], "attachment_too_large")
        self.assertEqual(a["big.bin"]["data"], b"")
        self.assertEqual(a["a.bin"]["data"], b"y" * 90)
        self.assertEqual(a["b.bin"]["skipped"], "aggregate_size_limit")

    def test_deep_mime_nesting_is_clean_error(self):
        txt = b"From: a@b.c\n" + b"".join(b"Content-Type: multipart/mixed; boundary=b%d\n\n--b%d\n" % (i, i) for i in range(2000))
        with self.assertRaises(ValueError):
            EP.parse_eml(txt + b"Content-Type: text/plain\n\nhi\n")

    def test_many_parts_and_hops_bounded(self):
        parts = b"".join(b"--B\nContent-Type: text/plain\n\np%d\n" % i for i in range(1000))
        with mock.patch.object(EP, "MAX_MIME_PARTS", 20):
            EP.parse_eml(_eml(parts))
        hops = b"".join(b"Received: from x (h%d [8.8.8.%d])\n" % (i, i % 250 + 1) for i in range(500))
        r = EP.parse_eml(hops + b"From: a@b.c\n\nbody")
        self.assertLessEqual(len(r["hops"]), EP.MAX_RECEIVED_HOPS)
        self.assertIn("h499 ", r["received_chain"][0] + " ")  # oldest (origin-side) hop kept

    def test_malformed_mime_does_not_raise(self):
        r = EP.parse_eml(b"From: a@b.c\nContent-Type: multipart/mixed\n\n--nope\ngarbage\xff\xfe")
        self.assertIsInstance(r["attachments"], list)

    def test_normal_attachment_unchanged(self):
        r = EP.parse_eml(_eml(_att(b"ok.pdf", b"%PDF-1")))
        self.assertEqual(r["attachments"][0]["data"], b"%PDF-1")
        self.assertNotIn("skipped", r["attachments"][0])


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in entries:
            z.writestr(n, d)
    return buf.getvalue()


class ScannerLimits(unittest.TestCase):
    def test_zip_bomb_flagged_and_not_clean(self):
        bomb = _zip([("a.bin", b"\0" * (60 * 1024 * 1024))])
        self.assertIsNotNone(AV.inspect_zip(bomb))
        with mock.patch.object(AV, "resolve_backend") as rb:
            out = AV.scan_bytes(bomb)
            rb.assert_not_called()
        self.assertFalse(out["ok"])
        self.assertNotIn("infected", out)

    def test_many_entries_flagged(self):
        self.assertIn("too many", AV.inspect_zip(_zip([("f%d" % i, b"x") for i in range(AV.ZIP_MAX_ENTRIES + 1)])))

    def test_benign_zip_and_garbage_pass_inspection(self):
        self.assertIsNone(AV.inspect_zip(_zip([("a.txt", b"hello")])))
        self.assertIsNone(AV.inspect_zip(b"PK\x03\x04garbage"))
        self.assertIsNone(AV.inspect_zip(b"plain"))

    def test_oversize_not_scanned(self):
        with mock.patch.object(AV, "MAX_SCAN_BYTES", 10):
            out = AV.scan_bytes(b"x" * 11)
        self.assertFalse(out["ok"])

    def test_scan_attachments_limits(self):
        parsed = {"attachments": [{"filename": "s.bin", "size": 1, "data": b"x", "skipped": "attachment_too_large"}] +
                  [{"filename": "f%d" % i, "size": 1, "data": b"x"} for i in range(4)]}
        with mock.patch.object(AV, "MAX_SCAN_FILES", 2), \
             mock.patch.object(AV, "scan_bytes", return_value={"ok": True, "infected": False, "signature": None}) as sb:
            res = AV.scan_attachments(parsed)
        self.assertIn("Not scanned", res[0]["error"])
        self.assertEqual(sb.call_count, 1)                    # only file #2 within the cap
        self.assertTrue(all(r["error"] for r in res[2:]))


class _R:
    def __init__(self, data):
        self.data = data
        self.headers = {}
    def raise_for_status(self): pass
    def json(self): return self.data


class SharedIntelClamps(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ, {SI.URL_ENV: "https://p.supabase.co", SI.KEY_ENV: "sb_publishable_x"})
        p.start(); self.addCleanup(p.stop)

    def test_clamps(self):
        self.assertEqual(SI._clamp_rows(10**12), SI._MAX_ROWS)
        self.assertEqual(SI._clamp_rows(-5), 0)
        self.assertEqual(SI._clamp_rows("junk"), SI._MAX_ROWS)
        self.assertEqual(SI._clamp_timeout(10**6), SI._MAX_TIMEOUT)
        self.assertEqual(SI._clamp_timeout(-1), SI._DEFAULT_TIMEOUT)
        self.assertEqual(SI._clamp_timeout(None), SI._DEFAULT_TIMEOUT)

    def test_huge_max_rows_and_runaway_server_bounded(self):
        calls = []
        class S:
            def get(self, url, **kw):
                calls.append(kw)
                return _R([{}] * 5000)                     # server ignores limit and always returns a "full" page
        out = SI.fetch_verified(max_rows=10**12, timeout=10**6, session=S())
        self.assertTrue(out["ok"])
        self.assertLessEqual(len(calls), SI._MAX_ROWS // SI._PAGE)
        self.assertTrue(all(c["timeout"] <= SI._MAX_TIMEOUT for c in calls))
        self.assertTrue(all(int(c["params"]["limit"]) <= SI._PAGE for c in calls))

    def test_max_rows_respected(self):
        class S:
            def get(self, url, **kw): return _R([{}] * int(kw["params"]["limit"]))
        out = SI.fetch_verified(max_rows=1500, session=S())
        self.assertEqual(out["rejected"], 1500)

    def test_oversized_response_refused(self):
        class S:
            def get(self, url, **kw):
                r = _R([]); r.headers = {"Content-Length": str(10**9)}; return r
        self.assertFalse(SI.fetch_verified(session=S())["ok"])


class AuthInvariants(unittest.TestCase):
    def test_admin_requires_app_metadata_and_aal2(self):
        sql = open(os.path.join(ROOT, "supabase/migrations/20261012000001_helpers.sql"), encoding="utf-8").read()
        self.assertIn("app_metadata", sql)
        self.assertIn("aal2", sql)
        self.assertNotRegex(sql.lower(), r"user_metadata'\s*->>\s*'role")

    def test_no_migration_trusts_user_metadata_or_grants_anon_rpc(self):
        for f in glob.glob(os.path.join(ROOT, "supabase/migrations/*.sql")):
            t = open(f, encoding="utf-8").read().lower()
            code = "\n".join(l for l in t.splitlines() if not l.strip().startswith("--"))
            self.assertNotIn("user_metadata", code, f)
            self.assertNotRegex(code, r"grant\s+execute\s+on\s+function\s+public\.(submit_indicators|review_queue|review_submission)[^;]*\bto\b[^;]*\banon\b", f)

    def test_owner_scoped_scan_policies(self):
        sql = open(os.path.join(ROOT, "supabase/migrations/20261012000003_scans.sql"), encoding="utf-8").read()
        self.assertEqual(len(re.findall(r"user_id = auth\.uid\(\)", sql)), 5)   # select, insert, update(x2), delete


class DeployConfig(unittest.TestCase):
    def test_streamlit_hardening(self):
        t = open(os.path.join(ROOT, ".streamlit/config.toml"), encoding="utf-8").read()
        self.assertIn("enableXsrfProtection = true", t)
        self.assertIn("enableStaticServing = false", t)
        self.assertIn('showErrorDetails = "none"', t)

    def test_secret_files_ignored(self):
        g = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read()
        for pat in ("client_secret*.json", ".env", ".streamlit/secrets.toml"):
            self.assertIn(pat, g)

    def test_traceback_only_in_debug(self):
        src = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
        for m in re.finditer(r"st\.code\(traceback\.format_exc\(\)\)", src):
            self.assertIn('SIH26106_DEBUG', src[m.start() - 40:m.end() + 60])


if __name__ == "__main__":
    unittest.main()
