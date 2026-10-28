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

    def test_undecodable_attachment_is_skipped_not_empty(self):
        orig = EP.message_from_bytes(_eml(_att(b"x.bin", b"abc")), policy=EP.policy.default)
        for part in orig.walk():
            if part.get_filename():
                def boom(*a, **k): raise RuntimeError("boom")
                part.get_payload = boom
        atts = EP._attachments(orig)
        self.assertTrue(atts and all(a.get("skipped") == "decode_error" for a in atts))

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


class ZipAndScannerHardening(unittest.TestCase):
    def test_prefixed_zip_bomb_detected(self):
        bomb = _zip([("a.bin", b"\0" * (60 * 1024 * 1024))])
        self.assertIsNotNone(AV.inspect_zip(b"MZ" + b"junk" * 100 + bomb))
        self.assertIsNotNone(AV.inspect_zip(b"\x00" * 50 + bomb))

    def test_nested_archives_and_entry_caps(self):
        many = _zip([("n%d.zip" % i, b"x") for i in range(AV.ZIP_MAX_NESTED + 1)])
        self.assertIn("nested", AV.inspect_zip(many))
        with mock.patch.object(AV, "ZIP_MAX_ENTRY_BYTES", 10):
            self.assertIn("oversized entry", AV.inspect_zip(_zip([("big", b"x" * 100)])))
        with mock.patch.object(AV, "ZIP_MAX_ENTRIES", 2):
            self.assertIn("too many", AV.inspect_zip(_zip([("a", b"1"), ("b", b"2"), ("c", b"3")])))

    def test_malformed_zip_fails_closed(self):
        good = _zip([("a.txt", b"hello" * 100)])
        broken = good.replace(b"PK\x01\x02", b"XX\x01\x02", 1)   # EOCD present, central directory damaged
        self.assertIsNotNone(AV.inspect_zip(broken))
        self.assertIsNone(AV.inspect_zip(b"MZ" + b"PK" + b"no archive here"))

    def test_inspector_exception_blocks_scan(self):
        with mock.patch.object(AV, "inspect_zip", side_effect=RuntimeError("boom")), \
             mock.patch.object(AV, "resolve_backend") as rb:
            out = AV.scan_bytes(b"data")
        self.assertFalse(out["ok"]); rb.assert_not_called()

    def test_unexpected_scanner_error_is_not_clean(self):
        with mock.patch.object(AV, "resolve_backend", return_value=("local", None)), \
             mock.patch.object(AV, "_scan_bytes_clamd", side_effect=RuntimeError("boom")):
            out = AV.scan_bytes(b"data")
        self.assertFalse(out["ok"]); self.assertNotIn("infected", out)
        with mock.patch.object(AV, "scan_bytes", side_effect=RuntimeError("boom")):
            res = AV.scan_attachments({"attachments": [{"filename": "a", "size": 1, "data": b"x"}]})
        self.assertFalse(res[0]["infected"]); self.assertFalse(res[0]["scanned"]); self.assertTrue(res[0]["error"])

    def test_skipped_attachment_reported_not_scanned(self):
        res = AV.scan_attachments({"attachments": [{"filename": "a", "size": 99, "data": b"", "skipped": "attachment_too_large"}]})
        self.assertFalse(res[0]["scanned"]); self.assertFalse(res[0]["infected"]); self.assertIn("Not scanned", res[0]["error"])

    def test_clamd_overall_deadline_with_trickling_server(self):
        import socket, threading, time as _t
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        def serve():
            c, _ = srv.accept()
            try:
                while True:
                    c.sendall(b"x"); _t.sleep(0.1)       # never finishes, resets each recv timeout
            except Exception:
                pass
        threading.Thread(target=serve, daemon=True).start()
        with mock.patch.object(AV, "CLAMD_HOST", "127.0.0.1"), mock.patch.object(AV, "CLAMD_PORT", port), \
             mock.patch.object(AV, "CLAMD_TOTAL_DEADLINE", 1):
            t0 = _t.monotonic()
            out = AV._scan_bytes_clamd(b"abc", timeout=5)
        srv.close()
        self.assertLess(_t.monotonic() - t0, 3)
        self.assertFalse(out["ok"])

    def test_clamd_roundtrip_clean_and_found(self):
        import socket, threading
        for reply, infected in ((b"stream: OK\0", False), (b"stream: Eicar-Test FOUND\0", True)):
            srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
            def serve(reply=reply, srv=srv):
                c, _ = srv.accept()
                buf = b""
                while not buf.endswith(b"\0\0\0\0"):
                    d = c.recv(4096)
                    if not d: break
                    buf += d
                c.sendall(reply); c.close()
            threading.Thread(target=serve, daemon=True).start()
            with mock.patch.object(AV, "CLAMD_HOST", "127.0.0.1"), mock.patch.object(AV, "CLAMD_PORT", srv.getsockname()[1]):
                out = AV._scan_bytes_clamd(b"abc")
            srv.close()
            self.assertTrue(out["ok"]); self.assertEqual(out["infected"], infected)


class AttachmentStatusUI(unittest.TestCase):
    ok_clean = {"ok": True, "infected": False, "signature": None}

    def st(self, att, outcome=None):
        return AV.attachment_status(att, outcome)

    def test_scanner_unavailable_benign_is_not_scanned(self):
        s, d, c = self.st({"filename": "a.pdf", "risky": False, "data": b"x"})
        self.assertEqual((s, c), ("Not scanned", AV.CAT_NOT_SCANNED))
        self.assertNotEqual(s, "Clean")

    def test_scanner_unavailable_risky_is_heuristic_only(self):
        s, d, c = self.st({"filename": "a.exe", "risky": True, "data": b"x"})
        self.assertEqual(s, "Potentially risky extension")
        self.assertEqual(c, AV.CAT_RISKY_EXT)
        self.assertNotEqual(c, AV.CAT_DETECTED)
        self.assertIn("not a malware verdict", d)
        self.assertNotIn("INFECTED", s)

    def test_skipped_is_not_scanned_with_reason_regardless_of_scanner(self):
        for risky in (False, True):
            for outcome in (None, self.ok_clean, {"ok": True, "infected": True, "signature": "X"}):
                s, d, c = self.st({"filename": "b", "risky": risky, "skipped": "attachment_too_large"}, outcome)
                self.assertEqual((s, c), ("Not scanned", AV.CAT_NOT_SCANNED))
                self.assertIn("per-file size limit", d)

    def test_decode_failure_is_not_scanned_end_to_end(self):
        msg = EP.message_from_bytes(_eml(_att(b"x.bin", b"abc")), policy=EP.policy.default)
        for part in msg.walk():
            if part.get_filename():
                def boom(*a, **k): raise RuntimeError("boom")
                part.get_payload = boom
        att = EP._attachments(msg)[0]
        for outcome in (None, self.ok_clean):
            s, d, c = self.st(att, outcome)
            self.assertEqual(s, "Not scanned"); self.assertIn("could not be decoded", d)

    def test_scanner_available_results(self):
        self.assertEqual(self.st({"filename": "a"}, self.ok_clean)[::2], ("Clean", AV.CAT_CLEAN))
        s, d, c = self.st({"filename": "a"}, {"ok": True, "infected": True, "signature": "Eicar"})
        self.assertEqual((s, d, c), ("INFECTED", "Eicar", AV.CAT_DETECTED))
        self.assertEqual(self.st({"filename": "a"}, {"ok": False, "error": "timed out"})[::2], ("Scan error", AV.CAT_ERROR))
        self.assertEqual(self.st({"filename": "a"}, {"ok": False, "error": "Not scanned: limit"})[2], AV.CAT_NOT_SCANNED)
        for bad in ({}, "junk", {"ok": False}):
            self.assertNotEqual(self.st({"filename": "a"}, bad)[0], "Clean")
        self.assertNotEqual(self.st(None)[0], "Clean")

    def test_only_successful_scans_are_clean(self):
        outs = [None, {"ok": False, "error": "x"}, {"ok": True, "infected": True}, {"ok": True, "infected": False}]
        cats = [self.st({"filename": "f"}, o)[2] for o in outs]
        self.assertEqual(cats.count(AV.CAT_CLEAN), 1)

    def test_app_uses_helper_and_separate_metrics(self):
        src = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
        self.assertIn("_av_mod.attachment_status(att, outcome)", src)
        self.assertIn('"Risky extension (heuristic)"', src)
        self.assertIn('"Detections (antivirus)"', src)
        self.assertIn('"Clean (scanned)"', src)
        self.assertNotIn('"Risky extension" if infected else "Clean"', src)
        self.assertNotIn('"Threats Found"', src)


class MalformedVerdicts(unittest.TestCase):
    def test_only_explicit_booleans_give_a_verdict(self):
        bad = [{"ok": True}, {"ok": True, "infected": None}, {"ok": True, "infected": "false"},
               {"ok": True, "infected": 0}, {"ok": True, "infected": 1}, {"ok": True, "infected": []},
               {"ok": 1, "infected": False}, {"ok": "yes", "infected": False}, {"ok": None, "infected": False},
               {"infected": False}, {}, [], "ok", 5, None]
        for outcome in bad:
            if outcome is None:
                continue                       # None means "no backend" in attachment_status (tested elsewhere)
            s, d, c = AV.attachment_status({"filename": "f"}, outcome)
            self.assertNotEqual(s, "Clean", outcome)
            self.assertNotEqual(s, "INFECTED", outcome)
            self.assertIn(c, (AV.CAT_ERROR, AV.CAT_NOT_SCANNED), outcome)
            self.assertIsNone(AV._verdict(outcome), outcome)
        self.assertEqual(AV.attachment_status({"filename": "f"}, {"ok": True})[:1], ("Scan error",))
        self.assertEqual(AV.attachment_status({"filename": "f"}, {"ok": True, "infected": None})[0], "Scan error")

    def test_explicit_booleans_accepted(self):
        self.assertEqual(AV.attachment_status({}, {"ok": True, "infected": False})[0], "Clean")
        self.assertEqual(AV.attachment_status({}, {"ok": True, "infected": True, "signature": "S"})[:2], ("INFECTED", "S"))

    def test_scan_attachments_rejects_malformed_results(self):
        att = {"attachments": [{"filename": "a", "size": 1, "data": b"x"}]}
        for bad in ({"ok": True}, {"ok": True, "infected": None}, {"ok": True, "infected": "no"}, "junk", None):
            with mock.patch.object(AV, "scan_bytes", return_value=bad):
                r = AV.scan_attachments(att)[0]
            self.assertFalse(r["scanned"]); self.assertFalse(r["infected"]); self.assertTrue(r["error"])

    def test_virustotal_empty_or_missing_stats_never_clean(self):
        for bad in (None, {}, {"harmless": 0, "malicious": 0}, "x", {"harmless": 5}):
            self.assertFalse(AV._vt_stats_ok(bad), bad)
        self.assertTrue(AV._vt_stats_ok({"harmless": 3, "malicious": 0}))


class _VTResp:
    def __init__(self, body, status=200, clock=None, cost=0):
        self.status_code, self._body = status, body
        self.clock, self.cost = clock, cost
    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.exceptions.HTTPError("http %s" % self.status_code)
    def iter_content(self, chunk_size=65536):
        if self.clock is not None:
            self.clock.t += self.cost            # time consumed while reading the body
        yield __import__("json").dumps(self._body).encode()
    def close(self): pass


class _Clock:
    def __init__(self): self.t = 1000.0; self.sleeps = []
    def monotonic(self): return self.t
    def sleep(self, s): self.sleeps.append(s); self.t += s


DONE = {"data": {"attributes": {"status": "completed", "stats": {"malicious": 0, "harmless": 60}}}}
QUEUED = {"data": {"attributes": {"status": "queued"}}}


class VirusTotalDeadline(unittest.TestCase):
    def run_vt(self, get_fn, post_fn=None, total=120):
        clk = _Clock()
        post_fn = post_fn or (lambda *a, **k: _VTResp({"data": {"id": "AID"}}))
        with mock.patch.object(AV.time, "monotonic", clk.monotonic), mock.patch.object(AV.time, "sleep", clk.sleep), \
             mock.patch.object(AV, "VT_TOTAL_DEADLINE", total), \
             mock.patch.object(AV.requests, "get", side_effect=lambda *a, **k: get_fn(clk, *a, **k)), \
             mock.patch.object(AV.requests, "post", side_effect=post_fn):
            return AV._scan_bytes_virustotal(b"data", "key"), clk

    def test_timeouts_bounded_by_remaining_budget(self):
        seen = []
        def get_fn(clk, url, **kw):
            seen.append(kw["timeout"]); clk.t += 40
            return _VTResp({}, status=404) if "/files/" in url else _VTResp(DONE)
        out, clk = self.run_vt(get_fn)
        for conn, read in seen:
            self.assertLessEqual(read, 30); self.assertLessEqual(conn, 10); self.assertGreater(read, 0)
        self.assertTrue(out["ok"] and out["infected"] is False)

    def test_time_consumed_in_lookup_expires_deadline(self):
        def get_fn(clk, url, **kw):
            clk.t += 200
            return _VTResp({}, status=404)
        with mock.patch.object(AV.requests, "post", side_effect=AssertionError("must not upload")):
            out, _ = self.run_vt(get_fn)
        self.assertFalse(out["ok"]); self.assertIn("time limit", out["error"])

    def test_time_consumed_in_upload_expires_deadline(self):
        def get_fn(clk, url, **kw):
            return _VTResp({}, status=404)
        def post_fn(*a, **k):
            _clock_holder[0].t += 130
            return _VTResp({"data": {"id": "AID"}})
        _clock_holder = [None]
        clk = _Clock(); _clock_holder[0] = clk
        gets = []
        with mock.patch.object(AV.time, "monotonic", clk.monotonic), mock.patch.object(AV.time, "sleep", clk.sleep), \
             mock.patch.object(AV.requests, "get", side_effect=lambda *a, **k: (gets.append(a[0]), get_fn(clk, *a, **k))[1]), \
             mock.patch.object(AV.requests, "post", side_effect=post_fn):
            out = AV._scan_bytes_virustotal(b"data", "key")
        self.assertFalse(out["ok"]); self.assertIn("time limit", out["error"])
        self.assertEqual(len(gets), 1)                       # no polling after the budget is gone

    def test_polling_stops_at_deadline_and_sleeps_are_clamped(self):
        def get_fn(clk, url, **kw):
            if "/files/" in url:
                return _VTResp({}, status=404)
            clk.t += 25                                      # each poll burns 25 s
            return _VTResp(QUEUED)
        out, clk = self.run_vt(get_fn, total=60)
        self.assertFalse(out["ok"])
        self.assertLessEqual(clk.t - 1000.0, 60 + 1e-6 + 25)  # never more than one request past the budget
        self.assertTrue(all(s <= AV.VT_POLL_INTERVAL for s in clk.sleeps))

    def test_nearly_expired_deadline_gives_tiny_timeout_then_stops(self):
        calls = []
        def get_fn(clk, url, **kw):
            calls.append(kw["timeout"])
            clk.t += 119.5 if "/files/" in url else 0
            return _VTResp({}, status=404)
        post = lambda *a, **k: calls.append(k["timeout"]) or _VTResp({"data": {"id": "AID"}})
        out, _ = self.run_vt(get_fn, post)
        self.assertGreaterEqual(len(calls), 2)
        for conn, read in calls[1:]:
            self.assertLessEqual(read, 0.5 + 1e-6)             # remaining budget, not the 30 s default
            self.assertLessEqual(conn, 0.5 + 1e-6)
        self.assertFalse(out["ok"])

    def test_slow_body_read_hits_deadline(self):
        def get_fn(clk, url, **kw):
            return _VTResp({"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 9}}}},
                           clock=clk, cost=500)
        out, _ = self.run_vt(get_fn)
        self.assertFalse(out["ok"]); self.assertIn("time limit", out["error"])

    def test_cached_lookup_clean_and_malformed(self):
        ok = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 9}}}}
        out, _ = self.run_vt(lambda clk, url, **kw: _VTResp(ok))
        self.assertEqual((out["ok"], out["infected"]), (True, False))
        det = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "harmless": 9}}}}
        out, _ = self.run_vt(lambda clk, url, **kw: _VTResp(det))
        self.assertTrue(out["ok"] and out["infected"] is True)
        # known file with empty stats must fall through to upload+poll, and an empty final analysis is not clean
        def get_fn(clk, url, **kw):
            if "/files/" in url:
                return _VTResp({"data": {"attributes": {"last_analysis_stats": {}}}})
            return _VTResp({"data": {"attributes": {"status": "completed", "stats": {}}}})
        out, _ = self.run_vt(get_fn)
        self.assertFalse(out["ok"])


class ZeroByteAttachments(unittest.TestCase):
    CLEAN = {"ok": True, "infected": False, "signature": None}

    def test_scan_bytes_empty_is_not_scanned(self):
        for empty in (b"", None):
            with mock.patch.object(AV, "resolve_backend", side_effect=AssertionError("no backend should run")):
                out = AV.scan_bytes(empty)
            self.assertIs(out["ok"], False)
            self.assertTrue(out["error"].startswith("Not scanned"))
            self.assertIsNone(AV._verdict(out))
            self.assertEqual(AV.attachment_status({"filename": "e"}, out)[::2], ("Not scanned", AV.CAT_NOT_SCANNED))

    def test_parsed_zero_byte_attachment_end_to_end(self):
        r = EP.parse_eml(_eml(_att(b"empty.txt", b"") + _att(b"empty.exe", b"")))
        atts = r["attachments"]
        self.assertEqual([a["size"] for a in atts], [0, 0])
        self.assertFalse(any(a.get("skipped") for a in atts))       # genuinely empty, not skipped/decode error
        res = AV.scan_attachments(r)
        self.assertTrue(all(not x["scanned"] and not x["infected"] and x["error"].startswith("Not scanned") for x in res))

    def test_panel_status_and_metrics_for_zero_byte(self):
        att = {"filename": "e.txt", "size": 0, "data": b"", "risky": False}
        # scanner available: outcome comes from scan_bytes
        s, d, c = AV.attachment_status(att, AV.scan_bytes(b""))
        self.assertEqual((s, c), ("Not scanned", AV.CAT_NOT_SCANNED))
        # even a stale/forged clean outcome cannot make an empty file Clean
        s, d, c = AV.attachment_status(att, self.CLEAN)
        self.assertEqual((s, c), ("Not scanned", AV.CAT_NOT_SCANNED))
        self.assertIn("empty", d)
        # scanner unavailable
        self.assertEqual(AV.attachment_status(att, None)[0], "Not scanned")
        cats = [AV.attachment_status(att, self.CLEAN)[2], AV.attachment_status(att, None)[2]]
        self.assertEqual(AV.summarize_categories(cats)["clean"], 0)
        self.assertEqual(AV.summarize_categories(cats)["not_scanned_or_error"], 2)

    def test_empty_txt_and_exe_every_scanner_state(self):
        outcomes = [None, self.CLEAN, AV.scan_bytes(b""), {"ok": True, "infected": False},
                    {"ok": False, "error": "x"}, {"ok": True, "infected": True, "signature": "S"}, {}, "junk"]
        for name, risky in (("empty.txt", False), ("empty.exe", True)):
            att = {"filename": name, "size": 0, "data": b"", "risky": risky}
            for o in outcomes:
                s, d, c = AV.attachment_status(att, o)
                self.assertEqual((s, c), ("Not scanned", AV.CAT_NOT_SCANNED), (name, o))
                self.assertIn("empty", d)
                self.assertEqual("potentially risky" in d, risky)
        parsed = EP.parse_eml(_eml(_att(b"empty.txt", b"") + _att(b"empty.exe", b"")))
        self.assertEqual([a["risky"] for a in parsed["attachments"]], [False, True])
        for backend in (None, self.CLEAN):
            cats = [AV.attachment_status(a, backend)[2] for a in parsed["attachments"]]
            self.assertEqual(AV.summarize_categories(cats),
                             {"found": 2, "detected": 0, "clean": 0, "risky_extension": 0, "not_scanned_or_error": 2})

    def test_nonempty_risky_extension_heuristic_preserved(self):
        att = {"filename": "a.exe", "size": 3, "data": b"abc", "risky": True}
        self.assertEqual(AV.attachment_status(att, None)[::2], ("Potentially risky extension", AV.CAT_RISKY_EXT))
        self.assertEqual(AV.summarize_categories([AV.attachment_status(att, None)[2]])["risky_extension"], 1)
        # skipped keeps its own reason ahead of the empty rule
        s, d, c = AV.attachment_status({"filename": "b.exe", "size": 0, "data": b"", "risky": True,
                                        "skipped": "decode_error"}, None)
        self.assertIn("could not be decoded", d)

    def test_genuine_results_unchanged_and_counted(self):
        real = {"filename": "a.pdf", "size": 5, "data": b"hello", "risky": False}
        self.assertEqual(AV.attachment_status(real, self.CLEAN)[::2], ("Clean", AV.CAT_CLEAN))
        self.assertEqual(AV.attachment_status(real, {"ok": True, "infected": True, "signature": "Eicar"}),
                         ("INFECTED", "Eicar", AV.CAT_DETECTED))
        empty = {"filename": "e", "size": 0, "data": b""}
        cats = [AV.attachment_status(real, self.CLEAN)[2],
                AV.attachment_status(real, {"ok": True, "infected": True, "signature": "E"})[2],
                AV.attachment_status(empty, self.CLEAN)[2],
                AV.attachment_status({"filename": "x.exe", "size": 3, "data": b"abc", "risky": True}, None)[2],
                AV.attachment_status({"filename": "s", "size": 9, "data": b"", "skipped": "decode_error"}, self.CLEAN)[2]]
        self.assertEqual(AV.summarize_categories(cats),
                         {"found": 5, "detected": 1, "clean": 1, "risky_extension": 1, "not_scanned_or_error": 2})

    def test_skipped_reasons_and_nonempty_scan_path_preserved(self):
        s, d, c = AV.attachment_status({"filename": "b", "size": 99, "data": b"", "skipped": "attachment_too_large"}, self.CLEAN)
        self.assertIn("per-file size limit", d)
        with mock.patch.object(AV, "resolve_backend", return_value=("local", None)), \
             mock.patch.object(AV, "_scan_bytes_clamd", return_value=self.CLEAN):
            self.assertEqual(AV.scan_bytes(b"x"), self.CLEAN)

    def test_app_uses_summary_helper(self):
        src = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
        self.assertIn("_av_mod.summarize_categories(_cats)", src)
        self.assertIn('m3.metric("Clean (scanned)", _sum["clean"])', src)


class TruncatedZip(unittest.TestCase):
    GOOD = _zip([("doc.txt", b"hello world " * 200), ("b.bin", b"\x01" * 500)])

    def eocd_cut(self, blob):
        return blob[:blob.rindex(b"PK\x05\x06")]           # drop the end-of-central-directory record

    def test_truncated_zip_starting_with_local_header_rejected(self):
        for blob in (self.GOOD[:60], self.GOOD[:30], b"PK\x03\x04", b"PK\x03\x04garbage", self.GOOD[:len(self.GOOD) // 2]):
            reason = AV.inspect_zip(blob)
            self.assertIsNotNone(reason, blob[:12])
            self.assertIn("ZIP", reason)

    def test_valid_zip_missing_eocd_rejected(self):
        cut = self.eocd_cut(self.GOOD)
        self.assertNotIn(b"PK\x05\x06", cut)
        self.assertIn("truncated or malformed", AV.inspect_zip(cut))

    def test_prefixed_zip_missing_eocd_rejected(self):
        for prefix in (b"MZ" + b"\x90" * 300, b"#!/bin/sh\n" * 50, b"\x00" * 4096):
            self.assertIsNotNone(AV.inspect_zip(prefix + self.eocd_cut(self.GOOD)), prefix[:4])

    def test_valid_benign_and_prefixed_zips_still_pass(self):
        self.assertIsNone(AV.inspect_zip(self.GOOD))
        self.assertIsNone(AV.inspect_zip(b"MZ" + b"\x90" * 300 + self.GOOD))

    def test_stray_pk_bytes_in_ordinary_content_not_a_zip(self):
        for blob in (b"PK", b"PK\x03", b"hello PK\x03\x04 world " * 10, b"x" * 100 + b"PK\x03\x04" + b"\xff" * 40,
                     b"%PDF-1.7 PK\x03\x04\x14\x00\x00\x00\x63\x00" + b"z" * 50, b"plain text PK\x01\x02 only"):
            self.assertIsNone(AV.inspect_zip(blob), blob[:20])

    def test_rejection_blocks_scanner_and_is_never_clean(self):
        blobs = [self.GOOD[:60], self.eocd_cut(self.GOOD), b"MZ" * 100 + self.eocd_cut(self.GOOD)]
        for blob in blobs:
            with mock.patch.object(AV, "resolve_backend", side_effect=AssertionError("must not scan")), \
                 mock.patch.object(AV, "_scan_bytes_clamd", side_effect=AssertionError("must not scan")), \
                 mock.patch.object(AV, "_scan_bytes_virustotal", side_effect=AssertionError("must not scan")):
                out = AV.scan_bytes(blob)
            self.assertIs(out["ok"], False)
            self.assertIn("archive bomb", out["error"])
            self.assertIsNone(AV._verdict(out))
            att = {"filename": "t.zip", "size": len(blob), "data": blob}
            s, d, c = AV.attachment_status(att, out)
            self.assertNotEqual(s, "Clean")
            self.assertIn(c, (AV.CAT_ERROR, AV.CAT_NOT_SCANNED))
            res = AV.scan_attachments({"attachments": [att]})[0]
            self.assertFalse(res["scanned"]); self.assertFalse(res["infected"])

    def test_ordinary_file_with_stray_pk_still_reaches_scanner(self):
        blob = b"just text PK\x03\x04 junk " * 20
        with mock.patch.object(AV, "resolve_backend", return_value=("local", None)), \
             mock.patch.object(AV, "_scan_bytes_clamd", return_value={"ok": True, "infected": False}) as c:
            out = AV.scan_bytes(blob)
        self.assertEqual(c.call_count, 1); self.assertTrue(out["ok"])


class MalformedInputs(unittest.TestCase):
    def test_wrong_types_rejected_cleanly(self):
        for bad in (None, 5, [], {"a": 1}):
            with self.assertRaises(EP.EmailRejectedError):
                EP.parse_eml(bad)
        self.assertEqual(EP.parse_eml(bytearray(b"From: a@b.c\n\nhi"))["from_addr"], "a@b.c")

    def test_rejections_share_base_class(self):
        self.assertTrue(issubclass(EP.EmailTooLargeError, EP.EmailRejectedError))
        txt = b"From: a@b.c\n" + b"".join(b"Content-Type: multipart/mixed; boundary=b%d\n\n--b%d\n" % (i, i) for i in range(2000))
        with self.assertRaises(EP.EmailRejectedError):
            EP.parse_eml(txt)

    def test_random_garbage_never_crashes(self):
        import random
        rnd = random.Random(1234)
        for _ in range(200):
            blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 600)))
            try:
                EP.parse_eml(blob)
            except EP.EmailRejectedError:
                pass

    def test_app_wires_rejection_and_scan_status(self):
        src = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
        self.assertIn("except EmailRejectedError", src)
        self.assertIn("attachment_status", src)
        self.assertNotIn('m3.metric("Clean", total_files - threats_found)', src)


class _R:
    def __init__(self, data, raw=None):
        self.data = data
        self.raw = raw
        self.headers = {}
        self.closed = False
    def raise_for_status(self): pass
    def iter_content(self, chunk_size=65536):
        raw = self.raw if self.raw is not None else __import__("json").dumps(self.data).encode()
        for i in range(0, len(raw), chunk_size):
            yield raw[i:i + chunk_size]
    def close(self): self.closed = True


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

    def test_streamed_body_over_2mb_refused_without_content_length(self):
        r = _R(None, raw=b"[" + b"1," * (SI._MAX_RESPONSE_BYTES // 2) + b"1]")
        class S:
            def get(self, url, **kw):
                assert kw.get("stream") is True
                return r
        self.assertFalse(SI.fetch_verified(session=S())["ok"])
        self.assertTrue(r.closed)

    def test_nan_inf_bounds(self):
        self.assertEqual(SI._clamp_rows(float("inf")), SI._MAX_ROWS)
        self.assertEqual(SI._clamp_rows(float("nan")), SI._MAX_ROWS)
        self.assertEqual(SI._clamp_timeout(float("nan")), SI._DEFAULT_TIMEOUT)
        self.assertEqual(SI._clamp_timeout(float("inf")), SI._MAX_TIMEOUT)

    def test_zero_rows_makes_no_request(self):
        class S:
            def get(self, *a, **k): raise AssertionError("no request expected")
        self.assertTrue(SI.fetch_verified(max_rows=0, session=S())["ok"])

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
