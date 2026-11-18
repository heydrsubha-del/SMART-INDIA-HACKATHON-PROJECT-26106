"""Phase 1 - universal evidence integration. Offline and deterministic: the ML probability is injected, threat memory is
mocked (nothing is persisted), the Tor refresh is a no-op, the ip-api.com lookup is answered from a fixture and ANY other
outbound request fails the test (tearDown). Reuses the existing investigation fixtures (make_result, _db, Base)."""
import copy
import ipaddress
import io
import json
import os
import re
import socket
import subprocess
import sys
import types
import unittest
from unittest import mock
from urllib.parse import urlsplit

import analyzer
import community_intel
import extortion_detection as ED
import investigation_agent as ia
import md_export
import report
import requests
from test_investigation_agent import Base, D, _db, make_result

FIXED_ML = (0.10, "legit", [("invoice", 0.25)])
MARK = "ZEBRA-SECRET-7731"
INVOICE = "Hello, attached is invoice 4411 for $3,000. Please pay within 7 days. Thanks."
SEXT = ("I have your private photos. Pay $3,000 in bitcoin to the wallet below within 48 hours or I will send them to all "
        "your contacts. Wallet: bc1qexampleexampleexampleexample (not a real address). " + MARK)
NEW_KEYS = {"scan_id", "evidence_register", "scan_findings", "evidence_error", "origin_intel_status"}
SID = ia.scan_id_for(b"fixture-scan")          # a valid scan id
FOREIGN = ia.scan_id_for(b"another-scan")       # a valid id belonging to a different scan


def eml(body, subject="Hello", sender="Sender <sender@example.com>"):
    return ("From: %s\r\nTo: v@example.com\r\nSubject: %s\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\n%s"
            % (sender, subject, body)).encode()


class GuardBlocked(ConnectionError):
    """Raised by the offline guard, AFTER the attempt has been recorded, for any network or process attempt."""


class GuardDNSBlocked(GuardBlocked, socket.gaierror):
    """Same, for name resolution: still a socket.gaierror, so code written for 'no network' keeps its offline behaviour."""


# (dotted target, positional argument that describes the attempt (None = describe nothing, e.g. a payload), resolution-style error?)
_GUARDED = (
    ("socket.getaddrinfo", 0, True), ("socket.gethostbyname", 0, True), ("socket.gethostbyname_ex", 0, True),
    ("socket.gethostbyaddr", 0, True), ("socket.create_connection", 0, False),
    ("socket.socket.connect", 1, False), ("socket.socket.connect_ex", 1, False),
    ("socket.socket.send", None, False), ("socket.socket.sendall", None, False), ("socket.socket.sendto", -1, False),
    ("requests.adapters.HTTPAdapter.send", "url", False),
    ("subprocess.Popen", 0, False), ("os.system", 0, False), ("os.popen", 0, False),
)
_FIXTURE_PATCHED = ("requests.sessions.Session.request",)       # answered from a fixture for ip-api.com, recorded + blocked otherwise


def _resolve(dotted):
    obj = {"socket": socket, "os": os, "subprocess": subprocess, "requests": requests}[dotted.split(".")[0]]
    for part in dotted.split(".")[1:]:
        obj = getattr(obj, part)
    return obj


_ORIGINALS = {name: _resolve(name) for name in [g[0] for g in _GUARDED] + list(_FIXTURE_PATCHED)}    # captured before any patch


def _require_guards(testcase):
    """Fail BEFORE any guarded call is made if a mechanism is not currently guarded (so a broken guard can never reach the network)."""
    unguarded = [n for n in _ORIGINALS if _resolve(n) is _ORIGINALS[n]]
    if unguarded:
        raise AssertionError("offline guard is not installed for: %s" % ", ".join(unguarded))


_IPAPI_PATH_RE = re.compile(r"^/json/([^/]+)$")                # the fixture's "/json/{ip}" endpoint shape; {ip} checked below
# Exact query string geolocate.py sends (see geolocate(): the literal f-string built for the live ip-api.com GET). The real
# call always sends exactly this query, so the fixture accepts only this exact string and nothing else -- not a superset,
# not a reordering, not "no query at all".
_IPAPI_EXACT_QUERY = "fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as"
# ASCII control characters (incl. DEL) and '#' (a fragment delimiter, even an empty one, is never part of the real
# request) in one pass instead of a per-character ord() loop plus a separate "#" in raw_url check.
_IPAPI_BAD_CHAR_RE = re.compile(r"[\x00-\x1f\x7f#]")


def _is_valid_ipapi_request(method, url):
    """Return True only for the exact ip-api.com GET made by geolocate.py.

    The fixture must not accidentally whitelist lookalike URLs. In particular, reject credentials, malformed or
    non-default ports, non-IP path segments, any query variation, and even an empty fragment delimiter (a bare '#').
    Invalid URLs return False so fake_request records and blocks them through the offline guard.
    """
    try:
        raw_url = str(url)
        # urlsplit() may strip some leading control/space characters; reject them rather than validating a normalized URL.
        # One regex scan covers control chars, DEL and any '#' (fragment delimiter, including an empty fragment).
        if not raw_url or raw_url != raw_url.strip() or _IPAPI_BAD_CHAR_RE.search(raw_url):
            return False

        parts = urlsplit(raw_url)
        if str(method).upper() != "GET" or parts.scheme != "http":
            return False
        if parts.hostname != "ip-api.com":
            return False
        if parts.username is not None or parts.password is not None:
            return False
        if parts.netloc.endswith(":"):                          # reject an explicitly empty port (port property is None)
            return False
        if parts.port is not None and parts.port != 80:          # ValueError for malformed/out-of-range ports is caught below
            return False

        match = _IPAPI_PATH_RE.match(parts.path)                # pattern is ^...$-anchored, so match == fullmatch here
        if match is None:
            return False
        ip_text = match.group(1)
        if "%" in ip_text:                                     # reject scoped IPv6 and percent-encoded path segments
            return False
        ipaddress.ip_address(ip_text)                           # only a literal IPv4 or IPv6 address is valid

        if parts.query != _IPAPI_EXACT_QUERY:
            return False
        return True
    except ValueError:                                          # malformed URL/port/IP -> fail closed, never crash the guard
        return False


def install_offline(case):
    """Make a test case strictly offline BEFORE any fixture runs (make_result() performs a geolocation lookup).
    The ip-api.com lookup is answered from a fixture. Every other HTTP request, name resolution, socket connect/send, adapter send,
    subprocess and shell call is RECORDED in case.unexpected BEFORE an exception is raised, so application code that swallows the
    exception cannot hide the attempt: the cleanup below fails the test. urllib and http.client are covered through the socket
    guards. Nothing is persisted, nothing depends on test order, and every patch is undone by cleanups (also when a test fails).
    Not a process-global hook: it only exists while the test case's patches are active."""
    import geolocate
    case.unexpected, case.served = [], []

    def record(mechanism, detail=""):
        # 100 chars silently truncated the exact-contract ip-api.com URLs used by the strict validation tests
        # below (host + the full real query string alone runs past 100 chars), so a rejected request's own
        # assertions ("the full URL is in the diagnostic") failed even though the guard correctly blocked it.
        # 500 is comfortably above every URL/command this guard ever records, while still bounding the entry
        # so a pathological caller can't grow this list without limit; it does not change WHAT gets blocked,
        # only how much of the detail shows up in the diagnostic for something already rejected and never sent.
        entry = ("%s %s" % (mechanism, str(detail)[:500])).strip()
        case.unexpected.append(entry)                          # appended first; raising happens after
        return entry

    def fake_request(session, method, url, **kw):
        if _is_valid_ipapi_request(method, url):                # deterministic stand-in for the geolocation lookup
            case.served.append(str(url))
            resp = requests.Response()
            resp.status_code, resp._content = 200, b'{"status": "fail", "message": "reserved range"}'
            return resp
        raise requests.ConnectionError("offline guard blocked %s" % record("requests.Session.request", url))

    def make_guard(name, pos, dns):
        def guard(*args, **kwargs):
            try:
                detail = args[1].url if pos == "url" else (args[pos] if pos is not None else "")
            except Exception:
                detail = ""
            entry = record(name, detail)
            if dns:
                raise GuardDNSBlocked(-2, "Name or service not known (offline guard blocked %s)" % entry)
            raise GuardBlocked("offline guard blocked %s" % entry)
        return guard

    geolocate.geolocate.cache_clear()
    patchers = [mock.patch.object(analyzer, "predict", return_value=FIXED_ML),
                mock.patch.object(analyzer, "load_or_train", return_value=object()),
                mock.patch.object(analyzer, "lookup_indicator", return_value=None),
                mock.patch.object(analyzer, "remember_indicator", return_value=True),
                mock.patch.object(analyzer, "refresh_stale_url_scores"),
                mock.patch("tor_check.maybe_update_tor_list"),
                mock.patch("tor_check.tor_exit_sources", return_value=[]),
                mock.patch("tracker.lookup_indicator", return_value=None),
                # geolocate() falls back to data/geo_cache.json and, if the optional maxminddb package and
                # GeoLite2 files happen to be present, to a local MaxMind lookup -- both are external, mutable
                # inputs (the cache file is shared with the live product and can gain entries; maxminddb's
                # presence varies by environment). Neither is part of the "offline fixture" this guard promises,
                # so both are pinned to "no data available" here, exactly like the blocked live API call, so
                # origin_risk is deterministic and isolated from whatever happens to be on disk.
                mock.patch.object(geolocate, "_load_cache", return_value={}),
                mock.patch.object(geolocate, "_geolite_reader", return_value=None),
                mock.patch("requests.sessions.Session.request", new=fake_request)]
    for name, pos, dns in _GUARDED:
        owner, _, attr = name.rpartition(".")
        patchers.append(mock.patch.object(_resolve(owner), attr, new=make_guard(name, pos, dns)))
    for p in patchers:
        p.start()
        case.addCleanup(p.stop)                                # registered only after a successful start
    case.addCleanup(lambda: case.assertEqual(case.unexpected, [], "a test made an unexpected network or process attempt"))


class ScanBase(unittest.TestCase):
    def setUp(self):
        install_offline(self)

    def scan(self, body=INVOICE, **kw):
        return analyzer.analyze_email(eml(body, **kw), "t.eml")

    def synthetic(self, **over):                                # a result with URLs, header anomalies and a Reply-To mismatch
        r = make_result()
        r["scan_id"] = ia.scan_id_for(b"synthetic-scan")
        r.update(over)
        r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
        return r


class EvidenceCreation(ScanBase):
    def test_register_structure_and_unique_ids(self):
        for label, res in (("invoice", self.scan()), ("sextortion", self.scan(SEXT)), ("rich", self.synthetic())):
            with self.subTest(scan=label):
                reg = res["evidence_register"]
                self.assertTrue(reg)
                ids = [e["id"] for e in reg]
                self.assertEqual(len(ids), len(set(ids)))
                self.assertTrue(all(re.fullmatch(r"S\d+", i) for i in ids))
                for e in reg:
                    self.assertTrue(all(k in e for k in ia._SCAN_FIELDS), e)
                    self.assertIn(e["origin"], ia.ORIGINS)
                    self.assertIn(e["status"], ia.EVIDENCE_STATUSES)
                    self.assertEqual(e["scan_id"], res["scan_id"])
                    self.assertTrue(e["observation"] and e["source"] and e["type"])
                self.assertEqual(ia.validate_scan_register(res), [])

    def test_scan_id_is_stable_and_distinguishes_scans(self):
        a, b = self.scan(INVOICE), self.scan(SEXT)
        self.assertEqual(a["scan_id"], self.scan(INVOICE)["scan_id"])
        self.assertNotEqual(a["scan_id"], b["scan_id"])
        self.assertRegex(a["scan_id"], r"^SC-[0-9a-f]{32}$")
        self.assertEqual(len(a["scan_id"]), 35)
        self.assertEqual(ia.scan_id_for(b""), "")
        self.assertEqual(ia.scan_id_for(None), "")
        self.assertNotEqual(ia.qualified_id(a["scan_id"], "E1"), ia.qualified_id(b["scan_id"], "E1"))

    def test_no_message_content_or_full_address_is_copied(self):
        res = self.synthetic()
        res["parsed"] = dict(res["parsed"], body_text=MARK + " body", subject=MARK + " subject")
        reg, fnd = ia.build_scan_evidence(res)
        dump = json.dumps([reg, fnd])
        self.assertNotIn(MARK, dump)
        self.assertNotIn("support@paypa1-secure.com", dump)           # the full From address is never copied (domains only)
        self.assertNotIn("/login/verify", dump)                       # no URL paths or query strings
        sext = json.dumps(self.scan(SEXT)["evidence_register"])
        self.assertNotIn(MARK, sext)
        self.assertNotIn("bc1qexample", sext)

    def test_missing_and_malformed_inputs_are_handled_without_exceptions(self):
        for bad in (None, "junk", 5, [], {}, {"scan_id": SID},
                    {"scan_id": SID, "ml": {"prob": "x"}, "headers": [], "geo": "g", "iocs": None, "parsed": 3, "verdict": 7,
                     "extortion": "junk", "origin_intel": 1, "community_intel": []}):
            with self.subTest(bad=repr(bad)[:40]):
                reg, fnd = ia.build_scan_evidence(bad)
                self.assertIsInstance(reg, list)
                self.assertIsInstance(fnd, list)
                res = {"scan_id": bad.get("scan_id", "") if isinstance(bad, dict) else "", "evidence_register": reg, "scan_findings": fnd}
                self.assertEqual(ia.validate_scan_register(res), [])
        reg, fnd = ia.build_scan_evidence({"scan_id": SID, "ml": {"prob": "x"}})
        ml = next(e for e in reg if e["type"] == "ML")
        self.assertEqual(ml["status"], "missing")                        # malformed ML output is never "ok"
        self.assertTrue(any(f["kind"] == "uncertain" and ml["id"] in f["evidence_ids"] for f in fnd))

    def test_malformed_detector_output_cannot_become_verified_evidence(self):
        base = self.scan(SEXT)
        good = base["extortion"]
        for bad in (None, {}, {"detected": "false"}, {"detected": 1}, {"detected": True}, "junk", dict(good, confidence=float("nan")),
                    dict(good, evidence=None)):
            with self.subTest(bad=repr(bad)[:50]):
                reg, fnd = ia.build_scan_evidence(dict(base, extortion=bad))
                x = [e for e in reg if e["type"] == "extortion"]
                self.assertEqual(len(x), 1)
                self.assertEqual(x[0]["status"], "failed")
                self.assertNotIn("confidence", x[0])
                self.assertIn("failed", x[0]["observation"])
                related = [f for f in fnd if x[0]["id"] in f["evidence_ids"]]
                self.assertTrue(related and all(f["kind"] == "uncertain" for f in related))
        reg, fnd = ia.build_scan_evidence(base)                         # a valid detection is real evidence with its rule confidence
        x = next(e for e in reg if e["type"] == "extortion")
        self.assertEqual((x["status"], x["origin"]), ("ok", "direct_machine"))
        self.assertEqual(x["confidence"], round(good["confidence"], 3))
        self.assertTrue(any(f["kind"] == "suspicious" and x["id"] in f["evidence_ids"] for f in fnd))

    def test_untrusted_header_claims_stay_untrusted(self):
        res = self.synthetic()
        auth = [e for e in res["evidence_register"] if e["type"] == "authentication"]
        self.assertEqual(len(auth), 3)
        self.assertTrue(all(e["origin"] == "untrusted_claim" for e in auth))
        ident = next(e for e in res["evidence_register"] if e["type"] == "header" and e["source"] == "email_parser")
        self.assertEqual(ident["origin"], "untrusted_claim")
        for prov in ("spf", "dkim", "dmarc"):                            # only a scanner-verified mechanism becomes trusted_external
            ae = {m: dict(v) for m, v in res["headers"]["auth_evidence"].items()}
            ae[prov]["provenance"] = "verified"
            hdrs = dict(res["headers"], auth_evidence=ae)
            reg, fnd = ia.build_scan_evidence(dict(res, headers=hdrs))
            by = {e["id"]: e for e in reg if e["type"] == "authentication"}
            self.assertEqual(sorted(e["origin"] for e in by.values()), ["trusted_external", "untrusted_claim", "untrusted_claim"])
            unverified = next(f for f in fnd if "unverified claims" in f["statement"])
            self.assertTrue(all(by[i]["origin"] == "untrusted_claim" for i in unverified["evidence_ids"]))
            # exactly the present-but-unverified mechanisms are cited; the verified one and any absent one are not
            self.assertEqual(sorted(unverified["evidence_ids"]),
                             sorted(i for i, e in by.items() if e["origin"] == "untrusted_claim" and e["status"] == "ok"))

    def test_geoip_is_an_approximate_inference_and_a_missing_origin_is_a_gap(self):
        res = self.synthetic()
        g = next(e for e in res["evidence_register"] if e["type"] == "GeoIP")
        self.assertEqual(g["origin"], "inference")
        self.assertIs(g["metadata"]["approximate"], True)
        self.assertIn("approximate", g["observation"])
        reg, fnd = ia.build_scan_evidence(dict(res, geo={"origin": {}, "anonymised": False}))
        g = next(e for e in reg if e["type"] == "GeoIP")
        self.assertEqual(g["status"], "missing")
        self.assertTrue(any(f["kind"] == "uncertain" and g["id"] in f["evidence_ids"] for f in fnd))

    def test_builder_is_pure_and_the_scanner_result_is_untouched(self):
        res = self.synthetic()
        before = copy.deepcopy(res)
        ia.build_scan_evidence(res)
        self.assertEqual(res, before)

    def test_investigation_evidence_carries_the_contract(self):
        r = make_result()
        r["scan_id"] = ia.scan_id_for(b"scan-a")
        with mock.patch("tor_check.tor_exit_sources", return_value=[]), mock.patch("tracker.lookup_indicator", return_value=None):
            inv = ia.investigate(r, use_ai=False)
        self.assertEqual(inv["scan_id"], r["scan_id"])
        ids = [e["id"] for e in inv["evidence"]]
        self.assertEqual(len(ids), len(set(ids)))
        for e in inv["evidence"]:
            self.assertTrue(all(e.get(k) for k in ("type", "source", "origin", "source_reference", "scan_id", "observed_utc")), e)
            self.assertIn(e["origin"], ia.ORIGINS)
            self.assertEqual(e["scan_id"], r["scan_id"])
        by = {e["tool"]: e for e in inv["evidence"]}
        self.assertEqual(by["review_authentication"]["origin"], "untrusted_claim")
        self.assertEqual(by["review_sender_identity"]["origin"], "untrusted_claim")
        self.assertEqual(by["review_origin"]["origin"], "inference")
        self.assertIs(by["review_origin"]["metadata"]["approximate"], True)
        self.assertEqual(by["review_urls"]["origin"], "direct_machine")
        ids_f = [f["finding_id"] for f in inv["findings"]]
        self.assertEqual(len(ids_f), len(set(ids_f)))
        self.assertTrue(all(i.startswith("IF") for i in ids_f))


class FindingLinkage(ScanBase):
    def test_machine_findings_cite_existing_evidence_consistently(self):
        for label, res in (("invoice", self.scan()), ("sextortion", self.scan(SEXT)), ("rich", self.synthetic())):
            with self.subTest(scan=label):
                ids = {e["id"]: e for e in res["evidence_register"]}
                self.assertTrue(res["scan_findings"])
                for f in res["scan_findings"]:
                    self.assertEqual(f["origin"], "machine")
                    self.assertTrue(f["evidence_ids"] and all(c in ids for c in f["evidence_ids"]))
                    if f["kind"] == "suspicious":
                        self.assertTrue(all(ids[c]["status"] in ("ok", "partial") for c in f["evidence_ids"]))
                    self.assertNotEqual(f["kind"], "verified")           # the scanner makes detector findings, not verified conclusions
        self.assertTrue(any(f["kind"] == "suspicious" and "extortion" in f["statement"].lower() for f in self.scan(SEXT)["scan_findings"]))

    def test_validator_rejects_unknown_foreign_and_inconsistent_references(self):
        good = self.synthetic()
        self.assertEqual(ia.validate_scan_register(good), [])
        first = good["scan_findings"][0]["evidence_ids"][0]

        def broken(mutate):
            r = copy.deepcopy(good)
            mutate(r)
            return " | ".join(ia.validate_scan_register(r))
        self.assertIn("unknown evidence S999", broken(lambda r: r["scan_findings"][0]["evidence_ids"].append("S999")))
        self.assertIn("malformed evidence reference", broken(lambda r: r["scan_findings"][0].update(evidence_ids=["%s/S1" % FOREIGN])))
        self.assertIn("different scan", broken(lambda r: r["scan_findings"][0].update(scan_id=FOREIGN)))
        self.assertIn("belongs to scan", broken(lambda r: r["evidence_register"][0].update(scan_id=FOREIGN)))
        self.assertIn("malformed scan_id", broken(lambda r: r["evidence_register"][0].update(scan_id="SC-other")))
        self.assertIn("duplicate evidence id", broken(lambda r: r["evidence_register"].append(dict(r["evidence_register"][0]))))
        self.assertIn("malformed finding", broken(lambda r: r["scan_findings"][0].update(evidence_ids=[])))
        self.assertIn("unknown origin/status", broken(lambda r: r["evidence_register"][0].update(origin="verified_by_ai")))
        self.assertIn("unknown origin/status", broken(lambda r: r["evidence_register"][0].update(status="great")))
        self.assertIn("not lists", broken(lambda r: r.update(evidence_register="x")))

        def cite_failed(r):
            for e in r["evidence_register"]:
                if e["id"] == first:
                    e["status"] = "failed"
            r["scan_findings"][0]["kind"] = "suspicious"
        self.assertIn("suspicious finding", broken(cite_failed))

    def test_missing_evidence_is_represented_as_uncertainty(self):
        res = self.synthetic(ml=None, geo={"origin": {}}, extortion=None)
        gaps = [e for e in res["evidence_register"] if e["status"] in ("missing", "failed")]
        self.assertTrue({"ML", "GeoIP", "extortion"} <= {e["type"] for e in gaps})
        for e in gaps:
            self.assertTrue(any(f["kind"] == "uncertain" and e["id"] in f["evidence_ids"] for f in res["scan_findings"]), e)

    def _inv(self):
        r = make_result()
        r["scan_id"] = ia.scan_id_for(b"scan-a")
        with mock.patch("tor_check.tor_exit_sources", return_value=[]), mock.patch("tracker.lookup_indicator", return_value=None):
            return r, ia.investigate(r, use_ai=False)

    def test_ai_findings_cannot_cite_unknown_or_foreign_evidence(self):
        r, inv = self._inv()
        fact = inv["evidence"][1]["facts"][0]
        good = {"statement": fact, "evidence_ids": ["E2"], "kind": "verified"}
        for bad_id in ("E99", "S1", "SC-other/E2", "e2", "", None, 2):
            with self.subTest(cited=bad_id):
                _, f, dropped = ia.validate_narrative({"findings": [dict(good, evidence_ids=[bad_id])]}, inv["evidence"], r)
                self.assertEqual((f, dropped), ([], 1))
        _, f, dropped = ia.validate_narrative({"findings": [good]}, inv["evidence"], r)
        self.assertEqual((len(f), dropped), (1, 0))
        self.assertEqual(f[0]["origin"], "ai")
        self.assertEqual(f[0]["finding_id"], "AF1")
        self.assertIn(f[0]["verification"], ("keyword_grounded", "unverified"))

    def test_ai_findings_are_secondary_and_unsupported_claims_stay_unverified(self):
        r, inv = self._inv()
        _, f, _ = ia.validate_narrative({"findings": [{"statement": "Authentication evidence shows many unrelated delivery concerns today",
                                                       "evidence_ids": ["E2"], "kind": "verified"}]}, inv["evidence"], r)
        self.assertEqual((f[0]["kind"], f[0]["supported"], f[0]["verification"]), ("uncertain", False, "unverified"))
        _, f, dropped = ia.validate_narrative({"summary": "All clear, score 2/100", "findings": [
            {"statement": "Risk is 2/100", "evidence_ids": ["E2"], "kind": "verified"}]}, inv["evidence"], r)
        self.assertEqual((f, dropped), ([], 2))                              # a wrong score claim and a free-form summary are dropped

    def test_ai_cannot_change_scanner_scores_or_tool_findings(self):
        def run(llm):
            r = make_result()
            r["scan_id"] = ia.scan_id_for(b"scan-a")
            snap = copy.deepcopy(r)
            with mock.patch("tor_check.tor_exit_sources", return_value=[]), mock.patch("tracker.lookup_indicator", return_value=None):
                inv = ia.investigate(r, use_ai=llm is not None, llm=llm)
            self.assertEqual(r, snap)
            return inv

        def llm(system, user, timeout):
            if "reply_format" in user and "findings" in user:
                return json.dumps({"summary": "Safe, score 1/100", "findings": [{"statement": "score 1/100", "evidence_ids": ["E1"], "kind": "verified"}]})
            return json.dumps({"action": "run", "index": 0, "reason": "next"})
        plain, ai = run(None), run(llm)
        self.assertEqual(ai["score_snapshot"], plain["score_snapshot"])
        tool = lambda inv: [(f["statement"], f["kind"], tuple(f["evidence_ids"])) for f in inv["findings"] if f["origin"] == "tool"]
        self.assertEqual(tool(ai), tool(plain))
        self.assertGreaterEqual(ai["rejected_model_outputs"], 1)
        self.assertFalse(any("1/100" in f["statement"] for f in ai.get("narrative_findings", [])))

    def test_evidence_from_another_scan_is_detected_and_never_rendered(self):
        r_a, inv_a = self._inv()
        r_b = self.scan(SEXT)
        self.assertEqual(ia.check_scan_binding(inv_a, r_a), "match")
        self.assertEqual(ia.check_scan_binding(inv_a, r_b), "mismatch")
        self.assertEqual(ia.check_scan_binding({}, {}), "legacy")
        self.assertEqual(ia.check_scan_binding({"scan_id": ""}, r_b), "unbound")
        md = ia.render_report(inv_a, r_b, include_base=False)
        self.assertIn("Investigation not included", md)
        self.assertNotIn("### Evidence register (investigation)", md)
        self.assertNotIn(inv_a["evidence"][1]["facts"][0], md)
        self.assertNotIn("E1", re.sub(r"[^A-Za-z0-9 ]", " ", md).split())
        full = ia.render_report(inv_a, r_a, include_base=False)
        self.assertIn("### Evidence register (investigation)", full)
        self.assertIn("binding: match", full)


class RetroHuntEvidence(Base):
    def setUp(self):
        install_offline(self)              # before Base.setUp, whose make_result() would otherwise look up the origin IP
        super().setUp()

    ROWS = [(D, "domain", .5, "observed", "2026-01-01", "2026-01-09", 3, "local_analysis"),
            ("a." + D, "domain", .4, "phishing", "2026-02-01", "2026-02-09", 2, "urlhaus")]

    def hunt(self, rows, conns=True):
        self.result["scan_id"] = ia.scan_id_for(b"scan-a")
        self.snap = copy.deepcopy(self.result)
        c = _db(rows)
        return self.run_inv(conns_factory=(lambda: [c]) if conns else None,
                            limits=ia.Limits(max_tool_calls=15, max_iterations=15, max_indicators=1))

    def retro(self, inv):
        return next(e for e in inv["evidence"] if e["tool"] == "retro_hunt_indicator" and e["args"].get("indicator") == D)

    def test_match_is_traceable_from_indicator_to_record_to_evidence(self):
        inv = self.hunt(self.ROWS)
        e = self.retro(inv)
        self.assertEqual((e["type"], e["origin"], e["scan_id"]), ("Retro-Hunt", "historical", self.result["scan_id"]))
        self.assertIn("indicator=" + D, e["source_reference"])
        self.assertTrue(e["records"])
        for r in e["records"]:
            self.assertEqual(r["hunted"], D)
            for k in ("stored indicator", "match", "source", "source class", "recorded source", "first seen", "last seen", "tier", "reason"):
                self.assertIn(k, r)
        self.assertTrue(any(f["evidence_ids"] == [e["id"]] and f["origin"] == "tool" for f in inv["findings"]))

    def test_exact_and_subdomain_matches_keep_their_classification(self):
        recs = {r["stored indicator"]: r for r in self.retro(self.hunt(self.ROWS))["records"]}
        self.assertTrue(recs[D]["match"].startswith("exact"))
        self.assertTrue(recs["a." + D]["match"].startswith("subdomain of the hunted domain"))
        self.assertEqual(recs["a." + D]["recorded source"], "urlhaus")
        self.assertEqual((recs[D]["first seen"], recs[D]["last seen"]), ("2026-01-01", "2026-01-09"))

    def test_historical_sightings_are_not_labelled_malicious_by_default(self):
        inv = self.hunt([(D, "domain", .5, "observed", "a", "b", 3, "local_analysis")])
        recs = self.retro(inv)["records"]
        self.assertTrue(recs and {r["tier"] for r in recs} == {"historical"})
        self.assertEqual(self.retro(inv)["origin"], "historical")
        self.assertFalse([f for f in inv["findings"] if f["kind"] == "suspicious" and self.retro(inv)["id"] in f["evidence_ids"]])
        text = " ".join(self.retro(inv)["facts"])
        self.assertIn("'seen before', not 'malicious'", text)                    # the sighting is explicitly NOT labelled malicious
        self.assertNotIn("malicious", text.replace("'seen before', not 'malicious'", ""))

    def test_the_current_scans_own_records_are_excluded(self):
        self.result["recorded_indicators"] = [("domain", D)]
        inv = self.hunt([(D, "domain", .5, "observed", "a", "b", 1, "local_analysis")])
        self.assertEqual(self.retro(inv)["records"], [])
        self.assertIn("no earlier sighting", " ".join(self.retro(inv)["facts"]))
        self.result["recorded_indicators"] = [("domain", D)]
        inv = self.hunt([(D, "domain", .5, "observed", "a", "b", 2, "local_analysis")])
        self.assertEqual(self.retro(inv)["records"][0]["times"], "1")        # only the EARLIER observation counts

    def test_missing_historical_sources_are_reported_as_gaps_not_as_clean(self):
        inv = self.hunt(self.ROWS, conns=False)
        e = self.retro(inv)
        self.assertEqual(e["records"], [])
        self.assertTrue(e["missing"] or e["status"] != "ok")
        self.assertTrue(any(f["kind"] == "uncertain" and e["id"] in f["evidence_ids"] for f in inv["findings"]))
        self.assertIn(inv["status"], ("partial", "complete"))


class ReportEvidence(ScanBase):
    def test_machine_report_has_a_register_that_contains_every_cited_id(self):
        res = self.synthetic()
        md = report.build_report(res, b"raw")
        self.assertIn("## 9. Evidence register (scanner)", md)
        sec = md[md.index("## 9. Evidence register"):]
        for e in res["evidence_register"]:
            self.assertRegex(sec, r"\| %s \| %s \|" % (e["id"], re.escape(e["type"])))
        for f in res["scan_findings"]:
            row = next(l for l in sec.splitlines() if l.startswith("| %s |" % f["id"]))
            self.assertTrue(all(c in row for c in f["evidence_ids"]), row)        # the finding row lists ITS evidence IDs
        self.assertIn("historical sighting = seen before, which is not proof", sec)
        self.assertIn(res["scan_id"], sec)

    def test_existing_report_is_preserved_and_legacy_results_are_unchanged(self):
        res = self.synthetic()
        legacy = {k: v for k, v in res.items() if k not in NEW_KEYS}
        old, new = report.build_report(legacy, b"raw").splitlines(), report.build_report(res, b"raw").splitlines()
        self.assertNotIn("Evidence register", "\n".join(old))
        it = iter(new)
        self.assertTrue(all(any(line == n for n in it) for line in old), "every legacy report line must still appear, in order")
        heads = [l for l in new if re.match(r"## \d\.", l)]
        self.assertEqual(heads[-2:], [h for h in heads if h.startswith(("## 8.", "## 9."))])
        self.assertTrue(heads[0].startswith("## 1."))

    def test_invalid_or_unavailable_registers_are_disclosed(self):
        res = self.synthetic()
        res["scan_findings"][0]["evidence_ids"].append("S999")
        self.assertIn("Evidence register failed validation", report.build_report(res, b"raw"))
        down = dict(self.synthetic(), evidence_register=[], scan_findings=[], evidence_error="RuntimeError")
        md = report.build_report(down, b"raw")
        self.assertIn("Evidence register unavailable", md)
        self.assertIn("not a clean result", md)

    def test_agentic_report_has_one_register_and_findings_link_to_it(self):
        r = make_result()
        r["scan_id"] = ia.scan_id_for(b"scan-a")
        with mock.patch("tor_check.tor_exit_sources", return_value=[]), mock.patch("tracker.lookup_indicator", return_value=None):
            inv = ia.investigate(r, use_ai=False)
        md = ia.render_report(inv, r, b"raw")
        sec = md[md.index("### Evidence register (investigation)"):]
        for e in inv["evidence"]:
            self.assertIn("| %s | %s |" % (e["id"], e["type"]), sec)
        self.assertEqual(sum(1 for l in md.splitlines() if l.startswith("| E1 |")), 1)       # defined once, not duplicated per section
        f = next(f for f in inv["findings"] if f["kind"] == "suspicious")
        line = next(l for l in md.splitlines() if l.startswith("- ") and f["statement"][:40] in l)
        self.assertIn("`[%s]`" % ",".join(f["evidence_ids"]), line)                          # the original [E#] reference format is kept
        self.assertIn(f["finding_id"], line)
        self.assertIn("## 9. Evidence register (scanner)", md) if "evidence_register" in r else None
        ai = [{"statement": "x", "evidence_ids": ["E1"], "kind": "uncertain", "supported": False, "finding_id": "AF1", "verification": "unverified",
               "origin": "ai"}]
        md2 = ia.render_report(dict(inv, narrative_findings=ai), r, include_base=False)
        self.assertRegex(md2, r"unverified AI claim, uncertain.*`\[E1\]` \(AF1")

    def test_batch_combined_report_keeps_each_emails_evidence_separate(self):
        import ast
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
        src = open(path, encoding="utf-8").read()
        tree, lines = ast.parse(src), src.splitlines()

        def smallest(needle, kinds):
            nodes = [n for n in ast.walk(tree) if isinstance(n, kinds) and needle in "\n".join(lines[n.lineno - 1:n.end_lineno])]
            return min(nodes, key=lambda n: n.end_lineno - n.lineno)

        a, b = self.scan(INVOICE), self.scan(SEXT)
        batch_items = [{"position": 1, "row": 2, "result": a}, {"position": 2, "row": 3, "result": b}]
        ns = {"scan_evidence_md": report.scan_evidence_md, "_batch_items_for_dl": batch_items,
              "cleaned_summary": "campaign summary text", "saved_batch": {"count": 2}, "_batch_machine_body": "machine body"}
        for needle, kinds in (("_ai_evidence_refs = []", (ast.Assign,)), ("_bi_tail = scan_evidence_md(_bi_result)", (ast.For,)),
                              ("_ai_evidence_refs_md = (", (ast.Assign,)), ("ai_only_batch_md = (", (ast.Assign,)),
                              ("combined_batch_md = (", (ast.Assign,))):
            exec(compile(ast.get_source_segment(src, smallest(needle, kinds)), "app.py::batch", "exec"), ns)

        ext_b = next(e for e in b["evidence_register"] if e["type"] == "extortion")["observation"]
        for md in (ns["ai_only_batch_md"], ns["combined_batch_md"]):
            self.assertIn("Email #1", md)
            self.assertIn("Email #2", md)
            self.assertIn(ext_b, md)
        # the strict check: email #2's own evidence text must not appear inside email #1's block, and vice versa --
        # applied to both the AI-only download and the combined download, since each builds its own Email #1/#2 blocks.
        for md in (ns["ai_only_batch_md"], ns["combined_batch_md"]):
            block1 = md[md.index("Email #1"):md.index("Email #2")]
            block2 = md[md.index("Email #2"):]
            self.assertIn(ext_b, block2)
            self.assertNotIn(ext_b, block1)
        self.assertFalse({e["scan_id"] for e in a["evidence_register"]} & {e["scan_id"] for e in b["evidence_register"]})

    def test_separate_scans_do_not_leak_evidence_into_each_other(self):
        a, b = self.scan(INVOICE), self.scan(SEXT)
        ra, rb = report.build_report(a, b"a"), report.build_report(b, b"b")
        self.assertIn(a["scan_id"], ra)
        self.assertNotIn(b["scan_id"], ra)
        self.assertIn(b["scan_id"], rb)
        self.assertNotIn(a["scan_id"], rb)
        ext_b = next(e for e in b["evidence_register"] if e["type"] == "extortion")["observation"]
        self.assertIn(ext_b, rb)
        self.assertNotIn(ext_b, ra)
        self.assertFalse({e["scan_id"] for e in a["evidence_register"]} & {e["scan_id"] for e in b["evidence_register"]})

    def test_downloads_and_exports_still_work_with_the_register(self):
        md = report.build_report(self.synthetic(), b"raw")
        for doc in (md_export.md_to_html_document(md, "T"), md_export.md_to_word_document(md, "T")):
            self.assertIn("Evidence register", doc)
            self.assertIn("S1", doc)

    def test_dossier_machine_and_combined_reports_include_the_register(self):
        import ast
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
        src = open(path, encoding="utf-8").read()
        tree, lines = ast.parse(src), src.splitlines()

        def smallest(needle, kinds):
            nodes = [n for n in ast.walk(tree) if isinstance(n, kinds) and needle in "\n".join(lines[n.lineno - 1:n.end_lineno])]
            return min(nodes, key=lambda n: n.end_lineno - n.lineno)
        res = self.synthetic()
        ns = {"scan_evidence_md": report.scan_evidence_md, "sel_res": res, "machine_md": "# MACHINE", "ai_md": "# AI",
              "ai_markdown_body": "stub ai text"}
        for needle, kinds in (("_evidence_tail = scan_evidence_md(sel_res)", (ast.Assign,)), ("machine_md + \"\\n\" + ", (ast.If,)),
                              ("combined_md = machine_md", (ast.Assign,))):
            exec(compile(ast.get_source_segment(src, smallest(needle, kinds)), "app.py::dossier", "exec"), ns)
        self.assertIn("## 9. Evidence register (scanner)", ns["machine_md"])
        self.assertIn("## 9. Evidence register (scanner)", ns["combined_md"])
        # The AI section's own prose is still free text and cites no IDs inline, but the same genuine, non-invented
        # scanner evidence register is now appended to it too (single-email and combined), so it is no longer bare.
        self.assertIn("## Evidence References (scanner register for this email)", ns["ai_md"])
        self.assertTrue(ns["combined_md"].endswith(ns["ai_md"]))
        self.assertIn("scan_evidence_md(result)", src[src.index("def _classification"):][:9000])


class PanelEvidence(unittest.TestCase):
    """investigation_panel imports Streamlit at module level, so it is imported against a stub and driven through a recorder."""

    def setUp(self):
        install_offline(self)
        stub = mock.MagicMock()
        patcher = mock.patch.dict(sys.modules, {"streamlit": stub})
        patcher.start()
        self.addCleanup(patcher.stop)
        sys.modules.pop("investigation_panel", None)
        import investigation_panel as ip
        self.addCleanup(lambda: sys.modules.pop("investigation_panel", None))
        self.out, self.warn = [], []
        ip.st = types.SimpleNamespace(markdown=lambda html, **k: self.out.append(html), warning=lambda m, **k: self.warn.append(m),
                                      caption=lambda m, **k: self.warn.append(m), session_state={})
        self.ip = ip
        self.r = make_result()
        self.r["scan_id"] = ia.scan_id_for(b"scan-a")
        with mock.patch("tor_check.tor_exit_sources", return_value=[]), mock.patch("tracker.lookup_indicator", return_value=None):
            self.inv = ia.investigate(self.r, use_ai=False)

    def test_findings_show_ids_origin_and_verification_and_ai_is_separate(self):
        inv = dict(self.inv, narrative_findings=[{"statement": "AI says so", "evidence_ids": ["E1"], "kind": "uncertain", "supported": False,
                                                  "finding_id": "AF1", "verification": "unverified", "origin": "ai"}])
        self.ip._findings(inv)
        html = "".join(self.out)
        f = inv["findings"][0]
        self.assertIn(f["evidence_ids"][0], html)
        self.assertIn(f["finding_id"], html)
        self.assertIn("tool_output", html)
        self.assertIn(ia.ORIGIN_LABEL["untrusted_claim"][:20], html)
        self.assertIn("AI-proposed (secondary)", html)
        self.assertIn("unverified AI claim", html)
        self.assertLess(html.index(f["statement"][:30]), html.index("AI-proposed (secondary)"))

    def test_register_lists_every_evidence_with_provenance_and_status(self):
        self.ip._register(self.inv)
        html = "".join(self.out)
        for e in self.inv["evidence"]:
            self.assertIn(">%s<" % e["id"], html)
            self.assertIn(e["source"].replace("&", "&amp;"), html.replace("&#x27;", "'"))
        self.assertIn(self.inv["scan_id"], html)
        self.assertIn("approximate", html.lower())

    def test_a_stale_investigation_from_another_scan_is_discarded(self):
        other = dict(self.r, scan_id=ia.scan_id_for(b"scan-b"))
        self.ip.st.session_state["agent_investigations"] = {"k": self.inv}
        self.ip.st.session_state["agent_reports"] = {"k": "OLD REPORT"}
        with mock.patch.object(self.ip, "_controls", return_value=(False, False, 6, 6, 60, False)):
            self.ip.render_investigation_panel(other, b"raw", [], None, "k")
        self.assertNotIn("k", self.ip.st.session_state["agent_investigations"])
        self.assertNotIn("k", self.ip.st.session_state["agent_reports"])
        self.assertTrue(any("different scan" in w for w in self.warn))
        self.assertEqual(self.out, [])


class Regression(ScanBase):
    def test_scores_and_verdicts_are_identical_to_the_pre_phase1_golden_values(self):
        # Captured by running the code as it was BEFORE Phase 1 (same fixed ML, same offline fixtures, same builder);
        # the current code produces the identical values.
        for body, want in ((INVOICE, ("Low", 10.7, False)),
                           ("I have your private documents on file. Please wire $3,000 within 7 days to renew the contract.", ("Low", 10.7, False)),
                           ("I have your private photos. Pay three thousand dollars or I will send them to all your contacts.", ("High", 30.7, True)),
                           ("I have your private videos. If you do not pay me, I will send them to your contacts.", ("Medium", 20.7, False))):
            with self.subTest(body=body[:30]):
                res = self.scan(body)
                self.assertEqual((res["level"], round(res["score"], 1), res["verdict"]["override_applied"]), want)
                self.assertAlmostEqual(res["ml"]["prob"], 0.10)

    def test_sample_emails_keep_their_pre_phase1_scores(self):
        import os
        import config as C
        golden = {"legit_newsletter.eml": ("Low", 4.4, False), "phishing_bec.eml": ("Low", 25.2, False),
                  "phishing_credential.eml": ("Medium", 35.4, False), "sextortion_private_photo.eml": ("High", 43.2, True)}
        for name, want in golden.items():
            with self.subTest(sample=name):
                path = os.path.join(C.SAMPLE_DIR, name)
                if not os.path.isfile(path):
                    self.skipTest("fixture samples/%s is absent from this checkout" % name)
                with open(path, "rb") as fh:
                    res = analyzer.analyze_email(fh.read(), name)
                self.assertEqual((res["level"], round(res["score"], 1), res["verdict"]["override_applied"]), want)
                self.assertEqual(ia.validate_scan_register(res), [])

    def test_every_pre_existing_field_is_identical_with_and_without_the_evidence_builder(self):
        for body in (INVOICE, SEXT):
            with self.subTest(body=body[:20]):
                with_ev = self.scan(body)
                with mock.patch.object(ia, "build_scan_evidence", side_effect=RuntimeError("boom")):
                    without = self.scan(body)
                self.assertEqual({k: v for k, v in with_ev.items() if k not in NEW_KEYS}, {k: v for k, v in without.items() if k not in NEW_KEYS})
                self.assertEqual(without["evidence_register"], [])
                self.assertEqual(without["evidence_error"], "RuntimeError")      # a builder fault never breaks or alters the scan
                self.assertNotIn("evidence_error", with_ev)

    def test_backward_compatible_result_structure(self):
        res = self.scan(SEXT)
        for k in ("name", "parsed", "ml", "headers", "extortion", "iocs", "geo", "origin_intel", "recorded_indicators", "score", "level",
                  "color", "verdict"):
            self.assertIn(k, res)
        self.assertTrue(NEW_KEYS - {"evidence_error"} <= set(res))
        self.assertTrue(ED.validate_result(res["extortion"])[0])

    def test_the_new_tests_stay_offline(self):
        self.scan(INVOICE)
        self.scan(SEXT)
        self.assertEqual(self.unexpected, [])


class EvidenceHelpers:
    """Builders shared by the evidence-status test classes."""

    def build(self, drop=(), **over):
        r = make_result()
        r["scan_id"] = SID
        for k in drop:
            r.pop(k, None)
        r.update(over)
        r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
        return r

    @staticmethod
    def items(res, typ, ref=None, source=None):
        return [e for e in res["evidence_register"] if e["type"] == typ and (ref is None or e["source_reference"] == ref)
                and (source is None or e["source"] == source)]

    @staticmethod
    def uncertain(res, e):
        return any(f["kind"] == "uncertain" and e["id"] in f["evidence_ids"] for f in res["scan_findings"])

    def check_gap(self, res, e, status):
        self.assertEqual(e["status"], status, e["observation"])
        self.assertTrue(self.uncertain(res, e), "no uncertain finding for %s" % e["id"])
        self.assertEqual(ia.validate_scan_register(res), [])


class MissingFailedEvidence(EvidenceHelpers, ScanBase):
    """Unavailable / skipped / failed / missing / completed checks are distinguished; a bad or absent output is never recorded
    as a successful (zero-result) check. Deterministic: results are built directly, no model, network or database."""

    def test_status_vocabulary_distinguishes_the_check_outcomes(self):
        self.assertTrue({"ok", "partial", "missing", "unavailable", "skipped", "failed"} <= set(ia.EVIDENCE_STATUSES))
        good = self.build()
        first = next(f for f in good["scan_findings"] if f["kind"] == "suspicious")
        for status in ("missing", "failed", "skipped", "unavailable", "error"):     # a suspicious finding can rest on none of these
            r = copy.deepcopy(good)
            for e in r["evidence_register"]:
                if e["id"] == first["evidence_ids"][0]:
                    e["status"] = status
            self.assertTrue(any("suspicious finding" in p for p in ia.validate_scan_register(r)), status)

    def test_geo_absent_malformed_or_without_origin_is_a_gap_not_a_result(self):
        for label, kw, status in (("absent", dict(drop=("geo",)), "missing"), ("string", dict(geo="g"), "failed"), ("list", dict(geo=[]), "failed"),
                                  ("int", dict(geo=5), "failed"), ("None", dict(geo=None), "failed"),
                                  ("origin string", dict(geo={"origin": "x"}), "failed"), ("origin int", dict(geo={"origin": 5}), "failed"),
                                  ("origin list", dict(geo={"origin": []}), "failed"), ("origin empty", dict(geo={"origin": {}}), "missing"),
                                  ("origin None", dict(geo={"origin": None}), "missing"), ("no ip", dict(geo={"origin": {"country": "X"}}), "missing")):
            with self.subTest(case=label):
                res = self.build(**kw)
                geo = self.items(res, "GeoIP")
                self.assertEqual(len(geo), 1)
                self.check_gap(res, geo[0], status)
                self.assertNotEqual(geo[0]["origin"], "direct_machine")
        ok = self.items(self.build(), "GeoIP")[0]
        self.assertIn(ok["status"], ("ok", "partial"))

    def test_ioc_output_absent_or_malformed_is_never_recorded_as_zero_indicators(self):
        base = make_result()["iocs"]
        cases = [("iocs absent", dict(drop=("iocs",)), "missing"), ("iocs string", dict(iocs="x"), "failed"), ("iocs list", dict(iocs=[]), "failed"),
                 ("iocs None", dict(iocs=None), "failed"), ("iocs int", dict(iocs=7), "failed"),
                 ("urls absent", dict(iocs={k: v for k, v in base.items() if k != "urls"}), "missing"),
                 ("urls None", dict(iocs=dict(base, urls=None)), "failed"), ("urls string", dict(iocs=dict(base, urls="x")), "failed"),
                 ("urls dict", dict(iocs=dict(base, urls={})), "failed"), ("urls int", dict(iocs=dict(base, urls=3)), "failed")]
        for label, kw, status in cases:
            with self.subTest(case=label):
                res = self.build(**kw)
                url = self.items(res, "URL", "result.iocs") + self.items(res, "URL", "result.iocs.urls")
                self.assertEqual(len(url), 1)
                self.check_gap(res, url[0], status)
                self.assertFalse(any("0 URL(s) extracted" in e["observation"] for e in res["evidence_register"]))
        for label, kw, status in (("domains absent", dict(iocs={k: v for k, v in base.items() if k != "domains"}), "missing"),
                                  ("ips absent", dict(iocs={k: v for k, v in base.items() if k != "ips"}), "missing"),
                                  ("domains None", dict(iocs=dict(base, domains=None)), "failed"), ("ips string", dict(iocs=dict(base, ips="x")), "failed")):
            with self.subTest(case=label):
                res = self.build(**kw)
                dom = self.items(res, "domain")
                self.assertEqual(len(dom), 1)
                self.check_gap(res, dom[0], status)
        res = self.build(iocs=dict(base, urls=[{"host": "a.example", "suspicious": False}, "junk", 5, None]))      # partly malformed -> partial
        url = self.items(res, "URL", "result.iocs.urls")[0]
        self.check_gap(res, url, "partial")
        self.assertEqual(url["metadata"]["malformed_entries"], 3)

    def test_a_genuinely_empty_extraction_is_a_completed_check(self):
        res = self.build(iocs={"urls": [], "domains": [], "ips": []})
        for e in self.items(res, "URL", "result.iocs.urls") + self.items(res, "domain"):
            self.assertEqual(e["status"], "ok")
            self.assertFalse(self.uncertain(res, e))
        self.assertIn("0 URL(s) extracted", self.items(res, "URL", "result.iocs.urls")[0]["observation"])

    def test_origin_intel_states_unavailable_failed_skipped_missing_and_malformed(self):
        for label, kw, status in (
                ("key absent", dict(drop=("origin_intel", "origin_intel_status")), "missing"),
                ("None, cause not recorded", dict(origin_intel=None, origin_intel_status=None), "missing"),
                ("None, module unavailable", dict(origin_intel=None, origin_intel_status={"state": "unavailable", "error": ""}), "unavailable"),
                ("None, assessment failed", dict(origin_intel=None, origin_intel_status={"state": "failed", "error": "ValueError"}), "failed"),
                ("None, skipped", dict(origin_intel=None, origin_intel_status={"state": "skipped", "error": ""}), "skipped"),
                ("None, junk state", dict(origin_intel=None, origin_intel_status={"state": 5}), "missing"),
                ("string", dict(origin_intel="x"), "failed"), ("int", dict(origin_intel=5), "failed"), ("list", dict(origin_intel=[]), "failed"),
                ("no candidate ip", dict(origin_intel={"selected_ip": None, "band": "None", "confidence": 0, "flags": []}), "missing")):
            with self.subTest(case=label):
                res = self.build(**kw)
                oi = self.items(res, "infrastructure", source="origin_intel")
                self.assertEqual(len(oi), 1)
                self.check_gap(res, oi[0], status)
        failed = self.items(self.build(origin_intel=None, origin_intel_status={"state": "failed", "error": "ValueError"}), "infrastructure")[0]
        self.assertIn("ValueError", failed["observation"])
        good = self.build(origin_intel={"selected_ip": "198.51.100.7", "band": "Medium", "confidence": 61, "flags": [], "location_disclaimer": "approximate"})
        e = self.items(good, "infrastructure", source="origin_intel")[0]
        self.assertEqual(e["status"], "ok")
        self.assertFalse(self.uncertain(good, e))

    def test_analyzer_records_why_origin_intel_is_absent_and_scoring_is_unaffected(self):
        import origin_intel
        ok = self.scan(SEXT)
        with mock.patch.object(analyzer, "origin_intel", None):
            unavailable = self.scan(SEXT)
        with mock.patch.object(origin_intel, "assess_origin", side_effect=RuntimeError("boom")):
            failed = self.scan(SEXT)
        self.assertEqual(ok["origin_intel_status"], {"state": "ok", "error": ""})
        self.assertEqual((unavailable["origin_intel"], unavailable["origin_intel_status"]), (None, {"state": "unavailable", "error": ""}))
        self.assertEqual((failed["origin_intel"], failed["origin_intel_status"]), (None, {"state": "failed", "error": "RuntimeError"}))
        for res, status in ((unavailable, "unavailable"), (failed, "failed")):
            e = next(e for e in res["evidence_register"] if e["source"] == "origin_intel")
            self.assertEqual(e["status"], status)
            self.assertTrue(any(f["kind"] == "uncertain" and e["id"] in f["evidence_ids"] for f in res["scan_findings"]))
            self.assertEqual(ia.validate_scan_register(res), [])
        same = lambda r: (r["level"], round(r["score"], 9), r["verdict"]["override_applied"], r["ml"], r["verdict"]["signals"])
        self.assertEqual(same(ok), same(unavailable))                 # the origin assessment never affects the score or verdict
        self.assertEqual(same(ok), same(failed))

    def test_community_intelligence_off_by_default_is_not_a_failure(self):
        import community_intel
        with mock.patch.object(community_intel, "enabled", return_value=False):
            res = self.scan(SEXT)
        self.assertNotIn("community_intel", res)
        self.assertFalse([e for e in res["evidence_register"] if e["source"] == "community_intel"])
        self.assertFalse([f for f in res["scan_findings"] if "ommunity" in f["statement"]])
        self.assertFalse([e for e in res["evidence_register"] if e["status"] == "failed" and "ommunity" in e["observation"]])
        self.assertEqual(ia.validate_scan_register(res), [])

    def test_community_intelligence_states_when_enabled(self):
        ok = {"enabled": True, "status": "ok", "matches": [{"indicator": "a.example", "type": "domain", "match": "exact", "verdict": "reported",
                                                           "confidence": 40, "found_in": ["from"], "source": "community"}], "checked": 3, "feed_size": 9}
        res = self.build(community_intel=ok)
        top = self.items(res, "threat intelligence", source="community_intel")
        self.assertEqual([e["status"] for e in top], ["ok", "ok"])
        self.assertTrue(all(e["origin"] == "historical" for e in top))
        self.assertFalse([f for f in res["scan_findings"] if f["kind"] == "suspicious" and top[1]["id"] in f["evidence_ids"]])   # sightings are not proof
        for label, ci, status in (("unavailable", {"enabled": True, "status": "unavailable", "matches": [], "checked": 0}, "unavailable"),
                                  ("error", {"enabled": True, "status": "error", "matches": []}, "failed"),
                                  ("failed", {"enabled": True, "status": "failed", "matches": []}, "failed"),
                                  ("no status", {"enabled": True, "matches": []}, "missing"),
                                  ("string", "x", "failed"), ("int", 5, "failed"), ("list", [], "failed"), ("None", None, "failed")):
            with self.subTest(case=label):
                r = self.build(community_intel=ci)
                e = self.items(r, "threat intelligence", source="community_intel")
                self.assertEqual(len(e), 1)
                self.check_gap(r, e[0], status)
        res = self.build(community_intel={"enabled": False, "status": "unavailable", "matches": []})       # disabled: skipped, never a failure
        e = self.items(res, "threat intelligence", source="community_intel")
        self.assertEqual([x["status"] for x in e], ["skipped"])
        self.assertFalse(self.uncertain(res, e[0]))
        self.assertEqual(ia.validate_scan_register(res), [])


class ValidatorHardening(ScanBase):
    """validate_scan_register() type-checks before any dict/set membership test and never raises; reports stay renderable."""

    BAD_REFS = [["S1"], {"id": "S1"}, 5, None, "None", "S1; DROP TABLE", "s1", "S", "S1 ", "S" + "9" * 50, [["S1"]], True, b"S1", 1.5, "",
                ("S1",), "SC-" + "a" * 32 + "/S1"]
    BAD_SCAN_IDS = [["x"], {"a": 1}, 5, None, "None", "SC-short", "SC-" + "A" * 32, "sc-" + "a" * 32, "SC-" + "a" * 31, "SC-" + "g" * 32,
                    " SC-" + "a" * 32, True]

    def good(self):
        r = self.synthetic()
        r["scan_id"] = SID
        r["evidence_register"], r["scan_findings"] = ia.build_scan_evidence(r)
        return r

    def assert_safe(self, res, expect_problem=True):
        problems = ia.validate_scan_register(res)                      # must not raise
        self.assertIsInstance(problems, list)
        self.assertTrue(all(isinstance(p, str) for p in problems))
        if expect_problem:
            self.assertTrue(problems)
        lines = report.scan_evidence_md(res)                           # must not raise, must stay renderable
        self.assertTrue(isinstance(lines, list) and all(isinstance(x, str) for x in lines))
        md = report.build_report(res, b"raw")
        self.assertIsInstance(md, str)
        if expect_problem:
            self.assertIn("Evidence register failed validation", md)
        self.assertIn("## 1.", md)                                     # the rest of the report is intact
        return problems

    def test_a_valid_register_passes(self):
        res = self.good()
        self.assertEqual(self.assert_safe(res, expect_problem=False), [])
        self.assertEqual(ia.validate_scan_register({"evidence_register": [], "scan_findings": [], "scan_id": ""}), [])   # unidentified but valid
        self.assertEqual(ia.validate_scan_register({}), [])                                                                 # legacy

    def test_malformed_evidence_references_in_findings(self):
        for ref in self.BAD_REFS:
            for shape in ("only", "mixed"):
                with self.subTest(ref=repr(ref)[:30], shape=shape):
                    r = self.good()
                    r["scan_findings"][0]["evidence_ids"] = [ref] if shape == "only" else [r["scan_findings"][0]["evidence_ids"][0], ref]
                    problems = self.assert_safe(r)
                    self.assertTrue(any("evidence reference" in p or "unknown evidence" in p or "malformed finding" in p for p in problems), problems)

    def test_malformed_evidence_item_ids(self):
        for bad in self.BAD_REFS:
            with self.subTest(id=repr(bad)[:30]):
                r = self.good()
                r["evidence_register"][0]["id"] = bad
                self.assertTrue(any("malformed id" in p or "unknown evidence" in p or "duplicate" in p for p in self.assert_safe(r)))

    def test_duplicate_ids(self):
        r = self.good()
        r["evidence_register"].append(dict(r["evidence_register"][0]))
        self.assertTrue(any("duplicate evidence id" in p for p in self.assert_safe(r)))
        r = self.good()
        r["scan_findings"].append(dict(r["scan_findings"][0]))
        self.assertTrue(any("duplicate finding id" in p for p in self.assert_safe(r)))

    def test_malformed_and_foreign_scan_ids(self):
        for bad in self.BAD_SCAN_IDS:
            for where in ("result", "evidence", "finding"):
                with self.subTest(scan_id=repr(bad)[:30], where=where):
                    r = self.good()
                    target = {"result": r, "evidence": r["evidence_register"][0], "finding": r["scan_findings"][0]}[where]
                    target["scan_id"] = bad
                    self.assertTrue(any("malformed scan_id" in p or "scan_id" in p for p in self.assert_safe(r)))
        for where in ("evidence", "finding"):
            with self.subTest(foreign=where):
                r = self.good()
                (r["evidence_register"][0] if where == "evidence" else r["scan_findings"][0]).update(scan_id=FOREIGN)
                self.assertTrue(any("belongs to" in p or "different scan" in p for p in self.assert_safe(r)))
        r = self.good()                                                  # a finding citing another scan's qualified reference
        r["scan_findings"][0]["evidence_ids"] = ["%s/S1" % FOREIGN]
        self.assertTrue(any("malformed evidence reference" in p for p in self.assert_safe(r)))

    def test_malformed_structure(self):
        for label, mutate in (
                ("register not a list", lambda r: r.update(evidence_register="x")), ("register dict", lambda r: r.update(evidence_register={})),
                ("findings not a list", lambda r: r.update(scan_findings=None)), ("item int", lambda r: r["evidence_register"].append(5)),
                ("item None", lambda r: r["evidence_register"].append(None)), ("item list", lambda r: r["evidence_register"].append([])),
                ("item missing fields", lambda r: r["evidence_register"].append({"id": "S99"})),
                ("finding int", lambda r: r["scan_findings"].append(5)), ("finding None", lambda r: r["scan_findings"].append(None)),
                ("finding id list", lambda r: r["scan_findings"][0].update(id=["SF1"])), ("finding id bad", lambda r: r["scan_findings"][0].update(id="F1")),
                ("kind list", lambda r: r["scan_findings"][0].update(kind=["suspicious"])), ("kind int", lambda r: r["scan_findings"][0].update(kind=3)),
                ("ids not list", lambda r: r["scan_findings"][0].update(evidence_ids="S1")), ("ids empty", lambda r: r["scan_findings"][0].update(evidence_ids=[])),
                ("origin list", lambda r: r["evidence_register"][0].update(origin=["direct_machine"])),
                ("status dict", lambda r: r["evidence_register"][0].update(status={})),
                ("observation list", lambda r: r["evidence_register"][0].update(observation=["x"]))):
            with self.subTest(case=label):
                r = self.good()
                mutate(r)
                self.assert_safe(r, expect_problem=label != "observation list") if label != "observation list" else self.assert_safe(r, False)

    def test_tables_render_only_well_formed_parts(self):
        r = self.good()
        r["evidence_register"] += [5, None, [], {"id": ["S1"]}]
        r["scan_findings"] += [None, {"id": "SF99", "evidence_ids": [["S1"], 5, None], "statement": "x", "kind": "uncertain"}]
        md = "\n".join(report.scan_evidence_md(r))
        self.assertIn("Evidence register failed validation", md)
        self.assertIn("| S1 |", md)

    def test_an_unexpected_failure_inside_the_validator_or_renderer_is_contained(self):
        r = self.good()
        with mock.patch.object(ia, "_validate_scan_register", side_effect=RuntimeError("boom")):
            self.assertEqual(ia.validate_scan_register(r), ["the register could not be validated (RuntimeError)"])
        with mock.patch.object(ia, "evidence_table_md", side_effect=RuntimeError("boom")):
            md = "\n".join(report.scan_evidence_md(r))
            self.assertIn("Evidence register could not be rendered", md)
            self.assertIn("(RuntimeError)", md)
            self.assertIsInstance(report.build_report(r, b"raw"), str)


class ScanIdLength(ScanBase):
    def test_scan_id_has_at_least_128_bits_and_is_deterministic(self):
        import hashlib
        raw = b"identical message bytes"
        a = ia.scan_id_for(raw)
        self.assertRegex(a, r"^SC-[0-9a-f]{32}$")
        self.assertGreaterEqual(4 * len(a[3:]), 128)
        self.assertEqual(a, ia.scan_id_for(bytearray(raw)))
        self.assertEqual(a, ia.scan_id_for(raw.decode()))
        self.assertEqual(a[3:], hashlib.sha256(raw).hexdigest()[:32])
        self.assertNotEqual(a, ia.scan_id_for(raw + b"."))
        self.assertTrue(ia.SCAN_ID_RE.match(a))
        self.assertEqual((ia.scan_id_for(b""), ia.scan_id_for(None)), ("", ""))

    def test_a_real_scan_uses_the_long_id_everywhere(self):
        res = self.scan()
        self.assertRegex(res["scan_id"], r"^SC-[0-9a-f]{32}$")
        self.assertTrue(all(e["scan_id"] == res["scan_id"] for e in res["evidence_register"]))
        self.assertIn(res["scan_id"], "\n".join(report.scan_evidence_md(res)))


class IntelligencePayloadValidation(EvidenceHelpers, ScanBase):
    """community_intel / origin_intel payloads are validated field by field BEFORE anything becomes evidence. Offline."""

    GOOD = {"indicator": "a.example", "type": "domain", "match": "exact", "verdict": "phishing", "confidence": 70, "found_in": ["from"],
            "source": "community"}

    def community(self, ci):
        res = self.build(community_intel=ci)
        return res, self.items(res, "threat intelligence", source="community_intel")

    def assert_community_gap(self, ci, status, matches=0):
        res, e = self.community(ci)
        self.assertEqual(e[0]["status"], status, e[0]["observation"])
        self.assertEqual(len(e), 1 + matches)
        self.assertNotEqual(e[0]["status"], "ok")
        self.assertTrue(self.uncertain(res, e[0]))
        self.assertEqual(ia.validate_scan_register(res), [])
        return res, e

    # ---- community intelligence -------------------------------------------------------------------------------------------
    def test_valid_community_results_stay_successful_and_contextual(self):
        res, e = self.community({"enabled": True, "status": "ok", "matches": [self.GOOD], "checked": 3, "feed_size": 9})
        self.assertEqual([x["status"] for x in e], ["ok", "ok"])
        self.assertTrue(all(x["origin"] == "historical" for x in e))
        self.assertIn("contextual, not confirmed malicious", e[0]["observation"])
        self.assertFalse(self.uncertain(res, e[0]))
        bad_verdict = dict(self.GOOD, verdict="confirmed malicious")                  # a feed verdict is still only a historical report
        res, e = self.community({"enabled": True, "status": "ok", "matches": [bad_verdict], "checked": 1, "feed_size": 1})
        self.assertFalse([f for f in res["scan_findings"] if f["kind"] in ("suspicious", "verified") and any(x["id"] in f["evidence_ids"] for x in e)])
        res, e = self.community({"enabled": True, "status": "ok", "matches": [], "checked": 0, "feed_size": 0})   # a legitimate empty result
        self.assertEqual([x["status"] for x in e], ["ok"])
        self.assertIn("0 community report(s)", e[0]["observation"])
        self.assertFalse(self.uncertain(res, e[0]))
        res, e = self.community({"enabled": True, "status": "ok", "matches": []})                        # checked/feed_size are optional
        self.assertEqual([x["status"] for x in e], ["ok"])

    def test_unavailable_is_not_a_successful_empty_result(self):
        for ci in ({"enabled": True, "status": "unavailable", "matches": [], "checked": 0, "feed_size": 0}, {"status": "unavailable", "matches": []}):
            self.assert_community_gap(ci, "unavailable")
        self.assert_community_gap({"enabled": True, "status": "unavailable", "matches": [self.GOOD]}, "failed")      # contradictory output
        self.assert_community_gap({"enabled": True, "status": "unavailable", "matches": "x"}, "failed")

    def test_unknown_status_values_never_default_to_ok(self):
        for status in ("OK", "Ok", "okay", "pending", "error", "failed", "unknown", "", " ok", "ok ", None, 5, True, ["ok"], {"s": "ok"}):
            with self.subTest(status=repr(status)):
                self.assert_community_gap({"enabled": True, "status": status, "matches": []}, "failed")
        self.assert_community_gap({"enabled": True, "matches": []}, "missing")                                    # no status at all
        self.assert_community_gap({"enabled": True, "status": "pending", "matches": [self.GOOD]}, "failed")      # valid matches do not rescue it

    def test_a_non_list_matches_value_is_failed(self):
        for matches in ("x", "[]", {}, {"a": 1}, None, 5, 1.5, True, ("a",)):
            with self.subTest(matches=repr(matches)):
                self.assert_community_gap({"enabled": True, "status": "ok", "matches": matches}, "failed")
        self.assert_community_gap({"enabled": True, "status": "ok"}, "failed")                                      # matches absent

    INVALID_ENTRIES = [None, "x", 5, [], {}, {"indicator": "a.example"}, dict(GOOD, type="mail"), dict(GOOD, type=None), dict(GOOD, confidence="high"),
                       dict(GOOD, confidence=True), dict(GOOD, confidence=float("nan")), dict(GOOD, confidence=-1), dict(GOOD, confidence=None),
                       dict(GOOD, indicator=""), dict(GOOD, indicator=5), dict(GOOD, match=None), dict(GOOD, verdict=None), dict(GOOD, verdict=["x"]),
                       dict(GOOD, found_in="x"), dict(GOOD, found_in=[1])]

    def test_invalid_entries_are_never_silently_dropped_behind_an_ok_status(self):
        for bad in self.INVALID_ENTRIES:
            with self.subTest(entry=repr(bad)[:60]):
                res, e = self.assert_community_gap({"enabled": True, "status": "ok", "matches": [self.GOOD, bad], "checked": 2, "feed_size": 5}, "partial", matches=1)
                self.assertIn("1 malformed match entry out of 2", e[0]["observation"])
                self.assertIn("a.example", e[1]["observation"])                                                    # the valid report is kept
                self.assert_community_gap({"enabled": True, "status": "ok", "matches": [bad], "checked": 1, "feed_size": 5}, "failed", matches=0)
        res, e = self.assert_community_gap({"enabled": True, "status": "ok", "matches": [self.GOOD, None, "x", 5]}, "partial", matches=1)
        self.assertIn("3 malformed match entries out of 4", e[0]["observation"])

    def test_incorrect_enabled_checked_and_feed_size_types(self):
        base = {"enabled": True, "status": "ok", "matches": [self.GOOD], "checked": 1, "feed_size": 1}
        for field, values in (("enabled", ("yes", "true", 1, 0, None, [], {})),
                              ("checked", (-1, "3", 1.5, True, None, [], {}, float("nan"))),
                              ("feed_size", (-1, "3", 1.5, False, None, [], {}))):
            for v in values:
                with self.subTest(field=field, value=repr(v)):
                    res, e = self.assert_community_gap(dict(base, **{field: v}), "failed", matches=0)   # no reports are recorded from a corrupt envelope
                    self.assertIn(field, e[0]["observation"])
        for k in ("checked", "feed_size"):
            self.assertEqual(self.community(dict(base, **{k: 0}))[1][0]["status"], "ok")             # zero is a valid count

    def test_disabled_community_intelligence_is_skipped_or_absent_never_failed(self):
        res, e = self.community({"enabled": False, "status": "unavailable", "matches": [], "checked": 0, "feed_size": 0})
        self.assertEqual([x["status"] for x in e], ["skipped"])
        self.assertFalse(self.uncertain(res, e[0]))
        res = self.build()
        self.assertFalse(self.items(res, "threat intelligence", source="community_intel"))       # key absent == OFF by default
        self.assertFalse([f for f in res["scan_findings"] if "ommunity" in f["statement"]])

    def test_real_community_lookup_output_satisfies_the_contract(self):
        rows = [{"type": "domain", "indicator": "evil-example.com", "verdict": "phishing", "confidence": 80}]
        body = "Please verify at http://evil-example.com/login today."
        with mock.patch.object(community_intel, "enabled", return_value=True), mock.patch.object(community_intel, "_feed", return_value=rows):
            res = self.scan(body)
        ci = res["community_intel"]
        self.assertEqual((ci["status"], len(ci["matches"])), ("ok", 1))
        e = [x for x in res["evidence_register"] if x["source"] == "community_intel"]
        self.assertEqual([x["status"] for x in e], ["ok", "ok"])
        self.assertEqual(ia.validate_scan_register(res), [])
        with mock.patch.object(community_intel, "enabled", return_value=True), mock.patch.object(community_intel, "_feed", return_value=None):
            down = self.scan(body)
        e = [x for x in down["evidence_register"] if x["source"] == "community_intel"]
        self.assertEqual([x["status"] for x in e], ["unavailable"])

    # ---- origin intelligence ----------------------------------------------------------------------------------------------
    VALID_OI = {"selected_ip": "198.51.100.7", "band": "Medium", "confidence": 61, "flags": [], "location_disclaimer": "approximate"}

    def origin(self, **over):
        oi = dict(self.VALID_OI)
        oi.update(over)
        res = self.build(origin_intel=oi)
        return res, self.items(res, "infrastructure", source="origin_intel")

    def suspicious_from(self, res, e):
        return [f for f in res["scan_findings"] if f["kind"] == "suspicious" and any(x["id"] in f["evidence_ids"] for x in e)]

    def test_valid_origin_assessments(self):
        for band, conf in (("High", 90), ("Medium", 61.5), ("Low", 0), ("Low", 100)):
            res, e = self.origin(band=band, confidence=conf)
            self.assertEqual((len(e), e[0]["status"]), (1, "ok"))
            self.assertFalse(self.uncertain(res, e[0]))
        for ip in ("203.0.113.9", "2001:db8::1", "8.8.8.8"):
            self.assertEqual(self.origin(selected_ip=ip)[1][0]["status"], "ok")
        flags = [{"severity": "low", "code": "x", "title": "minor", "evidence": "e", "hops": []},
                 {"severity": "medium", "code": "y", "title": "notable", "evidence": "e", "hops": [1, 2]},
                 {"severity": "high", "title": "serious"}]
        res, e = self.origin(flags=flags)
        self.assertEqual(e[0]["status"], "ok")
        self.assertEqual(sorted(f["severity"] for f in self.suspicious_from(res, e)), ["high", "medium"])     # a low flag is not a finding

    def test_a_valid_assessment_with_no_candidate_ip_is_missing_not_malformed(self):
        for sel in (None, "None"):
            res, e = self.origin(selected_ip=sel, band="None", confidence=0, flags=[])
            self.assertEqual(len(e), 1)
            self.check_gap(res, e[0], "missing")
            self.assertNotIn("malformed", e[0]["observation"])
            self.assertNotIn("malformed_fields", e[0]["metadata"])
            self.assertFalse(self.suspicious_from(res, e))

    def test_malformed_origin_fields_are_failed_and_never_suspicious(self):
        high_flag = [{"severity": "high", "code": "c", "title": "looks serious", "evidence": "e", "hops": []}]
        cases = {
            "selected_ip": ["999.1.1.1", "not-an-ip", "", " ", 5, ["1.1.1.1"], {}, True, "1.1.1", "none", "None "],
            "confidence": [-1, 101, 100.0001, "61", None, True, False, float("nan"), float("inf"), [], {}],
            "band": ["Extreme", "high", "HIGH", "", None, 5, ["High"], {}],
            "flags": [None, "x", {}, 5, [None], ["x"], [5], [{"severity": "high"}], [{"title": "t"}], [{"severity": "critical", "title": "t"}],
                      [{"severity": "high", "title": 5}], [{"severity": "high", "title": " "}], [{"severity": ["high"], "title": "t"}],
                      [{"severity": "high", "title": "t", "code": 5}], [{"severity": "high", "title": "t", "hops": "x"}]],
        }
        for field, values in cases.items():
            for v in values:
                with self.subTest(field=field, value=repr(v)[:50]):
                    over = {field: v}
                    if field != "flags":
                        over["flags"] = high_flag                         # a plausible high flag next to ONE bad field must not become a finding
                    res, e = self.origin(**over)
                    self.assertEqual(len(e), 1)
                    self.check_gap(res, e[0], "failed")
                    self.assertIn(field, e[0]["observation"])
                    self.assertEqual(e[0]["metadata"]["malformed_fields"], [field])
                    self.assertNotIn(repr(v)[:20] if isinstance(v, str) and len(v) > 3 else "\x00", e[0]["observation"])
                    self.assertFalse(self.suspicious_from(res, e))
                    self.assertNotIn("confidence", e[0])

    def test_missing_required_origin_fields_are_failed(self):
        for field in ("selected_ip", "confidence", "band", "flags"):
            with self.subTest(missing=field):
                oi = {k: v for k, v in self.VALID_OI.items() if k != field}
                res = self.build(origin_intel=oi)
                e = self.items(res, "infrastructure", source="origin_intel")
                self.check_gap(res, e[0], "failed")
                self.assertIn(field, e[0]["observation"])
        res = self.build(origin_intel={})
        e = self.items(res, "infrastructure", source="origin_intel")
        self.check_gap(res, e[0], "failed")
        self.assertEqual(e[0]["metadata"]["malformed_fields"], ["selected_ip", "confidence", "band", "flags"])

    def test_several_malformed_fields_are_all_reported(self):
        res, e = self.origin(selected_ip="x", confidence="y", band=5, flags="z")
        self.check_gap(res, e[0], "failed")
        self.assertEqual(e[0]["metadata"]["malformed_fields"], ["selected_ip", "confidence", "band", "flags"])

    def test_real_origin_assessments_satisfy_the_contract(self):
        import os
        import config as C
        raw = ("From: Sender <sender@example.com>\r\nTo: v@example.com\r\nSubject: Hi\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
               "Received: from mail.example.org (mail.example.org [8.8.8.8]) by mx.example.com with ESMTP; Mon, 01 Jan 2024 00:00:00 +0000\r\n"
               "Message-ID: <1@example.com>\r\n\r\nHello").encode()
        scans = {"no ip": analyzer.analyze_email(eml(INVOICE), "t.eml"), "with ip": analyzer.analyze_email(raw, "t.eml")}
        for name in ("legit_newsletter.eml", "phishing_bec.eml", "phishing_credential.eml", "sextortion_private_photo.eml"):
            path = os.path.join(C.SAMPLE_DIR, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    scans[name] = analyzer.analyze_email(fh.read(), name)
        for label, res in scans.items():
            with self.subTest(scan=label):
                self.assertEqual(origin_field_problems_of(res), [])
                e = [x for x in res["evidence_register"] if x["source"] == "origin_intel"]
                self.assertEqual(len(e), 1)
                self.assertNotEqual(e[0]["status"], "failed")                      # real output is never flagged as malformed
                self.assertEqual(e[0]["status"], "ok" if res["origin_intel"]["selected_ip"] else "missing")
                self.assertEqual(ia.validate_scan_register(res), [])


def origin_field_problems_of(res):
    return ia.origin_field_problems(res["origin_intel"]) if isinstance(res.get("origin_intel"), dict) else []


REQUIRED_GUARDS = ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex", "socket.gethostbyaddr", "socket.create_connection",
                   "socket.socket.connect", "socket.socket.connect_ex", "socket.socket.send", "socket.socket.sendall", "socket.socket.sendto",
                   "requests.adapters.HTTPAdapter.send", "subprocess.Popen", "os.system", "os.popen")
_DUMMY = object()          # stands in for a socket: the guards never touch it


class OfflineGuardBehaviour(unittest.TestCase):
    """install_offline() records and blocks network and process attempts. Isolated: every guarded call is preceded by an identity
    check that the function IS the guard (see _require_guards), the 'sockets' are dummy objects, and the targets are reserved
    .test names, so no request, DNS lookup, UDP send or process can run even if the guard were broken."""

    ATTEMPTS = {
        "socket.getaddrinfo": lambda: socket.getaddrinfo("guard.test", 80),
        "socket.gethostbyname": lambda: socket.gethostbyname("guard.test"),
        "socket.gethostbyname_ex": lambda: socket.gethostbyname_ex("guard.test"),
        "socket.gethostbyaddr": lambda: socket.gethostbyaddr("192.0.2.1"),
        "socket.create_connection": lambda: socket.create_connection(("guard.test", 80), timeout=1),
        "socket.socket.connect": lambda: socket.socket.connect(_DUMMY, ("guard.test", 80)),
        "socket.socket.connect_ex": lambda: socket.socket.connect_ex(_DUMMY, ("guard.test", 80)),
        "socket.socket.send": lambda: socket.socket.send(_DUMMY, b"payload"),
        "socket.socket.sendall": lambda: socket.socket.sendall(_DUMMY, b"payload"),
        "socket.socket.sendto": lambda: socket.socket.sendto(_DUMMY, b"payload", ("guard.test", 53)),
        "requests.adapters.HTTPAdapter.send": lambda: requests.adapters.HTTPAdapter().send(requests.Request("GET", "http://guard.test/").prepare()),
        "subprocess.Popen": lambda: subprocess.Popen(["guard-test-command"]),
        "os.system": lambda: os.system("guard-test-command"),
        "os.popen": lambda: os.popen("guard-test-command"),
    }

    def guarded(self):
        """A bare case with the guard installed; its patches are undone (after clearing the deliberate attempts) when this test ends."""
        case = unittest.TestCase()
        install_offline(case)
        self.addCleanup(case.doCleanups)
        self.addCleanup(case.unexpected.clear)                 # runs first (LIFO): these tests make deliberate attempts
        return case

    def assert_all_original(self):
        for name in _ORIGINALS:
            self.assertIs(_resolve(name), _ORIGINALS[name], "%s is still patched" % name)

    def test_the_guard_table_covers_every_required_mechanism(self):
        self.assertTrue(set(REQUIRED_GUARDS) <= set(_ORIGINALS), sorted(set(REQUIRED_GUARDS) - set(_ORIGINALS)))
        self.assertTrue(set(REQUIRED_GUARDS) <= set(self.ATTEMPTS))
        self.assertIn("requests.sessions.Session.request", _ORIGINALS)

    def test_every_mechanism_is_guarded_during_a_test_and_restored_afterwards(self):
        self.assert_all_original()                             # precondition: nothing leaked from an earlier test
        case = unittest.TestCase()
        install_offline(case)
        try:
            _require_guards(case)
            for name in _ORIGINALS:
                self.assertIsNot(_resolve(name), _ORIGINALS[name], name)
        finally:
            case.unexpected.clear()
            case.doCleanups()
        self.assert_all_original()

    def test_every_attempt_is_recorded_before_the_exception_even_if_the_caller_swallows_it(self):
        case = self.guarded()
        _require_guards(self)
        for name, attempt in self.ATTEMPTS.items():
            before = len(case.unexpected)
            try:
                attempt()
            except Exception as exc:                            # the application swallows the exception ...
                raised = exc
            else:
                self.fail("%s was not blocked" % name)
            self.assertEqual(len(case.unexpected), before + 1, name)       # ... but the attempt is already on record
            self.assertTrue(case.unexpected[-1].startswith(name), (name, case.unexpected[-1]))
            self.assertIsInstance(raised, GuardBlocked, name)
            self.assertIn(case.unexpected[-1], str(raised))
        self.assertEqual(len(case.unexpected), len(self.ATTEMPTS))
        for name in ("socket.socket.send", "socket.socket.sendall"):
            self.assertIn(name, case.unexpected)                # a payload is never recorded: the entry is just the mechanism
        self.assertFalse([e for e in case.unexpected if "payload" in e])

    def test_name_resolution_blocks_stay_gaierror_so_offline_handling_is_unchanged(self):
        case = self.guarded()
        _require_guards(self)
        for name in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex", "socket.gethostbyaddr"):
            with self.assertRaises(socket.gaierror):
                self.ATTEMPTS[name]()
        self.assertEqual(len(case.unexpected), 4)

    def test_urllib_and_http_client_attempts_are_caught_by_the_socket_guards(self):
        import http.client
        import urllib.request
        case = self.guarded()
        _require_guards(self)
        calls = {"urllib http": lambda: urllib.request.urlopen("http://guard.test/", timeout=1),
                 "urllib https": lambda: urllib.request.urlopen("https://guard.test/", timeout=1),
                 "http.client http": lambda: http.client.HTTPConnection("guard.test", 80, timeout=1).request("GET", "/"),
                 "http.client https": lambda: http.client.HTTPSConnection("guard.test", 443, timeout=1).request("GET", "/")}
        for label, call in calls.items():
            before = len(case.unexpected)
            with self.assertRaises(OSError):                    # URLError and GuardBlocked are both OSError
                call()
            new = case.unexpected[before:]
            self.assertTrue(new and all(e.startswith("socket.") for e in new), (label, new))
            self.assertTrue(any(e.startswith("socket.create_connection") for e in new), (label, new))

    def test_the_ip_api_fixture_is_served_and_every_other_http_request_is_recorded_and_blocked(self):
        case = self.guarded()
        _require_guards(self)
        r = requests.get("http://ip-api.com/json/192.0.2.1?" + _IPAPI_EXACT_QUERY, timeout=1)
        self.assertEqual((r.status_code, r.json()["status"]), (200, "fail"))
        self.assertEqual((len(case.served), case.unexpected), (1, []))
        for call in (lambda: requests.get("http://guard.test/x", timeout=1), lambda: requests.Session().get("http://guard.test/y", timeout=1),
                     lambda: requests.post("http://guard.test/z", data=b"payload", timeout=1)):
            before = len(case.unexpected)
            with self.assertRaises(requests.ConnectionError):
                call()
            self.assertEqual(len(case.unexpected), before + 1)
        self.assertTrue(all(e.startswith("requests.Session.request http://guard.test/") for e in case.unexpected))
        self.assertEqual(len(case.served), 1)

    def test_strict_ip_api_url_validation_rejects_lookalikes(self):
        case = self.guarded()
        _require_guards(self)

        # valid fixture request (the exact shape geolocate.py's live branch sends)
        r = requests.get("http://ip-api.com/json/203.0.113.9?" + _IPAPI_EXACT_QUERY, timeout=1)
        self.assertEqual((r.status_code, r.json()["status"]), (200, "fail"))
        self.assertEqual(len(case.served), 1)

        bad_urls = [
            "http://evil.example/path/ip-api.com?" + _IPAPI_EXACT_QUERY,     # ip-api.com only in the path, wrong host
            "http://ip-api.com.evil.example/json/1.1.1.1?" + _IPAPI_EXACT_QUERY,  # subdomain trick, wrong host
            "http://not-ip-api.com/json/1.1.1.1?" + _IPAPI_EXACT_QUERY,      # similar-looking host, wrong host
            "https://ip-api.com/json/1.1.1.1?" + _IPAPI_EXACT_QUERY,         # wrong scheme
            "http://user:pass@ip-api.com/json/1.1.1.1?" + _IPAPI_EXACT_QUERY,  # credentials present
            "http://ip-api.com:8080/json/1.1.1.1?" + _IPAPI_EXACT_QUERY,     # non-standard port
            "http://ip-api.com/json/?" + _IPAPI_EXACT_QUERY,                 # missing {ip} segment
            "http://ip-api.com/other/1.1.1.1?" + _IPAPI_EXACT_QUERY,         # wrong path shape
        ]
        for url in bad_urls:
            before = len(case.unexpected)
            with self.subTest(url=url):
                with self.assertRaises(requests.ConnectionError):
                    requests.get(url, timeout=1)
                self.assertEqual(len(case.unexpected), before + 1, url)   # rejection was recorded before raising
                self.assertTrue(case.unexpected[-1].startswith("requests.Session.request"), case.unexpected[-1])
                self.assertIn(url, case.unexpected[-1])
        self.assertEqual(len(case.served), 1)                   # only the one valid request was ever served

    def test_strict_ip_api_url_validation_rejects_bad_method_and_port(self):
        case = self.guarded()
        _require_guards(self)

        for method, kwargs in (("POST", {}), ("PUT", {}), ("DELETE", {})):
            before = len(case.unexpected)
            with self.subTest(method=method):
                with self.assertRaises(requests.ConnectionError):
                    requests.request(method, "http://ip-api.com/json/1.1.1.1?" + _IPAPI_EXACT_QUERY, timeout=1, **kwargs)
                self.assertEqual(len(case.unexpected), before + 1, method)
                self.assertTrue(case.unexpected[-1].startswith("requests.Session.request"), case.unexpected[-1])

        before = len(case.unexpected)
        with self.assertRaises(requests.ConnectionError):
            requests.get("http://ip-api.com:81/json/1.1.1.1?" + _IPAPI_EXACT_QUERY, timeout=1)
        self.assertEqual(len(case.unexpected), before + 1)
        self.assertEqual(len(case.served), 0)

    def test_strict_ip_api_url_validation_rejects_malformed_ports(self):
        case = self.guarded()
        _require_guards(self)

        for url in ("http://ip-api.com:abc/json/1.1.1.1?" + _IPAPI_EXACT_QUERY,
                    "http://ip-api.com:99999/json/1.1.1.1?" + _IPAPI_EXACT_QUERY):
            before = len(case.unexpected)
            with self.subTest(url=url):
                with self.assertRaises(requests.ConnectionError):
                    requests.get(url, timeout=1)
                self.assertEqual(len(case.unexpected), before + 1, url)   # recorded before raising, no crash
                self.assertTrue(case.unexpected[-1].startswith("requests.Session.request"), case.unexpected[-1])
                self.assertIn(url, case.unexpected[-1])
        self.assertEqual(len(case.served), 0)

    def test_strict_ip_api_url_validation_matches_the_exact_geolocate_contract(self):
        """geolocate.py's live branch always sends exactly one shape: GET http://ip-api.com/json/{ip}?<the fixed fields
        query>, no creds, default port, no fragment. Anything that deviates -- even a real IP, even a superset of the
        real query -- must be rejected and recorded, never silently served."""
        case = self.guarded()
        _require_guards(self)

        # the exact real contract: accepted
        r = requests.get("http://ip-api.com/json/198.51.100.7?" + _IPAPI_EXACT_QUERY, timeout=1)
        self.assertEqual((r.status_code, r.json()["status"]), (200, "fail"))
        self.assertEqual(len(case.served), 1)

        # IPv6 is a real address too and must also be accepted under the same exact contract
        r6 = requests.get("http://ip-api.com/json/2001:db8::1?" + _IPAPI_EXACT_QUERY, timeout=1)
        self.assertEqual((r6.status_code, r6.json()["status"]), (200, "fail"))
        self.assertEqual(len(case.served), 2)

        bad = [
            "http://ip-api.com/json/198.51.100.7",                                  # no query at all
            "http://ip-api.com/json/198.51.100.7?" + _IPAPI_EXACT_QUERY + "&extra=1",  # unexpected extra param
            "http://ip-api.com/json/198.51.100.7?fields=status",                     # unexpected/short query value
            "http://ip-api.com/json/198.51.100.7?" + _IPAPI_EXACT_QUERY.replace("status,", ""),  # altered query value
            "http://ip-api.com/json/198.51.100.7?fields=as,org,isp,lon,lat,city,regionName,countryCode,country,status",  # reordered
            "http://ip-api.com/json/198.51.100.7?" + _IPAPI_EXACT_QUERY + "#frag",   # fragment present
            "http://ip-api.com/json/198.51.100.7?" + _IPAPI_EXACT_QUERY + "#",       # empty fragment delimiter
            "http://ip-api.com/json/not-an-ip?" + _IPAPI_EXACT_QUERY,                # invalid IP path segment
            "http://ip-api.com/json/999.999.999.999?" + _IPAPI_EXACT_QUERY,          # out-of-range octets, invalid IP
            "http://ip-api.com/json/1.2.3.4/extra?" + _IPAPI_EXACT_QUERY,            # extra path segment after the IP
            "http://ip-api.com/json/192.0.2.1%00?" + _IPAPI_EXACT_QUERY,             # not a valid IP literal
        ]
        for url in bad:
            before = len(case.unexpected)
            with self.subTest(url=url):
                with self.assertRaises(requests.ConnectionError):
                    requests.get(url, timeout=1)
                self.assertEqual(len(case.unexpected), before + 1, url)   # recorded before raising
                self.assertTrue(case.unexpected[-1].startswith("requests.Session.request"), case.unexpected[-1])
                self.assertIn(url, case.unexpected[-1])
        self.assertEqual(len(case.served), 2)                             # only the two valid requests above were served

    def run_inner(self, body):
        """Run `body` as a real test case that uses install_offline, and return the unittest result."""
        class Inner(unittest.TestCase):
            def setUp(inner):
                install_offline(inner)

            def runTest(inner):
                _require_guards(inner)
                body(inner)
        return unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(Inner())

    def test_a_swallowed_attempt_still_fails_the_test_and_names_the_mechanism(self):
        self.assert_all_original()
        names = ("socket.getaddrinfo", "subprocess.Popen", "requests.adapters.HTTPAdapter.send", "socket.socket.sendto", "os.system")

        def body(inner):
            for n in names:
                try:
                    self.ATTEMPTS[n]()
                except Exception:
                    pass                                        # application code swallows the exception
        result = self.run_inner(body)
        self.assertFalse(result.wasSuccessful())
        text = "".join(tb for _, tb in result.failures + result.errors)
        self.assertIn("unexpected network or process attempt", text)
        for n in names:
            self.assertIn(n, text)
        self.assert_all_original()

    def test_every_patch_is_restored_even_when_the_test_body_fails(self):
        self.assert_all_original()

        def body(inner):
            raise RuntimeError("deliberate failure inside a guarded test")
        result = self.run_inner(body)
        self.assertEqual((len(result.errors), len(result.failures)), (1, 0))
        self.assert_all_original()

    def test_a_clean_guarded_test_passes_and_leaves_nothing_patched(self):
        result = self.run_inner(lambda inner: inner.assertEqual(inner.unexpected, []))
        self.assertTrue(result.wasSuccessful())
        self.assert_all_original()


if __name__ == "__main__":
    unittest.main()
