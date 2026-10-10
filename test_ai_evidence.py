"""AI-assessment data flow: sender fields, origin confidence, calibration, auth provenance."""
import sys, types, unittest

try:
    import cloud_backend  # noqa: F401
except Exception:                       # the AI module imports it at load; tests never call a model
    stub = types.ModuleType("cloud_backend")
    stub.BackendError = Exception
    stub.resolve_backend = lambda *a, **k: None
    sys.modules["cloud_backend"] = stub

import config as C
import header_analysis as H
import origin_intel
import ollama_threat as O
from email_parser import parse_eml

RECV = ("Received: from mail-sor-f69.google.com (mail-sor-f69.google.com [209.85.220.69]) by mx.corp-example.org "
        "with ESMTPS; Mon, 5 Oct 2026 10:00:01 +0000\n")


def raw_mail(frm="Google <noreply-accounts@google.com>", rp="bounce@scoutcamp.bounces.google.com",
             auth_ok=True, extra=""):
    ar = ("Authentication-Results: mx.corp-example.org; dkim=pass header.i=@google.com; "
          "spf=pass (google.com: domain of bounce@scoutcamp.bounces.google.com designates 209.85.220.69 as permitted sender) "
          "smtp.mailfrom=bounce@scoutcamp.bounces.google.com; dmarc=pass header.from=google.com\n") if auth_ok else ""
    return (ar + RECV + "Return-Path: <%s>\nFrom: %s\nTo: v@corp-example.org\nSubject: Security alert\n"
            "Date: Mon, 5 Oct 2026 10:00:00 +0000\nMessage-ID: <1@g>\n%s\nHello\n" % (rp, frm, extra)).encode()


def result_for(raw, level="Medium", score=32.7, prob=0.549, trusted=("mx.corp-example.org",), store_origin=True,
               suspicious_urls=1, urlhaus=0):
    parsed = parse_eml(raw)
    headers = H.analyze(parsed, trusted=set(trusted))
    geo = {"origin": {"ip": "209.85.220.69", "country": "US", "infra_label": "Hosting"},
           "hops": [], "origin_risk": 0.1, "summary": "x"}
    res = {"name": "t.eml", "parsed": parsed, "headers": headers,
           "iocs": {"urls": [], "suspicious_urls": [{"url": "https://accounts.google.com/AccountChooser", "host": "accounts.google.com"}] * suspicious_urls,
                    "url_score": 0.5 if suspicious_urls else 0.0, "domains": [], "ips": [], "emails": []},
           "geo": geo, "ml": {"prob": prob, "label": "phishing", "top_terms": []},
           "intelligence": {"urlhaus_matches": urlhaus}, "score": score, "level": level,
           "verdict": {"top_driver": "ML phishing language"}}
    if store_origin:
        res["origin_intel"] = origin_intel.assess_origin(parsed, geo, raw=raw)
    return res


class Sender(unittest.TestCase):
    def test_sender_fields_reach_ai_evidence_not_unknown(self):
        e = O.build_evidence(result_for(raw_mail()))["email"]
        self.assertEqual(e["from_address"], "noreply-accounts@google.com")
        self.assertIn("noreply-accounts@google.com", e["from"])
        self.assertNotEqual(e["from"], "Unknown")
        self.assertEqual(e["return_path_domain"], "scoutcamp.bounces.google.com")
        self.assertEqual(e["from_domain"], "google.com")

    def test_missing_sender_is_unknown_not_invented(self):
        e = O.build_evidence(result_for(raw_mail(frm="", rp="")))["email"]
        self.assertEqual(e["from_address"], "Unknown")


class OriginConfidence(unittest.TestCase):
    def test_ai_uses_stored_assessment(self):
        raw = raw_mail()
        res = result_for(raw)
        ev = O.build_evidence(res)["machine_analysis"]["origin_intelligence"]
        self.assertEqual(ev["confidence"], "{}/100".format(res["origin_intel"]["confidence"]))
        self.assertIn("same assessment object", ev["source"])

    def test_recompute_without_raw_is_labelled_and_can_differ(self):
        raw = raw_mail()
        with_raw = origin_intel.assess_origin(parse_eml(raw), {"origin": {"ip": "209.85.220.69"}, "hops": []}, raw=raw)
        res = result_for(raw, store_origin=False)
        ev = O.build_evidence(res)["machine_analysis"]["origin_intelligence"]
        self.assertIn("recomputed without raw-header corroboration", ev["source"])
        self.assertLessEqual(int(ev["confidence"].split("/")[0]), with_raw["confidence"])

    def test_distinct_metrics_are_named(self):
        m = O.build_evidence(result_for(raw_mail()))["machine_analysis"]
        self.assertIn("DIFFERENT metric", m["origin_risk_note"])
        self.assertIn("origin_confidence", m["origin_intelligence"]["metric"])


class Calibration(unittest.TestCase):
    def test_google_subdomain_is_info_and_not_hard_evidence(self):
        res = result_for(raw_mail())
        titles = [(a["severity"], a["title"]) for a in res["headers"]["anomalies"]]
        self.assertIn(("info", "Envelope sender on a related subdomain (authenticated)"), titles)
        self.assertFalse([t for t in titles if t[0] == "high"])
        cal = O.build_evidence(res)["calibration"]
        self.assertFalse(cal["hard_evidence_present"])
        self.assertEqual(cal["confirmed_facts"], [])
        self.assertTrue(cal["suspicious_indicators"])           # URL pattern stays a suspicious indicator
        self.assertIn("Medium (32.7/100)", cal["machine_verdict"])
        self.assertIn("not proof", cal["model_prediction"])

    def test_overstated_ai_gets_note_without_rewriting_text(self):
        res = result_for(raw_mail())
        ans = "THREAT VERDICT:\nPhishing.\n\nATTACK TYPE:\nCredential Phishing\n\nCONFIDENCE:\nHigh - sender mismatch."
        out = O._calibration_note(ans, res)
        self.assertTrue(out.startswith(ans))
        self.assertIn("Application calibration note", out)
        self.assertIn("32.7/100", out)

    def test_calibrated_ai_gets_no_note(self):
        res = result_for(raw_mail())
        ans = "THREAT VERDICT:\nSuspicious.\n\nATTACK TYPE:\nUnclear\n\nCONFIDENCE:\nLow - no hard evidence."
        self.assertEqual(O._calibration_note(ans, res), ans)

    def test_genuine_spoof_is_hard_evidence_and_allows_strong_verdict(self):
        res = result_for(raw_mail(frm="Google <ceo@google.com>", rp="x@evil-example.ru", auth_ok=False),
                         level="High", score=60)
        cal = O.build_evidence(res)["calibration"]
        self.assertTrue(cal["hard_evidence_present"])
        self.assertTrue(any("sender mismatch" in f.lower() for f in cal["confirmed_facts"]))
        ans = "ATTACK TYPE:\nPhishing\n\nCONFIDENCE:\nHigh - mismatch."
        self.assertEqual(O._calibration_note(ans, res), ans)

    def test_urlhaus_match_is_hard_evidence(self):
        cal = O.build_evidence(result_for(raw_mail(), urlhaus=2))["calibration"]
        self.assertTrue(cal["hard_evidence_present"])


class AuthProvenanceInAI(unittest.TestCase):
    def test_forged_pass_is_shown_unverified_and_does_not_hide_spoof(self):
        res = result_for(raw_mail(frm="Google <ceo@google.com>", rp="x@evil-example.ru"), trusted=())
        a = O.build_evidence(res)["machine_analysis"]["authentication_evidence"]
        self.assertEqual(a["dmarc"]["provenance"], "unverified")
        cal = O.build_evidence(res)["calibration"]
        self.assertTrue(any("sender mismatch" in f.lower() for f in cal["confirmed_facts"]))

    def test_verified_pass_shown_verified(self):
        a = O.build_evidence(result_for(raw_mail()))["machine_analysis"]["authentication_evidence"]
        self.assertEqual(a["spf"]["provenance"], "verified")

    def test_legacy_result_without_provenance_is_not_invented(self):
        res = result_for(raw_mail()); res["headers"].pop("auth_evidence")
        self.assertFalse(O.build_evidence(res)["machine_analysis"]["authentication_evidence"]["available"])


class NetworkTrustState(unittest.TestCase):
    def test_not_supplied_is_not_called_consistent(self):
        v = O.build_evidence(result_for(raw_mail()))["machine_analysis"]["vpn_tor_assessment"]
        self.assertIn("Not evaluated", v["network_trust_badge"])
        v2 = O.build_evidence(result_for(raw_mail()), network_trust={"badge": "Consistent"})["machine_analysis"]["vpn_tor_assessment"]
        self.assertEqual(v2["network_trust_badge"], "Consistent")


if __name__ == "__main__":
    unittest.main()
