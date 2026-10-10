"""Contradictions between the machine report and the AI assessment."""
import sys, types, unittest

try:
    import cloud_backend  # noqa: F401
except Exception:
    stub = types.ModuleType("cloud_backend")
    stub.BackendError = Exception
    stub.resolve_backend = lambda *a, **k: None
    sys.modules["cloud_backend"] = stub

import config as C
import origin_intel as OI
import ollama_threat as O
import test_ai_evidence as T          # shared fixtures
from email_parser import parse_eml

HOP1 = "from a.example.org (a.example.org [45.33.32.156]) by mx1.mid.example; Tue, 1 Sep 2026 10:00:00 +0000"
HOP2 = "from mx1.mid.example (mx1.mid.example [104.16.0.1]) by mx2.last.example; Tue, 1 Sep 2026 10:00:05 +0000"
HOP3_PRIVATE = "from mx2.last.example (mx2.last.example [10.1.1.1]) by mx.final.example; Tue, 1 Sep 2026 10:00:09 +0000"
GEO = {"origin": {"ip": "104.16.0.1"}, "hops": []}


def origin(chain):
    return OI.assess_origin({"received_chain": chain}, GEO)


def effects(a):
    return {e["indicator"]: e["effect"] for e in a["evidence"]}


class Auth(unittest.TestCase):
    def test_ai_sees_unverified_label_and_verified_label(self):
        un = O.build_evidence(T.result_for(T.raw_mail(), trusted=()))["machine_analysis"]
        self.assertIn("UNVERIFIED", un["spf"]); self.assertIn("UNVERIFIED", un["dmarc"])
        ok = O.build_evidence(T.result_for(T.raw_mail()))["machine_analysis"]
        self.assertIn("verified: stamped by a trusted receiving server", ok["spf"])
        self.assertNotIn("UNVERIFIED", ok["spf"])

    def test_legacy_result_without_provenance_is_flagged_not_established(self):
        res = T.result_for(T.raw_mail()); res["headers"].pop("auth_evidence")
        self.assertIn("unverified claim", O.build_evidence(res)["machine_analysis"]["spf"])

    def test_prompt_tells_model_unverified_is_not_proof(self):
        self.assertIn("UNVERIFIED", O.build_prompt(T.result_for(T.raw_mail(), trusted=())))


class OriginCorroboration(unittest.TestCase):
    def setUp(self):
        self._saved = set(C.TRUSTED_AUTHSERV_IDS)

    def tearDown(self):
        C.TRUSTED_AUTHSERV_IDS = self._saved

    def parsed_and_raw(self):
        raw = T.raw_mail()
        return parse_eml(raw), raw

    def test_unverified_auth_header_gets_less_weight_than_verified(self):
        p, raw = self.parsed_and_raw()
        geo = {"origin": {"ip": "209.85.220.69"}, "hops": []}
        C.TRUSTED_AUTHSERV_IDS = set()
        unv = OI.assess_origin(p, geo, raw=raw)
        C.TRUSTED_AUTHSERV_IDS = {"mx.corp-example.org"}
        ver = OI.assess_origin(p, geo, raw=raw)
        self.assertLess(unv["confidence"], ver["confidence"])
        self.assertTrue(any("UNVERIFIED" in e["detail"] for e in unv["evidence"]))
        self.assertFalse(any("UNVERIFIED" in e["detail"] for e in ver["evidence"]))

    def test_ai_and_panel_use_one_origin_object(self):
        res = T.result_for(T.raw_mail())
        ai = O.build_evidence(res)["machine_analysis"]["origin_intelligence"]
        self.assertEqual(ai["confidence"], "{}/100".format(res["origin_intel"]["confidence"]))


class Handoff(unittest.TestCase):
    def test_fully_verified_chain_earns_credit(self):
        a = origin([HOP1, HOP2, HOP3_PRIVATE])
        self.assertEqual(effects(a).get("Unbroken handoff chain"), "+15")

    def test_break_elsewhere_in_route_gets_no_unbroken_credit(self):
        broken = "from other.example (other.example [104.16.0.1]) by mx2.last.example; Tue, 1 Sep 2026 10:00:05 +0000"
        a = origin([HOP1, broken, HOP3_PRIVATE])
        self.assertEqual(a["selected_ip"], "104.16.0.1")
        self.assertIn("CHAIN_BREAK", [f["code"] for f in a["flags"]])
        self.assertNotIn("Unbroken handoff chain", effects(a))
        self.assertEqual(effects(a).get("Handoff break elsewhere in the route"), "0")

    def test_break_downstream_is_penalised(self):
        hop3 = "from wrong.example (wrong.example [10.1.1.1]) by mx.final.example; Tue, 1 Sep 2026 10:00:09 +0000"
        a = origin([HOP1, HOP2, hop3])
        self.assertEqual(effects(a).get("Handoff gaps downstream"), "-8")
        self.assertNotIn("Unbroken handoff chain", effects(a))

    def test_unverifiable_handoff_gets_no_credit(self):
        hop3 = "from [10.1.1.1] by mx.final.example; Tue, 1 Sep 2026 10:00:09 +0000"
        a = origin([HOP1, HOP2, hop3])
        self.assertNotIn("Unbroken handoff chain", effects(a))
        self.assertEqual(effects(a).get("Handoffs not verifiable"), "0")


class Recommendations(unittest.TestCase):
    HOLD_AND_SAFE = ("THREAT VERDICT:\nLikely legitimate.\n\nRECOMMENDED ACTION:\n1. Do not click any links until the sender is verified.\n"
                     "2. Mark the email as safe.\n\nANALYST NOTE:\nDone.")

    def test_conflicting_recommendations_get_consistency_note(self):
        out = O._calibration_note(self.HOLD_AND_SAFE, T.result_for(T.raw_mail()))
        self.assertIn("Application consistency note", out)
        self.assertIn("do not mark it safe", out)

    def test_negated_allowlist_is_not_a_conflict(self):
        ans = "RECOMMENDED ACTION:\n1. Do not click links until verified.\n2. Do not allowlist the sender yet.\n\nANALYST NOTE:\nx"
        self.assertNotIn("consistency note", O._calibration_note(ans, T.result_for(T.raw_mail())))

    def test_safe_only_recommendation_is_untouched(self):
        ans = "RECOMMENDED ACTION:\n1. Mark the email as safe.\n\nANALYST NOTE:\nx"
        self.assertEqual(O._calibration_note(ans, T.result_for(T.raw_mail())), ans)


class Classification(unittest.TestCase):
    def low_result(self):
        return T.result_for(T.raw_mail(), level="Low", score=8.0, prob=0.2, suspicious_urls=0)

    def test_phishing_label_on_low_risk_legit_email_is_marked_unconfirmed(self):
        ans = ("THREAT VERDICT:\nLikely legitimate low-risk marketing email.\n\nATTACK TYPE:\nPhishing\n\nCONFIDENCE:\nMedium - x")
        out = O._calibration_note(ans, self.low_result())
        self.assertIn("ATTACK TYPE:\nUnconfirmed (model stated: Phishing", out)
        self.assertIn("Likely legitimate low-risk marketing email", out)

    def test_genuine_phishing_evidence_keeps_label(self):
        res = T.result_for(T.raw_mail(frm="Google <ceo@google.com>", rp="x@evil-example.ru", auth_ok=False), level="High", score=62)
        ans = "ATTACK TYPE:\nPhishing\n\nCONFIDENCE:\nHigh - mismatch"
        self.assertEqual(O._calibration_note(ans, res), ans)

    def test_low_risk_label_is_not_touched(self):
        ans = "ATTACK TYPE:\nLow Risk\n\nCONFIDENCE:\nLow - fine"
        self.assertEqual(O._calibration_note(ans, self.low_result()), ans)


if __name__ == "__main__":
    unittest.main()
