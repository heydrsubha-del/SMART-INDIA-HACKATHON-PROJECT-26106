"""URL look-alike precision and email-address role attribution."""
import sys, types, unittest

try:
    import cloud_backend  # noqa: F401
except Exception:
    stub = types.ModuleType("cloud_backend")
    stub.BackendError = Exception
    stub.resolve_backend = lambda *a, **k: None
    sys.modules["cloud_backend"] = stub

import ioc_extract as X
import ollama_threat as O
import report
import header_analysis as H
import test_ai_evidence as T
from email_parser import parse_eml


class LegitimateSubdomains(unittest.TestCase):
    def test_email_label_is_not_a_gmail_lookalike(self):
        self.assertEqual(X.edit_distance("email", "gmail"), 1)          # the original false-positive trigger
        self.assertIsNone(X.lookalike_brand("links.email.claude.com"))

    def test_tracking_url_on_nested_subdomain_is_clean(self):
        u = X._judge_url("https://links.email.claude.com/u/click?upn=abc123")
        self.assertEqual((u["registrable"], u["flags"], u["risk"], u["suspicious"]), ("claude.com", [], 0.0, False))

    def test_other_nested_subdomains_and_allowlisted_domains(self):
        for h in ("click.email.example.org", "mail.email.google.com", "accounts.google.com", "links.mail.news.example.co.uk"):
            self.assertIsNone(X.lookalike_brand(h), h)

    def test_remaining_evidence_still_scores(self):
        # the domain is not whitelisted: other genuine signals on it still count
        u = X._judge_url("http://links.email.claude.com/account/verify")
        self.assertIn("Unencrypted HTTP link", u["flags"])
        self.assertIn("Path suggests a credential-entry page", u["flags"])
        self.assertEqual(u["risk"], 0.5)
        self.assertTrue(any("abuse TLD" in f or "TLD" in f for f in X._judge_url("https://email.evil-example.ru/x")["flags"]))


class GenuineLookalikesStillCaught(unittest.TestCase):
    def test_registered_name_squats(self):
        for h in ("paypa1-support.com", "micros0ft-securelogin.ru", "gmai1.com", "amazom.com", "hdfc-netbanking.online"):
            self.assertIsNotNone(X.lookalike_brand(h), h)
            self.assertEqual(X._judge_url("https://" + h + "/")["risk"], 0.9, h)

    def test_brand_homoglyph_and_lure_in_subdomains_still_caught(self):
        for h in ("paypal.evil-example.com", "login.paypa1.evil-example.com", "appleid.evil-example.net"):
            self.assertIsNotNone(X.lookalike_brand(h), h)

    def test_subdomain_word_on_hostile_domain_is_not_a_brand_claim(self):
        self.assertIsNone(X.lookalike_brand("email.evil-example.ru"))   # judged by TLD/other flags, not as gmail


RAW = (b"Return-Path: <bounce@links.email.claude.com>\nFrom: Claude <hello@claude.com>\nReply-To: support@claude.com\n"
       b"To: Subha <victim@corp-example.org>\nSubject: Welcome\nDate: Mon, 5 Oct 2026 10:00:00 +0000\nMessage-ID: <1@c>\n\n"
       b"Visit https://links.email.claude.com/u/click?upn=abc . Account: other.person@gmail.com. Questions: support@claude.com\n")


class EmailAttribution(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_eml(RAW)
        self.iocs = X.extract(self.parsed)
        self.roles = {d["address"]: d["roles"] for d in self.iocs["email_details"]}

    def test_roles_distinguish_sender_recipient_replyto_and_body(self):
        self.assertEqual(self.roles["hello@claude.com"], ["sender (From)"])
        self.assertEqual(self.roles["victim@corp-example.org"], ["recipient (To)"])
        self.assertIn("Reply-To", self.roles["support@claude.com"])
        self.assertIn("mentioned in body", self.roles["support@claude.com"])
        self.assertEqual(self.roles["other.person@gmail.com"], ["mentioned in body"])
        self.assertIn("envelope sender (Return-Path)", self.roles["bounce@links.email.claude.com"])

    def test_legacy_emails_list_unchanged_and_no_malice_verdict_attached(self):
        self.assertEqual(self.iocs["emails"], ["other.person@gmail.com", "support@claude.com"])
        for d in self.iocs["email_details"]:
            self.assertEqual(set(d), {"address", "roles", "in_body"})

    def test_masking(self):
        self.assertEqual(X.mask_email("other.person@gmail.com"), "o***@gmail.com")
        self.assertEqual(X.mask_email("garbage"), "***")

    def result(self):
        res = T.result_for(RAW)
        res["iocs"] = self.iocs
        return res

    def test_ai_evidence_has_roles_masked_and_no_raw_third_party_address(self):
        ev = O.build_evidence(self.result())["machine_analysis"]
        blob = str(ev["email_addresses"])
        self.assertNotIn("other.person@gmail.com", blob)
        self.assertNotIn("victim@corp-example.org", blob)
        self.assertIn("o***@gmail.com", blob)
        self.assertTrue(any("recipient (To)" in d["roles"] for d in ev["email_addresses"]))
        self.assertNotIn("email_iocs", ev)

    def test_ai_evidence_for_legacy_result_without_roles(self):
        res = self.result(); res["iocs"] = {k: v for k, v in self.iocs.items() if k != "email_details"}
        ev = O.build_evidence(res)["machine_analysis"]["email_addresses"]
        self.assertTrue(all(d["roles"] == ["role not recorded"] for d in ev))
        self.assertNotIn("other.person@gmail.com", str(ev))

    def test_report_shows_roles_and_malice_caveat(self):
        res = self.result()
        res["headers"] = H.analyze(self.parsed, trusted=set()); res["geo"] = {}
        res["verdict"] = {"contributions": [], "top_driver": "-"}
        res["score"], res["level"] = 3, "Low"; res["ml"] = {"prob": .1, "top_terms": []}
        md = report.build_report(res)
        self.assertIn("Email addresses and their roles", md)
        self.assertIn("| `other.person@gmail.com` | mentioned in body |", md)
        self.assertIn("not, by itself, evidence of malice", md)


class MachineAndAiShareUrlEvidence(unittest.TestCase):
    def test_benign_tracking_url_is_not_a_suspicious_indicator_for_either(self):
        parsed = parse_eml(RAW)
        iocs = X.extract(parsed)
        res = T.result_for(RAW, suspicious_urls=0)
        res["iocs"] = iocs
        self.assertEqual(iocs["suspicious_urls"], [])
        self.assertEqual(iocs["url_score"], 0.0)
        ev = O.build_evidence(res)
        self.assertEqual(ev["machine_analysis"]["url_score"], 0.0)
        self.assertFalse(any("URL" in s for s in ev["calibration"]["suspicious_indicators"]))

    def test_genuine_lookalike_url_reaches_both(self):
        raw = RAW.replace(b"https://links.email.claude.com/u/click?upn=abc", b"https://paypa1-support.com/login")
        iocs = X.extract(parse_eml(raw))
        self.assertEqual(iocs["url_score"], 0.9)
        res = T.result_for(raw); res["iocs"] = iocs
        ev = O.build_evidence(res)
        self.assertEqual(ev["machine_analysis"]["url_score"], 0.9)
        self.assertTrue(any("URL" in s for s in ev["calibration"]["suspicious_indicators"]))


if __name__ == "__main__":
    unittest.main()
