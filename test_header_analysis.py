import unittest

import config as C
import header_analysis as ha
from email_parser import parse_eml


def mail(frm, rp, auth, reply_to=None, display=None):
    h = [f"Return-Path: <{rp}>" if rp else None, f"From: {display or 'Sender'} <{frm}>", "To: victim@corp-example.org",
         "Subject: hello", "Date: Mon, 5 Oct 2026 10:00:00 +0000", "Message-ID: <1@x>",
         f"Reply-To: <{reply_to}>" if reply_to else None,
         f"Authentication-Results: mx.corp-example.org; {auth}" if auth else None,
         "Received: from mx.out.example.net (mx.out.example.net [45.33.32.156]) by mx.corp-example.org with ESMTP; Mon, 5 Oct 2026 10:00:01 +0000"]
    return parse_eml(("\r\n".join(x for x in h if x) + "\r\n\r\nHello there\r\n").encode())


GOOD = ("dkim=pass header.i=@google.com header.s=2023; spf=pass (google.com: domain of bounce@scoutcamp.bounces.google.com "
        "designates 45.33.32.156 as permitted sender) smtp.mailfrom=bounce@scoutcamp.bounces.google.com; "
        "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com")


def flags(r, word):
    return [a for a in r["anomalies"] if word in a["title"]]


class Mismatch(unittest.TestCase):
    # These fixtures model a deployment whose receiving server is mx.corp-example.org.
    # Without that trust configuration every result is unverified (see test_auth_trust.py).
    @classmethod
    def setUpClass(cls):
        cls._saved = set(C.TRUSTED_AUTHSERV_IDS)
        C.TRUSTED_AUTHSERV_IDS = {"mx.corp-example.org"}

    @classmethod
    def tearDownClass(cls):
        C.TRUSTED_AUTHSERV_IDS = cls._saved

    def test_google_aligned_subdomain_is_not_high(self):
        p = mail("noreply@google.com", "bounce@scoutcamp.bounces.google.com", GOOD)
        self.assertEqual((p["from_domain"], p["return_path_domain"]), ("google.com", "scoutcamp.bounces.google.com"))
        r = ha.analyze(p)
        self.assertFalse([a for a in r["anomalies"] if a["severity"] == "high"])
        f = flags(r, "related subdomain")[0]
        self.assertEqual(f["severity"], "info")
        self.assertIn("verified by authentication", f["detail"])
        self.assertEqual((r["auth_fail_score"], r["anomaly_score"]), (0.0, 0.0))

    def test_same_parent_without_proof_is_low_not_trusted(self):
        for auth in ("", "spf=none; dkim=none; dmarc=none", "spf=pass smtp.mailfrom=b@scoutcamp.bounces.google.com; dkim=none; dmarc=none"):
            r = ha.analyze(mail("noreply@google.com", "bounce@scoutcamp.bounces.google.com", auth))
            self.assertEqual(flags(r, "related subdomain")[0]["severity"], "low", auth)
            self.assertIn("not proven", flags(r, "related subdomain")[0]["title"])

    def test_same_parent_with_failed_auth_keeps_the_auth_alerts(self):
        r = ha.analyze(mail("noreply@google.com", "bounce@scoutcamp.bounces.google.com",
                            "spf=fail smtp.mailfrom=bounce@scoutcamp.bounces.google.com; dkim=fail; dmarc=fail header.from=google.com"))
        self.assertEqual(flags(r, "related subdomain")[0]["severity"], "low")
        highs = {a["title"] for a in r["anomalies"] if a["severity"] == "high"}
        self.assertTrue({"SPF fail", "DKIM fail", "DMARC fail"} <= highs)

    def test_genuine_spoof_still_high(self):
        r = ha.analyze(mail("ceo@google.com", "x@evil-example.ru", "spf=pass smtp.mailfrom=x@evil-example.ru; dkim=none; dmarc=fail header.from=google.com"))
        self.assertEqual(flags(r, "sender mismatch")[0]["severity"], "high")
        self.assertGreaterEqual(r["anomaly_score"], 0.34)

    def test_lookalike_and_prefix_tricks_are_not_same_org(self):
        for rp in ("x@google.com.evil-example.com", "x@notgoogle.com", "x@google.com.evil.co.uk", "x@g00gle.com"):
            dom = rp.split("@")[1]
            self.assertFalse(ha.same_org("google.com", dom), dom)
            r = ha.analyze(mail("noreply@google.com", rp, "spf=pass smtp.mailfrom=" + rp + "; dkim=none; dmarc=fail header.from=google.com"))
            self.assertEqual(flags(r, "sender mismatch")[0]["severity"], "high", rp)
            self.assertFalse(flags(r, "related subdomain"), rp)
            r2 = ha.analyze(mail("noreply@google.com", rp, GOOD.replace("scoutcamp.bounces.google.com", dom)))
            self.assertFalse(flags(r2, "related subdomain"), rp)

    def test_shared_hosting_parent_is_not_an_organisation(self):
        self.assertFalse(ha.same_org("alice.github.io", "mallory.github.io"))
        self.assertTrue(ha.same_org("a.alice.github.io", "alice.github.io"))
        r = ha.analyze(mail("hi@alice.github.io", "b@mallory.github.io",
                            "spf=pass smtp.mailfrom=b@mallory.github.io; dkim=none; dmarc=pass header.from=alice.github.io"))
        self.assertEqual(flags(r, "sender mismatch")[0]["severity"], "high")

    def test_third_party_bounce_domain_needs_dkim_alignment(self):
        base = "spf=pass smtp.mailfrom=b@bounces.espmail-example.net; dmarc=pass header.from=brand-example.com; dkim=pass {}"
        low = ha.analyze(mail("news@brand-example.com", "b@bounces.espmail-example.net", base.format("header.d=brand-example.com")))
        self.assertEqual(flags(low, "third-party")[0]["severity"], "low")
        for dk in ("header.d=espmail-example.net", ""):
            r = ha.analyze(mail("news@brand-example.com", "b@bounces.espmail-example.net", base.format(dk)))
            self.assertEqual(flags(r, "sender mismatch")[0]["severity"], "high", dk)
        r = ha.analyze(mail("news@brand-example.com", "b@bounces.espmail-example.net", "spf=pass; dkim=fail header.d=brand-example.com; dmarc=pass"))
        self.assertEqual(flags(r, "sender mismatch")[0]["severity"], "high")

    def test_reply_to(self):
        sub = ha.analyze(mail("a@google.com", "a@google.com", GOOD, reply_to="support@help.google.com"))
        self.assertEqual(flags(sub, "Reply-To on a related")[0]["severity"], "info")
        noauth = ha.analyze(mail("a@google.com", "a@google.com", "", reply_to="support@help.google.com"))
        self.assertEqual(flags(noauth, "Reply-To on a related")[0]["severity"], "low")
        evil = ha.analyze(mail("a@google.com", "a@google.com", GOOD, reply_to="x@evil-example.ru"))
        self.assertEqual(flags(evil, "Reply-To redirects")[0]["severity"], "high")

    def test_org_domain(self):
        self.assertEqual(ha.org_domain("scoutcamp.bounces.google.com"), "google.com")
        self.assertEqual(ha.org_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(ha.org_domain(""), ""); self.assertEqual(ha.org_domain(None), "")
        self.assertFalse(ha.same_org("", "google.com")); self.assertFalse(ha.same_org(None, None))

    def test_missing_and_malformed_input_never_raises(self):
        for p in ({}, {"auth_results": None}, {"from_domain": "a.com", "return_path_domain": ""}, {"from_domain": "a.com", "return_path_domain": "b.com", "auth_results": "smtp.mailfrom=;;; header.d=("}):
            r = ha.analyze(p); self.assertIn("anomalies", r)
        self.assertEqual(ha._domains_after("smtp.mailfrom=\"<>\"", "smtp.mailfrom"), [])

    def test_other_detections_unchanged(self):
        r = ha.analyze({"from_domain": "gmail.com", "from_display": "CEO PayPal", "full_text": "urgent wire transfer payment today",
                        "body_text": "urgent wire transfer", "received_chain": [], "attachments": [{"filename": "a.exe", "risky": True}]})
        titles = {a["title"] for a in r["anomalies"]}
        for t in ("Display-name brand impersonation", "Executive identity on a free mail account", "No Received chain", "Dangerous attachment type"):
            self.assertIn(t, titles)


if __name__ == "__main__":
    unittest.main()