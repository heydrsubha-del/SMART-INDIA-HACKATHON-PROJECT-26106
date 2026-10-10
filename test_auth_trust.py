import unittest
import header_analysis as H
from email_parser import parse_eml

TRUST = {"mx.good.example"}


def eml(top="", below="", frm="Corp <news@corp.com>", rp="bounces.corp.com", extra_recv=1, reply=""):
    recv = "".join("Received: from r{0} (r{0} [203.0.113.{0}]) by mx.good.example; Tue, 1 Sep 2026 10:00:00 +0000\n".format(i + 1)
                   for i in range(extra_recv))
    return ("{top}{recv}Return-Path: <x@{rp}>\nFrom: {frm}\nTo: a@b.example\nSubject: Hello\n{reply}{below}"
            "Message-ID: <1@x>\nDate: Tue, 1 Sep 2026 10:00:00 +0000\n\nPlain body.\n").format(
        top=top, recv=recv, rp=rp, frm=frm, below=below, reply=reply).encode()


GOOD = ("Authentication-Results: mx.good.example; spf=pass smtp.mailfrom=bounces.corp.com; "
        "dkim=pass header.d=corp.com; dmarc=pass header.from=corp.com\n")
FORGED = ("Authentication-Results: mx.good.example; spf=pass smtp.mailfrom=evil.example; "
          "dkim=pass header.d=corp.com; dmarc=pass header.from=corp.com\n")


def run(raw, trusted=TRUST):
    return H.analyze(parse_eml(raw), trusted=trusted)


def titles(r, sev=None):
    return [a["title"] for a in r["anomalies"] if sev is None or a["severity"] == sev]


class AuthTrust(unittest.TestCase):
    def test_trusted_evidence_is_verified_and_subdomain_is_info(self):
        r = run(eml(top=GOOD))
        self.assertEqual(r["auth_evidence"]["spf"]["provenance"], "verified")
        self.assertEqual(r["auth_evidence"]["dmarc"]["confidence"], "high")
        self.assertIn("Envelope sender on a related subdomain (authenticated)", titles(r, "info"))
        self.assertEqual(titles(r, "high"), [])

    def test_no_trusted_servers_configured_means_unverified_not_malicious(self):
        r = run(eml(top=GOOD), trusted=set())
        self.assertEqual(r["auth_evidence"]["spf"]["provenance"], "unverified")
        self.assertEqual(r["spf"], "pass")                      # outcome kept separate from provenance
        self.assertIn("Envelope sender on a related subdomain (not proven)", titles(r, "low"))
        self.assertEqual(titles(r, "high"), [])
        self.assertIn("Authentication results unverified", titles(r, "info"))

    def test_forged_header_below_receiving_block_cannot_clear_mismatch(self):
        # sender wrote a pass header naming the trusted id; it sits below two Received headers
        raw = eml(below=FORGED, frm="Corp <news@corp.com>", rp="evil.example", extra_recv=2)
        r = run(raw)
        self.assertEqual(r["auth_evidence"]["dmarc"]["provenance"], "unverified")
        self.assertIn("Envelope / header sender mismatch", titles(r, "high"))

    def test_forged_header_with_untrusted_id(self):
        forged = FORGED.replace("mx.good.example", "mx.google.com")   # familiar name is not trust
        r = run(eml(top=forged, rp="evil.example"))
        self.assertEqual(r["auth_evidence"]["spf"]["provenance"], "unverified")
        self.assertIn("Envelope / header sender mismatch", titles(r, "high"))

    def test_multiple_headers_topmost_trusted_fail_beats_lower_forged_pass(self):
        top = "Authentication-Results: mx.good.example; spf=fail smtp.mailfrom=bounces.corp.com; dkim=none; dmarc=fail header.from=corp.com\n"
        r = run(eml(top=top, below=GOOD, extra_recv=2))
        self.assertEqual((r["spf"], r["dmarc"]), ("fail", "fail"))
        self.assertEqual(r["auth_evidence"]["spf"]["provenance"], "verified")
        self.assertIn("SPF fail", titles(r, "high"))
        self.assertIn("conflicting", r["auth_evidence"]["spf"]["note"])

    def test_duplicate_trusted_id_lower_copy_is_not_evidence(self):
        top = "Authentication-Results: mx.good.example; spf=fail smtp.mailfrom=bounces.corp.com\n"
        r = run(eml(top=top + GOOD, extra_recv=2))
        self.assertEqual(r["spf"], "fail")
        self.assertEqual(r["auth_evidence"]["dmarc"]["provenance"], "unverified")  # only in the lower copy

    def test_unverified_conflict_reports_worst_claim(self):
        a = "Authentication-Results: x.example; spf=pass\n"
        b = "Authentication-Results: y.example; spf=fail\n"
        r = run(eml(top=a + b), trusted=set())
        self.assertEqual(r["spf"], "fail")
        self.assertEqual(r["auth_evidence"]["spf"]["provenance"], "unverified")

    def test_missing_results_unknown_and_not_flagged_malicious(self):
        r = run(eml())
        for m in ("spf", "dkim", "dmarc"):
            self.assertEqual(r["auth_evidence"][m]["provenance"], "unknown")
        self.assertEqual(titles(r, "high"), [])
        self.assertEqual(titles(r, "medium"), [])

    def test_unsupported_provenance_no_received_chain(self):
        raw = (b"Authentication-Results: mx.good.example; spf=pass smtp.mailfrom=bounces.corp.com; dmarc=pass\n"
               b"Return-Path: <x@bounces.corp.com>\nFrom: n@corp.com\nSubject: s\n\nbody\n")
        r = run(raw)
        self.assertEqual(r["auth_evidence"]["spf"]["provenance"], "unverified")
        self.assertIn("No Received chain", titles(r, "medium"))

    def test_flattened_input_without_header_records_is_unverified(self):
        parsed = {"auth_results": "mx.good.example; spf=pass; dmarc=pass", "from_domain": "corp.com",
                  "return_path_domain": "evil.example", "received_chain": ["x"]}
        r = H.analyze(parsed, trusted=TRUST)
        self.assertEqual(r["auth_evidence"]["dmarc"]["provenance"], "unverified")
        self.assertIn("Envelope / header sender mismatch", titles(r, "high"))

    def test_received_spf_parsed_but_never_verified(self):
        raw = eml(top="Received-SPF: fail (domain does not designate)\n")
        r = run(raw)
        self.assertEqual(r["spf"], "fail")
        self.assertEqual(r["auth_evidence"]["spf"]["provenance"], "unverified")
        self.assertIn("SPF fail", titles(r, "high"))

    def test_genuine_spoof_failing_trusted_auth_still_high(self):
        top = "Authentication-Results: mx.good.example; spf=fail smtp.mailfrom=evil.example; dkim=fail header.d=evil.example; dmarc=fail header.from=corp.com\n"
        r = run(eml(top=top, rp="evil.example"))
        self.assertIn("DMARC fail", titles(r, "high"))
        self.assertIn("Envelope / header sender mismatch", titles(r, "high"))

    def test_unverified_pass_does_not_suppress_brand_or_reply_to_spoof(self):
        raw = eml(top=GOOD, frm="PayPal Support <help@evil.example>", rp="evil.example",
                  reply="Reply-To: collect@elsewhere.example\n")
        r = run(raw, trusted=set())
        self.assertIn("Display-name brand impersonation", titles(r, "high"))
        self.assertIn("Reply-To redirects elsewhere", titles(r, "high"))

    def test_third_party_dkim_aligned_requires_verified(self):
        top = ("Authentication-Results: mx.good.example; spf=pass smtp.mailfrom=esp.example; "
               "dkim=pass header.d=corp.com; dmarc=pass header.from=corp.com\n")
        self.assertIn("Envelope sender on a third-party domain (DKIM-aligned)",
                      titles(run(eml(top=top, rp="esp.example")), "low"))
        self.assertIn("Envelope / header sender mismatch",
                      titles(run(eml(top=top, rp="esp.example"), trusted=set()), "high"))

    def test_scoring_inputs_unchanged_by_provenance(self):
        a, b = run(eml(top=GOOD)), run(eml(top=GOOD), trusted=set())
        self.assertEqual(a["auth_fail_score"], b["auth_fail_score"])


if __name__ == "__main__":
    unittest.main()
