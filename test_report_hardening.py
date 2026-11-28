"""Regression tests for the report-hardening corrections (offline, deterministic, no network, no database)."""
import copy
import os
import random
import unittest

import report as R

HERE = os.path.dirname(os.path.abspath(__file__))
INF = float("inf")


def edge(src=("domain", "a.com"), rel="resolves to", dst=("ip", "1.2.3.4"), conf=0.5, ev=("S1",), basis="observed", prov="p", why="w"):
    return {"src": {"type": src[0], "id": src[1], "label": src[1]}, "rel": rel, "dst": {"type": dst[0], "id": dst[1], "label": dst[1]},
            "confidence": conf, "evidence": list(ev), "basis": basis, "provenance": prov, "explanation": why}


def hdr(spf=("pass", True), dkim=("pass", True), dmarc=("pass", True), al=None):
    return {"spf": spf[0], "dkim": dkim[0], "dmarc": dmarc[0],
            "auth_evidence": {m: {"provenance": "verified" if v[1] else "unverified"} for m, v in (("spf", spf), ("dkim", dkim), ("dmarc", dmarc))},
            **({"alignment": al} if al is not None else {})}


def ident_row(result):
    return next(l for l in R.attribution_md(result) if l.startswith("| How confident"))


class UrlGrouping(unittest.TestCase):
    def test_host_normalisation_and_distinct_counts(self):
        urls = [{"url": "http://Click.Example.com./a?x=1", "host": "Click.Example.com.", "flags": ["f1"], "count": 2},
                {"url": "http://click.example.com/b", "host": "click.example.com", "flags": [], "count": 1},
                {"url": "http://click.example.com/b", "host": "click.example.com", "flags": [], "count": 1}]
        md = "\n".join(R.url_host_groups_md(urls))
        row = next(l for l in md.splitlines() if l.startswith("| `click.example.com`"))
        self.assertEqual(row.count("click.example.com"), 1)
        self.assertIn("| 2 | 4 |", row)                       # 2 distinct URLs, 4 occurrences
        self.assertIn("f1", row)                              # a flag is never dropped because the host is shared
        self.assertIn("tracking", row)
        self.assertIn("not malicious by itself", md)

    def test_idna_hosts_group_together(self):
        self.assertEqual(R.norm_host("B\u00fccher.Example."), R.norm_host("xn--bcher-kva.example"))
        self.assertEqual(R.norm_host(None), "")

    def test_flags_are_a_union_and_input_is_not_mutated(self):
        urls = [{"url": "http://x.com/1", "host": "x.com", "flags": ["a"], "count": 1}, {"url": "http://x.com/2", "host": "X.com", "flags": ["b"], "count": 1}]
        before = copy.deepcopy(urls)
        md = "\n".join(R.url_host_groups_md(urls))
        self.assertIn("a; b", md)
        self.assertEqual(urls, before)
        self.assertEqual(R.url_host_groups_md([]), [])


class EntityEdges(unittest.TestCase):
    def test_confidence_validation(self):
        for good in (0, 1, 0.5, 2):
            self.assertTrue(R.valid_conf(good), good)
        for bad in (True, False, float("nan"), INF, -INF, "x", None, [1]):
            self.assertFalse(R.valid_conf(bad), bad)

    def test_identical_edges_merge_with_all_evidence_and_confidence_range(self):
        rows = R.aggregate_edges([edge(conf=0.4, ev=("S2",)), edge(conf=0.8, ev=("S1", "S3")), edge(conf=1, ev=("S1",))])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence"], ["S1", "S2", "S3"])
        self.assertEqual(rows[0]["confidence"], "0.40-1.00")

    def test_integer_confidence_accepted_and_invalid_never_shown(self):
        self.assertEqual(R.aggregate_edges([edge(conf=1)])[0]["confidence"], "1.00")
        for bad in (True, float("nan"), INF, "high", None):
            self.assertEqual(R.aggregate_edges([edge(conf=bad)])[0]["confidence"], "n/a", bad)
        self.assertEqual(R.aggregate_edges([edge(conf=True), edge(conf=0.3)])[0]["confidence"], "0.30")   # invalid value ignored, not invented

    def test_different_entities_direction_basis_and_provenance_never_merge(self):
        base = edge()
        variants = [edge(src=("domain", "b.com")), edge(dst=("ip", "9.9.9.9")), edge(rel="sent from"), edge(basis="inferred"), edge(prov="other"),
                    edge(src=("ip", "a.com")),                                    # same value, different entity type
                    edge(src=("ip", "1.2.3.4"), dst=("domain", "a.com"))]         # reversed direction
        self.assertEqual(len(R.aggregate_edges([base] + variants)), 1 + len(variants))

    def test_deterministic_and_skips_malformed(self):
        es = [edge(conf=0.1 * i, ev=("S%d" % i,), dst=("ip", "1.1.1.%d" % (i % 3))) for i in range(9)] + ["x", None]
        first = R.aggregate_edges(es)
        for _ in range(5):
            random.shuffle(es)
            self.assertEqual(R.aggregate_edges(es), first)


class Attribution(unittest.TestCase):
    AL_OK = {"dmarc_pass": True, "spf_aligned": False, "dkim_aligned": True, "signers": ["example.com"], "mailfrom": ["bounce.amazonses.com"]}

    def res(self, headers, hops=True, **geo):
        return {"headers": headers, "geo": dict({"hops": [{"ip": "1.1.1.1"}] if hops else []}, **geo)}

    def test_verified_dmarc_with_alignment_is_moderate(self):
        self.assertIn("| Moderate |", ident_row(self.res(hdr(al=self.AL_OK))))

    def test_spf_pass_alone_does_not_establish_identity(self):
        al = {"dmarc_pass": False, "spf_aligned": False, "dkim_aligned": False, "signers": [], "mailfrom": []}
        row = ident_row(self.res(hdr(dkim=("none", False), dmarc=("none", False), al=al)))
        self.assertIn("Not established", row)
        self.assertIn("SPF pass alone", row)

    def test_untrusted_authentication_results_stay_unknown(self):
        row = ident_row(self.res(hdr(spf=("pass", False), dkim=("pass", False), dmarc=("pass", False), al=self.AL_OK)))
        self.assertIn("Not established", row)
        self.assertIn("trusted receiving server", row)

    def test_missing_alignment_is_unknown_not_positive(self):
        row = ident_row(self.res(hdr()))
        self.assertIn("Not established", row)
        self.assertIn("alignment is unknown", row)

    def test_dmarc_pass_without_alignment_is_not_enough(self):
        al = dict(self.AL_OK, dkim_aligned=False, spf_aligned=False)
        self.assertIn("Not established", ident_row(self.res(hdr(al=al))))

    def test_three_concepts_are_separate_and_location_is_never_established(self):
        md = "\n".join(R.attribution_md(self.res(hdr(al=self.AL_OK))))
        for q in ("mail-server infrastructure", "sender-domain identity", "physically"):
            self.assertIn(q, md)
        self.assertIn("| Not established | GeoIP is approximate", md)
        self.assertIn("| Not established | No public relay", "\n".join(R.attribution_md(self.res(hdr(), hops=False))))
        self.assertIn("| Low |", "\n".join(R.attribution_md(self.res(hdr(), anonymised=True))))

    def test_malformed_result_does_not_raise(self):
        self.assertIsInstance(R.attribution_md(None), list)


class AmazonSes(unittest.TestCase):
    def test_ses_is_not_suspicious_and_alignment_is_stated(self):
        al = {"dmarc_pass": True, "spf_aligned": False, "dkim_aligned": True, "signers": ["example.com"]}
        md = "\n".join(R.ses_note({"return_path_domain": "0101.eu-west-1.amazonses.com", "from_domain": "Example.com"}, hdr(al=al)))
        self.assertIn("not suspicious by itself", md)
        self.assertIn("DKIM aligned with From (signers: example.com): yes", md)
        self.assertIn("SPF aligned with From: no", md)
        self.assertIn("stamped by a trusted receiving server", md)

    def test_one_verified_mechanism_does_not_make_all_trusted(self):
        md = "\n".join(R.ses_note({"return_path_domain": "amazonses.com", "from_domain": "example.com"}, hdr(spf=("pass", True), dkim=("pass", False), dmarc=("pass", False))))
        self.assertIn("(treated as claims): DKIM, DMARC", md)
        self.assertNotIn("All three results", md)
        self.assertIn("alignment was not computed", md)

    def test_non_ses_and_lookalike_hosts_are_ignored(self):
        for rp in ("example.com", "amazonses.com.evil.test", "notamazonses.com", ""):
            self.assertEqual(R.ses_note({"return_path_domain": rp}, hdr()), [], rp)

    def test_header_analysis_exposes_alignment(self):
        with open(os.path.join(HERE, "header_analysis.py"), encoding="utf-8") as f:
            self.assertIn('"alignment": ev,', f.read())


class Availability(unittest.TestCase):
    REG = [{"id": "S1", "type": "header", "source": "email_parser", "origin": "direct_machine", "status": "ok"},
           {"id": "S2", "type": "infrastructure", "source": "origin_intel", "origin": "inference", "status": "ok"},
           {"id": "S3", "type": "authentication", "source": "header_analysis", "origin": "untrusted_claim", "status": "failed"},
           {"id": "S4", "type": "domain", "source": "ioc_extract", "origin": "weird", "status": "missing"}, "junk"]

    def test_counts_and_wording(self):
        md = "\n".join(R.availability_md(self.REG))
        self.assertIn("2 of 4 evidence item(s) completed; 1 malformed entry ignored", md)
        self.assertIn("1 extracted or derived locally by a scanner", md)
        self.assertIn("0 returned by an external service", md)
        self.assertIn("1 with unrecognised origin", md)
        self.assertIn("S3 authentication/header_analysis", md)
        self.assertIn("**not** a negative finding", md)
        self.assertNotIn("confirmed", md.lower())             # machine extraction is never described as confirmed
        self.assertEqual(md, "\n".join(R.availability_md(copy.deepcopy(self.REG))))

    def test_unhashable_or_malformed_origin_does_not_raise(self):
        md = "\n".join(R.availability_md([{"id": "S1", "origin": ["direct_machine"], "status": "ok"}, {"id": "S2", "origin": {"x": 1}, "status": "ok"}]))
        self.assertIn("2 with unrecognised origin", md)

    def test_empty_and_non_list(self):
        self.assertEqual(R.availability_md([]), [])
        self.assertEqual(R.availability_md(None), [])


class Redaction(unittest.TestCase):
    RES = {"iocs": {"email_details": [{"address": "victim@corp.example", "roles": ["To"]}, {"address": "sender@evil.example", "roles": ["From"]}]}}
    MD = ("To victim@corp.example from sender@evil.example\n"
          "| `https://t.example.com/path/abcdefghijklmnopqrstuvwxyz123456?uid=secret&k=v#f` | x |")

    def test_recipient_and_tokens_redacted_sender_kept(self):
        out = R.redact_md(self.MD, self.RES)
        self.assertNotIn("victim@corp.example", out)
        self.assertIn("v***@corp.example", out)
        self.assertIn("sender@evil.example", out)             # not a recipient: stays, it is investigative evidence
        for secret in ("secret", "abcdefghijklmnopqrstuvwxyz123456", "k=v"):
            self.assertNotIn(secret, out)
        self.assertIn("https://t.example.com/path/[token]", out)   # host and path structure preserved
        self.assertIn("uid=[redacted]", out)

    def test_idempotent_pure_and_leaves_stored_result_alone(self):
        before = copy.deepcopy(self.RES)
        once = R.redact_md(self.MD, self.RES)
        self.assertEqual(R.redact_md(once, self.RES), once)
        self.assertEqual(self.RES, before)
        self.assertEqual(R.redact_md(self.MD, None).count("victim@corp.example"), 1)    # no result: no recipients known, nothing invented

    def test_batch_results_each_contribute_recipients(self):
        r2 = {"iocs": {"email_details": [{"address": "other@corp.example", "roles": ["Cc"]}]}}
        out = R.redact_md("victim@corp.example other@corp.example", [self.RES, r2, None])
        self.assertNotIn("victim@corp.example", out)
        self.assertNotIn("other@corp.example", out)

    def test_non_string_and_garbage_are_safe(self):
        self.assertIsNone(R.redact_md(None))
        self.assertEqual(R.recipients_of({"iocs": {"email_details": "x"}}, 5, None), set())

    def test_every_export_path_is_wired(self):
        with open(os.path.join(HERE, "app.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertIn("redact_md(_x, sel_res)", src)                       # single-email AI, machine and combined downloads
        for name in ("_batch_machine_body", "cleaned_summary", "_ai_evidence_refs_md"):
            self.assertIn("%s = redact_md(%s, _batch_results)" % (name, name), src)    # batch AI, machine and combined downloads
        self.assertIn('md_text = redact_md(str(markdown or ""))', src)    # HTML and Word are rendered from this single choke point
        with open(os.path.join(HERE, "report.py"), encoding="utf-8") as f:
            self.assertIn('return redact_md("\\n".join(lines), result)', f.read())   # build_report (per-email machine report)


if __name__ == "__main__":
    unittest.main()
