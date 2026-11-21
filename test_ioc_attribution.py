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


def _extract_urls(text, **extra):
    parsed = {"body_text": text, "html_body": "", "headers": {}}
    parsed.update(extra)
    return X.extract(parsed)["urls"]


BACKSLASH_URL = r"http://evil.example\@good.example/login"       # a browser goes to evil.example, urlparse() says good.example
PERCENT_URL = r"http://evil.example%5C@good.example/login"       # %5C is not a backslash: both parsers say good.example
IPV6_URL = "https://[2606:4700:4700::1111]:8443/path?token=secret"


def _has_ambiguity_flag(u):
    return any(f.startswith("Ambiguous address") for f in u["flags"])


class UrlHostAmbiguity(unittest.TestCase):
    def test_backslash_in_the_authority_is_not_attributed_to_the_hostname_urlparse_reports(self):
        iocs = X.extract({"body_text": "Click " + BACKSLASH_URL + " now", "html_body": "", "headers": {}})
        u = iocs["urls"][0]
        self.assertEqual(u["url"], BACKSLASH_URL)                    # the indicator itself is retained
        self.assertEqual((u["host"], u["registrable"]), ("", ""))     # but no hostname is invented for it
        self.assertNotIn("good.example", iocs["domains"])
        self.assertTrue(_has_ambiguity_flag(u))

    def test_scoring_is_not_lowered_by_the_missing_hostname(self):
        u = _extract_urls(BACKSLASH_URL)[0]
        self.assertEqual(u["risk"], X._judge_url("http://good.example/login")["risk"])     # scored on the parser's host exactly as before
        self.assertTrue(u["suspicious"])
        short = _extract_urls(r"http://evil.example\@bit.ly/abc")[0]
        self.assertEqual(short["risk"], X._judge_url("http://bit.ly/abc")["risk"])
        self.assertIn("URL shortener hides the real destination", short["flags"])
        self.assertTrue(short["suspicious"])
        self.assertEqual((short["host"], short["registrable"]), ("", ""))

    def test_percent_encoded_5c_is_not_a_backslash_separator(self):
        u = _extract_urls(PERCENT_URL)[0]
        self.assertEqual(u["url"], PERCENT_URL)
        self.assertEqual((u["host"], u["registrable"]), ("good.example", "good.example"))   # both parsers agree on this one
        self.assertFalse(_has_ambiguity_flag(u))

    def test_a_backslash_after_the_authority_does_not_move_the_host(self):
        u = _extract_urls(r"http://good.example/a\b")[0]
        self.assertEqual(u["host"], "good.example")
        self.assertFalse(_has_ambiguity_flag(u))

    def test_other_backslash_authority_forms_are_also_ambiguous(self):
        for text in (r"HTTP://evil.example\@good.example/x", r"https://evil.example\good.example/", r"http://\evil.example/",
                     r"www.evil.example\@good.example/x", r"http://user:pw@evil.example\@good.example:8080/p"):
            with self.subTest(text=text):
                u = _extract_urls("see " + text)[0]
                self.assertEqual((u["host"], u["registrable"]), ("", ""))
                self.assertTrue(_has_ambiguity_flag(u))

    def test_html_href_with_a_backslash_authority_is_handled_the_same_way(self):
        urls = X.extract({"body_text": "", "html_body": "", "headers": {},
                          "html_links": [{"href": BACKSLASH_URL, "text": "open"}]})["urls"]
        self.assertEqual(urls[0]["source"], "html href")
        self.assertEqual((urls[0]["host"], urls[0]["registrable"]), ("", ""))
        self.assertTrue(_has_ambiguity_flag(urls[0]))


class BracketedIpv6Extraction(unittest.TestCase):
    def test_complete_ipv6_url_with_a_port_is_extracted_not_truncated_at_the_bracket(self):
        u = _extract_urls("Open " + IPV6_URL + " today")[0]
        self.assertEqual(u["url"], IPV6_URL)
        self.assertEqual(u["host"], "2606:4700:4700::1111")           # no brackets
        self.assertTrue(u["url"].endswith("]:8443/path?token=secret"))  # the port and the path survive
        self.assertNotEqual(u["url"], "https://[2606:4700:4700::1111")

    def test_ipv6_urls_without_a_port_or_a_path_and_in_other_spellings(self):
        for url in ("https://[2606:4700:4700::1111]/x", "https://[2606:4700:4700::1111]", "http://[2606:4700:4700::1111]:80/",
                    "https://[2606:4700:4700:0:0:0:0:1111]/x"):
            with self.subTest(url=url):
                u = _extract_urls("go " + url + " now")[0]
                self.assertEqual(u["url"], url)                                  # the URL text is kept exactly as written ...
                self.assertEqual(u["host"], "2606:4700:4700::1111")               # ... while the host is the canonical (compressed) address
        self.assertEqual(X._judge_url("https://[2606:4700:4700::ABCD]/")["host"], "2606:4700:4700::abcd")

    def test_an_ipv6_url_followed_by_ordinary_prose_punctuation_is_trimmed_correctly(self):
        base = "https://[2606:4700:4700::1111]"
        for text, expected in (("See " + base + ":8443/path.", base + ":8443/path"),
                               ("(see " + base + "/x), then", base + "/x"),
                               ("Open " + base + "!", base),
                               ("Is it " + base + ":8443?", base + ":8443"),
                               ("<" + base + "/x>", base + "/x"),
                               ('"' + base + '/x"', base + "/x"),
                               ("go " + base + "/x;", base + "/x"),
                               ("[" + base + "/x]", base + "/x"),
                               ("a " + base + ", b", base)):
            with self.subTest(text=text):
                u = _extract_urls(text)[0]
                self.assertEqual(u["url"], expected)
                self.assertEqual(u["host"], "2606:4700:4700::1111")

    def test_malformed_and_unclosed_ipv6_brackets_never_produce_a_hostname(self):
        for text in ("http://[2606:4700:4700::1111/path", "http://[2606:4700:4700::zzzz]/x", "http://[2606:4700:4700::1111::1]/x",
                     "http://[]/x", "http://[::1"):
            with self.subTest(text=text):
                u = _extract_urls("x " + text + " y")[0]
                self.assertEqual((u["host"], u["registrable"]), ("", ""))
                self.assertTrue(u["url"].startswith("http://["))        # the indicator is kept, no host is invented

    def test_ipv6_urls_are_now_judged_by_the_existing_heuristics_and_nothing_else_changed(self):
        u = X._judge_url("http://[2606:4700:4700::1111]/x")
        self.assertEqual(u["host"], "2606:4700:4700::1111")
        self.assertIn("Unencrypted HTTP link", u["flags"])

    def test_existing_ipv4_and_dns_url_extraction_is_unchanged(self):
        text = "Go to http://8.8.4.44:8080/x. Also (https://evil.example/path?x=1) and https://sub.evil.example/a, plus www.evil.example/page!"
        urls = _extract_urls(text)
        self.assertEqual([u["url"] for u in urls], ["http://8.8.4.44:8080/x", "https://evil.example/path?x=1",
                                                   "https://sub.evil.example/a", "www.evil.example/page"])
        self.assertEqual([u["host"] for u in urls], ["8.8.4.44", "evil.example", "sub.evil.example", "www.evil.example"])
        self.assertEqual(urls[2]["registrable"], "evil.example")
        self.assertIn("Link points at a raw IP address, not a domain name", urls[0]["flags"])
        self.assertGreaterEqual(urls[0]["risk"], 0.85)
        for u in urls:
            self.assertFalse(_has_ambiguity_flag(u))


def _extract(text, **extra):
    parsed = {"body_text": text, "html_body": "", "headers": {}}
    parsed.update(extra)
    return X.extract(parsed)


RAW_IP_FLAG = "Link points at a raw IP address, not a domain name"
CANON6 = "2606:4700:4700::1111"


class IpLiteralClassification(unittest.TestCase):
    def test_an_ipv6_url_populates_ip_indicators_and_never_the_domain_collection(self):
        iocs = _extract("Open " + IPV6_URL + " now")
        self.assertEqual(iocs["ips"], [CANON6])
        self.assertEqual(iocs["domains"], [])
        self.assertEqual((iocs["counts"]["ips"], iocs["counts"]["domains"]), (1, 0))
        u = iocs["urls"][0]
        self.assertEqual((u["host"], u["registrable"]), (CANON6, ""))            # an IP address is never a registrable domain
        for ip in iocs["ips"]:
            self.assertNotIn("[", ip)
            self.assertNotIn("]", ip)

    def test_equivalent_ipv6_spellings_collapse_to_one_canonical_indicator(self):
        text = ("a https://[2606:4700:4700:0:0:0:0:1111]/x b https://[2606:4700:4700::1111]:8443/y "
                "c https://[2606:4700:4700:0000:0000:0000:0000:1111]/z d https://[2606:4700:4700::1111]/w e")
        iocs = _extract(text)
        self.assertEqual(len(iocs["urls"]), 4)
        self.assertEqual({u["host"] for u in iocs["urls"]}, {CANON6})
        self.assertEqual(iocs["ips"], [CANON6])
        self.assertEqual(iocs["domains"], [])

    def test_an_ipv6_html_href_is_classified_the_same_way(self):
        iocs = _extract("", html_links=[{"href": "http://[2606:4700:4700:0:0:0:0:1111]:8080/p", "text": "open"}])
        self.assertEqual(iocs["urls"][0]["host"], CANON6)
        self.assertEqual((iocs["ips"], iocs["domains"]), ([CANON6], []))

    def test_ipv4_detection_and_scoring_are_unchanged_and_the_literal_is_not_a_domain(self):
        iocs = _extract("Go to http://8.8.4.44:8080/x now")
        u = iocs["urls"][0]
        self.assertEqual(u["host"], "8.8.4.44")
        self.assertIn(RAW_IP_FLAG, u["flags"])
        self.assertGreaterEqual(u["risk"], 0.85)
        self.assertEqual(iocs["ips"], ["8.8.4.44"])
        self.assertEqual((u["registrable"], iocs["domains"]), ("", []))          # it used to be the meaningless "4.44"

    def test_an_ipv4_only_present_as_an_html_href_host_is_now_listed_as_an_ip(self):
        iocs = _extract("", html_links=[{"href": "http://8.8.4.44/p", "text": "open"}])
        self.assertEqual((iocs["ips"], iocs["domains"]), (["8.8.4.44"], []))

    def test_dns_names_stay_domains_and_never_become_ips(self):
        iocs = _extract("see http://evil.example/p and https://sub.evil.example/q and www.evil.example/r")
        self.assertEqual(iocs["domains"], ["evil.example"])
        self.assertEqual(iocs["ips"], [])
        self.assertEqual([u["registrable"] for u in iocs["urls"]], ["evil.example"] * 3)
        self.assertEqual([u["host"] for u in iocs["urls"]], ["evil.example", "sub.evil.example", "www.evil.example"])

    def test_the_ipv6_helper_canonicalises_and_rejects(self):
        self.assertEqual(X._ipv6_literal("2606:4700:4700:0:0:0:0:1111"), CANON6)
        self.assertEqual(X._ipv6_literal("2606:4700:4700::ABCD"), "2606:4700:4700::abcd")
        for bad in ("fe80::1%eth0", "fe80::1%25eth0", "2606:4700:4700::1111%", "2606:4700:4700::zzzz", "2606:4700:4700::1111::1",
                    "8.8.8.8", "example.com", ""):
            with self.subTest(bad=bad):
                self.assertIsNone(X._ipv6_literal(bad))


SCOPED_URLS = ("https://[fe80::1%25eth0]/", "https://[fe80::1%eth0]/", "https://[2606:4700:4700::1111%25eth0]/x",
               "https://[2606:4700:4700::1111%eth0]:8443/x", "https://[2606:4700:4700::1111%2525eth0]/")


class ScopedAndMalformedIpv6(unittest.TestCase):
    def test_scoped_ipv6_urls_are_rejected_at_extraction(self):
        for url in SCOPED_URLS:
            with self.subTest(url=url):
                iocs = _extract("see " + url + " now")
                u = iocs["urls"][0]
                self.assertEqual(u["url"], url)                                   # the indicator is kept whole ...
                self.assertEqual((u["host"], u["registrable"]), ("", ""))          # ... but never attributed to a host
                self.assertEqual((iocs["ips"], iocs["domains"]), ([], []))         # no IP, domain or threat-memory indicator
                self.assertNotIn(RAW_IP_FLAG, u["flags"])                         # and never scored as an ordinary raw IP

    def test_valid_public_ipv6_controls_are_still_accepted(self):
        for url, expected in (("https://[2606:4700:4700::1111]/x", CANON6), ("https://[2001:4860:4860::8888]:8443/", "2001:4860:4860::8888"),
                              ("http://[2606:4700:4700:0:0:0:0:1111]/", CANON6)):
            with self.subTest(url=url):
                iocs = _extract("see " + url + " now")
                self.assertEqual(iocs["urls"][0]["host"], expected)
                self.assertEqual(iocs["ips"], [expected])

    def test_malformed_ipv6_controls_never_become_hosts_ips_or_domains(self):
        for text in ("http://[2606:4700:4700::1111/path", "http://[2606:4700:4700::zzzz]/x", "http://[2606:4700:4700::1111::1]/x",
                     "http://[]/x", "http://[::1", "http://[2606:4700:4700::1111%]/x"):
            with self.subTest(text=text):
                iocs = _extract("x " + text + " y")
                u = iocs["urls"][0]
                self.assertEqual((u["host"], u["registrable"]), ("", ""))
                self.assertEqual((iocs["ips"], iocs["domains"]), ([], []))


class RawIpv6Scoring(unittest.TestCase):
    def test_a_raw_ipv6_literal_gets_the_same_flag_and_score_as_a_raw_ipv4(self):
        v6 = X._judge_url("https://[2606:4700:4700::1111]/")
        v4 = X._judge_url("https://8.8.4.44/")
        self.assertIn(RAW_IP_FLAG, v6["flags"])
        self.assertIn(RAW_IP_FLAG, v4["flags"])
        self.assertEqual(v6["risk"], v4["risk"])
        self.assertGreaterEqual(v6["risk"], 0.85)
        self.assertTrue(v6["suspicious"])
        self.assertEqual(v6["host"], CANON6)

    def test_the_http_flag_and_the_raw_ip_flag_combine_the_same_way_for_both_families(self):
        v6 = X._judge_url("http://[2606:4700:4700::1111]:8443/x")
        v4 = X._judge_url("http://8.8.4.44:8443/x")
        self.assertEqual(sorted(v6["flags"]), sorted(v4["flags"]))
        self.assertEqual(v6["risk"], v4["risk"])

    def test_scoped_and_malformed_ipv6_are_not_scored_as_raw_ips(self):
        for url in ("https://[fe80::1%25eth0]/", "https://[fe80::1%eth0]/", "https://[2606:4700:4700::zzzz]/"):
            with self.subTest(url=url):
                self.assertNotIn(RAW_IP_FLAG, X._judge_url(url)["flags"])

    def test_ordinary_dns_urls_are_not_affected(self):
        ok = X._judge_url("https://example.com/")
        self.assertEqual((ok["flags"], ok["risk"], ok["suspicious"]), ([], 0.0, False))
        http = X._judge_url("http://evil.example/")
        self.assertNotIn(RAW_IP_FLAG, http["flags"])
        self.assertEqual(http["risk"], 0.3)
        self.assertEqual(X._judge_url("https://sub.evil.example/a")["registrable"], "evil.example")

    def test_the_score_version_was_bumped_because_ipv6_literals_are_now_scored(self):
        self.assertGreater(X.URL_SCORE_VERSION, 2)


PUBLIC_IPV6 = ("2001:4860:4860::8888", "2606:4700:4700::1111")
NON_PUBLIC_IPV6 = {
    "loopback": "::1", "unspecified": "::", "unique-local fd00::/8": "fd00::1", "unique-local fc00::/8": "fc00::1",
    "link-local": "fe80::1", "link-local (top of fe80::/10)": "febf::1", "documentation": "2001:db8::1",
    "multicast (link-local scope)": "ff02::1", "multicast (global scope)": "ff0e::1", "reserved block": "4000::1",
    "6to4": "2002:808:808::1", "IPv4-mapped": "::ffff:8.8.8.8", "site-local (deprecated)": "fec0::1",
}


class NonPublicIpv6Scoring(unittest.TestCase):
    def test_a_publicly_routable_ipv6_literal_gets_the_existing_raw_ip_score(self):
        for lit in PUBLIC_IPV6:
            with self.subTest(lit=lit):
                u = X._judge_url("https://[%s]/" % lit)
                self.assertEqual(u["host"], lit)
                self.assertEqual(u["flags"], [RAW_IP_FLAG])
                self.assertEqual(u["risk"], 0.85)
                self.assertTrue(u["suspicious"])
                self.assertEqual(u["risk"], X._judge_url("https://8.8.4.44/")["risk"])       # the IPv4 reference
                self.assertTrue(X._is_public_ipv6(lit))

    def test_loopback_unique_local_link_local_and_other_non_public_ipv6_are_not_scored_as_raw_ips(self):
        for label, lit in NON_PUBLIC_IPV6.items():
            with self.subTest(label=label, lit=lit):
                self.assertFalse(X._is_public_ipv6(lit))
                for scheme, base in (("https", 0.0), ("http", 0.3)):
                    u = X._judge_url("%s://[%s]/" % (scheme, lit))
                    self.assertNotIn(RAW_IP_FLAG, u["flags"])
                    self.assertEqual(u["risk"], base)                                       # only the scheme heuristic applies, as for any non-IP host

    def test_non_public_ipv6_is_still_canonicalised_and_listed_as_an_ip_never_as_a_domain(self):
        for lit in ("::1", "fd00::1", "fe80::1", "2001:db8::1"):
            with self.subTest(lit=lit):
                iocs = _extract("see http://[%s]/x now" % lit)
                u = iocs["urls"][0]
                self.assertEqual((u["host"], u["registrable"]), (lit, ""))
                self.assertEqual((iocs["ips"], iocs["domains"]), ([lit], []))
        self.assertEqual(_extract("see http://[FD00:0:0:0:0:0:0:1]/x now")["urls"][0]["host"], "fd00::1")

    def test_scoped_ipv6_is_still_rejected_whatever_its_base_address(self):
        for url in ("https://[2001:4860:4860::8888%25eth0]/", "https://[2001:4860:4860::8888%eth0]/", "https://[fe80::1%25eth0]/",
                    "https://[::1%eth0]/"):
            with self.subTest(url=url):
                iocs = _extract("see " + url + " now")
                u = iocs["urls"][0]
                self.assertEqual((u["host"], u["registrable"]), ("", ""))
                self.assertEqual((iocs["ips"], iocs["domains"]), ([], []))
                self.assertNotIn(RAW_IP_FLAG, u["flags"])

    def test_the_public_ipv6_helper_rejects_garbage_and_non_ipv6_input(self):
        for bad in ("", "garbage", "8.8.8.8", "2606:4700:4700::1111::1", "fe80::1%eth0"):
            with self.subTest(bad=bad):
                self.assertFalse(X._is_public_ipv6(bad))

    def test_ipv4_mapped_addresses_are_never_public_even_when_the_embedded_ipv4_is_globally_reachable(self):
        import ipaddress
        for embedded in ("8.8.8.8", "1.1.1.1"):
            self.assertTrue(ipaddress.IPv4Address(embedded).is_global)                  # the embedded address really is public
        for lit in ("::ffff:8.8.8.8", "::ffff:808:808", "0:0:0:0:0:ffff:808:808", "::ffff:1.1.1.1"):
            with self.subTest(lit=lit):
                self.assertIsNotNone(ipaddress.IPv6Address(lit).ipv4_mapped)            # and the literal really is IPv4-mapped
                self.assertFalse(X._is_public_ipv6(lit))
                for scheme, base in (("https", 0.0), ("http", 0.3)):
                    u = X._judge_url("%s://[%s]/" % (scheme, lit))
                    self.assertNotIn(RAW_IP_FLAG, u["flags"])
                    self.assertEqual(u["risk"], base)

    def test_deprecated_site_local_ipv6_is_never_public(self):
        import ipaddress
        for lit in ("fec0::1", "fec0::", "fed0::8888", "feff:ffff::1"):
            with self.subTest(lit=lit):
                self.assertTrue(ipaddress.IPv6Address(lit).is_site_local)               # inside fec0::/10
                self.assertFalse(X._is_public_ipv6(lit))
                for scheme, base in (("https", 0.0), ("http", 0.3)):
                    u = X._judge_url("%s://[%s]/" % (scheme, lit))
                    self.assertNotIn(RAW_IP_FLAG, u["flags"])
                    self.assertEqual(u["risk"], base)
        iocs = _extract("see http://[FEC0:0:0:0:0:0:0:1]/x now")                           # canonicalisation and classification are unchanged
        u = iocs["urls"][0]
        self.assertEqual((u["host"], u["registrable"]), ("fec0::1", ""))
        self.assertEqual((iocs["ips"], iocs["domains"]), (["fec0::1"], []))

    def test_public_ipv6_and_neighbouring_ranges_keep_their_classification(self):
        for lit in PUBLIC_IPV6:
            self.assertTrue(X._is_public_ipv6(lit))
        for lit in ("fe80::1", "febf::1", "fc00::1", "fd00::1", "::1", "2001:db8::1", "2002:808:808::1", "ff02::1", "4000::1"):
            with self.subTest(lit=lit):
                self.assertFalse(X._is_public_ipv6(lit))

    def test_ipv4_scoring_is_untouched_including_private_and_loopback_addresses(self):
        for url in ("http://10.0.0.1/", "http://127.0.0.1/", "http://192.168.1.1/", "http://169.254.169.254/", "https://8.8.4.44/"):
            with self.subTest(url=url):
                u = X._judge_url(url)
                self.assertIn(RAW_IP_FLAG, u["flags"])
                self.assertGreaterEqual(u["risk"], 0.85)

    def test_the_score_version_separates_this_behaviour_from_the_earlier_broader_one(self):
        self.assertGreater(X.URL_SCORE_VERSION, 3)


class BackslashAmbiguityPreserved(unittest.TestCase):
    def test_a_backslash_authority_still_withholds_the_host_and_adds_no_indicator(self):
        iocs = _extract("Click " + BACKSLASH_URL + " now")
        u = iocs["urls"][0]
        self.assertEqual((u["host"], u["registrable"]), ("", ""))
        self.assertNotIn("good.example", iocs["domains"] + iocs["ips"])
        self.assertTrue(_has_ambiguity_flag(u))

    def test_a_percent_encoded_backslash_in_the_path_is_not_an_authority_separator(self):
        url = r"http://evil.example/%5C@good.example/login"
        iocs = _extract("Click " + url + " now")
        u = iocs["urls"][0]
        self.assertEqual(u["url"], url)
        self.assertEqual((u["host"], u["registrable"]), ("evil.example", "evil.example"))   # good.example is only text in the path
        self.assertEqual(iocs["domains"], ["evil.example"])
        self.assertFalse(_has_ambiguity_flag(u))


if __name__ == "__main__":
    unittest.main()
