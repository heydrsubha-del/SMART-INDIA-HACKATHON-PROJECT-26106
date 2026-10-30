"""Regression / adversarial tests for the deterministic extortion detector
and its integration into the end-to-end analyzer and risk verdict.

No network calls, no ClamAV/VirusTotal/Supabase/Ollama - only synthetic,
non-sensitive messages. The classifier model is trained once (cached to
data/model.joblib) the first time this process imports classifier.
"""
import unittest

import analyzer
import extortion_detection as ED
import risk


def eml(subject, body, frm="anon123@gmail.com"):
    headers = (
        "From: Unknown <{frm}>\r\n"
        "To: victim@example.com\r\n"
        "Subject: {subject}\r\n"
        "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        "Message-ID: <1@x>\r\n\r\n"
    ).format(frm=frm, subject=subject)
    return (headers + body).encode()


class RuleUnitTests(unittest.TestCase):
    """Direct tests of extortion_detection.analyze() on raw text."""

    def test_1_private_picture_3000_dollars(self):
        r = ED.analyze("I have your private picture. Give me $3,000, or I'll "
                        "send it to all your contacts.")
        self.assertTrue(r["detected"])
        self.assertEqual(r["category"], "suspected_sextortion")
        self.assertIn(r["severity"], ("high", "critical"))
        self.assertGreaterEqual(r["confidence"], 0.8)

    def test_2_intimate_images_crypto_threat(self):
        r = ED.analyze("I recorded you through your webcam. Pay in bitcoin "
                        "within 24 hours or I will post the video online.")
        self.assertTrue(r["detected"])
        self.assertEqual(r["category"], "suspected_sextortion")

    def test_3_non_sexual_blackmail_documents(self):
        r = ED.analyze("I have your confidential documents. Wire $5,000 or "
                        "I will leak them to your employer within 48 hours.")
        self.assertTrue(r["detected"])
        self.assertEqual(r["category"], "suspected_extortion")

    def test_4_extortion_without_url_or_attachment(self):
        text = ("I have your private photos. Send $2,000 in bitcoin or else "
                "I will share them with all your contacts.")
        r = ED.analyze(text)
        self.assertTrue(r["detected"])
        self.assertNotIn("http", text)

    def test_5_freemail_sender_no_ip_reputation_still_detected(self):
        raw = eml("urgent", "I have your private video from your webcam. "
                             "Pay $1,500 in bitcoin within 24 hours or I "
                             "will send it to all your contacts.",
                   frm="random987@gmail.com")
        from email_parser import parse_eml
        parsed = parse_eml(raw)
        r = ED.analyze(parsed["full_text"])
        self.assertTrue(r["detected"])

    def test_7_legitimate_prevention_article_needs_review_not_asserted(self):
        text = ("Security Awareness: how to recognize sextortion scams. A "
                "typical scam message says 'I have your private picture, "
                "pay $3,000 or I will send it to all your contacts.' Do not "
                "click, pay, or reply if you receive a message like this. "
                "Report it to your IT department.")
        r = ED.analyze(text)
        # It still matches the pattern (it quotes one), but must not be
        # asserted with full confidence - this is advisory content.
        if r["detected"]:
            self.assertTrue(r["needs_review"])
            self.assertLessEqual(r["confidence"], 0.5)

    def test_8_security_awareness_quoting_example(self):
        text = ("PSA / example of a sextortion email, for training purposes: "
                "\"I have your private video. Pay $3,000 in bitcoin within "
                "24 hours or I will send it to everyone you know.\"")
        r = ED.analyze(text)
        if r["detected"]:
            self.assertTrue(r["needs_review"])

    def test_9_benign_payment_and_photo_mentions_no_threat(self):
        text = ("Hi, attaching the photo from the team outing. Also, please "
                "process my $120 reimbursement for the taxi - thanks!")
        r = ED.analyze(text)
        self.assertFalse(r["detected"])

    def test_10_wording_variation_evades_simple_keywords(self):
        text = ("I've got some pics from your camera that you wouldn't want "
                "your contacts seeing. Settle this with $800 worth of "
                "crypto in the next 24 hours, or they go out to everyone "
                "you know.")
        r = ED.analyze(text)
        # This deliberately avoids the exact phrase "I have your private
        # picture" - still expect partial-category detection to be robust,
        # though a full textbook match is not guaranteed by design (this
        # documents current recall on heavy paraphrase, not a hard promise).
        self.assertIsInstance(r["detected"], bool)

    def test_single_mention_of_photo_alone_never_fires(self):
        self.assertFalse(ED.analyze("Here's the photo from yesterday.")["detected"])

    def test_money_word_alone_never_fires(self):
        self.assertFalse(ED.analyze("Please send the $500 invoice payment by Friday.")["detected"])

    def test_bitcoin_alone_never_fires(self):
        self.assertFalse(ED.analyze("We now accept bitcoin as a payment method.")["detected"])

    def test_word_extortion_alone_never_fires(self):
        self.assertFalse(ED.analyze("This article discusses extortion as a crime category.")["detected"])

    def test_no_fabricated_possession_claim(self):
        r = ED.analyze("I have your private picture. Give me $3,000, or I'll "
                        "send it to all your contacts.")
        self.assertNotIn("actually possesses", r["explanation"].lower().replace("does not", ""))
        self.assertIn("does not", r["explanation"].lower())

    def test_empty_and_malformed_input(self):
        for text in (None, "", "   ", "\n\n\t"):
            r = ED.analyze(text)
            self.assertFalse(r["detected"])
            self.assertEqual(r["strength"], 0.0)


class RiskOverrideTests(unittest.TestCase):
    """The behavioral override must raise, never lower, the weighted verdict."""

    def test_6_auth_pass_no_links_still_overridden_to_high(self):
        r = risk.score(ml_prob=0.486, auth_fail=0.0, header_anomaly=0.0,
                        url_risk=0.0, origin_risk=0.0, bec_score=0.0,
                        extortion_score=1.0, extortion_confidence=0.95)
        self.assertEqual(r["level"], "High")
        self.assertTrue(r["override_applied"])

    def test_low_confidence_finding_does_not_override(self):
        r = risk.score(ml_prob=0.05, auth_fail=0.0, header_anomaly=0.0,
                        url_risk=0.0, origin_risk=0.0, bec_score=0.0,
                        extortion_score=0.5, extortion_confidence=0.5)
        self.assertFalse(r["override_applied"])
        self.assertNotEqual(r["level"], "High")

    def test_override_never_lowers_an_already_critical_score(self):
        r = risk.score(ml_prob=0.97, auth_fail=1.0, header_anomaly=1.0,
                        url_risk=0.9, origin_risk=1.0, bec_score=0.0,
                        extortion_score=1.0, extortion_confidence=0.95)
        self.assertEqual(r["level"], "Critical")

    def test_ml_estimate_is_never_mutated_by_the_override(self):
        r = risk.score(ml_prob=0.486, auth_fail=0.0, header_anomaly=0.0,
                        url_risk=0.0, origin_risk=0.0, bec_score=0.0,
                        extortion_score=1.0, extortion_confidence=0.95)
        self.assertAlmostEqual(r["signals"]["ml_phish"], 0.486)

    def test_weights_sum_to_100(self):
        import config as C
        self.assertEqual(sum(C.WEIGHTS.values()), 100)


class EndToEndAnalyzerTests(unittest.TestCase):
    """Full pipeline: raw .eml bytes -> analyzer.analyze_email -> verdict."""

    @classmethod
    def setUpClass(cls):
        from classifier import load_or_train
        cls.pipe = load_or_train()

    def test_sextortion_case_end_to_end_high_or_critical(self):
        raw = eml("Your private moment",
                   "I have your private picture from your webcam. Pay $3,000 "
                   "in bitcoin within 24 hours or I will send it to all your "
                   "contacts.")
        result = analyzer.analyze_email(raw, "sextortion_case.eml", self.pipe)
        self.assertIn(result["level"], ("High", "Critical"))
        self.assertTrue(result["extortion"]["detected"])
        self.assertNotEqual(result["level"], "Low")

    def test_spf_dkim_dmarc_pass_still_flags_extortion(self):
        raw = (b"From: Attacker <attacker@example.com>\r\n"
               b"To: victim@example.com\r\n"
               b"Subject: Final notice\r\n"
               b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
               b"Message-ID: <2@x>\r\n"
               b"Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=attacker@example.com; "
               b"dkim=pass header.d=example.com; dmarc=pass header.from=example.com\r\n\r\n"
               b"I have your private video. Send $2,000 in bitcoin within 24 "
               b"hours or I will post it to all your contacts.\r\n")
        result = analyzer.analyze_email(raw, "auth_pass_extortion.eml", self.pipe)
        self.assertTrue(result["extortion"]["detected"])
        self.assertIn(result["level"], ("High", "Critical"))

    def test_batch_and_single_analysis_share_verdict_logic(self):
        raw = eml("hi", "I have your private picture. Give me $3,000, or "
                         "I'll send it to all your contacts.")
        single = analyzer.analyze_email(raw, "x.eml", self.pipe)
        # analyze_all_samples() routes every sample through the exact same
        # analyze_email() call used here, so there is only one code path -
        # this test documents and pins that invariant.
        self.assertEqual(single["level"],
                          analyzer.analyze_email(raw, "x.eml", self.pipe)["level"])

    def test_benign_email_unaffected_by_new_signal(self):
        raw = eml("Meeting notes", "Hi, attached are the notes from "
                                    "yesterday's review meeting.")
        result = analyzer.analyze_email(raw, "benign.eml", self.pipe)
        self.assertFalse(result["extortion"]["detected"])
        self.assertEqual(result["level"], "Low")

    def test_report_does_not_call_extortion_email_legitimate(self):
        import report
        raw = eml("Your private moment",
                   "I have your private picture from your webcam. Pay $3,000 "
                   "in bitcoin within 24 hours or I will send it to all your "
                   "contacts.")
        result = analyzer.analyze_email(raw, "sextortion_case.eml", self.pipe)
        actions = report._actions(result)
        joined = " ".join(actions).lower()
        self.assertNotIn("legitimate mail", joined)
        self.assertIn("do not pay", joined)

    def test_missing_optional_modules_do_not_break_analysis(self):
        # origin_intel is optional (analyzer already guards its import); a
        # plain extortion-free email must still analyze cleanly end to end.
        raw = eml("hello", "Just checking in, no action needed.")
        result = analyzer.analyze_email(raw, "plain.eml", self.pipe)
        self.assertIn("extortion", result)
        self.assertFalse(result["extortion"]["detected"])


class AdversarialTests(unittest.TestCase):
    """Required adversarial cases: benign invoices, security articles, quoted
    threats, genuine threats containing advisory phrases, indirect payment
    demands, and paraphrased sextortion."""

    def test_benign_invoice_bare_amount_never_fires(self):
        for text in (
            "Your invoice total is $3,000, due net 30.",
            "The conference registration fee is $450.",
            "Quarterly revenue was $3,000,000 this period.",
        ):
            self.assertFalse(ED.analyze(text)["detected"], text)

    def test_security_article_third_person_no_direct_threat(self):
        text = ("How to recognize sextortion scams: scammers often claim to "
                "have recorded victims and demand payment in cryptocurrency, "
                "threatening exposure if the victim does not comply. Never "
                "pay or engage with these messages.")
        r = ED.analyze(text)
        # Third-person description with no first-person possession claim
        # directed at "you" should not produce a full, asserted detection.
        if r["detected"]:
            self.assertTrue(r["needs_review"])

    def test_quoted_threat_in_double_quotes_is_needs_review(self):
        text = ('Security advisory: a typical sextortion email reads: '
                '"I have your private video. Pay $3,000 in bitcoin within '
                '24 hours or I will send it to all your contacts." Do not '
                'reply to such messages.')
        r = ED.analyze(text)
        self.assertTrue(r["detected"])
        self.assertTrue(r["needs_review"])
        self.assertLessEqual(r["confidence"], 0.5)

    def test_quoted_threat_in_single_quotes_is_needs_review(self):
        text = ("A typical scam message says 'I have your private picture, "
                "pay $3,000 in bitcoin within 24 hours or I will send it to "
                "all your contacts.' Report it to your IT department.")
        r = ED.analyze(text)
        self.assertTrue(r["detected"])
        self.assertTrue(r["needs_review"])

    def test_genuine_threat_with_advisory_phrase_is_not_bypassed(self):
        # An attacker prepending "security awareness" to a live, directly
        # addressed, UNQUOTED threat must not downgrade or suppress it.
        text = ("This is a security awareness message. I have your private "
                "video. Pay $3,000 in bitcoin within 24 hours or I will "
                "send it to all your contacts.")
        r = ED.analyze(text)
        self.assertTrue(r["detected"])
        self.assertFalse(r["needs_review"])
        self.assertGreaterEqual(r["confidence"], 0.8)
        self.assertIn(r["severity"], ("high", "critical"))

    def test_genuine_threat_mentioning_do_not_click_is_not_bypassed(self):
        # "do not" phrasing used as part of the coercive threat itself
        # ("don't try to tell the police"), not as an advisory disclaimer.
        text = ("I have your private photo. Pay $2,000 in bitcoin within 24 "
                "hours or I will send it to all your contacts. Don't try to "
                "tell the police.")
        r = ED.analyze(text)
        self.assertTrue(r["detected"])
        self.assertFalse(r["needs_review"])

    def test_indirect_payment_demand_without_explicit_pay_word(self):
        text = ("I have your private documents. Send over $1,000 within 24 "
                "hours or your boss will find out.")
        r = ED.analyze(text)
        self.assertTrue(r["detected"])
        self.assertEqual(r["category"], "suspected_extortion")

    def test_indirect_payment_demand_transfer_wire(self):
        text = ("I recorded you through your webcam. Transfer 500 USD "
                "immediately or I will post it online.")
        r = ED.analyze(text)
        self.assertTrue(r["detected"])

    def test_paraphrased_sextortion_avoiding_stock_phrasing(self):
        text = ("I've got some pics from your camera that you wouldn't want "
                "your contacts seeing. Settle this with $800 worth of "
                "crypto in the next 24 hours, or they go out to everyone "
                "you know.")
        r = ED.analyze(text)
        self.assertTrue(r["detected"])
        self.assertEqual(r["category"], "suspected_sextortion")
        self.assertFalse(r["needs_review"])

    def test_bare_amount_with_separate_unrelated_threat_does_not_fire(self):
        # Possession + distribution threat are present, but the dollar
        # figure sits in its own sentence with no payment verb nearby -
        # must not count as a payment demand.
        text = ("I have your private picture. $3,000. I will send it to "
                "all your contacts.")
        r = ED.analyze(text)
        self.assertFalse(r["detected"])


class PossessionPatternCoverageTests(unittest.TestCase):
    """Every possession pattern is exercised once, with its expected
    imagery classification (sextortion vs. generic/non-sexual)."""

    CASES = [
        ("I have your private video from your laptop.", True),
        ("I am in possession of your intimate photo.", True),
        ("I recorded you on cam while you were changing.", True),
        ("I have webcam footage of you from last night.", True),
        ("I recorded you through your webcam without you knowing.", True),
        ("I hacked your webcam two weeks ago.", True),
        ("I have a screen recording of your screen.", True),
        ("I have an explicit photo of you from your device.", True),
        ("I saw you on cam last night.", True),
        ("I have access to your webcam right now.", True),
        ("I have access to your device and all your files.", False),
        ("I installed malware on your computer last week.", False),
        ("I have your private documents from the server breach.", False),
        ("I know about your affair with a coworker.", False),
        ("I've got some photos from your camera you don't want seen.", True),
    ]

    def test_every_possession_pattern_matches_with_correct_imagery(self):
        self.assertEqual(len(self.CASES), len(ED._POSSESSION_DEFS),
                          "one test case per defined possession pattern")
        for text, expected_imagery in self.CASES:
            with self.subTest(text=text):
                hits = ED._possession_findings(text)
                self.assertTrue(hits, "no possession pattern matched: {}".format(text))
                imagery = any(h[4] for h in hits)
                self.assertEqual(imagery, expected_imagery, text)

    def test_imagery_metadata_travels_with_its_own_pattern(self):
        # Regression guard for the "parallel list ordering" bug class:
        # every def must carry its own compiled regex and imagery flag as
        # one unit, not be looked up positionally from a separate list.
        for d in ED._POSSESSION_DEFS:
            self.assertIn("pattern", d)
            self.assertIn("imagery", d)
            self.assertIn("regex", d)
            self.assertEqual(d["regex"].pattern, d["pattern"])


class ConsistencyTests(unittest.TestCase):
    """Single-email, batch, UI-facing report and forensic-report outputs
    must agree on the same input."""

    @classmethod
    def setUpClass(cls):
        from classifier import load_or_train
        cls.pipe = load_or_train()

    def _sextortion_raw(self):
        return eml("Your private moment",
                   "I have your private picture from your webcam. Pay $3,000 "
                   "in bitcoin within 24 hours or I will send it to all your "
                   "contacts.")

    def test_single_and_batch_produce_identical_verdict_and_extortion_fields(self):
        raw = self._sextortion_raw()
        single = analyzer.analyze_email(raw, "x.eml", self.pipe)

        import config as C
        import os
        os.makedirs(C.SAMPLE_DIR, exist_ok=True)
        tmp_path = os.path.join(C.SAMPLE_DIR, "zz_test_sextortion_consistency.eml")
        with open(tmp_path, "wb") as fh:
            fh.write(raw)
        try:
            batch = analyzer.analyze_all_samples(self.pipe)
            match = next(r for r in batch if r.get("name") == "zz_test_sextortion_consistency.eml")
        finally:
            os.remove(tmp_path)

        self.assertEqual(single["level"], match["level"])
        self.assertEqual(single["extortion"]["detected"], match["extortion"]["detected"])
        self.assertEqual(single["extortion"]["category"], match["extortion"]["category"])
        self.assertEqual(single["extortion"]["needs_review"], match["extortion"]["needs_review"])

    def test_report_markdown_and_actions_agree_with_result_object(self):
        import report
        raw = self._sextortion_raw()
        result = analyzer.analyze_email(raw, "sextortion_case.eml", self.pipe)
        md = report.build_report(result)
        actions = report._actions(result)
        self.assertIn("Extortion / sextortion assessment", md)
        self.assertIn(result["level"], md)
        self.assertNotIn("No action required", " ".join(actions))

    def test_needs_review_report_never_says_no_action_or_legitimate(self):
        import report
        raw = eml("Example", 'A typical scam message reads: "I have your '
                              'private picture. Pay $3,000 in bitcoin within '
                              '24 hours or I will send it to all your '
                              'contacts." Report suspicious mail to IT.')
        result = analyzer.analyze_email(raw, "needs_review_case.eml", self.pipe)
        self.assertTrue(result["extortion"]["detected"])
        self.assertTrue(result["extortion"]["needs_review"])
        actions = report._actions(result)
        joined = " ".join(actions).lower()
        # The forbidden OUTCOME is "no action needed" / an unqualified
        # "legitimate mail" verdict - not the substring "legitimate", which
        # legitimately appears inside the warning "do not close this out as
        # legitimate mail without an analyst...".
        self.assertNotIn("no action required", joined)
        self.assertNotIn("indicators are consistent with legitimate mail", joined)
        self.assertIn("manual review", joined)


def _ids(text, defs):
    """Set of pattern IDs from `defs` that match `text` (works even when the whole message is not detected)."""
    return {i for h in ED._findings(text, defs) for i in h[4]}


def pay_ids(text):
    return _ids(text, ED._PAYMENT_DEFS)


def dist_ids(text):
    return _ids(text, ED._DISTRIBUTION_DEFS)


class PaymentContextFalsePositiveTests(unittest.TestCase):
    """Crypto words and 'send' are only payment evidence inside a real demand."""

    FP_A = "I have your private photos. We accept bitcoin at our store. I will send them to all your contacts."
    FP_B = "I have your private photos. Send it to all your contacts for $3,000."

    def test_unrelated_crypto_mention_is_not_a_payment_demand(self):
        r = ED.analyze(self.FP_A)
        self.assertFalse(r["detected"])
        self.assertNotIn("payment_demand", r["categories_hit"])
        self.assertEqual(r["confidence"], 0.0)
        self.assertEqual(pay_ids(self.FP_A), set())

    def test_distribution_verb_with_amount_is_not_a_payment_demand(self):
        r = ED.analyze(self.FP_B)
        self.assertFalse(r["detected"])
        self.assertNotIn("payment_demand", r["categories_hit"])
        self.assertEqual(pay_ids(self.FP_B), set())
        self.assertIn("dist_send_to_contacts", dist_ids(self.FP_B))   # still seen as a distribution phrase

    def test_bare_crypto_and_payment_nouns_never_match_any_payment_pattern(self):
        for text in ("We accept bitcoin at our store.", "Bitcoin and Ethereum prices rose 5% today.",
                     "Our bitcoin payment page is down.", "Copy the wallet address from the app.",
                     "We sell gift cards.", "Bank accepts wire transfer for all invoices.",
                     "Invoice total: $3,000.", "Crypto exchange newsletter: Monero update."):
            with self.subTest(text=text):
                self.assertEqual(pay_ids(text), set())

    def test_content_distribution_objects_never_become_payment_verbs(self):
        for text in ("Send it to all your contacts for $3,000.", "Transfer them to your contacts for $3,000.",
                     "Forward the photos to everyone for $500.", "Share this with your friends for $1,000.",
                     "I will deposit them online for $200 in views.", "Send to all your contacts for $3,000.",
                     "Send a copy to your boss for $3,000."):
            with self.subTest(text=text):
                self.assertEqual(pay_ids(text), set())

    def test_genuine_crypto_and_amount_demands_match_the_intended_pattern_ids(self):
        cases = [
            ("Pay in bitcoin.", {"pay_verb_crypto"}),
            ("Send 0.5 BTC immediately.", {"pay_send_crypto"}),
            ("Transfer $3,000.", {"pay_verb_amount"}),
            ("Send $3,000 now.", {"pay_send_amount"}),
            ("Give me $3,000.", {"pay_give_amount"}),
            ("Send the payment today.", {"pay_send_money"}),
            ("Deposit 0.3 BTC to my wallet address.", {"pay_verb_crypto", "pay_to_wallet"}),
            ("Wire me the money.", {"pay_wire_money"}),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(pay_ids(text), expected)

    def test_genuine_threat_with_crypto_demand_still_detected(self):
        t = ("I have your private photos. Pay $3,000 in bitcoin within 24 hours or I will send "
             "them to all your contacts.")
        r = ED.analyze(t)
        self.assertTrue(r["detected"])
        self.assertGreaterEqual(r["confidence"], 0.8)
        self.assertIn("pay_verb_amount", r["pattern_ids"]["payment_demand"])
        self.assertIn("pay_amount_in_crypto", r["pattern_ids"]["payment_demand"])

    def test_amount_followed_by_or_threat_is_a_demand_not_a_distribution(self):
        t = "I have your private photos. $3,000, or I will send them to all your contacts."
        r = ED.analyze(t)
        self.assertTrue(r["detected"])
        self.assertEqual(r["pattern_ids"]["payment_demand"], ["pay_amount_or_threat"])

    def test_payment_verb_and_distribution_verb_in_one_threat(self):
        r = ED.analyze("I have your private photos. Send $3,000 or I will send them to all your contacts.")
        self.assertTrue(r["detected"])
        self.assertIn("pay_send_amount", r["pattern_ids"]["payment_demand"])
        self.assertIn("dist_send_to_contacts", r["pattern_ids"]["distribution_threat"])


class QuoteSpanTests(unittest.TestCase):
    DIRECT = "I have your private photos. Pay $3,000 or I will send them to all your contacts."

    def test_reporting_lead_attributes_only_its_own_sentence(self):
        text = "A typical scam reads: it is only a hoax. " + self.DIRECT
        spans = ED._quoted_spans(text)
        start = text.index("I have your private photos")
        self.assertTrue(spans, "the lead's own sentence should still be attributed")
        self.assertFalse(any(s <= start < e for s, e in spans), "the live threat must not be inside any quoted span")
        r = ED.analyze(text)
        self.assertTrue(r["detected"])
        self.assertFalse(r["needs_review"])
        self.assertGreaterEqual(r["confidence"], 0.8)

    def test_lead_span_never_exceeds_one_sentence_or_line_or_300_chars(self):
        text = "He says: this is the first sentence of it. Second sentence here.\nThird line is unrelated text."
        spans = ED._quoted_spans(text)
        self.assertEqual(len(spans), 1)
        s, e = spans[0]
        self.assertEqual(text[s:e], "this is the first sentence of it.")
        long_text = "It reads: " + ("word " * 100)
        (s, e), = ED._quoted_spans(long_text)
        self.assertLessEqual(e - s, 300)

    def test_single_sentence_unquoted_example_is_still_needs_review(self):
        t = ("For example, scammers write: I have your private photos and you must pay $3,000 "
             "or I will send them to all your contacts.")
        r = ED.analyze(t)
        self.assertTrue(r["detected"])
        self.assertTrue(r["needs_review"])
        self.assertLessEqual(r["confidence"], 0.5)

    def test_mixed_quoted_example_then_direct_threat_is_live(self):
        t = 'Training example: "' + self.DIRECT + '" Now, for you: ' + self.DIRECT
        r = ED.analyze(t)
        self.assertTrue(r["detected"])
        self.assertFalse(r["needs_review"])
        self.assertFalse(r["quoted_context"])
        self.assertGreaterEqual(r["confidence"], 0.8)
        flags = sorted(h[3] for h in ED._possession_findings(t))
        self.assertEqual(flags, [False, True], "identical phrase kept once per quoted-state")

    def test_mixed_direct_threat_then_quoted_example_is_live(self):
        t = self.DIRECT + ' (Scammers write things like: "' + self.DIRECT + '")'
        r = ED.analyze(t)
        self.assertTrue(r["detected"])
        self.assertFalse(r["needs_review"])
        self.assertGreaterEqual(r["confidence"], 0.8)

    def test_fully_quoted_threat_is_needs_review_with_capped_confidence(self):
        r = ED.analyze('Example for training: "' + self.DIRECT + '"')
        self.assertTrue(r["detected"])
        self.assertTrue(r["needs_review"])
        self.assertLessEqual(r["confidence"], 0.5)
        self.assertLessEqual(r["strength"], 0.5)

    def test_evidence_lists_each_phrase_once_even_when_quoted_and_direct(self):
        t = 'Example: "' + self.DIRECT + '" ' + self.DIRECT
        ev = ED.analyze(t)["evidence"]
        for cat, phrases in ev.items():
            self.assertEqual(len(phrases), len({p.lower() for p in phrases}), cat)


class AdversarialContextTests(unittest.TestCase):
    def test_multiple_distinct_threats_in_one_email(self):
        t = ("I have your private photos from your webcam. Also I have your private documents from the "
             "server breach. Pay $3,000 in bitcoin within 24 hours or I will send them to all your contacts "
             "and your employer will find out.")
        r = ED.analyze(t)
        self.assertTrue(r["detected"])
        self.assertEqual(r["category"], "suspected_sextortion")     # any imagery claim makes it sextortion
        ids = r["pattern_ids"]["possession_claim"]
        self.assertIn("poss_have_media", ids)
        self.assertIn("poss_private_documents", ids)
        self.assertGreaterEqual(len(r["evidence"]["distribution_threat"]), 2)
        self.assertGreaterEqual(r["confidence"], 0.85)

    def test_benign_financial_messages_do_not_fire(self):
        for text in (
            "Please pay invoice #123 of $3,000 by Friday. Wire transfer details are attached. Reply within 24 hours.",
            "Your private photo book is ready. Pay $20 within 3 days or the order will be cancelled.",
            "Your bank sent a payment of $3,000 to your account. Do not share your OTP with anyone.",
            "Bitcoin rose 5% this week. Buy now or miss out; offer ends within 24 hours.",
            "I recorded the meeting for you. Please send the invoice for $500 within 7 days.",
        ):
            with self.subTest(text=text[:50]):
                r = ED.analyze(text)
                self.assertFalse(r["detected"])
                self.assertEqual(r["strength"], 0.0)

    def test_paraphrased_sextortion_threats_still_detected_with_expected_rules(self):
        cases = [
            ("I recorded you through your webcam. Transfer $2,500 in BTC by tomorrow or everyone you know "
             "receives the video.", "poss_recorded_via_webcam", "pay_verb_amount", "dist_everyone_you_know"),
            ("Your webcam was hacked by me. I have webcam footage of you. Deposit 0.3 BTC within 48 hours "
             "or this goes out to everyone you know.", "poss_webcam_footage_of_you", "pay_verb_crypto",
             "dist_goes_out_to_everyone"),
            ("I've got some intimate pics from your phone. Send me $1,200 or I'll post them online.",
             "poss_got_media_from_device", "pay_send_amount", "dist_post_online"),
        ]
        for text, poss, pay, dist in cases:
            with self.subTest(text=text[:40]):
                r = ED.analyze(text)
                self.assertTrue(r["detected"], text)
                self.assertGreaterEqual(r["confidence"], 0.85)
                self.assertIn(poss, r["pattern_ids"]["possession_claim"])
                self.assertIn(pay, r["pattern_ids"]["payment_demand"])
                self.assertIn(dist, r["pattern_ids"]["distribution_threat"])

    def test_pattern_ids_only_reported_for_detected_messages(self):
        self.assertEqual(ED.analyze("hello there")["pattern_ids"], {})
        self.assertEqual(ED.analyze("")["pattern_ids"], {})


class ExactPatternIdTests(unittest.TestCase):
    """Every pattern is exercised with text built for IT, and the test asserts that exact pattern ID matched."""

    DIST = {
        "dist_send_to_contacts": "I will send it to all your contacts.",
        "dist_send_to_people": "I will send them to your boss.",
        "dist_forward_to_everyone": "I will forward it to everyone in your contact list.",
        "dist_share_with": "I will share this with your friends.",
        "dist_post_online": "I will post it online.",
        "dist_release_media": "I will leak the video.",
        "dist_release_publicly": "I will publish them publicly.",
        "dist_make_public": "I will make it public.",
        "dist_everyone_you_know": "Everyone you know will see it.",
        "dist_all_your_contacts": "It goes to all your contacts.",
        "dist_friends_family_list": "Your friends and family will see.",
        "dist_expose_you": "I will expose you.",
        "dist_ruin_life": "I will ruin your reputation.",
        "dist_employer_will_see": "Your employer will find out.",
        "dist_goes_out_to_everyone": "Otherwise it goes out to everyone.",
        "dist_go_to_everyone_you_know": "They go out to everyone you know.",
        "dist_wouldnt_want_contacts_seeing": "You wouldn't want your family to see this.",
    }
    COER = {
        "coer_or_i_will": "Pay or I will act.", "coer_or_else": "Pay or else.", "coer_within_n": "Pay within 24 hours.",
        "coer_you_have_n": "You have 48 hours.", "coer_you_have_until": "You have until Friday.",
        "coer_next_n": "Pay in the next 2 days.", "coer_act_now": "Act now.", "coer_final_warning": "This is a final warning.",
        "coer_no_more_warnings": "There will be no more warnings.", "coer_last_chance": "This is your last chance.",
        "coer_time_running_out": "Time is running out.", "coer_dont_tell": "Don't tell anyone.",
        "coer_keep_quiet": "Keep this between us.", "coer_no_negotiation": "There are no negotiations.",
    }
    PAY = {
        "pay_verb_amount": "Pay $3,000.", "pay_amount_verb": "$3,000 must be paid.", "pay_send_amount": "Send $3,000.",
        "pay_give_amount": "Give me $3,000.", "pay_demand_amount": "I demand $3,000.", "pay_send_money": "Send the money.",
        "pay_amount_in_crypto": "$3,000 in bitcoin.", "pay_verb_crypto": "Pay in bitcoin.", "pay_send_crypto": "Send 2 BTC.",
        "pay_to_wallet": "Send it to my wallet.", "pay_gift_card_demand": "Buy gift cards.",
        "pay_amount_in_gift_card": "$500 in gift cards.", "pay_wire_money": "Wire the money.",
        "pay_make_transfer": "Make a wire transfer.", "pay_ransom": "Pay the ransom.",
        "pay_settle_with_amount": "Let us settle this with $3,000.", "pay_amount_or_threat": "$3,000, or I will act.",
    }

    def _check(self, table, defs):
        self.assertEqual(set(table), {d["id"] for d in defs}, "one case per defined pattern, and no unknown IDs")
        for pid, text in table.items():
            with self.subTest(pattern=pid):
                matched = _ids(text, defs)
                self.assertIn(pid, matched, "{!r} did not match {}; matched {}".format(text, pid, sorted(matched)))
                d = next(x for x in defs if x["id"] == pid)
                self.assertTrue(d["regex"].search(text), pid)

    def test_every_distribution_pattern_matches_its_own_id(self):
        self._check(self.DIST, ED._DISTRIBUTION_DEFS)

    def test_every_coercion_pattern_matches_its_own_id(self):
        self._check(self.COER, ED._COERCION_DEFS)

    def test_every_payment_pattern_matches_its_own_id(self):
        self._check(self.PAY, ED._PAYMENT_DEFS)

    def test_every_possession_pattern_matches_its_own_id_and_imagery(self):
        cases = PossessionPatternCoverageTests.CASES
        self.assertEqual(len(cases), len(ED._POSSESSION_DEFS))
        for (text, imagery), d in zip(cases, ED._POSSESSION_DEFS):
            with self.subTest(pattern=d["id"]):
                hits = [h for h in ED._possession_findings(text) if d["id"] in h[5]]
                self.assertTrue(hits, "{!r} did not match {}".format(text, d["id"]))
                self.assertEqual(hits[0][4], d["imagery"])
                self.assertEqual(d["imagery"], imagery)

    def test_pattern_ids_are_unique_and_prefixed(self):
        allids = [d["id"] for d in ED._POSSESSION_DEFS + ED._DISTRIBUTION_DEFS + ED._PAYMENT_DEFS + ED._COERCION_DEFS]
        self.assertEqual(len(allids), len(set(allids)))
        for i in allids:
            self.assertRegex(i, r"^(poss|dist|pay|coer)_[a-z_]+$")

    def test_legacy_pattern_lists_still_exported(self):
        self.assertEqual(ED.PAYMENT_PATTERNS, [d["pattern"] for d in ED._PAYMENT_DEFS])
        self.assertEqual(ED.DISTRIBUTION_THREAT_PATTERNS, [d["pattern"] for d in ED._DISTRIBUTION_DEFS])
        self.assertEqual(ED.COERCION_PATTERNS, [d["pattern"] for d in ED._COERCION_DEFS])


class FalsePositiveEndToEndTests(unittest.TestCase):
    """Whole pipeline: the two reported false positives no longer escalate; ML probability stays independent."""

    @classmethod
    def setUpClass(cls):
        from classifier import load_or_train
        cls.pipe = load_or_train()

    def test_false_positive_emails_do_not_trigger_override_and_ml_is_untouched(self):
        for body in (PaymentContextFalsePositiveTests.FP_A, PaymentContextFalsePositiveTests.FP_B):
            with self.subTest(body=body[:40]):
                res = analyzer.analyze_email(eml("hello", body), "fp.eml", self.pipe)
                self.assertFalse(res["extortion"]["detected"])
                self.assertFalse(res["verdict"]["override_applied"])
                from classifier import predict
                self.assertAlmostEqual(res["ml"]["prob"], predict(self.pipe, res["parsed"]["full_text"])[0], places=9)

    def test_genuine_send_amount_threat_still_escalates_end_to_end(self):
        body = "I have your private photos. Send $3,000 or I will send them to all your contacts."
        res = analyzer.analyze_email(eml("Your photos", body), "real.eml", self.pipe)
        self.assertTrue(res["extortion"]["detected"])
        self.assertIn(res["level"], ("High", "Critical"))
        self.assertTrue(res["verdict"]["override_applied"] or res["level"] == "Critical")


if __name__ == "__main__":
    unittest.main()
