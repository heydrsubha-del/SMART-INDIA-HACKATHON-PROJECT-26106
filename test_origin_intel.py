import unittest
import origin_intel as oi

# oldest hop first, as app.py's parsed["received_chain"] documents
CLEAN = [
 "from mail-out.sender-example.com (mail-out.sender-example.com [45.33.32.156]) by mx.google.com with ESMTPS; Mon, 5 Oct 2026 10:00:00 +0000",
 "from mx.google.com (mx.google.com [93.184.216.34]) by inbox.corp-example.org with ESMTP; Mon, 5 Oct 2026 10:00:05 +0000",
]
GEO = {"origin": {"ip": "45.33.32.156", "country": "Testland", "infra_label": "Datacenter", "infra": "datacenter"},
       "hops": [{"ip": "45.33.32.156", "country": "Testland", "isp": "ExampleHost", "infra": "datacenter", "infra_label": "Datacenter"},
                {"ip": "93.184.216.34", "country": "Testland", "isp": "ExampleCloud", "infra": "datacenter", "infra_label": "Datacenter"}]}

class T(unittest.TestCase):
    def test_parse(self):
        h = oi.parse_received(CLEAN[0])
        self.assertEqual(h["from_ip"], "45.33.32.156"); self.assertEqual(h["by"], "mx.google.com")
        self.assertEqual(h["protocol"], "ESMTPS"); self.assertIsNotNone(h["ts"])

    def test_malformed_never_raises(self):
        for bad in ("", None, "garbage ; not a date", "from ( by ;", "from [999.1.1.1]"):
            h = oi.parse_received(bad); self.assertIsNone(h["from_ip"])

    def test_clean_route_selects_and_explains(self):
        a = oi.assess_origin({"received_chain": CLEAN, "from_addr": "a@sender-example.com"}, GEO)
        self.assertEqual(a["selected_ip"], "45.33.32.156")
        self.assertTrue(a["evidence"]); self.assertLessEqual(a["confidence"], oi.CONFIDENCE_CAP)
        self.assertEqual(a["flags"], [])
        self.assertIn("NOT the sender's physical location", a["location_disclaimer"])

    def test_private_ips_never_selected(self):
        chain = ["from a (a [10.0.0.5]) by b with ESMTP; Mon, 5 Oct 2026 10:00:00 +0000"]
        a = oi.assess_origin({"received_chain": chain}, {})
        self.assertIsNone(a["selected_ip"]); self.assertEqual(a["band"], "None")

    def test_timestamp_backwards_and_helo_mismatch(self):
        chain = ["from [104.16.0.99] (evil [151.101.1.50]) by relay.x.net with SMTP; Mon, 5 Oct 2026 12:00:00 +0000",
                 "from relay.x.net (relay.x.net [151.101.1.9]) by mx.rcpt.org with ESMTP; Mon, 5 Oct 2026 09:00:00 +0000"]
        a = oi.assess_origin({"received_chain": chain}, {})
        codes = {f["code"] for f in a["flags"]}
        self.assertIn("TS_BACKWARDS", codes); self.assertIn("HELO_IP_MISMATCH", codes)

    def test_provider_absent(self):
        chain = [c.replace("mx.google.com", "mx.other-example.net") for c in CLEAN]
        a = oi.assess_origin({"received_chain": chain, "from_addr": "ceo@gmail.com"}, GEO)
        self.assertIn("PROVIDER_ABSENT", {f["code"] for f in a["flags"]})

    def test_provider_present_not_flagged(self):
        a = oi.assess_origin({"received_chain": CLEAN, "from_addr": "ceo@gmail.com"}, GEO)
        self.assertNotIn("PROVIDER_ABSENT", {f["code"] for f in a["flags"]})

    def test_anon_hop_mid_route(self):
        geo = {"hops": [{"ip": "45.33.32.156", "infra": "tor", "infra_label": "Tor exit", "tor_exit_confirmed": True}]}
        a = oi.assess_origin({"received_chain": CLEAN}, geo)
        self.assertIn("ANON_HOP", {f["code"] for f in a["flags"]})

    def test_header_corroboration_raises_confidence(self):
        raw = (b"X-Originating-IP: [45.33.32.156]\r\nReceived-SPF: pass (x) client-ip=45.33.32.156;\r\n\r\nbody")
        base = oi.assess_origin({"received_chain": CLEAN}, GEO)
        corr = oi.assess_origin({"received_chain": CLEAN}, GEO, raw=raw)
        self.assertGreater(corr["confidence"], base["confidence"])

    def test_disagreement_does_not_mutate_existing_origin(self):
        geo = {"origin": {"ip": "93.184.216.34"}, "hops": []}
        a = oi.assess_origin({"received_chain": CLEAN}, geo)
        self.assertEqual(a["existing_origin_ip"], "93.184.216.34")
        self.assertEqual(geo["origin"]["ip"], "93.184.216.34")

    def test_history_excludes_self_log_and_survives_failure(self):
        calls = {"45.33.32.156": (3, 80.0)}
        h, rows = oi.correlate_history(["45.33.32.156", "93.184.216.34"], "me", "h1", [],
                                       history_fn=lambda ip: calls[ip] if ip in calls else (_ for _ in ()).throw(RuntimeError("db")),
                                       self_logged_ip="45.33.32.156")
        self.assertEqual(h["45.33.32.156"], (2, 80.0)); self.assertEqual(h["93.184.216.34"], (0, 0))

    def test_session_correlation(self):
        other = {"name": "other", "_evidence_hash": "h2", "level": "phishing", "score": 91,
                 "parsed": {"from_addr": "x@evil.test"}, "iocs": {"urls": [{"url": "http://evil.test/a"}], "domains": ["evil.test"]},
                 "geo": {"hops": [{"ip": "45.33.32.156"}]}}
        me = {"name": "me", "_evidence_hash": "h1", "geo": GEO}
        _, rows = oi.correlate_history(["45.33.32.156"], "me", "h1", [me, other])
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]["Email"], "other")

    def test_infra_no_invented_data(self):
        r = oi.infrastructure_profile(["45.33.32.156"], GEO)[0]
        self.assertEqual(r["ASN"], "unavailable"); self.assertEqual(r["Hosting provider"], "Yes")
        r2 = oi.infrastructure_profile(["8.8.4.4"], {})[0]
        self.assertEqual(r2["ISP / network"], "unavailable")

    def test_asn_from_existing_geo_record(self):
        geo = {"hops": [{"ip": "45.33.32.156", "asn": "AS32934 Facebook, Inc.", "isp": "Facebook, Inc."}]}
        r = oi.infrastructure_profile(["45.33.32.156"], geo)[0]
        self.assertEqual((r["ASN"], r["AS organization"]), ("AS32934", "Facebook, Inc."))
        a = oi.assess_origin({"received_chain": CLEAN}, geo)
        self.assertEqual((a["route"][0]["asn"], a["route"][0]["as_org"]), ("AS32934", "Facebook, Inc."))

    def test_split_asn_edge_cases(self):
        self.assertEqual(oi._split_asn("AS15169"), ("AS15169", None))
        self.assertEqual(oi._split_asn(""), (None, None))
        self.assertEqual(oi._split_asn(None), (None, None))
        self.assertEqual(oi._split_asn("garbage"), (None, None))

    def test_corroboration_headers_only_and_large_body(self):
        raw = b"X-Originating-IP: [45.33.32.156]\r\n\r\n" + b"A" * 5_000_000
        self.assertEqual(oi.header_corroboration(raw), [("45.33.32.156", "X-Originating-IP")])
        self.assertEqual(oi.header_corroboration(None), [])
        self.assertEqual(oi.header_corroboration(b"\xff\xfe not a mail"), [])

    def test_asn_diagnostic_is_specific(self):
        msg = oi.asn_diagnostic(["45.33.32.156"], {"45.33.32.156": "local cache"})
        for part in ("45.33.32.156", "local cache", "GeoLite2-ASN.mmdb", "maxminddb package"):
            self.assertIn(part, msg)
        self.assertEqual(set(oi.geodb_status()), {"dir", "maxminddb", "asn_db", "city_db"})

    def test_headline_plain_language(self):
        a = oi.assess_origin({"received_chain": CLEAN, "from_addr": "a@sender-example.com"}, GEO)
        title, text = oi.headline(a)
        self.assertIn("45.33.32.156", title); self.assertIn("confidence", title)
        self.assertIn("no routing inconsistencies", text)
        t2, x2 = oi.headline(oi.assess_origin({}, {}))
        self.assertIn("could not be determined", t2)
        chain = [c.replace("mx.google.com", "mx.other-example.net") for c in CLEAN]
        a = oi.assess_origin({"received_chain": chain, "from_addr": "ceo@gmail.com"}, GEO)
        self.assertIn("flagged (highest: medium)", oi.headline(a)[1])

    def test_ipv6_hop(self):
        h = oi.parse_received("from mx.example.com (mx.example.com [IPv6:2606:4700:4700::1111]) by r.org with ESMTP; Mon, 5 Oct 2026 10:00:00 +0000")
        self.assertEqual(h["from_ip"], "2606:4700:4700::1111")
        self.assertTrue(oi.is_public_ip(h["from_ip"]))

    def test_duplicate_ip_and_missing_timestamps(self):
        chain = ["from a.example.com (a.example.com [45.33.32.156]) by b.example.com with SMTP",
                 "from b.example.com (b.example.com [45.33.32.156]) by c.rcpt.org with SMTP"]
        a = oi.assess_origin({"received_chain": chain}, {})
        self.assertEqual(a["selected_ip"], "45.33.32.156"); self.assertEqual(len(a["alternatives"]), 0)

    def test_no_input_mutation(self):
        import copy
        p = {"received_chain": list(CLEAN), "from_addr": "a@x.com"}; g = copy.deepcopy(GEO); p0 = copy.deepcopy(p)
        oi.assess_origin(p, g); self.assertEqual((p, g), (p0, GEO))

    def test_markdown_pipe_escape_and_sections(self):
        chain = [CLEAN[0].replace("mail-out.sender-example.com [", "a|b.example.com [")]
        a = oi.assess_origin({"received_chain": chain}, GEO)
        md = oi.to_markdown(a, oi.infrastructure_profile(oi.route_ips(a), GEO))
        for s in ("Confidence", "Supporting indicators", "Limitations", "Intelligence sources", "NOT the sender's physical location"):
            self.assertIn(s, md)
        self.assertNotIn("a|b", md)

    def test_empty_inputs(self):
        self.assertIn("No origin assessment", oi.to_markdown(oi.assess_origin({}, {})))
        self.assertIn("No origin assessment", oi.to_markdown(None))

if __name__ == "__main__":
    unittest.main(verbosity=2)