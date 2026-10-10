import unittest
from datetime import datetime, timezone
import domain_intel as di

NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

BOOT = {"services": [[["com", "net"], ["https://rdap.example-registry.org/"]], [["xyz"], ["http://insecure.example.org/"]]]}


def rdap_obj(created="2026-10-01T00:00:00Z", expires="2027-10-01T00:00:00Z", ns=("ns1.evil-example.com",), status=("active",)):
    return {"events": [{"eventAction": "registration", "eventDate": created},
                       {"eventAction": "expiration", "eventDate": expires},
                       {"eventAction": "last changed", "eventDate": "2026-10-05T00:00:00Z"}],
            "nameservers": [{"ldhName": n.upper()} for n in ns], "status": list(status),
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc"]]],
                          "publicIds": [{"type": "IANA Registrar ID", "identifier": "1234"}]}]}


def make_fetch(zone, rdap=None, rdap_error=None, calls=None):
    """zone: {(name, type): ("ok"|"nx", [(type_num, data, ttl)])}"""
    def fetch(url, headers=None):
        if calls is not None:
            calls.append(url)
        if url.startswith(di.DOH_ENDPOINT):
            import urllib.parse as up
            q = dict(up.parse_qsl(up.urlsplit(url).query))
            st, ans = zone.get((q["name"], q["type"]), ("ok", []))
            return {"Status": 3 if st == "nx" else 0,
                    "Answer": [{"name": q["name"], "type": t, "TTL": ttl, "data": d} for t, d, ttl in ans]}
        if url == di.RDAP_BOOTSTRAP:
            return BOOT
        if "/domain/" in url:
            if rdap_error:
                raise rdap_error
            return rdap
        raise AssertionError("unexpected url " + url)
    return fetch


EVIL_ZONE = {
    ("evil-example.com", "A"): ("ok", [(1, "45.33.32.9", 60)]),
    ("evil-example.com", "NS"): ("ok", [(2, "ns1.evil-example.com.", 300)]),
    ("evil-example.com", "TXT"): ("ok", [(16, '"v=spf1 +all"', 300)]),
    ("evil-example.com", "MX"): ("ok", []),
}


class T(unittest.TestCase):
    # ---- untrusted input ----
    def test_normalize_accepts_good(self):
        self.assertEqual(di.normalize_domain("Example.COM."), "example.com")
        self.assertEqual(di.normalize_domain("bücher.example.org"), "xn--bcher-kva.example.org")

    def test_normalize_rejects_unsafe(self):
        for bad in ("localhost", "intranet.corp", "printer.local", "10.0.0.5", "169.254.169.254", "[::1]", "a", "foo",
                    "http://x.com", "user@x.com", "x.com:8080", "x.com/path", "x.com?q=1", "bad_label.com", "a b.com",
                    "-x.com", "x..com", "x" * 64 + ".com", ("a." * 130) + "com", "metadata.internal", "x.onion", "1.2.3.4.5",
                    "x.com\r\nHost: y", "", None, 5, "evil.com#", "x.123"):
            self.assertIsNone(di.normalize_domain(bad), bad)

    def test_registrable(self):
        self.assertEqual(di.registrable("mail.evil.com"), "evil.com")
        self.assertEqual(di.registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(di.registrable("example.com"), "example.com")

    def test_fetch_refuses_non_https_and_internal(self):
        for url in ("http://example.com/x", "https://127.0.0.1/x", "https://localhost/x", "https://u:p@example.com/x",
                    "https://example.com:8443/x", "file:///etc/passwd", "https://169.254.169.254/latest"):
            with self.assertRaises(di.LookupFailure) as c:
                di.fetch_json(url)
            self.assertEqual(c.exception.kind, "blocked", url)

    def test_redirect_to_internal_blocked(self):
        h = di._SafeRedirect()
        with self.assertRaises(di.LookupFailure):
            h.redirect_request(None, None, 302, "x", {}, "https://127.0.0.1/admin")
        with self.assertRaises(di.LookupFailure):
            h.redirect_request(None, None, 302, "x", {}, "http://example.com/")

    def test_invalid_domain_never_queries(self):
        calls = []
        r = di.dns_lookup("10.0.0.1", make_fetch({}, calls=calls))
        self.assertEqual(calls, []); self.assertTrue(r["errors"])
        r2 = di.rdap_lookup("localhost", make_fetch({}, calls=calls))
        self.assertEqual(calls, []); self.assertEqual(r2["state"], "error")

    # ---- collection ----
    def test_collect_domains_roles_and_cap(self):
        parsed = {"from_addr": "Boss <ceo@Evil-Example.com>", "reply_to": "x@other.net", "return_path": "<b@evil-example.com>"}
        iocs = {"urls": [{"url": "http://login.evil-example.com/a", "host": "login.evil-example.com"}, {"url": "http://10.0.0.1/x"}],
                "domains": ["evil-example.com", "third.org", "localhost"]}
        doms, skipped = di.collect_domains(parsed, iocs)
        names = [d["domain"] for d in doms]
        self.assertEqual(names[:3], ["evil-example.com", "other.net", "login.evil-example.com"])
        self.assertEqual(doms[0]["roles"], ["From", "Return-Path", "Body domain"])
        self.assertNotIn("localhost", names); self.assertNotIn("10.0.0.1", names)
        many = {"domains": [f"d{i}.example.org" for i in range(20)]}
        d2, sk = di.collect_domains({}, many); self.assertEqual((len(d2), sk), (di.MAX_DOMAINS, 12))
        self.assertEqual(di.collect_domains(None, None), ([], 0))

    # ---- DNS ----
    def test_dns_parses_records(self):
        zone = {("evil-example.com", "MX"): ("ok", [(15, "10 mail.evil-example.com.", 300)]),
                ("evil-example.com", "TXT"): ("ok", [(16, '"v=spf1 ip4:45.33.32.0/24 " "-all"', 300)]),
                ("evil-example.com", "CNAME"): ("ok", [(5, "x.cdn.net.", 60)]),
                ("evil-example.com", "AAAA"): ("ok", [(28, "2606:4700:4700::1111", 60)]),
                ("_dmarc.evil-example.com", "TXT"): ("ok", [(16, '"v=DMARC1; p=none"', 300)])}
        r = di.dns_lookup("evil-example.com", make_fetch(zone), want_dmarc=True, now=NOW)
        self.assertEqual(r["records"]["MX"][0], {"value": "mail.evil-example.com", "priority": 10, "ttl": 300})
        self.assertTrue(r["records"]["TXT"][0]["value"].startswith("v=spf1 ip4:45.33.32.0/24 -all"))
        self.assertEqual(r["records"]["CNAME"][0]["value"], "x.cdn.net")
        self.assertEqual(r["dmarc"][0]["value"], "v=DMARC1; p=none")
        self.assertEqual(r["looked_up_at"], "2026-10-10 12:00:00 UTC")

    def test_dns_nxdomain_and_failures_graceful(self):
        r = di.dns_lookup("gone-example.com", make_fetch({("gone-example.com", t): ("nx", []) for t in di.RECORD_TYPES}))
        self.assertTrue(r["nxdomain"])

        def boom(url, headers=None):
            raise di.LookupFailure("rate_limited", "429")
        r2 = di.dns_lookup("evil-example.com", boom)
        self.assertFalse(r2["nxdomain"]); self.assertTrue(r2["errors"])
        self.assertTrue(all(v.startswith("error:rate_limited") for v in r2["status"].values() if v.startswith("error")))

    # ---- RDAP ----
    def test_rdap_parse(self):
        r = di.rdap_lookup("mail.evil-example.com", make_fetch({}, rdap_obj()), now=NOW)
        d = r["data"]
        self.assertEqual((r["state"], r["queried"]), ("ok", "evil-example.com"))
        self.assertEqual((d["registrar"], d["registrar_iana_id"], d["created"], d["age_days"]), ("Example Registrar Inc", "1234", "2026-10-01", 9))
        self.assertEqual(d["nameservers"], ["ns1.evil-example.com"]); self.assertEqual(d["status"], ["active"])
        self.assertIn("rdap.example-registry.org", r["source"])

    def test_rdap_states(self):
        nf = di.rdap_lookup("evil-example.com", make_fetch({}, rdap_error=di.LookupFailure("http_error", "HTTP 404")), now=NOW)
        self.assertEqual(nf["state"], "not_found")
        rl = di.rdap_lookup("evil-example.com", make_fetch({}, rdap_error=di.LookupFailure("rate_limited", "429")), now=NOW)
        self.assertEqual(rl["state"], "rate_limited")
        ns = di.rdap_lookup("evil-example.org", make_fetch({}), now=NOW)
        self.assertEqual(ns["state"], "no_service")
        insecure = di.rdap_lookup("evil-example.xyz", make_fetch({}), now=NOW)   # http-only service is refused
        self.assertEqual(insecure["state"], "no_service")
        self.assertEqual(di.parse_rdap({}, NOW)["registrar"], None)

    def test_rdap_bad_bootstrap_host_refused(self):
        di._BOOT["data"] = None
        bad = {"services": [[["com"], ["https://127.0.0.1/"]]]}

        def f(url, headers=None):
            return bad if url == di.RDAP_BOOTSTRAP else self.fail("must not query internal host")
        r = di.rdap_lookup("evil-example.com", f, now=NOW)
        self.assertEqual(r["state"], "error")
        di._BOOT["data"] = None

    # ---- analysis ----
    def lookup(self, zone, rdap, roles=("From",), **kw):
        di._BOOT["data"] = None
        return di.lookup_domain("evil-example.com", roles, make_fetch(zone, rdap), now=NOW, **kw)

    def test_young_plus_signals_but_age_alone_not_enough(self):
        rec = self.lookup(EVIL_ZONE, rdap_obj())
        codes = {f["code"] for f in di.analyze([rec], {"origin_ip": "45.33.32.9"})}
        self.assertTrue({"NEW_DOMAIN", "SPF_PERMISSIVE", "SINGLE_NS", "YOUNG_PLUS_SIGNALS"} <= codes, codes)
        # age alone: a clean, young, well-configured domain stays low and never "malicious"
        clean = {("evil-example.com", "A"): ("ok", [(1, "45.33.32.9", 3600)]), ("evil-example.com", "MX"): ("ok", [(15, "10 mx.evil-example.com.", 3600)]),
                 ("evil-example.com", "NS"): ("ok", [(2, "ns1.evil-example.com.", 1), (2, "ns2.evil-example.com.", 1)]),
                 ("evil-example.com", "TXT"): ("ok", [(16, '"v=spf1 include:_spf.x.net -all"', 300)]),
                 ("_dmarc.evil-example.com", "TXT"): ("ok", [(16, '"v=DMARC1; p=reject"', 300)])}
        rec2 = self.lookup(clean, rdap_obj(ns=("ns1.evil-example.com", "ns2.evil-example.com")))
        fl = di.analyze([rec2])
        self.assertEqual({f["code"] for f in fl}, {"NEW_DOMAIN"})
        self.assertEqual(fl[0]["severity"], "low")
        sev, text = di.overall(fl)
        self.assertNotIn("malicious", text.lower()); self.assertIn("not a verdict", text.lower())

    def test_no_mail_path_for_sender_domain(self):
        rec = self.lookup({("evil-example.com", "NS"): ("ok", [(2, "ns1.x.net.", 300), (2, "ns2.x.net.", 300)])}, rdap_obj(created="2015-01-01T00:00:00Z"))
        self.assertIn("NO_MAIL_PATH", {f["code"] for f in di.analyze([rec])})

    def test_old_domain_not_flagged_new(self):
        rec = self.lookup(EVIL_ZONE, rdap_obj(created="2015-01-01T00:00:00Z"))
        self.assertNotIn("NEW_DOMAIN", {f["code"] for f in di.analyze([rec])})

    def test_facts_vs_inferences_labelled(self):
        rec = self.lookup(EVIL_ZONE, rdap_obj())
        fl = di.analyze([rec])
        self.assertTrue(all(f["basis"] in ("fact", "inference") for f in fl))
        self.assertEqual(next(f for f in fl if f["code"] == "NEW_DOMAIN")["basis"], "fact")
        self.assertEqual(next(f for f in fl if f["code"] == "YOUNG_PLUS_SIGNALS")["basis"], "inference")

    def test_nxdomain_sender_flagged_medium(self):
        rec = self.lookup({("evil-example.com", t): ("nx", []) for t in di.RECORD_TYPES}, di.LookupFailure("http_error", "HTTP 404") and None) if False else None
        di._BOOT["data"] = None
        rec = di.lookup_domain("evil-example.com", ("From",), make_fetch({("evil-example.com", t): ("nx", []) for t in di.RECORD_TYPES},
                                                                      rdap_error=di.LookupFailure("http_error", "HTTP 404")), now=NOW)
        f = next(f for f in di.analyze([rec]) if f["code"] == "DOMAIN_NOT_FOUND")
        self.assertEqual(f["severity"], "medium")

    def test_lookup_failure_yields_no_false_findings(self):
        def boom(url, headers=None):
            raise di.LookupFailure("unavailable", "offline")
        di._BOOT["data"] = None
        rec = di.lookup_domain("evil-example.com", ("From",), boom, now=NOW)
        codes = {f["code"] for f in di.analyze([rec])}
        self.assertEqual(rec["rdap"]["state"], "error")
        self.assertNotIn("DOMAIN_NOT_FOUND", codes); self.assertNotIn("NO_MAIL_PATH", codes)

    def test_identity_mismatch_and_route_correlation(self):
        a = self.lookup(EVIL_ZONE, rdap_obj(created="2015-01-01T00:00:00Z"))
        di._BOOT["data"] = None
        b = di.lookup_domain("reply-example.net", ("Reply-To",), make_fetch(
            {("reply-example.net", "A"): ("ok", [(1, "151.101.1.7", 300)])}, rdap_obj(created="2026-09-20T00:00:00Z")), now=NOW)
        fl = di.analyze([a, b], {"route_ips": ["45.33.32.9"]})
        codes = {f["code"] for f in fl}
        self.assertIn("REPLYTO_MISMATCH", codes); self.assertIn("IP_IN_ROUTE", codes)
        self.assertEqual(next(f for f in fl if f["code"] == "REPLYTO_MISMATCH")["severity"], "medium")  # young reply-to

    def test_spf_origin_logic(self):
        z = dict(EVIL_ZONE); z[("evil-example.com", "TXT")] = ("ok", [(16, '"v=spf1 ip4:45.33.32.0/24 -all"', 300)])
        rec = self.lookup(z, rdap_obj(created="2015-01-01T00:00:00Z"))
        inside = {f["code"] for f in di.analyze([rec], {"origin_ip": "45.33.32.50"})}
        outside = {f["code"] for f in di.analyze([rec], {"origin_ip": "151.101.1.1"})}
        self.assertIn("ORIGIN_IN_SPF", inside); self.assertNotIn("ORIGIN_NOT_IN_SPF", inside)
        self.assertIn("ORIGIN_NOT_IN_SPF", outside)
        z[("evil-example.com", "TXT")] = ("ok", [(16, '"v=spf1 ip4:45.33.32.0/24 include:_spf.google.com -all"', 300)])
        rec = self.lookup(z, rdap_obj(created="2015-01-01T00:00:00Z"))
        self.assertNotIn("ORIGIN_NOT_IN_SPF", {f["code"] for f in di.analyze([rec], {"origin_ip": "151.101.1.1"})})

    def test_private_ip_record_and_history(self):
        z = {("evil-example.com", "A"): ("ok", [(1, "10.1.2.3", 300), (1, "45.33.32.9", 300)])}
        rec = self.lookup(z, rdap_obj(created="2015-01-01T00:00:00Z"))
        fl = di.analyze([rec], history={"45.33.32.9": (3, 88.0)})
        codes = {f["code"] for f in fl}
        self.assertIn("PRIVATE_IP_RECORD", codes)
        self.assertEqual(next(f for f in fl if f["code"] == "IP_IN_THREAT_MEMORY")["severity"], "medium")

    def test_threat_memory_domain(self):
        rec = self.lookup(EVIL_ZONE, rdap_obj(created="2015-01-01T00:00:00Z"))
        mem = {"evil-example.com": {"observations": 3, "reputation": 0.9, "first_seen": "2026-09-01", "last_seen": "2026-10-05", "source": "urlhaus"}}
        f = next(f for f in di.analyze([rec], memory=mem) if f["code"] == "DOMAIN_IN_THREAT_MEMORY")
        self.assertEqual((f["severity"], f["basis"]), ("medium", "fact"))
        mem["evil-example.com"].update(reputation=0.5)
        self.assertEqual(next(f for f in di.analyze([rec], memory=mem) if f["code"] == "DOMAIN_IN_THREAT_MEMORY")["severity"], "info")
        mem["evil-example.com"].update(observations=1)
        self.assertNotIn("DOMAIN_IN_THREAT_MEMORY", {f["code"] for f in di.analyze([rec], memory=mem)})

    def test_entity_graph_links_different_domains_by_ip(self):
        import sys, types
        for m in ("plotly", "plotly.graph_objects"):
            sys.modules.setdefault(m, types.ModuleType(m))
        import correlate
        def case(name, dom, ip):
            return {"name": name, "_evidence_hash": name, "level": "phishing", "score": 90,
                    "parsed": {"from_addr": "a@" + dom}, "iocs": {"domains": [dom]}, "geo": {"origin": {"ip": "151.101.1.1"}},
                    "domain_dns": [{"domain": dom, "ips": [ip]}]}
        G = correlate.build_graph([case("m1", "one-example.com", "45.33.32.156"), case("m2", "two-example.net", "45.33.32.156"),
                                   {"name": "m3", "_evidence_hash": "m3", "parsed": {}, "iocs": {}, "geo": {}}])
        shared = {(s["kind"], s["indicator"]): s["cases"] for s in correlate.shared_indicators(G)}
        self.assertEqual(sorted(shared[("ip", "45.33.32.156")]), ["m1", "m2"])
        self.assertEqual(G.edges["domain:one-example.com", "ip:45.33.32.156"]["rel"], "resolves to")
        self.assertEqual(G.edges["case:m1", "ip:151.101.1.1"]["rel"], "originated at")   # untouched
        # a domain IP equal to the origin IP must not overwrite "originated at"
        c = case("m4", "x-example.org", "151.101.1.1")
        G2 = correlate.build_graph([c]); self.assertEqual(G2.edges["case:m4", "ip:151.101.1.1"]["rel"], "originated at")
        # cases without domain_dns behave exactly as before
        G3 = correlate.build_graph([{k: v for k, v in c.items() if k != "domain_dns"}])
        self.assertNotIn("resolves to", {d["rel"] for _, _, d in G3.edges(data=True)})

    # ---- cache / batch ----
    def test_cache_and_ratelimit_batch(self):
        calls, cache = [], {}
        di._BOOT["data"] = None
        f = make_fetch(EVIL_ZONE, rdap_obj(), calls=calls)
        di.lookup_domain("evil-example.com", ("From",), f, cache, NOW)
        n = len(calls)
        again = di.lookup_domain("evil-example.com", ("From",), f, cache, NOW)
        self.assertEqual(len(calls), n); self.assertTrue(again["cached"])
        di._BOOT["data"] = None
        lim = make_fetch(EVIL_ZONE, rdap_error=di.LookupFailure("rate_limited", "429"))
        out = di.lookup_all([{"domain": "a-example.com", "roles": ["From"]}, {"domain": "b-example.com", "roles": ["Link host"]}], lim, None, NOW)
        self.assertEqual(out[0]["rdap"]["state"], "rate_limited")
        self.assertIn("skipped", out[1]["rdap"]["error"])

    # ---- correlation ----
    def test_session_correlation_and_shared_infra(self):
        rec = self.lookup(EVIL_ZONE, rdap_obj())
        other_case = {"name": "other", "_evidence_hash": "h2", "level": "phishing", "score": 91,
                      "parsed": {"from_addr": "x@evil-example.com"}, "iocs": {"domains": ["sub.evil-example.com"]}}
        me = {"name": "me", "_evidence_hash": "h1", "parsed": {"from_addr": "a@evil-example.com"}}
        sib = {"domain": "sibling-example.net", "dns": {"records": {"A": [{"value": "45.33.32.9"}], "NS": [{"value": "ns1.evil-example.com"}],
                                                                    "MX": [], "AAAA": [], "TXT": [], "CNAME": []}}, "rdap": {"data": {"registrar": "Example Registrar Inc", "created": "2026-10-01"}}}
        rows = di.correlate([rec], [me, other_case], "me", "h1", cache={("sibling-example.net", ""): {"_t": 0, "rec": sib}})
        rel = {r["Relation"] for r in rows}
        self.assertTrue({"same domain", "shared IP", "shared name server", "same registrar + creation date"} <= rel, rel)
        self.assertEqual(sum(1 for r in rows if r["Other email"] == "other"), 2)
        self.assertFalse(any(r["Other email"] == "me" for r in rows))

    def test_ip_rows_reuse_geo_and_never_invent(self):
        rec = self.lookup(EVIL_ZONE, rdap_obj())
        geo = {"hops": [{"ip": "45.33.32.9", "asn": "AS64500 ExampleNet", "infra_label": "Datacenter"}]}
        r = di.ip_rows([rec], geo, {"45.33.32.9": (2, 80.0)}, asn_fn=lambda ip: (None, None))[0]
        self.assertEqual((r["ASN"], r["Network"], r["Infrastructure"]), ("AS64500", "ExampleNet", "Datacenter"))
        self.assertIn("2 sighting", r["Threat memory"])
        r2 = di.ip_rows([rec], {}, None, asn_fn=lambda ip: (None, None))[0]
        self.assertEqual((r2["ASN"], r2["Network"]), ("unavailable", "unavailable"))

    # ---- markdown ----
    def test_markdown(self):
        rec = self.lookup(EVIL_ZONE, rdap_obj())
        rec["roles"] = ["From|x"]
        fl = di.analyze([rec])
        md = di.to_markdown([rec], fl, di.ip_rows([rec], {}, None, asn_fn=lambda i: (None, None)), [], 2)
        for s in ("Summary", "DNS records and registration", "Indicators", "verified fact", "inference", "Limitations", "2 further domain"):
            self.assertIn(s, md)
        self.assertNotIn("From|x", md)
        self.assertIn("No domain & DNS lookup was run", di.to_markdown([], []))

    def test_no_input_mutation(self):
        import copy
        rec = self.lookup(EVIL_ZONE, rdap_obj()); r0 = copy.deepcopy(rec)
        di.analyze([rec]); self.assertEqual(rec, r0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
