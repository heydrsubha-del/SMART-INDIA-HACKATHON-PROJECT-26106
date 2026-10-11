import unittest, retro_hunt as R

class T(unittest.TestCase):
    def test_email_name_with_parentheses_counted_once(self):
        case = {"name": "invoice (1).eml", "_evidence_hash": "h", "parsed": {"from_domain": "evil.example"},
                "iocs": {}, "geo": {"origin": {"ip": "203.0.113.9"}, "hops": [{"ip": "203.0.113.9"}]}}
        rows = R.hunt_cases([("domain", "evil.example"), ("ip", "203.0.113.9")], [case], current_name="cur")
        c = R.counts(rows)
        self.assertEqual(c["emails"], 1)
        self.assertEqual(c["email_rows"], len(rows))
        self.assertEqual(len(rows), 2)   # origin IP + hop IP merged into one sighting

    def test_current_email_not_counted_and_empty(self):
        case = {"name": "cur", "_evidence_hash": "h", "parsed": {"from_domain": "evil.example"}}
        self.assertEqual(R.hunt_cases([("domain", "evil.example")], [case], "cur", "h"), [])
        self.assertEqual(R.counts([]), {"emails": 0, "email_rows": 0, "intel": 0, "intel_local": 0, "intel_feed": 0,
                                        "intel_community": 0, "intel_unknown": 0, "log": 0})

if __name__ == "__main__":
    unittest.main()

class FeedSplit(unittest.TestCase):
    def test_local_sightings_not_counted_as_feed(self):
        row = lambda src: {"Source": "Threat memory", "Where": f"observed via {src} (reputation 0.30)"}
        c = R.counts([row("local_analysis"), row("URLhaus")])
        self.assertEqual((c["intel"], c["intel_feed"]), (2, 1))


class SourceClasses(unittest.TestCase):
    def row(self, src, cls=None):
        r = {"Source": "Threat memory", "Where": f"observed via {src} (reputation 0.30)"}
        if cls:
            r["Class"] = cls
        return r

    def test_classify_source(self):
        for src, want in (("local_analysis", "local"), ("LOCAL_ANALYSIS", "local"), ("urlhaus", "external_feed"),
                          ("URLhaus", "external_feed"), ("community", "community"), ("Community:verified", "community"),
                          ("community_reviewed", "community"), ("?", "unknown"), ("", "unknown"), (None, "unknown"),
                          ("someotherfeed", "unknown"), ("communityfeed", "unknown")):
            self.assertEqual(R.classify_source(src), want, src)

    def test_four_way_counts_and_total(self):
        rows = [self.row("local_analysis"), self.row("local_analysis"), self.row("URLhaus"), self.row("community"),
                self.row("community:verified"), self.row("mystery-feed"), self.row("?")]
        c = R.counts(rows)
        self.assertEqual((c["intel"], c["intel_local"], c["intel_feed"], c["intel_community"], c["intel_unknown"]), (7, 2, 1, 2, 2))
        self.assertEqual(c["intel"], c["intel_local"] + c["intel_feed"] + c["intel_community"] + c["intel_unknown"])

    def test_community_never_counts_as_external_feed(self):
        c = R.counts([self.row("community"), self.row("community:verified")])
        self.assertEqual((c["intel_feed"], c["intel_community"]), (0, 2))

    def test_unknown_source_not_silently_a_feed(self):
        c = R.counts([self.row("never-heard-of-it"), {"Source": "Threat memory", "Where": "unknown via ? (reputation 0.10)"},
                      {"Source": "Threat memory", "Where": "no source text at all"}])
        self.assertEqual((c["intel_feed"], c["intel_unknown"]), (0, 3))

    def test_stored_class_wins_over_text(self):
        self.assertEqual(R.counts([self.row("urlhaus", cls="community")])["intel_feed"], 0)

    def test_summary_never_presents_community_as_confirmed(self):
        text = R.summary([self.row("community")] * 2, 1)
        self.assertIn("2 community-reported and not confirmed malicious", text)
        self.assertIn("0 from known external feeds", text)
        self.assertIn("not 'malicious'", text)

    def test_hunt_memory_rows_carry_class_end_to_end(self):
        import sqlite3
        c = sqlite3.connect(":memory:")
        c.execute("CREATE TABLE threat_intel (id INTEGER PRIMARY KEY AUTOINCREMENT, indicator TEXT, indicator_type TEXT, reputation REAL, category TEXT, first_seen TEXT, last_seen TEXT, observations INTEGER, source TEXT)")
        c.execute("CREATE TABLE attackers (date TEXT, ip TEXT, country TEXT, score REAL, verdict TEXT)")
        for i, src in enumerate(("local_analysis", "urlhaus", "community", "weird")):
            c.execute("INSERT INTO threat_intel (indicator,indicator_type,reputation,category,first_seen,last_seen,observations,source) VALUES (?,?,?,?,?,?,?,?)",
                      (f"d{i}.example.org", "domain", .5, "x", "a", "b", 2, src))
        rows = []
        for i in range(4):
            rows += R.hunt_memory([("domain", f"d{i}.example.org")], [c])
        k = R.counts(rows)
        self.assertEqual((k["intel_local"], k["intel_feed"], k["intel_community"], k["intel_unknown"]), (1, 1, 1, 1))