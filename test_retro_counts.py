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
        self.assertEqual(R.counts([]), {"emails": 0, "email_rows": 0, "intel": 0, "intel_feed": 0, "log": 0})

if __name__ == "__main__":
    unittest.main()

class FeedSplit(unittest.TestCase):
    def test_local_sightings_not_counted_as_feed(self):
        row = lambda src: {"Source": "Threat memory", "Where": f"observed via {src} (reputation 0.30)"}
        c = R.counts([row("local_analysis"), row("URLhaus")])
        self.assertEqual((c["intel"], c["intel_feed"]), (2, 1))
