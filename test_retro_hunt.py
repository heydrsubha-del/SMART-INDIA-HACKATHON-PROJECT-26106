import sqlite3, unittest
import retro_hunt as rh


def db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE threat_intel (id INTEGER PRIMARY KEY AUTOINCREMENT, indicator TEXT NOT NULL, indicator_type TEXT NOT NULL, reputation REAL DEFAULT 0.0, category TEXT DEFAULT 'unknown', first_seen TEXT, last_seen TEXT, observations INTEGER DEFAULT 1, source TEXT DEFAULT 'local_analysis')")
    c.execute("CREATE TABLE attackers (date TEXT, ip TEXT, country TEXT, score REAL, verdict TEXT)")
    rows = [("evil-example.com", "domain", .5, "observed", "2026-09-01", "2026-10-05", 4, "local_analysis"),
            ("login.evil-example.com", "domain", .8, "phishing", "2026-09-10", "2026-09-10", 1, "urlhaus"),
            ("notevil-example.com", "domain", .5, "observed", "x", "y", 1, "local_analysis"),   # must NOT match (suffix trap)
            ("http://login.evil-example.com/a", "url", .9, "malware", "2026-09-11", "2026-09-11", 2, "urlhaus"),
            ("http://other.org/?r=evil-example.com", "url", .9, "x", "a", "b", 1, "urlhaus"),   # substring only: must NOT match
            ("45.33.32.156", "ip", .5, "observed", "2026-09-02", "2026-10-01", 3, "local_analysis")]
    c.executemany("INSERT INTO threat_intel (indicator,indicator_type,reputation,category,first_seen,last_seen,observations,source) VALUES (?,?,?,?,?,?,?,?)", rows)
    c.executemany("INSERT INTO attackers VALUES (?,?,?,?,?)", [("2026-09-02 10:00:00", "45.33.32.156", "X", 80, "Phishing"), ("2026-10-01 10:00:00", "45.33.32.156", "X", 91, "Critical")])
    return c


class T(unittest.TestCase):
    def test_indicators(self):
        ind = rh.build_indicators(["Evil-Example.com.", "evil-example.com", "1.2.3.4", ""], ["45.33.32.156", "45.33.32.156", "nope"])
        self.assertEqual(ind, [("domain", "evil-example.com"), ("ip", "45.33.32.156")])

    def test_memory_matches_exact_and_subdomain_only(self):
        rows = rh.hunt_memory([("domain", "evil-example.com")], [db()])
        inds = {(r["Indicator"], r["Match"]) for r in rows}
        self.assertIn(("evil-example.com", "exact"), inds)
        self.assertIn(("login.evil-example.com", "subdomain"), inds)
        self.assertIn(("http://login.evil-example.com/a", "subdomain"), inds)
        self.assertFalse(any("notevil" in r["Indicator"] or "other.org" in r["Indicator"] for r in rows))

    def test_ip_memory_and_self_exclusion(self):
        rows = rh.hunt_memory([("ip", "45.33.32.156")], [db()])
        log = next(r for r in rows if r["Source"] == "Scored-email log")
        self.assertEqual((log["Times"], log["Score"]), (2, 91.0))
        rows = rh.hunt_memory([("ip", "45.33.32.156")], [db()], self_logged_ip="45.33.32.156")
        self.assertEqual(next(r for r in rows if r["Source"] == "Scored-email log")["Times"], 1)

    def test_sql_injection_like_input_is_inert(self):
        rows = rh.hunt_memory([("domain", "x'; DROP TABLE threat_intel;--"), ("domain", "100%_.com")], [db()])
        self.assertEqual(rows, [])

    def test_broken_connection_skipped(self):
        bad = sqlite3.connect(":memory:")   # no tables
        self.assertEqual(rh.hunt_memory([("ip", "1.2.3.4")], [bad, None]), [])
        self.assertEqual(rh.hunt([("ip", "1.2.3.4")], None, [bad]), [])

    def test_cases_hunt(self):
        mk = lambda n, **kw: dict({"name": n, "_evidence_hash": n, "level": "phishing", "score": 90, "parsed": {}, "iocs": {}, "geo": {}}, **kw)
        cases = [mk("me", parsed={"from_addr": "a@evil-example.com"}),
                 mk("c1", parsed={"from_addr": "Boss <b@mail.evil-example.com>"}),
                 mk("c2", iocs={"urls": [{"url": "http://evil-example.com/x"}]}),
                 mk("c3", geo={"origin": {"ip": "45.33.32.156"}}),
                 mk("c4", domain_dns=[{"domain": "zzz-example.net", "ips": ["45.33.32.156"]}]),
                 mk("c5", parsed={"from_addr": "x@unrelated.org"}), {"name": "bad", "error": "x"}]
        rows = rh.hunt_cases([("domain", "evil-example.com"), ("ip", "45.33.32.156")], cases, "me", "me")
        who = {(r["Where"].split(" (")[0], r["Match"]) for r in rows}
        self.assertEqual(who, {("c1", "subdomain"), ("c2", "exact"), ("c3", "exact"), ("c4", "exact")})

    def test_summary_and_markdown(self):
        self.assertIn("no earlier sighting", rh.summary([], 3)); self.assertIn("only means", rh.summary([], 3))
        rows = rh.hunt_memory([("domain", "evil-example.com")], [db()]); rows[0]["Where"] = "a|b"
        md = rh.to_markdown(rows, 1)
        self.assertIn("not 'malicious'", md); self.assertNotIn("a|b", md); self.assertIn("| Source |", md)

if __name__ == "__main__":
    unittest.main()
