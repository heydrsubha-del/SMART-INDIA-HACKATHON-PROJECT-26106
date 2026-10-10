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
        z = rh.summary([], 3)
        for part in ("Hunted 3", "0 email(s)", "threat-memory indicator records: 0", "Scored-email log entries: 0", "No earlier sighting"):
            self.assertIn(part.lower(), z.lower())
        rows = rh.hunt_memory([("domain", "evil-example.com")], [db()]); rows[0]["Where"] = "a|b"
        md = rh.to_markdown(rows, 1)
        self.assertIn("not 'malicious'", md); self.assertNotIn("a|b", md); self.assertIn("| Source |", md)

class Dedup(unittest.TestCase):
    def mk(self, n, **kw):
        return dict({"name": n, "_evidence_hash": n, "level": "phishing", "score": 90, "parsed": {}, "iocs": {}, "geo": {}}, **kw)

    def test_one_email_one_sighting_per_artifact(self):
        # origin IP is also a relay hop; host matches both exact and registrable indicators; email supplied twice
        c = self.mk("c1", parsed={"from_addr": "b@mail.evil-example.com"}, iocs={"domains": ["mail.evil-example.com"]},
                    geo={"origin": {"ip": "45.33.32.156"}, "hops": [{"ip": "45.33.32.156"}]})
        inds = [("domain", "mail.evil-example.com"), ("domain", "evil-example.com"), ("ip", "45.33.32.156")]
        rows = rh.hunt_cases(inds, [c, dict(c), self.mk("me")], "me", "me")
        self.assertEqual(len(rows), 2)
        dom = next(r for r in rows if r["Type"] == "domain"); ip = next(r for r in rows if r["Type"] == "ip")
        self.assertEqual((dom["Indicator"], dom["Match"]), ("mail.evil-example.com", "exact"))   # most specific kept
        self.assertIn("From", dom["Where"]); self.assertIn("Body domain", dom["Where"])           # fields merged
        self.assertIn("Origin IP", ip["Where"]); self.assertIn("Relay hop", ip["Where"])

    def test_distinct_emails_stay_distinct(self):
        a = self.mk("a", parsed={"from_addr": "x@evil-example.com"}); b = self.mk("b", parsed={"from_addr": "y@evil-example.com"}, score=40)
        rows = rh.hunt_cases([("domain", "evil-example.com")], [a, b], "me", "me")
        self.assertEqual([r["Where"].split(" (")[0] for r in rows], ["a", "b"])

    def test_memory_dedup_keeps_distinct_records(self):
        d1, d2 = db(), db()
        d2.execute("UPDATE threat_intel SET last_seen='2026-10-09', observations=7 WHERE indicator='evil-example.com'")
        inds = [("domain", "evil-example.com"), ("domain", "login.evil-example.com")]
        same = rh.hunt_memory(inds, [d1, db()])                     # identical record in two stores -> once
        self.assertEqual(sum(1 for r in same if r["Indicator"] == "evil-example.com"), 1)
        self.assertEqual(sum(1 for r in same if r["Indicator"] == "login.evil-example.com"), 1)   # reached by 2 indicators -> once
        diff = rh.hunt_memory(inds, [d1, d2])                       # same indicator, different counts/dates -> both kept
        self.assertEqual(sum(1 for r in diff if r["Indicator"] == "evil-example.com"), 2)
        self.assertEqual({r["Last seen"] for r in diff if r["Indicator"] == "evil-example.com"}, {"2026-10-05", "2026-10-09"})
        self.assertEqual(len([r for r in rh.hunt_memory([("ip", "45.33.32.156")], [d1, db()]) if r["Source"] == "Scored-email log"]), 1)

    def test_own_analysis_is_not_a_prior_sighting(self):
        own = {("domain", "evil-example.com"), ("url", "http://login.evil-example.com/a")}
        rows = rh.hunt_memory([("domain", "evil-example.com")], [db()], self_indicators=own)
        by = {r["Indicator"]: r for r in rows}
        self.assertEqual(by["evil-example.com"]["Times"], 3)                     # 4 observations - this email's own
        self.assertEqual(by["http://login.evil-example.com/a"]["Times"], 1)      # 2 - 1
        self.assertEqual(by["login.evil-example.com"]["Times"], 1)               # not this email's own record: untouched
        c = db(); c.execute("UPDATE threat_intel SET observations=1 WHERE indicator='evil-example.com'")
        rows = rh.hunt_memory([("domain", "evil-example.com")], [c], self_indicators=own)
        self.assertNotIn("evil-example.com", {r["Indicator"] for r in rows})     # only this email recorded it -> no sighting

    def test_summary_counts_match_rows_and_never_contradict(self):
        cases = [self.mk("c1", parsed={"from_addr": "b@evil-example.com"})]
        rows = rh.hunt([("domain", "evil-example.com"), ("ip", "45.33.32.156")], cases, [db()], "me", "me")
        c = rh.counts(rows)
        self.assertEqual(c["emails"], 1)
        self.assertEqual(c["intel"], sum(1 for r in rows if r["Source"] == "Threat memory"))
        self.assertEqual(c["log"], 1)
        text = rh.summary(rows, 2)
        self.assertIn("1 email(s)", text); self.assertIn(f"Threat-memory indicator records: {c['intel']}", text)
        self.assertNotIn("No earlier sighting", text)
        empty = rh.summary(rh.hunt([("ip", "9.9.9.9")], [], [db()], "me", "me"), 1)
        self.assertIn("Earlier emails this session: 0", empty); self.assertIn("No earlier sighting", empty)


if __name__ == "__main__":
    unittest.main()