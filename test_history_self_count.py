"""Retro-Hunt self-exclusion against the REAL tracker.py (temporary SQLite file)."""
import os, sqlite3, tempfile, unittest

import retro_hunt as R
import tracker as T


class SelfCount(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._db = T.DB_FILE
        T.DB_FILE = os.path.join(self.dir, "mem.db")
        T._INDICATOR_CACHE.clear(); T._LOOKUP_CACHE.clear(); T._SCHEMA_DONE.clear()

    def tearDown(self):
        T.DB_FILE = self._db
        T._INDICATOR_CACHE.clear(); T._LOOKUP_CACHE.clear(); T._SCHEMA_DONE.clear()

    def hunt(self, self_rec):
        conn = sqlite3.connect(T.DB_FILE)
        try:
            return R.hunt_memory([("domain", "evil.example")], [conn], None, self_rec)
        finally:
            conn.close()

    def test_remember_returns_whether_an_observation_was_written(self):
        self.assertTrue(T.remember_indicator("evil.example", "domain", 0.5))
        self.assertFalse(T.remember_indicator("evil.example", "domain", 0.5))   # in-process repeat
        self.assertFalse(T.remember_indicator("", "domain", 0.5))

    def test_first_email_own_observation_is_not_an_earlier_sighting(self):
        rec = {("domain", "evil.example")} if T.remember_indicator("evil.example", "domain", 0.5) else set()
        self.assertEqual(self.hunt(rec), [])

    def test_second_email_in_same_process_sees_the_earlier_sighting(self):
        T.remember_indicator("evil.example", "domain", 0.5)                   # email A recorded it (obs=1)
        recorded_b = {("domain", "evil.example")} if T.remember_indicator("evil.example", "domain", 0.5) else set()
        self.assertEqual(recorded_b, set())                                   # B wrote nothing (cache hit)
        rows = self.hunt(recorded_b)
        self.assertEqual([r["Times"] for r in rows], [1])                     # A's sighting is reported
        # legacy assumption (always subtract one) would have hidden it:
        self.assertEqual(self.hunt({("domain", "evil.example")}), [])

    def test_prior_runs_plus_current_email(self):
        T.remember_indicator("evil.example", "domain", 0.5)                   # earlier run
        T._INDICATOR_CACHE.clear()                                            # new process
        rec = {("domain", "evil.example")} if T.remember_indicator("evil.example", "domain", 0.5) else set()
        self.assertEqual([r["Times"] for r in self.hunt(rec)], [1])           # obs=2, minus own 1

    def test_same_indicator_twice_in_one_email_is_one_observation(self):
        got = [T.remember_indicator("evil.example", "domain", 0.5) for _ in range(2)]
        self.assertEqual(got, [True, False])


if __name__ == "__main__":
    unittest.main()
