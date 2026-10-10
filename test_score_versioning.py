"""Cached URL scores must not outlive the heuristics that produced them (temporary SQLite only)."""
import os, sqlite3, tempfile, unittest

import ioc_extract as X
import tracker as T

URL = "https://accounts.google.com/accountchooser?continue=https%3a%2f%2fexample.org%2f"   # sanitized, lower-case as tracker stores it
V = X.URL_SCORE_VERSION


def rescore(u):
    return X._judge_url(u)["risk"]


class ScoreVersioning(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._db = T.DB_FILE
        T.DB_FILE = os.path.join(self.dir, "mem.db")
        self.reset()

    def tearDown(self):
        T.DB_FILE = self._db
        self.reset()

    def reset(self):
        for c in (T._INDICATOR_CACHE, T._LOOKUP_CACHE, T._SCHEMA_DONE, T._SCORES_REFRESHED):
            c.clear()

    def legacy_db(self):
        """A pre-versioning database: no score_version column, one stale local URL score and unrelated rows."""
        c = sqlite3.connect(T.DB_FILE)
        c.execute("CREATE TABLE threat_intel (id INTEGER PRIMARY KEY AUTOINCREMENT, indicator TEXT NOT NULL, "
                  "indicator_type TEXT NOT NULL, reputation REAL DEFAULT 0.0, category TEXT DEFAULT 'unknown', "
                  "first_seen TEXT, last_seen TEXT, observations INTEGER DEFAULT 1, source TEXT DEFAULT 'local_analysis')")
        c.executemany("INSERT INTO threat_intel (indicator,indicator_type,reputation,category,first_seen,last_seen,"
                      "observations,source) VALUES (?,?,?,?,?,?,?,?)", [
            (URL, "url", 0.5, "observed", "2026-10-01", "2026-10-09", 4, "local_analysis"),
            ("http://bad.example/payload", "url", 1.0, "malware", "2026-09-01", "2026-09-02", 1, "urlhaus"),
            ("old-domain.example", "domain", 0.5, "observed", "2026-09-05", "2026-09-06", 2, "local_analysis"),
        ])
        c.commit(); c.close()

    def row(self, indicator):
        c = sqlite3.connect(T.DB_FILE)
        try:
            return c.execute("SELECT reputation, observations, first_seen, source, score_version FROM threat_intel "
                             "WHERE indicator = ?", (indicator,)).fetchone()
        finally:
            c.close()

    def test_legacy_database_is_migrated_without_losing_rows(self):
        self.legacy_db()
        T.get_connection().close()
        c = sqlite3.connect(T.DB_FILE)
        cols = [r[1] for r in c.execute("PRAGMA table_info(threat_intel)")]
        n = c.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0]
        c.close()
        self.assertEqual((cols[-1], n), ("score_version", 3))

    def test_refresh_recomputes_only_stale_local_url_scores(self):
        self.legacy_db()
        self.assertEqual(T.refresh_stale_url_scores(rescore, V), 1)
        self.assertEqual(self.row(URL), (0.0, 4, "2026-10-01", "local_analysis", V))            # recomputed, history kept
        self.assertEqual(self.row("http://bad.example/payload"), (1.0, 1, "2026-09-01", "urlhaus", None))
        self.assertEqual(self.row("old-domain.example"), (0.5, 2, "2026-09-05", "local_analysis", None))
        self.assertEqual(T.refresh_stale_url_scores(rescore, V), 0)                              # once per process

    def test_remember_replaces_a_stale_local_score_but_keeps_feed_intelligence(self):
        self.legacy_db()
        T.remember_indicator(URL, "url", 0.0, "observed", "local_analysis", V)
        self.assertEqual(self.row(URL)[0], 0.0)
        self.reset()
        T.remember_indicator("http://bad.example/payload", "url", 0.2, "observed", "local_analysis", V)
        self.assertEqual(self.row("http://bad.example/payload")[0], 1.0)                         # urlhaus 1.0 survives

    def test_same_version_still_never_lowers_evidence(self):
        T.remember_indicator("http://x.example/a", "url", 0.9, "observed", "local_analysis", V)
        self.reset()
        T.remember_indicator("http://x.example/a", "url", 0.1, "observed", "local_analysis", V)
        self.assertEqual(self.row("http://x.example/a")[0], 0.9)

    def test_stored_reputation_ignores_obsolete_local_scores_only(self):
        mk = lambda rep, src, ver: (1, "i", "url", rep, "c", "a", "b", 1, src, ver)
        self.assertIsNone(T.stored_reputation(mk(0.5, "local_analysis", None), V))
        self.assertIsNone(T.stored_reputation(mk(0.5, "local_analysis", V - 1), V))
        self.assertEqual(T.stored_reputation(mk(0.5, "local_analysis", V), V), 0.5)
        self.assertEqual(T.stored_reputation(mk(1.0, "urlhaus", None), V), 1.0)
        self.assertEqual(T.stored_reputation((1, "i", "url", 0.7, "c", "a", "b", 1, "local_analysis"), None), 0.7)


if __name__ == "__main__":
    unittest.main()
