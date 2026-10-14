"""Offline. (1) corpus py column vs the REAL indicator_sanitizer; (2) every Python/SQL difference is categorised;
(3) corpus sql columns vs sql_model.py (a Python model - NOT PostgreSQL). Needs AUDIT_DIR (or ./security_audit_inputs) for the model."""
import unittest
from indicator_sanitizer import sanitize_indicator
import sql_model as M
from validation_corpus import R, render_sql, _sql_literal
OK_DIFF = ("INTENTIONAL", "GAP", "DEFERRED", "SQL_WEAKER")

class Corpus(unittest.TestCase):
    def test_python_column_matches_real_sanitizer(self):
        for k, v, py, *_ , note in R:
            r = sanitize_indicator(v, k)
            self.assertEqual(bool(r.ok and r.value == v), bool(py), (k, v, note))
    def test_every_difference_is_categorised(self):
        for k, v, py, _n, new, c, _ in R:
            if bool(py) != bool(new):
                self.assertTrue(c.startswith(OK_DIFF), (v, c))
            else:
                self.assertIn(c, ("PARITY", "GAP1_CLOSED"), (v, c))
            if new and not py:
                self.assertEqual(c, "SQL_WEAKER_UNFIXED", v)     # SQL accepting what Python rejects must be an explicit, known gap
    def test_sql_columns_match_model(self):
        for k, v, _p, now, new, c, _ in R:
            self.assertEqual(M.valid_indicator(k, v, labels=False), bool(now), ("now", v))
            self.assertEqual(M.valid_indicator(k, v, labels=True), bool(new), ("new", v))
    def test_sql_file_renders_read_only(self):
        s = render_sql().lower()
        self.assertEqual(s.count("\n  ('"), len(R))
        for bad in ("insert ", "update ", "delete ", "create ", "drop ", "alter ", "grant ", "revoke "):
            self.assertNotIn(bad, s)
        self.assertNotIn("ipv6 url branch", s)
    def test_sql_text_columns_escape_quotes(self):
        self.assertEqual("'a''b'", _sql_literal("a'b"))
        with self.assertRaises(TypeError):
            _sql_literal(None)

if __name__ == "__main__":
    unittest.main()
