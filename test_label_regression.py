"""Regression tests for the subdomain-label rule. They exercise sql_model.py (a Python model of the proposed SQL) plus the REAL
indicator_sanitizer for the subset invariant. PostgreSQL is not involved; validation_checks.sql is what must confirm the SQL."""
import random, string, unittest
import sql_model as M
from indicator_sanitizer import _looks_like_token as py_token

READABLE = "misunderstandings straightforwardness accountverification customersupportcenter passwordresetservice microsoftonlineservices internationalization institutionalization counterrevolutionary electroencephalogram telecommunications characteristically unconstitutional responsibilities interdepartmental intercontinental unprofessionally compartmentalization uncharacteristically internationalisation representatives disproportionately counterproductive environmentalists photographically telecommunication confidentiality interoperability".split()
NOT_ENGLISH_LIKE = ["dhanyavadsabhikaryakram", "aabbccddeeffgghhii", "ggggggggggggggggggggg"]   # Python accepts these; SQL intentionally rejects

class Readable(unittest.TestCase):
    def test_readable_words_preserved_in_domains(self):
        for w in READABLE:
            self.assertTrue(M.valid_indicator("domain", w + ".example.com"), w)
            self.assertFalse(py_token(w), w)                          # and Python agrees they are readable
    def test_formerly_rejected_words_now_preserved(self):
        for w in ("misunderstandings", "straightforwardness"):
            self.assertTrue(M.valid_indicator("domain", w + ".example.com"), w)
            self.assertTrue(M.valid_indicator("url", "http://%s.example.com/login" % w), w)
    def test_intentional_sql_stricter_than_python(self):                    # documented non-parity: Python accepts, SQL rejects
        for w in NOT_ENGLISH_LIKE:
            self.assertFalse(py_token(w), w)
            self.assertFalse(M.valid_indicator("domain", w + ".example.com"), w)
    def test_short_words_and_hyphenated_phrases(self):
        for d in ("login.example.com", "secure-login.example.com", "my-account-page.example.org", "authentication.example.com"):
            self.assertTrue(M.valid_indicator("domain", d), d)

class Tokens(unittest.TestCase):
    def test_random_and_structured_labels_rejected(self):
        for lab in ("x9f3kq2m7a1b", "qzxkvbnmplwjhgfdsa", "ggggggggggggggggggggg", "deadbeefdeadbeefdead", "abcdefabcdefabcdefab",
                    "123e4567-e89b-12d3-a456-426614174000", "qwertyuiopasdfghjkl", "eyjhbgcioijiuzi1nij9", "1234567890123", "user8f3a9c2d1e", "internationalizationwords",
                    "internationalization2", "internationalization-x"):
            self.assertFalse(M.valid_indicator("domain", lab + ".example.com"), lab)
    def test_uuid_and_jwt_paths_rejected(self):
        for p in ("123e4567-e89b-12d3-a456-426614174000", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "x7k2m9q4w8z1"):
            self.assertFalse(M.valid_indicator("url", "http://example.com/a/" + p), p)
            self.assertFalse(M.valid_indicator("url", "http://example.com/" + p + "/" + p), p)
    def test_path_segments_keep_strict_rule_no_exception(self):
        self.assertFalse(M.valid_indicator("url", "http://example.com/internationalization"))
        self.assertTrue(M.valid_indicator("url", "http://internationalization.example.com/login"))
    def test_repeated_long_segment(self):
        self.assertFalse(M.valid_indicator("url", "http://example.com/" + "/".join(["g" * 65] * 3)))

class Suffixes(unittest.TestCase):
    def test_two_part_public_suffixes(self):
        v = lambda d: M.valid_indicator("domain", d)
        self.assertFalse(v("x9f3kq2m7a1b.example.co.uk")); self.assertTrue(v("x9f3kq2m7a1b.co.uk"))
        self.assertFalse(v("x9f3kq2m7a1b.shop.example.com.au")); self.assertTrue(v("x9f3kq2m7a1b.example.com.au") is False)
        self.assertTrue(v("internationalization.example.co.uk")); self.assertTrue(v("shop.example.com.au"))
        self.assertTrue(v("x9f3kq2m7a1b.com")); self.assertFalse(v("x9f3kq2m7a1b.example.com"))
    def test_suffix_list_matches_sanitizer(self):
        import indicator_sanitizer as S
        self.assertEqual(M.SUFFIXES, set(S._TWO_PART_SUFFIXES))

class Invariants(unittest.TestCase):
    def test_sql_accepted_labels_are_subset_of_python_accepted(self):      # never weaker than Python
        rnd = random.Random(7); alph = [string.ascii_lowercase, string.ascii_lowercase + string.digits, "aeiou", "abcdef", "abcdefghij-"]
        for _ in range(40000):
            s = "".join(rnd.choices(rnd.choice(alph), k=rnd.randint(1, 40))).strip("-") or "a"
            if not M.label_rejected(s):
                self.assertFalse(py_token(s), s)
    def test_subset_invariant_on_english_like_concatenations(self):
        rnd = random.Random(11); words = [w for w in READABLE] + "login secure account update verify service portal online bank mail cloud support center payment".split()
        for _ in range(20000):
            s = "".join(rnd.choices(words, k=rnd.randint(1, 3)))
            if not M.label_rejected(s):
                self.assertFalse(py_token(s), s)
    def test_sql_never_accepts_what_looks_like_token_unless_exception(self):
        for s in READABLE + ["x9f3kq2m7a1b", "ggggggggggggggggggggg"]:
            self.assertEqual(M.label_rejected(s), M.looks_like_token(s) and not M.readable_exception(s))
    def test_measured_random_letter_residual_is_bounded(self):               # documents the weakness; uniform random lowercase letters
        rnd = random.Random(2); cap = {16: .01, 18: .005, 20: .005, 24: .005}
        for n, lim in cap.items():
            hit = sum(not M.label_rejected("".join(rnd.choices(string.ascii_lowercase, k=n))) for _ in range(20000)) / 20000
            self.assertLess(hit, lim, (n, hit))
        for n in (25, 30, 40):
            self.assertTrue(all(M.label_rejected("".join(rnd.choices(string.ascii_lowercase, k=n))) for _ in range(2000)))

if __name__ == "__main__":
    unittest.main()
