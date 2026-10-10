"""Regression: href destinations are extracted/analysed (or honestly reported as not extracted), and a
country-only origin match is labelled weak evidence."""
import ast, os, unittest

import ioc_extract
import report
from email_parser import parse_eml

HERE = os.path.dirname(os.path.abspath(__file__))


def mail(body_parts, ctype="multipart/alternative"):
    return ("From: A <a@example.com>\nTo: v@example.org\nSubject: News\nMIME-Version: 1.0\n"
            'Content-Type: {}; boundary="b"\n\n{}--b--\n'.format(ctype, body_parts)).encode()


PLAIN = '--b\nContent-Type: text/plain; charset=utf-8\n\nHello. To stop these emails, unsubscribe here.\n'
HTML = ('--b\nContent-Type: text/html; charset=utf-8\n\n<html><body><p>Hello.</p>'
        '<a href="https://evil-login.example.top/u?id=1&amp;x=2">Unsubscribe</a>'
        '<a href=\'mailto:stop@example.com\'>mail us</a></body></html>\n')


class HrefExtraction(unittest.TestCase):
    def test_href_destination_extracted_even_when_plain_part_preferred(self):
        p = parse_eml(mail(PLAIN + HTML))
        self.assertIn("unsubscribe", p["body_text"].lower())
        self.assertNotIn("evil-login", p["body_text"])                     # plain body has no URL...
        self.assertEqual(p["html_links"][0]["href"], "https://evil-login.example.top/u?id=1&x=2")   # ...the href is found
        io = ioc_extract.extract(p)
        u = [x for x in io["urls"] if x["host"] == "evil-login.example.top"]
        self.assertEqual(len(u), 1)
        self.assertEqual((u[0]["source"], u[0]["anchor_text"]), ("html href", "Unsubscribe"))
        self.assertIn("example.top", io["domains"])
        self.assertEqual(io["link_extraction"]["status"], "extracted")

    def test_href_is_judged_like_any_url(self):
        io = ioc_extract.extract(parse_eml(mail(HTML, "multipart/alternative")))
        self.assertTrue(io["urls"][0]["suspicious"])                      # .top TLD flagged by existing heuristics

    def test_mention_without_destination_is_reported_not_denied(self):
        p = parse_eml(mail(PLAIN))
        io = ioc_extract.extract(p)
        self.assertEqual(io["urls"], [])
        self.assertEqual(io["link_extraction"]["status"], "not_extracted")
        self.assertIn("NOT evidence", io["link_extraction"]["note"])

    def test_mailto_only_is_not_counted_as_web_url(self):
        html = '--b\nContent-Type: text/html; charset=utf-8\n\n<a href="mailto:stop@example.com">Unsubscribe</a>\n'
        io = ioc_extract.extract(parse_eml(mail(html)))
        self.assertEqual(io["urls"], [])
        self.assertEqual(io["link_extraction"]["non_web_links"], 1)
        self.assertEqual(io["link_extraction"]["status"], "not_extracted")

    def test_no_link_mention_keeps_none_status(self):
        io = ioc_extract.extract(parse_eml(mail('--b\nContent-Type: text/plain\n\nLunch at noon.\n')))
        self.assertEqual(io["link_extraction"]["status"], "none")

    def test_body_urls_unchanged_and_not_duplicated_with_href(self):
        both = ('--b\nContent-Type: text/html; charset=utf-8\n\nVisit https://accounts.google.com/x '
                '<a href="https://accounts.google.com/x">here</a>\n')
        io = ioc_extract.extract(parse_eml(mail(both)))
        self.assertEqual(len(io["urls"]), 1)

    def test_report_says_destination_not_extracted_not_no_urls(self):
        iocs = ioc_extract.extract(parse_eml(mail(PLAIN)))
        self.assertIn("could be extracted", iocs["link_extraction"]["note"])
        src = open(os.path.join(HERE, "report.py"), encoding="utf-8").read()
        self.assertIn('status") == "not_extracted"', src)


def _load_sem():
    """Load the pure _sem_* helpers from app.py without importing streamlit."""
    src = open(os.path.join(HERE, "app.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    keep = []
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name in ("_sem_band", "_sem_known", "_sem_norm", "_sem_reason_text",
                                                         "_sem_country_only", "_sem_headline"):
            keep.append(n)
        elif isinstance(n, ast.Assign) and any(getattr(t, "id", "").startswith("_SEM") for t in n.targets):
            keep.append(n)
    ns = {}
    exec(compile(ast.Module(keep, []), "app_sem", "exec"), ns)
    return ns


class CountryOnlyIsWeak(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = _load_sem()

    def test_country_only_match_is_labelled_weak_not_common_operator(self):
        m = {"similarity": 0.70, "score": 0.72, "band": "Related", "reasons": ["same country"], "ip": "1.2.3.4", "country": "US"}
        text = self.ns["_sem_reason_text"](m)
        self.assertIn("weak evidence", text); self.assertIn("does not indicate a common attacker or operator", text)
        self.assertIn("weak evidence", self.ns["_sem_headline"]([m]))
        self.assertEqual(m["score"], 0.72)                                # scoring/band untouched

    def test_stronger_traits_keep_plain_wording(self):
        m = {"similarity": 0.8, "score": 0.9, "band": "Strong", "reasons": ["same origin IP", "same country"]}
        self.assertEqual(self.ns["_sem_reason_text"](m), "same origin IP; same country")
        self.assertNotIn("weak evidence", self.ns["_sem_headline"]([dict(m, ip="1.2.3.4")]))

    def test_method_note_states_country_is_weak(self):
        self.assertIn("only shared trait is the country is weak evidence", self.ns["_SEM_METHOD_NOTE"])


if __name__ == "__main__":
    unittest.main()
