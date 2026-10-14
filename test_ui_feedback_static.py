import unittest

def _src(p):
    return open(p, encoding="utf-8", newline="").read()

class UiStatic(unittest.TestCase):
    def test_feedback_layout_and_claims(self):
        s = _src("app.py")
        self.assertNotIn("height:230px", s)
        self.assertNotIn('st.info("BASE MODEL")', s)
        self.assertIn("has not been changed by this action", s)
        self.assertIn("min_samples=20", _src("classifier.py"))  # threshold shown in UI

    def test_admin_actions_distinct(self):
        s = _src("admin_review.py")
        self.assertIn('type="primary"', s)
        self.assertIn('type="secondary"', s)
        self.assertIn("No submissions are waiting", s)

    def test_analysis_nav_targets_exist(self):
        s = _src("app.py")
        for a in ("ai-overview", "ai-assessment", "ai-agentic", "ai-downloads"):
            self.assertIn('href="#%s"' % a, s)
            self.assertIn('id="%s"' % a, s)

if __name__ == "__main__":
    unittest.main()
