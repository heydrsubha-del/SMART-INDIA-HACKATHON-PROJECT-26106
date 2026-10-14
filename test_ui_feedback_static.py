import unittest

import ui_helpers as uh


def _read(p):
    with open(p, encoding="utf-8", newline="") as f:
        return f.read()


class SaveThenRetrain(unittest.TestCase):
    def run_flow(self, add=lambda: None, retrain=lambda: {"status": "waiting"}, trained=None):
        calls = []
        out = uh.save_then_retrain(add, retrain, trained or (lambda: calls.append(1)), "Saved.")
        return out, calls

    def test_save_failure_reports_error_only(self):
        def bad(): raise RuntimeError("db")
        out, _ = self.run_flow(add=bad)
        self.assertEqual([k for k, _ in out], ["error"])

    def test_retrain_failure_keeps_saved_message(self):
        def bad(): raise RuntimeError("train")
        out, calls = self.run_flow(retrain=bad)
        self.assertEqual(out[0], ("success", "Saved."))
        self.assertEqual(out[1][0], "warning")
        self.assertIn("feedback is saved", out[1][1])
        self.assertNotIn("could not be saved", " ".join(m for _, m in out))
        self.assertEqual(calls, [])

    def test_retrain_not_called_when_save_fails(self):
        hit = []
        def bad(): raise RuntimeError("db")
        uh.save_then_retrain(bad, lambda: hit.append(1), lambda: None, "x")
        self.assertEqual(hit, [])

    def test_trained_only_when_backend_confirms(self):
        out, calls = self.run_flow(retrain=lambda: {"status": "trained"})
        self.assertIn("accepted", out[-1][1]); self.assertEqual(calls, [1])
        for st in ({"status": "waiting"}, {"status": "rejected", "baseline_accuracy": .9, "candidate_accuracy": .8}, {}):
            out, calls = self.run_flow(retrain=lambda st=st: st)
            self.assertNotIn("accepted", " ".join(m for _, m in out))
            self.assertEqual(calls, [])

    def test_cache_refresh_failure_is_not_a_save_failure(self):
        def bad(): raise RuntimeError("cache")
        out, _ = self.run_flow(retrain=lambda: {"status": "trained"}, trained=bad)
        self.assertEqual(out[0][0], "success")
        self.assertNotIn("could not be saved", " ".join(m for _, m in out))


class FeedbackState(unittest.TestCase):
    def test_persists_across_reruns_and_clears_on_email_change(self):
        s = {}
        uh.set_feedback(s, "h1", [("success", "ok")])
        self.assertEqual(uh.current_feedback(s, "h1"), [("success", "ok")])
        self.assertEqual(uh.current_feedback(s, "h1"), [("success", "ok")])   # rerun
        self.assertEqual(uh.current_feedback(s, "h2"), [])
        self.assertEqual(uh.current_feedback(s, "h1"), [])                    # stale cleared

    def test_new_submission_replaces_old(self):
        s = {}
        uh.set_feedback(s, "h1", [("error", "old")])
        uh.set_feedback(s, "h1", [("success", "new")])
        self.assertEqual(uh.current_feedback(s, "h1"), [("success", "new")])


class Navigation(unittest.TestCase):
    def test_every_nav_link_has_an_anchor_helper(self):
        html = uh.nav_html()
        for i, _ in uh.SECTIONS:
            self.assertIn(f'href="#{i}"', html)
            self.assertEqual(uh.section_anchor(i), f'<div id="{i}"></div>')

    def test_downloads_anchor_emitted_on_every_report_state(self):
        # ready, error and not-run branches must each emit the target (no dead link)
        self.assertGreaterEqual(_read("app.py").count('_uh.section_anchor("ai-downloads")'), 3)


class Styling(unittest.TestCase):
    def test_primary_secondary_and_admin_buttons(self):
        a = _read("app.py")
        self.assertIn('key="confirm_threat", type="primary"', a)
        self.assertIn('key="false_positive", type="secondary"', a)
        adm = _read("admin_review.py")
        self.assertIn('type="primary"', adm); self.assertIn('type="secondary"', adm)


if __name__ == "__main__":
    unittest.main()
