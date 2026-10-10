"""Leakage safeguards and independent-set quality gates (sanitized text; temp files only)."""
import itertools, os, sqlite3, tempfile, unittest

import pandas as pd

import classifier as K
import config as C
import gen_data as G
import model_audit as A


def frame(rows):
    return pd.DataFrame(rows, columns=["text", "label"])


class Helpers(unittest.TestCase):
    def test_normalize_collapses_slot_fills_and_urls(self):
        a = A.normalize_text("Order #12345 shipped. Track: http://x.example/a?b=1")
        b = A.normalize_text("order #99 shipped. track: https://y.example/zz")
        self.assertEqual(a, b)

    def test_brand_report_flags_label_giveaways(self):
        skew = frame([("Netflix payment failed %d" % i, "phish") for i in range(20)] + [("hello netflix", "legit")])
        balanced = frame([("Netflix payment failed", "phish")] * 10 + [("Netflix receipt attached", "legit")] * 10)
        self.assertIn("netflix", A.brand_label_report(skew)["one_sided"])
        self.assertNotIn("netflix", A.brand_label_report(balanced)["one_sided"])

    def test_feedback_duplicates_and_holdout_overlap_are_dropped(self):
        holdout = frame([("Your parcel 111 is ready", "legit")])
        fb = frame([("Pay now at http://a.example/1", "phish"), ("Pay now at http://b.example/2", "phish"),
                    ("Your parcel 222 is ready", "legit"), ("Quarterly report attached", "legit")])
        clean, info = A.drop_feedback_leaks(fb, holdout)
        self.assertEqual(list(clean["text"]), ["Pay now at http://a.example/1", "Quarterly report attached"])
        self.assertEqual(info, {"duplicates": 1, "overlap_with_holdout": 1})

    def test_metrics_counts(self):
        m = A.metrics(["phish", "phish", "legit", "legit"], ["phish", "legit", "phish", "legit"])
        self.assertEqual((m["tp"], m["fn"], m["fp"], m["tn"], m["precision"], m["recall"]), (1, 1, 1, 1, 0.5, 0.5))


class Retraining(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls._old = (C.EMAILS_CSV, C.MODEL_PATH, K.FEEDBACK_DB)
        C.EMAILS_CSV = os.path.join(cls.tmp, "emails.csv")
        C.MODEL_PATH = os.path.join(cls.tmp, "model.joblib")
        K.FEEDBACK_DB = os.path.join(cls.tmp, "feedback.db")
        G.generate(path=C.EMAILS_CSV)
        cls.df = pd.read_csv(C.EMAILS_CSV)
        cls.pipe, cls.metrics = K.train(save=False)
        cls.ind = A.load_independent_eval()

    @classmethod
    def tearDownClass(cls):
        C.EMAILS_CSV, C.MODEL_PATH, K.FEEDBACK_DB = cls._old

    def set_feedback(self, rows):
        if os.path.exists(K.FEEDBACK_DB):
            os.remove(K.FEEDBACK_DB)
        c = sqlite3.connect(K.FEEDBACK_DB)
        c.execute("CREATE TABLE feedback_samples (id INTEGER PRIMARY KEY, text_hash TEXT, text TEXT, label TEXT, created_at TEXT)")
        c.executemany("INSERT INTO feedback_samples (text, label) VALUES (?, ?)", rows)
        c.commit(); c.close()

    def test_train_reports_no_template_leakage_and_few_one_sided_brands(self):
        self.assertEqual(self.metrics["leakage"]["test_rows_sharing_template_with_train"], 0)
        self.assertLessEqual(len(self.metrics["brand_one_sided"]), 2)

    def test_near_duplicate_feedback_cannot_trigger_retraining(self):
        self.set_feedback([("Verify your account 12%d at http://e.example/%d now" % (i, i), "phish") for i in range(30)]
                          + [("Meeting notes attached %d" % i, "legit") for i in range(30)])
        model, info = K.train_with_feedback(min_samples=20, save=False)
        self.assertIsNone(model)
        self.assertEqual(info["status"], "waiting")
        self.assertGreater(info["dropped"]["duplicates"], 0)

    def test_feedback_that_makes_a_brand_a_label_giveaway_is_rejected(self):
        words = ["alpha", "bravo", "cedar", "delta", "ember", "fjord", "gamma", "harbor", "indigo", "juniper"]
        phish = ["Netflix membership %s %s requires payment verification" % p for p in itertools.permutations(words, 2)][:80]
        legit = ["Weekly planning note %s %s from the team" % p for p in itertools.permutations(words, 2)][:80]
        self.set_feedback([(t, "phish") for t in phish] + [(t, "legit") for t in legit])
        model, info = K.train_with_feedback(min_samples=20, save=False)
        self.assertIsNone(model)
        self.assertEqual(info["status"], "rejected")
        self.assertIn("netflix", info["one_sided_brands"])

    def test_independent_set_quality_floor(self):
        m = A.evaluate(self.pipe, self.ind)          # 48 hand-written examples, none from gen_data templates
        self.assertGreaterEqual(m["precision"], 0.80)
        self.assertLessEqual(m["fp"], 5)
        self.assertGreaterEqual(m["recall"], 0.75)

    def test_brand_held_out_generalisation(self):
        m = A.brand_holdout_eval(self.df, K._build)["pooled"]
        self.assertEqual(m["fp"], 0)
        self.assertGreaterEqual(m["recall"], 0.85)


if __name__ == "__main__":
    unittest.main()


class SanitizeTraining(unittest.TestCase):
    def test_strips_personal_identifiers_keeps_host(self):
        out = A.sanitize_for_training("Mail jane.doe@gmail.com see https://accounts.google.com/AccountChooser?Email=jane%40x.com&id=9")
        self.assertNotIn("jane", out); self.assertNotIn("Email=", out); self.assertIn("https://accounts.google.com/", out)
