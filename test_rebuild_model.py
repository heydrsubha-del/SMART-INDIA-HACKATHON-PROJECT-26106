"""rebuild_model: dry-run changes nothing; --apply backs up first and keeps non-generator rows."""
import hashlib, os, tempfile, unittest

import pandas as pd

import classifier as K
import config as C
import gen_data as G
import rebuild_model as R


def digest(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class Rebuild(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self._old = (C.EMAILS_CSV, C.MODEL_PATH, K.FEEDBACK_DB)
        C.EMAILS_CSV, C.MODEL_PATH = os.path.join(self.d, "emails.csv"), os.path.join(self.d, "model.joblib")
        K.FEEDBACK_DB = os.path.join(self.d, "none.db")
        G.generate(path=C.EMAILS_CSV)
        df = pd.read_csv(C.EMAILS_CSV)
        extra = pd.DataFrame([("custom analyst example one", "legit", "manual_1"),
                              ("custom analyst example two", "phish", "manual_2")], columns=df.columns)
        pd.concat([df, extra]).to_csv(C.EMAILS_CSV, index=False)
        K.train(save=True)
        with open(C.MODEL_PATH + ".adaptive", "wb") as fh:
            fh.write(b"x")
        self.before = {p: digest(p) for p in (C.EMAILS_CSV, C.MODEL_PATH, C.MODEL_PATH + ".adaptive")}

    def tearDown(self):
        C.EMAILS_CSV, C.MODEL_PATH, K.FEEDBACK_DB = self._old

    def test_dry_run_changes_nothing(self):
        r = R.run(apply=False, out=lambda *_: None)
        self.assertFalse(r["applied"])
        self.assertEqual(self.before, {p: digest(p) for p in self.before})
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith("backup_")], [])

    def test_apply_backs_up_and_keeps_non_generator_rows(self):
        r = R.run(apply=True, out=lambda *_: None)
        self.assertTrue(r["applied"])
        self.assertEqual(digest(os.path.join(r["backup"], "emails.csv")), self.before[C.EMAILS_CSV])
        self.assertEqual(digest(os.path.join(r["backup"], "model.joblib")), self.before[C.MODEL_PATH])
        self.assertTrue(os.path.exists(os.path.join(r["backup"], "model.joblib.adaptive")))
        self.assertFalse(os.path.exists(C.MODEL_PATH + ".adaptive"))
        texts = set(pd.read_csv(C.EMAILS_CSV)["text"])
        self.assertTrue({"custom analyst example one", "custom analyst example two"} <= texts)


if __name__ == "__main__":
    unittest.main()
