"""Brand names must not leak the label in the synthetic corpus (sanitized text only)."""
import csv, os, tempfile, unittest

import classifier as K
import config as C
import gen_data as G

NOTICE = ("Security alert. A new app was granted access to your Google Account. If you did not grant "
          "access, check activity and secure your account. You received this email to let you know "
          "about important changes to your Google Account and services.")
PHISH = ("Google Account: we detected unusual sign-in activity on your account. Click here to verify "
         "your identity immediately. http://secure-verify-login.tk/account Failure to act will result "
         "in permanent account closure.")


class BrandBalance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls._old = (C.EMAILS_CSV, C.MODEL_PATH)
        C.EMAILS_CSV = os.path.join(cls.tmp, "emails.csv")
        C.MODEL_PATH = os.path.join(cls.tmp, "model.joblib")
        G.generate(path=C.EMAILS_CSV)
        with open(C.EMAILS_CSV, encoding="utf-8") as fh:
            cls.rows = list(csv.DictReader(fh))
        cls.pipe, _ = K.train(save=False)

    @classmethod
    def tearDownClass(cls):
        C.EMAILS_CSV, C.MODEL_PATH = cls._old

    def test_every_brand_appears_in_both_classes(self):
        for brand in G.PHISH_BRANDS:
            labels = {r["label"] for r in self.rows if brand.lower() in r["text"].lower()}
            self.assertEqual(labels, {"phish", "legit"}, brand)

    def test_legit_notification_scores_below_threshold(self):
        self.assertLess(K.predict(self.pipe, NOTICE)[0], 0.5)

    def test_brand_phishing_still_detected(self):
        self.assertGreaterEqual(K.predict(self.pipe, PHISH)[0], 0.9)


if __name__ == "__main__":
    unittest.main()