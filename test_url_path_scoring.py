"""Credential-path heuristic must match path tokens, not substrings (sanitized URLs only)."""
import unittest

import ioc_extract as X


class CredentialPath(unittest.TestCase):
    def test_account_chooser_is_not_a_credential_lure(self):
        u = X._judge_url("https://accounts.google.com/AccountChooser?continue=https%3A%2F%2Fexample.org%2F")
        self.assertEqual((u["flags"], u["risk"], u["suspicious"]), ([], 0.0, False))

    def test_real_credential_paths_still_flagged(self):
        for url in ("https://example.org/login", "https://example.org/account-verify",
                    "https://example.org/signin.php", "https://example.org/verifyaccount.php",
                    "https://example.org/secureloginbank"):
            self.assertEqual(X._judge_url(url)["risk"], 0.5, url)

    def test_other_signals_unaffected(self):
        u = X._judge_url("http://paypa1-support.top/AccountChooser")
        self.assertGreaterEqual(u["risk"], 0.9)


if __name__ == "__main__":
    unittest.main()
