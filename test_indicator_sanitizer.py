"""indicator_sanitizer: nothing personal or tokenised may come out; uncertain indicators are rejected."""
import copy
import unittest

from indicator_sanitizer import ACCEPTED, REJECTED, SANITIZED, sanitize_indicator as S

TOKEN = "aB3xK9pQ2mZ7vL1nR8tY4wC6"


class Urls(unittest.TestCase):
    def test_query_fragment_and_userinfo_removed(self):
        r = S("https://alice:hunter2@Example.COM:8443/login?session=abc&email=a@b.com#top")
        self.assertEqual((r.status, r.value), (SANITIZED, "https://example.com/login"))
        for secret in ("alice", "hunter2", "session", "a@b.com", "top", "8443"):
            self.assertNotIn(secret, repr(r))

    def test_high_entropy_path_dropped_with_everything_after(self):
        r = S("https://evil.example.net/verify/%s/confirm" % TOKEN)
        self.assertEqual(r.value, "https://evil.example.net/verify")
        self.assertNotIn(TOKEN, repr(r))

    def test_other_token_shapes_dropped(self):
        for seg in ("0123456789abcdef0123", "123e4567-e89b-12d3-a456-426614174000", "eyJhbGciOi.eyJzdWIiOi.sig",
                    "98765432101", "x7k2m9q4p1z8", "jane%40example.com", "id=77", "a" * 70):
            r = S("https://example.org/ok/%s/tail" % seg)
            self.assertEqual(r.value, "https://example.org/ok", seg)

    def test_readable_paths_kept_and_clean_url_accepted(self):
        r = S("https://evil.example.net/reset-password/step-2")
        self.assertEqual((r.status, r.value), (ACCEPTED, "https://evil.example.net/reset-password/step-2"))

    def test_path_parameters_removed(self):
        self.assertEqual(S("https://example.org/a;jsessionid=XYZ/b").value, "https://example.org/a/b")

    def test_email_in_path_never_returned(self):
        r = S("https://example.org/u/jane@corp.example")
        self.assertEqual(r.value, "https://example.org/u")

    def test_unsupported_or_malformed_urls_rejected(self):
        for v in ("mailto:jane@example.com", "javascript:alert(1)", "ftp://example.com/x", "http://", "https://exa mple.com",
                  "example.com/path", "https://[::1"):
            self.assertEqual(S(v, "url").status, REJECTED, v)

    def test_private_hosts_in_urls_rejected(self):
        for v in ("http://127.0.0.1/a", "http://192.168.1.5/login", "http://localhost/x", "http://printer.local/x"):
            self.assertEqual(S(v).status, REJECTED, v)

    def test_public_ip_url_accepted(self):
        self.assertEqual(S("http://8.8.8.8/x").value, "http://8.8.8.8/x")


class Domains(unittest.TestCase):
    def test_safe_domains(self):
        self.assertEqual(S("Login.Example.co.uk").value, "login.example.co.uk")
        self.assertEqual(S("example.com").status, ACCEPTED)

    def test_personalised_subdomain_rejected(self):
        self.assertEqual(S("a8f3k29dj1x7.example.com").status, REJECTED)

    def test_malformed_and_reserved_domains_rejected(self):
        for v in ("example", "-bad-.com", "exa_mple.com", "host.local", "1.2.3", "example.com/path", "example.com:80"):
            self.assertEqual(S(v, "domain").status, REJECTED, v)

    def test_email_addresses_rejected_everywhere(self):
        for v, k in (("jane.doe@example.com", None), ("jane.doe@example.com", "domain"), ("x@y.example.org", "url")):
            r = S(v, k)
            self.assertEqual(r.status, REJECTED)
            self.assertIsNone(r.value); self.assertNotIn("jane", repr(r))


class Ips(unittest.TestCase):
    def test_public_ips_accepted(self):
        self.assertEqual(S("8.8.8.8").status, ACCEPTED)
        self.assertEqual(S("2001:4860:4860:0:0:0:0:8888").value, "2001:4860:4860::8888")

    def test_non_global_rejected(self):
        for v in ("10.0.0.5", "172.16.0.1", "192.168.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0",
                  "224.0.0.1", "192.0.2.1", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1", "999.1.1.1", "1.2.3"):
            self.assertEqual(S(v, "ip").status, REJECTED, v)

    def test_ip_with_port_rejected(self):
        self.assertEqual(S("8.8.8.8:53", "ip").status, REJECTED)


class Hashes(unittest.TestCase):
    def test_valid_hashes(self):
        for n in (32, 40, 64):
            self.assertEqual(S("a1" * (n // 2)).indicator_type, "hash")
        self.assertEqual(S("A1" * 16).value, "a1" * 16)

    def test_invalid_hashes_rejected(self):
        for v in ("a1" * 15, "zz" * 16, "a1" * 17):
            self.assertEqual(S(v, "hash").status, REJECTED, v)


class General(unittest.TestCase):
    def test_garbage_rejected_and_never_raises(self):
        for v in ("", "   ", None, 42, "bad\x00value", "two words", "x" * 5000):
            self.assertEqual(S(v).status, REJECTED)

    def test_rejected_result_has_no_value_or_input_echo(self):
        r = S("secret-token@evil.example")
        self.assertIsNone(r.value); self.assertNotIn("secret-token", repr(r)); self.assertFalse(r.ok)

    def test_unknown_kind_rejected(self):
        self.assertEqual(S("example.com", "phone").status, REJECTED)

    def test_original_scan_evidence_unchanged(self):
        iocs = {"urls": [{"url": "https://u:p@example.com/a/%s?t=1" % TOKEN, "risk": 0.9}], "ips": ["10.0.0.1", "8.8.8.8"],
                "emails": ["jane@example.com"], "domains": ["example.com"]}
        before = copy.deepcopy(iocs)
        for u in iocs["urls"]:
            S(u["url"])
        for ip in iocs["ips"]:
            S(ip)
        for e in iocs["emails"]:
            S(e)
        self.assertEqual(iocs, before)


if __name__ == "__main__":
    unittest.main()
