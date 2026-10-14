import unittest
from unittest.mock import patch
from urllib.request import Request

from safe_http import (
    _AllowlistedRedirectHandler,
    _validate_url,
    _normalized_hosts,
    open_https,
)


class SafeHttpTests(unittest.TestCase):
    def setUp(self):
        self.hosts = _normalized_hosts({"API.example.com"})
        self.handler = _AllowlistedRedirectHandler(self.hosts)

    def test_allows_only_https_default_port_exact_host(self):
        _validate_url("https://api.example.com/v1", self.hosts)
        _validate_url("https://api.example.com.:443/v1", self.hosts)
        for url in (
            "http://api.example.com/v1",
            "https://api.example.com.evil.test/v1",
            "https://evil-api.example.com/v1",
            "https://user:pass@api.example.com/v1",
            "https://api.example.com:8443/v1",
            "https://api.example.com:not-a-port/v1",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                _validate_url(url, self.hosts)

    def test_redirects_remain_on_allowlisted_https_host(self):
        req = Request("https://api.example.com/start")
        redirected = self.handler.redirect_request(
            req, None, 302, "Found", {}, "https://api.example.com/next"
        )
        self.assertIsNotNone(redirected)
        self.assertEqual(redirected.full_url, "https://api.example.com/next")

    def test_redirects_cannot_change_host_or_downgrade_to_http(self):
        req = Request("https://api.example.com/start")
        for target in (
            "https://evil.test/collect",
            "https://api.example.com.evil.test/collect",
            "http://api.example.com/cleartext",
            "https://api.example.com:8443/other-port",
        ):
            with self.subTest(target=target):
                self.assertIsNone(
                    self.handler.redirect_request(req, None, 302, "Found", {}, target)
                )

    def test_empty_allowlist_is_rejected(self):
        with self.assertRaises(ValueError):
            _normalized_hosts(set())

    def test_open_https_rejects_invalid_url_before_opening(self):
        with patch("safe_http.build_opener") as build_opener:
            with self.assertRaises(ValueError):
                open_https("http://api.example.com/path", allowed_hosts=self.hosts, timeout=2)
        build_opener.assert_not_called()

    def test_open_https_passes_timeout_to_allowlisted_opener(self):
        expected = object()
        with patch("safe_http.build_opener") as build_opener:
            build_opener.return_value.open.return_value = expected
            result = open_https(
                Request("https://api.example.com/path"),
                allowed_hosts=self.hosts,
                timeout=7,
            )
        self.assertIs(result, expected)
        build_opener.return_value.open.assert_called_once()
        self.assertEqual(build_opener.return_value.open.call_args.kwargs["timeout"], 7)


if __name__ == "__main__":
    unittest.main()
