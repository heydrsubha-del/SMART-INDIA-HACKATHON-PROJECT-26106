"""shared_intel_client: read-only, anon-key-only, re-sanitizing, fail-soft. HTTP is mocked; nothing is sent anywhere."""
import base64
import json
import os
import re
import unittest
from unittest import mock

import shared_intel_client as C


def _jwt(role):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return "%s.%s.sig" % (b({"alg": "HS256"}), b({"role": role}))


class Resp:
    def __init__(self, data, status=200):
        self.data, self.status = data, status
    def raise_for_status(self):
        if self.status >= 400:
            raise RuntimeError("http %s" % self.status)
    def json(self):
        return self.data


def row(value, kind="domain", verdict="malicious", conf=0.8):
    return {"indicator_type": kind, "value_norm": value, "verdict": verdict, "confidence": conf}


class Base(unittest.TestCase):
    def setUp(self):
        env = {C.URL_ENV: "https://proj.supabase.co", C.KEY_ENV: _jwt("anon")}
        patcher = mock.patch.dict(os.environ, env); patcher.start(); self.addCleanup(patcher.stop)


class Config(Base):
    def test_not_configured(self):
        with mock.patch.dict(os.environ, {C.KEY_ENV: ""}):
            self.assertFalse(C.is_configured())
            self.assertFalse(C.fetch_verified()["ok"])

    def test_service_role_and_secret_keys_refused_without_any_request(self):
        for key in (_jwt("service_role"), "sb_secret_abc123", "a.b.c"):
            with mock.patch.dict(os.environ, {C.KEY_ENV: key}), mock.patch.object(C.requests, "get") as get:
                r = C.fetch_verified()
                self.assertFalse(r["ok"]); get.assert_not_called(); self.assertNotIn(key, r["error"])

    def test_publishable_and_anon_keys_allowed(self):
        for key in ("sb_publishable_abc", _jwt("anon")):
            with mock.patch.dict(os.environ, {C.KEY_ENV: key}), mock.patch.object(C.requests, "get", return_value=Resp([])):
                self.assertTrue(C.fetch_verified()["ok"])

    def test_remote_http_refused_localhost_http_allowed(self):
        with mock.patch.dict(os.environ, {C.URL_ENV: "http://example.org"}):
            self.assertFalse(C.fetch_verified()["ok"])
        with mock.patch.dict(os.environ, {C.URL_ENV: "http://localhost:54321"}), mock.patch.object(C.requests, "get", return_value=Resp([])):
            self.assertTrue(C.fetch_verified()["ok"])

    def test_module_never_reads_a_service_key_env_var(self):
        src = open(C.__file__, encoding="utf-8").read()
        self.assertIsNone(re.search(r"(getenv|environ)[^\n]*SERVICE", src, re.I))


class Fetch(Base):
    def test_request_is_read_only_verified_only_and_carries_no_email_data(self):
        with mock.patch.object(C.requests, "get", return_value=Resp([])) as get, \
             mock.patch.object(C.requests, "post") as post:
            C.fetch_verified()
        post.assert_not_called()
        _, kw = get.call_args
        self.assertEqual(kw["params"]["status"], "eq.verified")
        self.assertEqual(set(kw["headers"]), {"apikey", "Authorization", "Accept"})
        self.assertNotIn("reviewed_by", kw["params"]["select"])

    def test_good_rows_returned_as_community_source(self):
        page = [row("evil.example.net"), row("http://evil.example.net/login", "url", "suspicious", 0.4), row("8.8.4.4", "ip")]
        with mock.patch.object(C.requests, "get", return_value=Resp(page)):
            r = C.fetch_verified()
        self.assertEqual([x["indicator"] for x in r["rows"]], ["evil.example.net", "http://evil.example.net/login", "8.8.4.4"])
        self.assertTrue(all(x["source"] == "community" for x in r["rows"]))
        self.assertEqual(r["rejected"], 0)

    def test_unsafe_or_altered_rows_dropped_and_counted(self):
        page = [row("a@b.example.org"), row("http://x.example.org/a?t=1", "url"), row("10.0.0.1", "ip"),
                row("Evil.Example.NET"), row("ok.example.net", verdict="benign"), row("ok.example.net", kind="email"),
                "junk", row("fine.example.net")]
        with mock.patch.object(C.requests, "get", return_value=Resp(page)):
            r = C.fetch_verified()
        self.assertEqual([x["indicator"] for x in r["rows"]], ["fine.example.net"])
        self.assertEqual(r["rejected"], 7)

    def test_bad_confidence_is_clamped_not_trusted(self):
        with mock.patch.object(C.requests, "get", return_value=Resp([row("a.example.net", conf=7), row("b.example.net", conf="x")])):
            self.assertEqual([x["confidence"] for x in C.fetch_verified()["rows"]], [1.0, 0.5])

    def test_pagination_merges_pages(self):
        full = [row("d%d.example.net" % i) for i in range(C._PAGE)]
        with mock.patch.object(C.requests, "get", side_effect=[Resp(full), Resp([row("last.example.net")])]) as get:
            r = C.fetch_verified()
        self.assertEqual(len(r["rows"]), C._PAGE + 1)
        self.assertEqual(get.call_args_list[1][1]["params"]["offset"], str(C._PAGE))

    def test_http_and_network_errors_fail_soft_without_leaking_key(self):
        key = os.environ[C.KEY_ENV]
        for effect in (Resp([], 500), RuntimeError("boom " + key)):
            with mock.patch.object(C.requests, "get", side_effect=[effect] if isinstance(effect, Exception) else None,
                                   return_value=None if isinstance(effect, Exception) else effect):
                r = C.fetch_verified()
            self.assertFalse(r["ok"]); self.assertEqual(r["rows"], []); self.assertNotIn(key, r["error"])

    def test_non_list_response_rejected(self):
        with mock.patch.object(C.requests, "get", return_value=Resp({"message": "nope"})):
            self.assertFalse(C.fetch_verified()["ok"])


if __name__ == "__main__":
    unittest.main()
