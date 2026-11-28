#!/usr/bin/env python3
"""One-shot authenticated submit_indicators() test. TEST PROJECT ONLY: the target comes solely from the environment
(see manual_target_guard.py); there is no default project, and a production ref on the denylist is refused.

Uses the publishable/anon key + a normal user's password-grant token. No service-role key. No credentials,
JWTs, headers or request/response bodies are printed, logged or written. Sends exactly one synthetic indicator,
never retries. Run only after explicit approval.
"""
import base64
import getpass
import json
import os
import sys

import requests

import manual_target_guard as guard

KEY_ENV = guard.KEY_ENV                        # optional; otherwise prompted without echo
INDICATOR, INDICATOR_TYPE, VERDICT = "security-review.example.com", "domain", "suspicious"
TIMEOUT = (5, 15)                              # connect, read (DB statement_timeout is 8s)
KNOWN_RPC = {"auth_required", "invalid_payload", "too_many_items", "blocked", "rate_limited", "queue_full"}


def abort(msg, code=2):
    print("ABORT: " + msg)
    sys.exit(code)


def claims(jwt):
    return guard.claims(jwt)


def sign_in(base, key, email, password):
    try:
        r = requests.post(base + "/auth/v1/token", params={"grant_type": "password"}, timeout=TIMEOUT,
                          allow_redirects=False, headers={"apikey": key, "Content-Type": "application/json"},
                          json={"email": email, "password": password})
    except requests.RequestException as e:
        abort("auth request failed (%s)" % type(e).__name__)
    if r.status_code == 429:
        abort("auth rate limited (HTTP 429)")
    if r.status_code != 200:
        abort("authentication failed (HTTP %d)" % r.status_code)
    try:
        tok = r.json().get("access_token")
    except Exception:
        tok = None
    if not isinstance(tok, str) or not tok:
        abort("auth response had no usable token")
    return tok


def check_token(tok):
    c = claims(tok)
    if not isinstance(c, dict):
        abort("token unreadable")
    if c.get("is_anonymous") is True:
        abort("session is anonymous; the function would reject it")
    if c.get("role") != "authenticated":
        abort("token role is not 'authenticated'")
    role = str((c.get("app_metadata") or {}).get("role", "")).lower()
    if "admin" in role:
        abort("this account has an admin role; use a normal non-admin user")


def main():
    try:
        target = guard.load_target()                             # config only, no network; fails closed
    except guard.Abort as e:
        abort(str(e))
    BASE, HOST = target.base, target.host
    key = os.environ.get(KEY_ENV, "").strip() or getpass.getpass("Publishable/anon key (hidden): ").strip()
    try:
        guard.check_key(key, target)
        guard.verify_test_project(target, key)                   # is_test_project() must be true before sign-in or any write
    except guard.Abort as e:
        abort(str(e))
    email = input("Disposable test user email: ").strip()
    password = getpass.getpass("Password (hidden): ")
    if not email or not password:
        abort("email and password required")
    print("Authenticating against %s ..." % HOST)
    token = sign_in(BASE, key, email, password)
    del password
    check_token(token)
    print("Authenticated as a normal authenticated user.")
    print("Will submit ONE item: type=%s value=%s verdict=%s -> %s" % (INDICATOR_TYPE, INDICATOR, VERDICT, HOST))
    if input("Type SUBMIT to send, anything else to cancel: ").strip() != "SUBMIT":
        abort("cancelled by user", 0)

    body = {"p_items": [{"indicator_type": INDICATOR_TYPE, "value_norm": INDICATOR, "claimed_verdict": VERDICT}]}
    try:
        r = requests.post(BASE + "/rest/v1/rpc/submit_indicators", json=body, timeout=TIMEOUT, allow_redirects=False,
                          headers={"apikey": key, "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    except requests.ConnectTimeout:
        abort("connect timeout; request was not sent", 3)
    except requests.RequestException as e:
        print("RESULT: OUTCOME UNKNOWN (%s). NOT retrying; the submission may have committed." % type(e).__name__)
        print("Check indicator_submissions in the test project before any rerun.")
        sys.exit(3)

    print("HTTP status: %d" % r.status_code)
    if 300 <= r.status_code < 400:
        abort("unexpected redirect (not followed)", 3)
    if r.status_code == 429:
        print("RESULT: rate_limited_by_api")
        sys.exit(4)
    if r.status_code >= 400:
        try:
            msg = str(r.json().get("message", ""))
        except Exception:
            msg = ""
        code = msg if msg in KNOWN_RPC else ("auth_error" if r.status_code in (401, 403) else "server_error")
        if msg == "canceling statement due to statement timeout":
            code = "statement_timeout (possible global-lock contention)"
        print("RESULT: error code = " + code)
        sys.exit(4)
    try:
        d = r.json()
        a, dup, rej = (d.get(k) for k in ("accepted", "duplicates", "rejected"))
        assert all(type(x) is int and x >= 0 for x in (a, dup, rej))
    except Exception:
        print("RESULT: unexpected response shape (not displayed)")
        sys.exit(4)
    print("RESULT: accepted=%d duplicates=%d rejected=%d" % (a, dup, rej))
    if a == 1:
        print("OK: stored as a quarantined submission.")
    elif dup == 1:
        print("DUPLICATE: already submitted by this user; do not resubmit.")
    elif rej == 1:
        print("REJECTED by SQL validation (counted against rate limits). Do not retry; review the validator.")


if __name__ == "__main__":
    main()