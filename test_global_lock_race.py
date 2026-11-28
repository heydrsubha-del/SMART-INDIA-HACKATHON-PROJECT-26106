#!/usr/bin/env python3
"""One-shot two-user concurrency smoke test. TEST PROJECT ONLY: the target comes solely from the environment
(see manual_target_guard.py); there is no default project, and a production ref on the denylist is refused.

Requires race_seed.sql to have completed within the last 10 minutes and shown
 global_hour_total=1999. The script sends exactly one RPC per user, never retries,
and does not print credentials, tokens, headers, or response bodies.
"""
import base64
import getpass
import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone

import requests

import manual_target_guard as guard

KEY_ENV = guard.KEY_ENV
VALUES = {"A": "tango.example.com", "B": "uniform.example.com"}
TIMEOUT = (5, 25)
KNOWN = {"auth_required", "invalid_payload", "too_many_items", "blocked", "rate_limited", "queue_full"}


def abort(message, code=2):
    print("ABORT: " + message)
    raise SystemExit(code)


def jwt_claims(token):
    return guard.claims(token)


def parse_uuid(prompt):
    raw = input(prompt).strip()
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError):
        abort("invalid UUID format")


def parse_seed_time():
    raw = input("Paste seed_time exactly as printed by race_seed.sql: ").strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        abort("seed_time could not be parsed; use the exact SQL output")
    if parsed.tzinfo is None:
        abort("seed_time must include its timezone; copy the exact SQL output")
    if parsed.microsecond != 777:
        abort("seed_time lacks the expected .000777 marker")
    age = (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()
    if age < -30 or age > 600:
        abort("seed_time is more than 10 minutes old or too far in the future; do not run the race")
    return parsed


def confirm_global_hour_total():
    raw = input("Enter global_hour_total exactly as printed by race_seed.sql (must be 1999): ").strip()
    if raw != "1999":
        abort("global_hour_total must be exactly 1999 as reported by race_seed.sql; do not run the race")


def sign_in(base, key, label, expected_uid):
    email = input("User %s email: " % label).strip()
    password = getpass.getpass("User %s password (hidden): " % label)
    if not email or not password:
        abort("credentials required")
    try:
        response = requests.post(
            base + "/auth/v1/token",
            params={"grant_type": "password"},
            timeout=TIMEOUT,
            allow_redirects=False,
            headers={"apikey": key, "Content-Type": "application/json"},
            json={"email": email, "password": password},
        )
    except requests.RequestException as exc:
        abort("auth request failed (%s)" % type(exc).__name__)
    finally:
        password = None
    if 300 <= response.status_code < 400:
        abort("unexpected auth redirect; not followed")
    if response.status_code != 200:
        abort("authentication failed for user %s (HTTP %d)" % (label, response.status_code))
    try:
        token = response.json().get("access_token")
    except Exception:
        token = None
    claims = jwt_claims(token) if isinstance(token, str) else None
    if (not isinstance(claims, dict) or claims.get("role") != "authenticated"
            or claims.get("is_anonymous") is True):
        abort("user %s token is not a normal authenticated session" % label)
    if str(claims.get("sub", "")).lower() != expected_uid.lower():
        abort("user %s signed in, but UID does not match the UUID used for seeding/cleanup" % label)
    if "admin" in str((claims.get("app_metadata") or {}).get("role", "")).lower():
        abort("user %s has an admin role" % label)
    return token


def worker(base, label, key, token, barrier, results):
    body = {"p_items": [{
        "indicator_type": "domain",
        "value_norm": VALUES[label],
        "claimed_verdict": "suspicious",
    }]}
    try:
        barrier.wait(timeout=30)
        response = requests.post(
            base + "/rest/v1/rpc/submit_indicators",
            json=body,
            timeout=TIMEOUT,
            allow_redirects=False,
            headers={
                "apikey": key,
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
            },
        )
    except threading.BrokenBarrierError:
        results[label] = ("NOT_SENT", None)
        return
    except requests.RequestException as exc:
        results[label] = ("UNKNOWN_" + type(exc).__name__, None)
        return  # May have committed; do not retry.

    if 300 <= response.status_code < 400:
        results[label] = ("unexpected_redirect", response.status_code)
        return
    if response.status_code >= 400:
        try:
            message = str(response.json().get("message", ""))
        except Exception:
            message = ""
        results[label] = (message if message in KNOWN else "server_error", response.status_code)
        return
    try:
        data = response.json()
        accepted, duplicates, rejected = (data.get(name) for name in ("accepted", "duplicates", "rejected"))
        if not all(type(value) is int and value >= 0 for value in (accepted, duplicates, rejected)):
            raise ValueError("bad counts")
        results[label] = (
            "accepted" if (accepted, duplicates, rejected) == (1, 0, 0)
            else "not_accepted(a=%s,d=%s,r=%s)" % (accepted, duplicates, rejected),
            response.status_code,
        )
    except Exception:
        results[label] = ("unreadable_response", response.status_code)


def main():
    try:
        target = guard.load_target()                  # config only, no network; fails closed
    except guard.Abort as exc:
        abort(str(exc))

    uid_a = parse_uuid("Paste User A UUID (must match race_seed.sql and race_cleanup.sql): ")
    uid_b = parse_uuid("Paste User B UUID (must match race_seed.sql and race_cleanup.sql): ")
    if uid_a == uid_b:
        abort("A and B must be different users")
    parse_seed_time()  # Validate freshness and marker before asking for credentials.
    confirm_global_hour_total()  # Seed output must have shown global_hour_total=1999; checked before credentials.

    key = os.environ.get(KEY_ENV, "").strip() or getpass.getpass("Test-project publishable/anon key (hidden): ").strip()
    try:
        guard.check_key(key, target)
        guard.verify_test_project(target, key)        # is_test_project() must be true before sign-in or any write
    except guard.Abort as exc:
        abort(str(exc))
    token_a = sign_in(target.base, key, "A", uid_a)
    token_b = sign_in(target.base, key, "B", uid_b)
    print("Both users authenticated as the expected normal, non-admin test users.")

    if input("Type RACE to send exactly ONE request per user simultaneously to the test project: ").strip() != "RACE":
        abort("cancelled", 0)

    barrier = threading.Barrier(2)
    results = {}
    threads = [
        threading.Thread(target=worker, args=(target.base, "A", key, token_a, barrier, results)),
        threading.Thread(target=worker, args=(target.base, "B", key, token_b, barrier, results)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for label in ("A", "B"):
        result, status = results.get(label, ("NO_RESULT", None))
        print("User %s: %s (HTTP %s)" % (label, result, status))

    outcomes = sorted(result for result, _ in results.values())
    if outcomes == ["accepted", "rate_limited"]:
        print("PASS: one accepted and one rate_limited. This is consistent with the lock working, but is not definitive proof of overlap.")
        print("Run race_cleanup.sql now using the same UUIDs and seed_time.")
    elif outcomes == ["accepted", "accepted"]:
        print("FAIL: both requests were accepted. If the seed was fresh and showed 1999, investigate before doing anything else.")
        print("Do not rerun. Review the test project's database and then carefully run race_cleanup.sql.")
        raise SystemExit(5)
    else:
        print("INCONCLUSIVE: do not rerun. Inspect the test project's rows, then review race_cleanup.sql for cleanup.")
        raise SystemExit(3)


if __name__ == "__main__":
    main()
