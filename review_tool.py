"""Reviewer CLI for quarantined community submissions (run by an authorized reviewer, NOT part of the public app).

  python review_tool.py list
  python review_tool.py approve <id> [note]
  python review_tool.py reject  <id> [note]

Env: SIH26106_SUPABASE_URL, SIH26106_SUPABASE_ANON_KEY (public), SIH26106_REVIEWER_JWT (the reviewer's own signed-in
session token with MFA). The service-role key is never used and is refused. Promotion to 'verified' happens inside the
database function, which re-checks that the caller is an admin with MFA; this tool only forwards the decision.
"""
import base64
import json
import os
import sys

import requests

import shared_intel_client as _sic

JWT_ENV = "SIH26106_REVIEWER_JWT"
TIMEOUT = 15


def _jwt_role(token):
    try:
        part = token.split(".")[1]
        return str(json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))).get("role", "")).lower()
    except Exception:
        return ""


def _setup():
    url, key, jwt = (os.environ.get(n, "").strip() for n in (_sic.URL_ENV, _sic.KEY_ENV, JWT_ENV))
    base = _sic._base_url(url) if url else None
    if not base or not key or not jwt:
        return None, "not_configured"
    if _sic._key_problem(key) or _jwt_role(jwt) != "authenticated":
        return None, "unsafe_credentials"          # service-role keys/tokens are refused
    return (base, {"apikey": key, "Authorization": "Bearer " + jwt, "Content-Type": "application/json"}), ""


def _call(fn, body):
    cfg, err = _setup()
    if err:
        return {"ok": False, "error": err}
    base, headers = cfg
    try:
        resp = requests.post("%s/rest/v1/rpc/%s" % (base, fn), headers=headers, json=body, timeout=TIMEOUT)
        if resp.status_code in (401, 403):
            return {"ok": False, "error": "forbidden"}
        if resp.status_code >= 400:
            try:
                return {"ok": False, "error": str(resp.json().get("message", "server_error"))[:40]}
            except Exception:
                return {"ok": False, "error": "server_error"}
        return {"ok": True, "data": resp.json()}
    except Exception:
        return {"ok": False, "error": "unavailable"}


def list_pending(limit=50):
    return _call("review_queue", {"p_limit": int(limit)})


def decide(submission_id, decision, note=None):
    if decision not in ("approve", "reject"):
        return {"ok": False, "error": "invalid_decision"}
    return _call("review_submission", {"p_id": str(submission_id), "p_decision": decision, "p_note": note})


def main(argv):
    if not argv or argv[0] not in ("list", "approve", "reject") or (argv[0] != "list" and len(argv) < 2):
        print(__doc__); return 2
    res = list_pending() if argv[0] == "list" else decide(argv[1], argv[0], argv[2] if len(argv) > 2 else None)
    if not res["ok"]:
        print("Error: " + res["error"]); return 1
    if argv[0] == "list":
        for r in res["data"]:
            print("%s  %-6s %-10s x%s  %s" % (r["id"], r["indicator_type"], r["claimed_verdict"], r["distinct_contributors"], r["value_norm"]))
        print("%d pending" % len(res["data"]))
    else:
        print(res["data"].get("status"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
