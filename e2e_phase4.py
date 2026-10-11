"""Phase 4 end-to-end test against the TEST Supabase project ONLY (manual script, not part of `unittest`).

Safety: every request first re-checks (1) SIH26106_E2E_CONFIRM == "TEST-PROJECT-ONLY:<ref>" (bound to the ref, so it
cannot be reused for another project), (2) the ref is not in SIH26106_E2E_PROD_REFS, (3) the URL is https and its host is
exactly <SIH26106_E2E_PROJECT_REF>.supabase.co (no localhost), (4) the key is not a service-role/secret key. The first
request to a project also requires public.is_test_project() = true. Any mismatch aborts before the request. Redirects are
never followed. Only the public anon key and the test users' own session tokens are used; synthetic data only.
Feature flags are overridden inside this process only.

Results are PASS / FAIL / SKIP. A negative-authorization check ("X cannot do Y") only counts when a positive control proves
the feature works for an allowed caller; otherwise it is reported as SKIP (inconclusive). Exit code 0 only when nothing
failed and nothing was skipped.

  python e2e_phase4.py check | enroll-mfa | run
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import string
import struct
import sys
import time
from unittest import mock
from urllib.parse import urlsplit

import requests

import shared_intel_client as SIC

CONFIRM_ENV, REF_ENV, PROD_REFS_ENV = "SIH26106_E2E_CONFIRM", "SIH26106_E2E_PROJECT_REF", "SIH26106_E2E_PROD_REFS"
CONFIRM_PREFIX = "TEST-PROJECT-ONLY:"
_REF_RE = re.compile(r"^[a-z0-9]{6,40}$")
EMAIL_ENV, PASS_ENV, TOTP_ENV = "SIH26106_E2E_REVIEWER_EMAIL", "SIH26106_E2E_REVIEWER_PASSWORD", "SIH26106_E2E_REVIEWER_TOTP_SECRET"
_state = {"marker_ok": None}


class Abort(Exception):
    pass


def _cfg():
    """Raises Abort unless the target is provably the declared test project. Called before EVERY request."""
    url, key, ref = (os.environ.get(n, "").strip() for n in (SIC.URL_ENV, SIC.KEY_ENV, REF_ENV))
    if not _REF_RE.match(ref):
        raise Abort("set %s to the TEST project's reference id (Project Settings > General)" % REF_ENV)
    if os.environ.get(CONFIRM_ENV) != CONFIRM_PREFIX + ref:
        raise Abort("set %s=%s%s to confirm this is the test project" % (CONFIRM_ENV, CONFIRM_PREFIX, ref))
    if ref in {r.strip() for r in os.environ.get(PROD_REFS_ENV, "").split(",") if r.strip()}:
        raise Abort("this ref is listed in %s: it is a production project" % PROD_REFS_ENV)
    base = SIC._base_url(url) if url else None
    if not base or not key:
        raise Abort("missing or invalid %s or %s" % (SIC.URL_ENV, SIC.KEY_ENV))
    if SIC._key_problem(key):
        raise Abort("refusing a service-role/secret key")
    parts = urlsplit(base)
    if parts.scheme != "https" or parts.hostname != ref + ".supabase.co":
        raise Abort("URL host %s must be exactly %s.supabase.co over https" % (parts.hostname, ref))
    return base, key, ref


def call(method, path, token=None, extra_headers=None, **kw):
    base, key, _ = _cfg()
    if _state["marker_ok"] != base:
        r = requests.post(base + "/rest/v1/rpc/is_test_project", json={}, timeout=15, allow_redirects=False,
                          headers=_headers(key, None))
        try:
            ok = r.status_code == 200 and r.json() is True
        except ValueError:
            ok = False
        if not ok:
            raise Abort("this project does not answer is_test_project() = true: NOT the test project, aborting")
        _state["marker_ok"] = base
    headers = _headers(key, token)
    headers.update(extra_headers or {})
    return requests.request(method, base + path, headers=headers, timeout=15, allow_redirects=False, **kw)


def _headers(key, token):
    h = {"apikey": key, "Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    elif not key.startswith("sb_"):
        h["Authorization"] = "Bearer " + key
    return h


def totp(secret, now=None, digits=6):
    key = base64.b32decode(secret.replace(" ", "").upper() + "=" * (-len(secret.replace(" ", "")) % 8))
    mac = hmac.new(key, struct.pack(">Q", int((time.time() if now is None else now) // 30)), hashlib.sha1).digest()
    o = mac[-1] & 15
    return str((int.from_bytes(mac[o:o + 4], "big") & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


# ---------------------------------------------------------------- helpers
def rpc(token, fn, body):
    return call("POST", "/rest/v1/rpc/" + fn, token, json=body)


def _token(resp):
    try:
        return resp.json().get("access_token") if resp.status_code == 200 else None
    except Exception:
        return None


def login(email, pw):
    return _token(call("POST", "/auth/v1/token?grant_type=password", json={"email": email, "password": pw}))


def mfa_session(token, secret):
    user = call("GET", "/auth/v1/user", token).json()
    fids = [f["id"] for f in user.get("factors") or [] if f.get("factor_type") == "totp" and f.get("status") == "verified"]
    if not fids:
        return None
    ch = call("POST", "/auth/v1/factors/%s/challenge" % fids[0], token, json={}).json().get("id")
    return _token(call("POST", "/auth/v1/factors/%s/verify" % fids[0], token, json={"challenge_id": ch, "code": totp(secret)}))


def enroll_mfa():
    if os.environ.get(TOTP_ENV):
        print("%s is already set. Enrolling again would add a second factor and break the saved secret." % TOTP_ENV); return 1
    tok = login(os.environ.get(EMAIL_ENV, ""), os.environ.get(PASS_ENV, ""))
    if not tok:
        print("Reviewer login failed (check the test reviewer email/password)."); return 1
    r = call("POST", "/auth/v1/factors", tok, json={"factor_type": "totp", "friendly_name": "e2e-" + secrets.token_hex(2)})
    if r.status_code != 200:
        print("MFA enrol failed (HTTP %s). Is TOTP MFA enabled in the test project?" % r.status_code); return 1
    d = r.json(); fid, sec = d["id"], d["totp"]["secret"]
    ch = call("POST", "/auth/v1/factors/%s/challenge" % fid, tok, json={}).json().get("id")
    v = call("POST", "/auth/v1/factors/%s/verify" % fid, tok, json={"challenge_id": ch, "code": totp(sec)})
    if v.status_code != 200:
        print("MFA verify failed (HTTP %s)." % v.status_code); return 1
    print("MFA enrolled for the TEST reviewer ONLY (throwaway account; never reuse this secret). Keep it out of git; set it\n"
          "in your shell for later runs:\n  export %s=%s" % (TOTP_ENV, sec))
    return 0


RESULTS, PENDING, CONTROLS = [], [], {}          # RESULTS: (status, name) with status pass | fail | skip


def _redact(text):
    return re.sub(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", "[jwt]", str(text))[:120]


def check(name, cond, detail=""):
    RESULTS.append(("pass" if cond else "fail", name))
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond or not detail else "  [" + _redact(detail) + "]"))


def skip(name, reason):
    RESULTS.append(("skip", name))
    print("SKIP  %s  [%s]" % (name, reason))


def negative(name, cond, detail="", control="reviewer"):
    """A 'cannot do X' check. Recorded only once the positive control it depends on is known (see finish)."""
    PENDING.append((name, bool(cond), detail, control))


def resolve_negatives():
    for name, cond, detail, control in PENDING:
        if CONTROLS.get(control):
            check(name, cond, detail)
        else:
            skip(name, "inconclusive: positive control '%s' did not pass, so a denial proves nothing" % control)
    PENDING.clear()


def jr(r):
    try:
        return r.json()
    except ValueError:
        return None


def _code(r):
    body = jr(r)
    return str(body.get("code", "")) if isinstance(body, dict) else ""


def denied(r):
    """True only for an AUTHORIZATION refusal: HTTP 401/403 carrying SQLSTATE 42501 (permission denied / RLS) or a
    not_authorized error. A bare 401, an expired token, a missing function (404) or a 204 no-op does NOT count."""
    return r.status_code in (401, 403) and (_code(r) == "42501" or "not_authorized" in (r.text or ""))


def community(dom):
    import community_intel as CI
    _cfg()
    with mock.patch.dict(os.environ, {CI.FLAG_ENV: "1"}):
        CI.reset_cache(); out = CI.lookup({"from_domain": dom}, {}, {}); CI.reset_cache()
    return out


def scan(dom, flag, base_env=None):
    import analyzer
    import community_intel as CI
    raw = ("From: x@%s\nTo: v@corp-example.org\nSubject: e2e synthetic\nDate: Mon, 5 Oct 2026 10:00:00 +0000\n"
           "Message-ID: <e2e@x>\n\nsynthetic body\n" % dom).encode()
    geo = {"origin_risk": 0.0, "origin": {"ip": "8.8.4.4"}, "hops": []}
    env = dict(base_env or {})
    if flag:
        env[CI.FLAG_ENV] = "1"
    with mock.patch.dict(os.environ, env), mock.patch.object(analyzer, "predict", return_value=(0.1, "legit", [])), \
         mock.patch.object(analyzer.geolocate, "trace", return_value=dict(geo)), \
         mock.patch.object(analyzer, "remember_indicator", return_value=False), \
         mock.patch.object(analyzer, "lookup_indicator", return_value=None), \
         mock.patch.object(analyzer, "refresh_stale_url_scores"), mock.patch.object(analyzer, "origin_intel", None):
        if not flag:
            os.environ.pop(CI.FLAG_ENV, None)
        CI.reset_cache(); res = analyzer.analyze_email(raw, "e2e.eml", pipe=object()); CI.reset_cache()
    return res


def run():
    import indicator_sanitizer as IS
    base, _, ref = _cfg()
    print("Project ref: %s | host: %s" % (ref, urlsplit(base).hostname))
    for flag in ("SIH26106_COMMUNITY_INTEL", "SIH26106_CONTRIBUTIONS"):
        if os.environ.get(flag, "").strip().lower() in ("1", "true", "yes", "on"):
            print("WARNING: %s is enabled in this shell; this script overrides it only inside its own process." % flag)
    call("GET", "/rest/v1/shared_indicators?select=id&limit=1")           # forces the marker check
    check("target is the TEST project (is_test_project() = true)", _state["marker_ok"] == base)
    tag = "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))
    dx, dy, dz = ("synthetic-%s-%s.example.org" % (tag, s) for s in ("x", "y", "z"))
    if not all(IS.sanitize_indicator(d, "domain").status == "accepted" for d in (dx, dy, dz)):
        raise Abort("the synthetic indicators are rejected by the local sanitizer; refusing to run a test that cannot succeed")

    # --- anonymous access
    r = call("GET", "/rest/v1/shared_indicators?select=value_norm&status=eq.verified&limit=1")
    check("anon can read verified indicators", r.status_code == 200 and isinstance(jr(r), list), "HTTP %s %s" % (r.status_code, _code(r)))
    r = call("GET", "/rest/v1/indicator_submissions?select=id&limit=1")
    negative("anon cannot read submissions", denied(r) or (r.status_code == 200 and jr(r) == []), "HTTP %s" % r.status_code)
    negative("no-session caller cannot submit", denied(rpc(None, "submit_indicators", {"p_items": []})), control="submit")

    # --- contributor (Supabase anonymous sign-in)
    tok_a = _token(call("POST", "/auth/v1/signup", json={}))
    check("anonymous sign-in available (enable it in Auth settings of the TEST project)", tok_a)
    if not tok_a:
        skip("contribution, review, scan-isolation and failure-handling checks", "no anonymous session")
        return finish()
    item = lambda d: [{"indicator_type": "domain", "value_norm": d, "claimed_verdict": "malicious"}]
    r = rpc(tok_a, "submit_indicators", {"p_items": item(dx)})
    accepted = r.status_code == 200 and isinstance(jr(r), dict) and jr(r).get("accepted") == 1
    check("sanitized synthetic indicator accepted into quarantine", accepted, "HTTP %s %s" % (r.status_code, r.text))
    CONTROLS["submit"] = accepted
    r = rpc(tok_a, "submit_indicators", {"p_items": item(dx)})
    check("duplicate submission not stored twice", r.status_code == 200 and jr(r) == {"accepted": 0, "duplicates": 1, "rejected": 0}, r.text)
    bad = [{"indicator_type": "url", "value_norm": "http://%s/x?t=1" % dx, "claimed_verdict": "malicious"},
           {"indicator_type": "domain", "value_norm": "someone@example.com", "claimed_verdict": "malicious"},
           {"indicator_type": "ip", "value_norm": "10.0.0.5", "claimed_verdict": "malicious"},
           {"indicator_type": "url", "value_norm": "http://%s/aB3xK9pQ2mZ7vL1nR8tY4wC6" % dx, "claimed_verdict": "malicious"}]
    r = rpc(tok_a, "submit_indicators", {"p_items": bad})
    check("invalid indicators rejected (query string, email, private IP, token path)", r.status_code == 200 and jr(r) == {"accepted": 0, "duplicates": 0, "rejected": 4}, r.text)
    r = rpc(tok_a, "submit_indicators", {"p_items": [dict(item(dx)[0], status="verified", contributor_id="00000000-0000-0000-0000-000000000001")]})
    check("client-supplied status/identity ignored (duplicate, not a new row)", r.status_code == 200 and isinstance(jr(r), dict) and jr(r).get("duplicates") == 1, r.text)

    # --- pending stays pending and is not public
    r = call("GET", "/rest/v1/shared_indicators?select=value_norm&value_norm=eq.%s" % dx)
    check("pending indicator is NOT in the public verified set", r.status_code == 200 and jr(r) == [], "HTTP %s %s" % (r.status_code, _code(r)))
    r = call("GET", "/rest/v1/indicator_submissions?select=status&value_norm=eq.%s" % dx, tok_a)
    check("owner sees status = pending", r.status_code == 200 and jr(r) == [{"status": "pending"}], r.text)
    cm = community(dx)
    check("scan does not retrieve a pending indicator (feed reachable, no match)", cm["status"] == "ok" and cm["matches"] == [], str(cm["status"]))

    # --- ordinary users cannot approve / modify trusted data (counted only if the reviewer positive control passes)
    negative("ordinary user cannot read the review queue", denied(rpc(tok_a, "review_queue", {"p_limit": 5})))
    negative("ordinary user cannot approve", denied(rpc(tok_a, "review_submission", {"p_id": "00000000-0000-0000-0000-000000000001", "p_decision": "approve"})))
    for label, resp in (("insert", call("POST", "/rest/v1/shared_indicators", tok_a, json={"indicator_type": "domain", "value_norm": dz, "verdict": "malicious", "status": "verified"})),
                        ("update", call("PATCH", "/rest/v1/shared_indicators?value_norm=eq.%s" % dx, tok_a, json={"status": "verified"})),
                        ("delete", call("DELETE", "/rest/v1/shared_indicators?value_norm=eq.%s" % dx, tok_a))):
        negative("ordinary user cannot %s trusted records" % label, denied(resp), "HTTP %s %s" % (resp.status_code, _code(resp)))
    negative("submission status cannot be changed by its owner", denied(call("PATCH", "/rest/v1/indicator_submissions?value_norm=eq.%s" % dx, tok_a, json={"status": "approved"})))

    # --- reviewer (admin role + MFA)
    email, pw, sec = (os.environ.get(n, "") for n in (EMAIL_ENV, PASS_ENV, TOTP_ENV))
    rv = login(email, pw) if email and pw else None
    check("reviewer can sign in", rv, "set %s and %s" % (EMAIL_ENV, PASS_ENV))
    rv2 = mfa_session(rv, sec) if rv and sec else None
    if rv:
        negative("reviewer WITHOUT MFA (aal1) is refused", denied(rpc(rv, "review_queue", {"p_limit": 5})))
    check("reviewer MFA session obtained", rv2, "run enroll-mfa, then export %s" % TOTP_ENV)
    if not rv2:
        skip("review, approval, rejection, self-review and verified-retrieval checks", "no reviewer aal2 session")
    else:
        q = rpc(rv2, "review_queue", {"p_limit": 200})
        rows = jr(q) if q.status_code == 200 and isinstance(jr(q), list) else []
        row = next((x for x in rows if x.get("value_norm") == dx), None)
        check("reviewer sees the pending submission, without contributor identity", row is not None and "contributor_id" not in row, "HTTP %s %s" % (q.status_code, _code(q)))
        approved = False
        if row is None:
            skip("approval and verified-retrieval checks", "pending submission not found in the review queue")
        else:
            r = rpc(rv2, "review_submission", {"p_id": row["id"], "p_decision": "approve", "p_note": "e2e synthetic"})
            approved = r.status_code == 200 and isinstance(jr(r), dict) and jr(r).get("status") == "approved"
            check("reviewer approves", approved, r.text)
            CONTROLS["reviewer"] = approved
            r = rpc(rv2, "review_submission", {"p_id": row["id"], "p_decision": "approve"})
            check("approving twice is refused", r.status_code == 400 and "already_reviewed" in r.text, r.text)
        rpc(tok_a, "submit_indicators", {"p_items": item(dy)})
        qy = jr(rpc(rv2, "review_queue", {"p_limit": 200}))
        ry = next((x for x in (qy if isinstance(qy, list) else []) if x.get("value_norm") == dy), None)
        if ry is None:
            skip("reject checks", "second submission not found in the review queue")
        else:
            rj = jr(rpc(rv2, "review_submission", {"p_id": ry["id"], "p_decision": "reject", "p_note": "e2e"}))
            check("reviewer rejects a submission", isinstance(rj, dict) and rj.get("status") == "rejected")
            check("rejected indicator never becomes verified", jr(call("GET", "/rest/v1/shared_indicators?select=id&value_norm=eq.%s" % dy)) == [])
        rpc(rv2, "submit_indicators", {"p_items": item(dz)})
        qz = jr(rpc(rv2, "review_queue", {"p_limit": 200}))
        qz = next((x for x in (qz if isinstance(qz, list) else []) if x.get("value_norm") == dz), None)
        if qz is None:
            skip("reviewer cannot approve their own submission", "reviewer's own submission not found in the review queue")
        else:
            r = rpc(rv2, "review_submission", {"p_id": qz["id"], "p_decision": "approve"})
            check("reviewer cannot approve their own submission", r.status_code == 400 and "self_review" in r.text, r.text)

        # --- verified retrieval and scanning
        if not approved:
            skip("verified retrieval and scan checks", "the approval did not succeed")
        else:
            r = call("GET", "/rest/v1/shared_indicators?select=value_norm,verdict,status&value_norm=eq.%s" % dx)
            body = jr(r) if r.status_code == 200 else None
            check("anon can now read the approved indicator", isinstance(body, list) and len(body) == 1 and body[0].get("status") == "verified", "HTTP %s %s" % (r.status_code, _code(r)))
            cm = community(dx)
            check("scan retrieves the verified community indicator", cm["status"] == "ok" and any(m["indicator"] == dx and m["source"] == "community" for m in cm["matches"]), str(cm["status"]))
            on, off = scan(dx, True), scan(dx, False)
            check("scan result carries community_intel only when the flag is on", "community_intel" in on and "community_intel" not in off)
            check("detection score and level are identical with community intel on/off", (on["score"], on["level"]) == (off["score"], off["level"]))

    # --- private scan isolation (needs two email users: disable 'confirm email' in the TEST project)
    ua, ub = ("e2e-%s-%s@example.test" % (tag, s) for s in "ab")
    pwd = "E2e-" + secrets.token_hex(8)
    ta = _token(call("POST", "/auth/v1/signup", json={"email": ua, "password": pwd}))
    tb = _token(call("POST", "/auth/v1/signup", json={"email": ub, "password": pwd}))
    if not (ta and tb):
        skip("private-scan isolation and self-escalation checks", "email sign-up gave no session (disable 'Confirm email' in the TEST project)")
    else:
        r = call("POST", "/rest/v1/scans", ta, extra_headers={"Prefer": "return=representation"}, json={"evidence_hash": "a" * 64, "summary": {"score": 10}})
        body = jr(r) if r.status_code == 201 else None
        sid = body[0].get("id") if isinstance(body, list) and body and isinstance(body[0], dict) else None
        check("user A can store a private scan summary", sid is not None, "HTTP %s %s" % (r.status_code, _code(r)))
        CONTROLS["scans"] = sid is not None
        if sid is None:
            skip("scan isolation checks (B cannot read/modify, no cross-user assignment, anonymous refused, body keys refused)",
                 "user A could not store a scan: the scans INSERT grant/policy or an RPC needs a decision")
        else:
            check("user B cannot read A's scan", jr(call("GET", "/rest/v1/scans?select=id&id=eq.%s" % sid, tb)) == [])
            call("PATCH", "/rest/v1/scans?id=eq.%s" % sid, tb, json={"summary": {"hacked": True}})
            call("DELETE", "/rest/v1/scans?id=eq.%s" % sid, tb)
            mine = jr(call("GET", "/rest/v1/scans?select=summary&id=eq.%s" % sid, ta))
            check("user B could not modify or delete A's scan", mine == [{"summary": {"score": 10}}], str(mine))
            negative("user A cannot assign a scan to another user", denied(call("POST", "/rest/v1/scans", ta, json={"user_id": "00000000-0000-0000-0000-000000000001", "evidence_hash": "b" * 64, "summary": {}})), control="scans")
            negative("anonymous sign-in session cannot store private scans", denied(call("POST", "/rest/v1/scans", tok_a, json={"evidence_hash": "c" * 64, "summary": {}})), control="scans")
            r = call("POST", "/rest/v1/scans", ta, json={"evidence_hash": "d" * 64, "summary": {"body": "x"}})
            negative("scan summaries with email-content keys are refused", r.status_code in (400, 403), "HTTP %s" % r.status_code, control="scans")
        call("PUT", "/auth/v1/user", ta, json={"data": {"role": "admin"}})            # self-escalation attempt via user_metadata
        fresh = login(ua, pwd)
        negative("self-set user_metadata admin claim grants no review rights", bool(fresh) and denied(rpc(fresh, "review_queue", {"p_limit": 5})))

    # --- database failure handling (no real database is contacted: a closed local port)
    import community_intel as CI
    try:
        import contribution_client as CC
    except ImportError:
        CC = None
    with mock.patch.dict(os.environ, {SIC.URL_ENV: "http://127.0.0.1:9", CI.FLAG_ENV: "1"}):
        CI.reset_cache()
        res = scan(dx, True, {SIC.URL_ENV: "http://127.0.0.1:9"})
        sub = None
        if CC is not None:
            CC._last_submit.clear()
            with mock.patch.dict(os.environ, {CC.FLAG_ENV: "1"}):
                sub = CC.submit([{"indicator_type": "domain", "value_norm": dx}], "suspicious", True, token="t", timeout=2)
        CI.reset_cache()
    if sub is None:
        skip("contribution fails softly when the database is down", "contribution_client.py not importable")
    else:
        check("contribution fails softly when the database is down", sub["ok"] is False and sub["error"] == "unavailable", sub["error"])
    check("scan still completes when the database is down (community intel unavailable)", res["score"] is not None and res.get("community_intel", {}).get("status") == "unavailable")
    return finish()


def finish():
    resolve_negatives()
    n = [sum(1 for st, _ in RESULTS if st == k) for k in ("pass", "fail", "skip")]
    print("\n%d passed, %d failed, %d skipped/inconclusive" % tuple(n))
    return 0 if n[0] and not n[1] and not n[2] else 1


def main(argv):
    try:
        if argv[:1] == ["check"]:
            base, _, ref = _cfg(); call("GET", "/rest/v1/shared_indicators?select=id&limit=1")
            print("OK: test project ref %s (host %s), is_test_project() = true" % (ref, urlsplit(base).hostname)); return 0
        if argv[:1] == ["enroll-mfa"]:
            return enroll_mfa()
        if argv[:1] == ["run"]:
            return run()
        print(__doc__); return 2
    except Abort as exc:
        print("ABORTED (nothing was sent to a non-test project): %s" % exc); return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
