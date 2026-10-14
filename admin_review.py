"""Reviewer-only Admin Review page for quarantined community submissions. OFF unless SIH26106_ADMIN_REVIEW is truthy.

Authorization is entirely server-side: public.review_queue / review_submission re-check that the caller's JWT has
app_metadata.role = 'admin' AND aal = 'aal2'. This module never grants roles, never uses a service-role key (refused), keeps
tokens only in st.session_state, never logs tokens/secrets (stderr diagnostics are scrubbed), and never decides anything on
its own: every approve/reject is an explicit per-row button behind a per-attempt confirmation. Audit logging stays in the DB.
"""
import base64
import os
import re
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import unquote

import requests

import contribution_client as _cc
import shared_intel_client as _sic

FLAG_ENV = "SIH26106_ADMIN_REVIEW"
REVIEW_KEY, QUEUE_KEY, ENROLL_KEY, ATTEMPT_KEY = "_review_session", "_review_queue", "_review_enroll", "_review_attempt"
TIMEOUT, NOTE_MAX = 15, 200
_CODE = re.compile(r"\d{6}")
_DB_ERRORS = {"forbidden", "invalid_decision", "note_too_long", "not_found", "already_reviewed", "self_review", "reason_required", "invalid_indicator", "allowlisted"}
_MSG = {
    "not_configured": "Admin review is not configured.", "unsafe_credentials": "A service-role or secret key was supplied; only the public anon key is allowed.",
    "auth_required": "Sign in with Google first.", "unavailable": "The service is unavailable right now. Please try again.",
    "forbidden": "Not an authorized admin, or this session has not passed MFA.", "rate_limited": "Too many requests. Please wait a little.",
    "invalid_code": "Enter the 6-digit code from your authenticator app.", "mfa_invalid": "That code was not accepted. Try the next code.",
    "mfa_not_elevated": "MFA verification did not raise the session to the required level.", "enroll_failed": "Could not start authenticator setup.",
    "rejected": "The request was rejected.", "server_error": "The server could not complete the request.",
    "self_review": "You cannot review your own submission.",
    "reason_required": "Self-review requires a reason in the note (10-200 characters). It will be audited and labelled self-reviewed.", "already_reviewed": "Already reviewed.", "not_found": "Submission not found.",
    "allowlisted": "Blocked: this indicator is on the allowlist.", "invalid_indicator": "Blocked: invalid indicator.",
    "note_too_long": "Note is too long (200 characters max).", "invalid_decision": "Invalid decision.",
    "not_admin": "Access denied: administrator privileges required",
}


def enabled():
    return os.environ.get(FLAG_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _setup():
    url, key = os.environ.get(_sic.URL_ENV, "").strip(), os.environ.get(_sic.KEY_ENV, "").strip()
    base = _sic._base_url(url) if url else None
    if not base or not key:
        return None, "not_configured"
    if _sic._key_problem(key):
        return None, "unsafe_credentials"
    return (base, key), ""


def _call(stage, method, base, key, path, token, body=None):
    """(response, error_code). Never raises, never follows redirects, never logs tokens."""
    try:
        resp = requests.request(method, base + path, json=body, timeout=TIMEOUT, allow_redirects=False,
                                headers={"apikey": key, "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    except Exception as exc:
        _cc._diag(stage, exc=exc)
        return None, "unavailable"
    sc = resp.status_code
    if sc < 300:
        return resp, ""
    _cc._diag(stage, resp)
    if sc < 400 or sc >= 500:
        return resp, "unavailable"
    return resp, "forbidden" if sc in (401, 403) else "rate_limited" if sc == 429 else "rejected"


def _db_error(resp, default="server_error"):
    try:
        msg = str(resp.json().get("message", ""))
    except Exception:
        msg = ""
    return msg if msg in _DB_ERRORS else default


def base_token(store, base, key):
    """(access_token, err) of the ordinary (aal1) Google-backed session. Used ONLY for the MFA endpoints."""
    state = _cc.auth_state(store)
    if state == "session":
        return store[_cc.SESSION_KEY]["access_token"], ""
    if state == "id_token":
        try:
            sess, err = _cc._sign_in_google(store, base, key, TIMEOUT)
        except Exception as exc:
            _cc._diag("admin_signin", exc=exc)
            return None, "unavailable"
        return (sess["access_token"], "") if sess else (None, err)
    return None, "auth_required"


def review_token(store):
    """Access token of a verified-MFA (aal2) review session, else None. Client-side hint only; the database re-checks."""
    sess = store.get(REVIEW_KEY) if hasattr(store, "get") else None
    tok = sess.get("access_token") if isinstance(sess, dict) else None
    claims = _cc._jwt_claims(tok) if isinstance(tok, str) else None
    if claims is None or claims.get("aal") != "aal2" or _cc._is_anonymous(tok):
        return None
    return tok


def admin_role_check(base, key, token):
    """(True, '') only if Supabase Auth (GET /auth/v1/user, server-verified) reports a non-anonymous user whose trusted
    app_metadata.role == 'admin'. Anything else is ('not_admin') or a transport error code. UI gate only; the DB re-checks."""
    resp, err = _call("admin_role", "GET", base, key, "/auth/v1/user", token)
    if err == "forbidden":
        return False, "not_admin"
    if err:
        return False, err
    try:
        d = resp.json()
        ok = isinstance(d, dict) and not d.get("is_anonymous") and isinstance(d.get("app_metadata"), dict) and d["app_metadata"].get("role") == "admin"
    except Exception as exc:
        _cc._diag("admin_role", resp, exc=exc)
        return False, "unavailable"
    return (True, "") if ok else (False, "not_admin")


def verified_factors(base, key, token):
    resp, err = _call("admin_factors", "GET", base, key, "/auth/v1/user", token)
    if err:
        return None, err
    try:
        fs = resp.json().get("factors") or []
        return [f["id"] for f in fs if isinstance(f, dict) and f.get("factor_type") == "totp" and f.get("status") == "verified" and isinstance(f.get("id"), str)], ""
    except Exception as exc:
        _cc._diag("admin_factors", resp, exc=exc)
        return None, "unavailable"


_SVG_NS = "http://www.w3.org/2000/svg"
_SVG_TAGS = frozenset(("svg", "g", "rect", "path", "circle", "polygon", "polyline", "line"))
_SVG_ATTRS = frozenset(("width", "height", "viewBox", "preserveAspectRatio", "version", "x", "y", "cx", "cy", "r", "x1", "y1", "x2", "y2",
                        "d", "points", "transform", "style", "class", "id", "fill", "fill-rule", "fill-opacity", "stroke", "stroke-width",
                        "stroke-opacity", "stroke-linecap", "stroke-linejoin", "opacity", "shape-rendering"))
_SVG_VALUE = re.compile(r"[A-Za-z0-9\s.,#%():;+\-_]*")             # no quotes, <, >, &, /, = : nothing that can break out of an attribute
_SVG_BAD_VALUE = re.compile(r"url\s*\(|javascript|data:|expression|@import", re.I)
_SVG_PROLOG = re.compile(r"\s*(?:<\?xml\s[^>]*?\?>|<!--(?:(?!--).)*-->|<!DOCTYPE[^>\[]*>)", re.S | re.I)   # xml decl, comment, plain DOCTYPE only
_SVG_MAX_CHARS, _SVG_MAX_NODES, _SVG_MAX_DEPTH = 400_000, 20_000, 10


def _svg_local(tag):
    ns, _, name = tag[1:].partition("}") if tag.startswith("{") else ("", "", tag)
    if ns not in ("", _SVG_NS) or name not in _SVG_TAGS:
        raise ValueError("tag " + _cc._scrub(name or tag, 30))
    return name


def _svg_emit(el, out, depth, count):
    name = _svg_local(el.tag)
    count[0] += 1
    if depth > _SVG_MAX_DEPTH or count[0] > _SVG_MAX_NODES:
        raise ValueError("too large or deep")
    if (el.text or "").strip() or (el.tail or "").strip():
        raise ValueError("text content")
    attrs = []
    for k, v in el.attrib.items():
        if k not in _SVG_ATTRS:
            raise ValueError("attribute " + _cc._scrub(k, 30))
        if not _SVG_VALUE.fullmatch(v) or _SVG_BAD_VALUE.search(v):
            raise ValueError("value of " + k)
        attrs.append(' %s="%s"' % (k, v))
    head = "<" + name + (' xmlns="%s"' % _SVG_NS if depth == 0 else "") + "".join(attrs)
    if len(el) == 0:
        out.append(head + "/>")
        return
    out.append(head + ">")
    for ch in el:
        _svg_emit(ch, out, depth + 1, count)
    out.append("</" + name + ">")


def _svg_parse(qr):
    """(clean_svg, None) or (None, reason). Supabase returns the QR as raw SVG over REST (xml declaration, a generator comment,
    then <svg>) or as a data URI in client libraries. The markup is PARSED as XML and re-emitted from an allow-list of drawing
    elements/attributes, so scripts, event handlers, links, styles with url(), DOCTYPE internal subsets/entities, CDATA and
    processing instructions can never pass through. Reasons name tags/attributes only, never payload content."""
    if not isinstance(qr, str):
        return None, "qr_code rejected: not a string"
    s = qr.strip()
    try:
        if s.startswith("data:image/svg+xml"):
            head, _, body = s.partition(",")
            s = (base64.b64decode(body, validate=True).decode("utf-8") if head.endswith(";base64") else unquote(body)).strip()
        if len(s) > _SVG_MAX_CHARS:
            return None, "qr_code rejected: too large"
        for _ in range(8):
            m = _SVG_PROLOG.match(s)
            if not m:
                break
            s = s[m.end():]
        s = s.lstrip()
        if not s.startswith("<svg") or "<!" in s or "<?" in s:
            return None, "qr_code rejected: unexpected markup before or inside <svg>"
        root, out = ET.fromstring(s), []  # nosec B314: input is size-limited and rejects all DTD/entity/PI markup before parsing.
        if _svg_local(root.tag) != "svg":
            return None, "qr_code rejected: root is not svg"
        _svg_emit(root, out, 0, [0])
        return "".join(out), None
    except ValueError as exc:
        return None, "qr_code rejected: " + _cc._scrub(exc, 60)
    except Exception:
        return None, "qr_code rejected: not well-formed"


def _svg(qr):
    return _svg_parse(qr)[0]


def enroll(base, key, token):
    """Start TOTP enrollment. Returns ({'factor_id','svg','secret'}, '') or (None, code). Never grants any role."""
    resp, err = _call("admin_enroll", "POST", base, key, "/auth/v1/factors", token,
                      {"factor_type": "totp", "friendly_name": "reviewer-%d" % int(time.time()), "issuer": "Algorithmistic"})
    if err:
        return None, "enroll_failed" if err == "rejected" else err
    try:
        d = resp.json()
        fid, t = d["id"], d["totp"]
        uuid.UUID(fid)
        secret, qr = t["secret"], t["qr_code"]
        svg, why = _svg_parse(qr)
        why = why or ("secret missing" if not isinstance(secret, str) or not secret else None)
    except Exception as exc:
        _cc._diag("admin_enroll", resp, exc=exc, note="unexpected enrollment fields")
        return None, "enroll_failed"
    if why:
        _cc._diag("admin_enroll", resp, note=why)
        return None, "enroll_failed"
    return {"factor_id": fid, "svg": svg, "secret": secret}, ""


def verify(store, base, key, token, factor_id, code):
    """MFA challenge + verify. On success stores the aal2 session in `store`; returns '' or an error code."""
    code = code.strip() if isinstance(code, str) else ""
    if not _CODE.fullmatch(code):
        return "invalid_code"
    try:
        uuid.UUID(str(factor_id))
    except ValueError:
        return "mfa_invalid"
    resp, err = _call("admin_mfa_challenge", "POST", base, key, "/auth/v1/factors/%s/challenge" % factor_id, token, {})
    if err:
        return err
    try:
        cid = resp.json()["id"]
        assert isinstance(cid, str) and cid
    except Exception as exc:
        _cc._diag("admin_mfa_challenge", resp, exc=exc)
        return "unavailable"
    resp, err = _call("admin_mfa_verify", "POST", base, key, "/auth/v1/factors/%s/verify" % factor_id, token, {"challenge_id": cid, "code": code})
    if err:
        return "mfa_invalid" if err == "rejected" else err
    sess, err = _cc._read_session(resp)
    if err:
        return err
    if (_cc._jwt_claims(sess["access_token"]) or {}).get("aal") != "aal2":
        _cc._diag("admin_mfa_verify", resp, note="session is not aal2 after verify")
        return "mfa_not_elevated"
    store[REVIEW_KEY] = sess
    return ""


def queue(base, key, token, limit=50):
    resp, err = _call("admin_queue", "POST", base, key, "/rest/v1/rpc/review_queue", token, {"p_limit": int(limit)})
    if err:
        return None, "forbidden" if err == "rejected" and _db_error(resp) == "forbidden" else err
    try:
        rows = resp.json()
        if not isinstance(rows, list):
            raise ValueError("unexpected queue shape")
        return [r for r in rows if isinstance(r, dict)], ""
    except Exception as exc:
        _cc._diag("admin_queue", resp, exc=exc)
        return None, "unavailable"


def decide(base, key, token, submission_id, decision, note=None):
    """Forward ONE explicit reviewer decision to the DB function (which re-checks admin+aal2, writes audit_log). '' or error."""
    if decision not in ("approve", "reject"):
        return "invalid_decision"
    note = (note or "").strip() or None
    if note and len(note) > NOTE_MAX:
        return "note_too_long"
    try:
        sid = str(uuid.UUID(str(submission_id)))
    except ValueError:
        return "not_found"
    resp, err = _call("admin_decide", "POST", base, key, "/rest/v1/rpc/review_submission", token, {"p_id": sid, "p_decision": decision, "p_note": note})
    if err == "rejected":
        return _db_error(resp)
    return err


def _clear(store):
    for k in (REVIEW_KEY, QUEUE_KEY, ENROLL_KEY):
        store.pop(k, None)


def render(st, signin=None):
    """Streamlit UI. `signin` is an optional zero-arg callable returning a Google sign-in URL (only called when needed)."""
    store = st.session_state
    cfg, err = _setup()
    if err:
        st.caption(_MSG[err])
        return
    base, key = cfg
    st.caption("Reviewers only. Access is enforced by the database (admin role + MFA); this page cannot grant it.")
    tok = review_token(store)
    if tok is None:
        bt, err = base_token(store, base, key)
        if err:
            st.info(_MSG.get(err, _MSG["server_error"]))
            if err == "auth_required" and signin:
                try:
                    st.link_button("Sign in with Google", signin(), key="admin_signin")
                except Exception:
                    st.caption("Couldn't start Google sign-in right now.")
            return
        ok, err = admin_role_check(base, key, bt)
        if not ok:
            (st.error if err == "not_admin" else st.warning)(_MSG.get(err, _MSG["server_error"]))
            store.pop(ENROLL_KEY, None)
            return
        enr = store.get(ENROLL_KEY)
        if enr is None:
            factors, err = verified_factors(base, key, bt)
            if err:
                st.warning(_MSG.get(err, _MSG["server_error"]))
                return
            factor = factors[0] if factors else None
            if factor is None and st.button("Set up authenticator app", key="admin_enroll_btn"):
                enr, err = enroll(base, key, bt)
                if err:
                    st.warning(_MSG[err])
                    return
                store[ENROLL_KEY] = enr
                st.rerun()
        else:
            factor = enr["factor_id"]
            st.write("Scan this QR code with an authenticator app, or enter the key manually, then type the 6-digit code.")
            st.image(enr["svg"], width=200)
            st.code(enr["secret"])
            st.caption("The key is shown only during setup and is never stored or logged.")
            if st.button("Cancel setup", key="admin_enroll_cancel"):
                store.pop(ENROLL_KEY, None)
                st.rerun()
        if factor:
            code = st.text_input("Authenticator code", max_chars=6, key="admin_totp", type="password")
            if st.button("Verify", key="admin_verify"):
                err = verify(store, base, key, bt, factor, code)
                if err:
                    st.warning(_MSG.get(err, _MSG["server_error"]))
                else:
                    store.pop(ENROLL_KEY, None)
                    st.rerun()
        return
    if st.button("End review session", key="admin_end"):
        _clear(store)
        st.rerun()
    rows = store.get(QUEUE_KEY)
    if rows is None or st.button("Refresh queue", key="admin_refresh"):
        rows, err = queue(base, key, tok)
        if err:
            if err == "forbidden":
                _clear(store)
            st.warning(_MSG.get(err, _MSG["server_error"]))
            return
        store[QUEUE_KEY] = rows
    flash = store.pop("_review_flash", None)
    if flash:
        st.success(flash)
    st.write("%d pending" % len(rows))
    n = store.get(ATTEMPT_KEY, 0)
    for r in rows:
        rid = str(r.get("id", ""))
        with st.container(border=True):
            st.code(str(r.get("value_norm", ""))[:300])        # st.code: contributor-supplied text is never rendered as markup
            st.caption("%s | claimed %s | %s contributor(s) | %s" % (r.get("indicator_type"), r.get("claimed_verdict"), r.get("distinct_contributors"), r.get("created_at")))
            note = st.text_input("Note (optional, max %d)" % NOTE_MAX, max_chars=NOTE_MAX, key="rv_n_%s_%d" % (rid, n))
            ok = st.checkbox("I confirm this decision", key="rv_c_%s_%d" % (rid, n))
            a, b = st.columns(2)
            pick = "approve" if a.button("Approve", key="rv_a_%s_%d" % (rid, n), disabled=not ok) else "reject" if b.button("Reject", key="rv_r_%s_%d" % (rid, n), disabled=not ok) else None
            if pick:
                err = decide(base, key, tok, rid, pick, note)
                store[ATTEMPT_KEY] = n + 1                     # fresh confirmation required for every attempt
                store.pop(QUEUE_KEY, None)
                if err == "forbidden":
                    _clear(store)
                if err:
                    st.warning(_MSG.get(err, _MSG["server_error"]))
                else:
                    store["_review_flash"] = "Recorded: %s." % ("approved" if pick == "approve" else "rejected")
                    st.rerun()
