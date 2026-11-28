"""Fail-closed target guard shared by the MANUAL Supabase scripts (test_authenticated_submission.py, test_global_lock_race.py).

No project reference is a usable default: the target comes only from the environment, and every check must pass before the
scripts may send a single request or ask for credentials. Nothing in this module logs, prints or stores a key or token.

Environment (all required unless noted):
  ALGORITHMISTIC_TEST_SUPABASE_URL   https://<ref>.supabase.co  (exact; no port, path, query or userinfo)
  ALGORITHMISTIC_TEST_PROJECT_REF    the TEST project's reference id; must equal the URL host label exactly
  ALGORITHMISTIC_TEST_CONFIRM        TEST-PROJECT-ONLY:<ref>   (bound to the ref, so it cannot be reused for another project)
  ALGORITHMISTIC_TEST_ANON_KEY       publishable/anon key only (optional: otherwise prompted without echo)
  ALGORITHMISTIC_PROD_REFS           optional, comma-separated extra production refs, added to the built-in denylist
Before any write the project must answer public.is_test_project() = true. A service-role/secret key is always refused.
"""
import base64
import json
import os
import re
from urllib.parse import urlsplit

import requests

URL_ENV, REF_ENV, CONFIRM_ENV = "ALGORITHMISTIC_TEST_SUPABASE_URL", "ALGORITHMISTIC_TEST_PROJECT_REF", "ALGORITHMISTIC_TEST_CONFIRM"
KEY_ENV, PROD_REFS_ENV = "ALGORITHMISTIC_TEST_ANON_KEY", "ALGORITHMISTIC_PROD_REFS"
CONFIRM_PREFIX = "TEST-PROJECT-ONLY:"
# Known production project(s): a DENYLIST, never a target. Extend with ALGORITHMISTIC_PROD_REFS.
PROD_DENYLIST = frozenset({"qozfyuiloitutpfthuwn"})
_REF_RE = re.compile(r"^[a-z0-9]{6,40}$")
TIMEOUT = (5, 15)


class Abort(Exception):
    pass


class Target:
    __slots__ = ("ref", "host", "base")

    def __init__(self, ref, host, base):
        self.ref, self.host, self.base = ref, host, base


def prod_refs():
    extra = {r.strip().lower() for r in os.environ.get(PROD_REFS_ENV, "").split(",") if r.strip()}
    return set(PROD_DENYLIST) | extra


def load_target():
    """Validate configuration only (no network). Raises Abort on anything missing, mismatched or uncertain."""
    ref = os.environ.get(REF_ENV, "").strip()
    url = os.environ.get(URL_ENV, "").strip()
    if not _REF_RE.match(ref):
        raise Abort("set %s to the TEST project's reference id (lowercase letters/digits)" % REF_ENV)
    if ref.lower() in prod_refs():
        raise Abort("this ref is on the production denylist; refusing")
    if os.environ.get(CONFIRM_ENV, "") != CONFIRM_PREFIX + ref:
        raise Abort("set %s=%s%s to confirm this is the test project" % (CONFIRM_ENV, CONFIRM_PREFIX, ref))
    if not url:
        raise Abort("set %s to https://<ref>.supabase.co" % URL_ENV)
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise Abort("target URL is not valid")
    if (parts.scheme != "https" or parts.hostname != ref + ".supabase.co" or port is not None
            or parts.username or parts.password or parts.path not in ("", "/") or parts.query or parts.fragment):
        raise Abort("target URL must be exactly https://%s.supabase.co and match the project ref" % ref)
    host = ref + ".supabase.co"
    return Target(ref, host, "https://" + host)


def claims(jwt):
    try:
        p = jwt.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return None


def check_key(key, target):
    """Publishable/anon keys only. Anything else (secret, service_role, opaque, other project) is refused."""
    if not key or key.startswith("sb_secret_"):
        raise Abort("key missing or is a secret/service key")
    if key.startswith("sb_publishable_"):
        return
    c = claims(key)
    if not isinstance(c, dict) or c.get("role") != "anon":
        raise Abort("key is not a publishable/anon key")
    if c.get("ref") not in (None, target.ref):
        raise Abort("key belongs to a different project")


def verify_test_project(target, key):
    """Must be called, and must succeed, before sign-in or any write. Fails closed on any uncertainty."""
    try:
        r = requests.post(target.base + "/rest/v1/rpc/is_test_project", json={}, timeout=TIMEOUT, allow_redirects=False,
                          headers={"apikey": key, "Content-Type": "application/json"})
        ok = r.status_code == 200 and r.json() is True
    except (requests.RequestException, ValueError):
        ok = False
    if not ok:
        raise Abort("project did not answer public.is_test_project() = true; NOT a verified test project, aborting")
