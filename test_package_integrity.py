"""Offline structural checks of the SQL package against the exported definitions (text/ACL level only - no SQL is executed).
Needs AUDIT_DIR (or ./security_audit_inputs) with the five CSV exports."""
import collections, csv, difflib, glob, os, re, unittest
import sql_model as M

D = M.audit_dir(); HERE = os.path.dirname(os.path.abspath(__file__))
rd = lambda p: open(os.path.join(HERE, p), encoding="utf-8").read()
MIG, RB = rd("supabase/migrations/20261014000001_protect_indicator_submission.sql"), rd("supabase/proposals/20261012_protect_indicator_submission_ROLLBACK.sql")

def export_defs():
    out = {}
    for f in glob.glob(os.path.join(D, "*.csv")):
        for r in csv.DictReader(open(f, newline="", encoding="utf-8")):
            for v in r.values():
                m = re.match(r"CREATE OR REPLACE FUNCTION (\S+?)\(", (v or "").replace("\r", ""))
                if m and "$function$" in v:
                    out.setdefault(m.group(1), v.replace("\r", "").strip())
    return out
EX = export_defs()
BASE = rd("supabase/migrations/20261013000001_contributions.sql")   # the pre-hardening functions: what the rollback must restore and what the migration changes
def body(sql, name):
    m = re.search(r"create or replace function %s\(.*?(\$function\$|\$\$)(.*?)\1;" % re.escape(name), sql, re.S | re.I)
    return m.group(2) if m else None
def norm(b):                                              # comments and whitespace are not behaviour
    return [re.sub(r"\s+", " ", l).strip() for l in re.sub(r"--[^\n]*", "", b).splitlines() if l.strip()]
def line_changes(name):
    old, new = collections.Counter(norm(body(BASE, name))), collections.Counter(norm(body(MIG, name)))
    return sorted((old - new).elements()), sorted((new - old).elements())
def fn(sql, name):
    m = re.search(r"create or replace function %s\(.*?\$function\$;" % re.escape(name), sql, re.S | re.I)
    return m.group(0)[:-1] if m else None
split = lambda t: (t[:t.index("$function$")], t[t.index("$function$"):])

class Rollback(unittest.TestCase):
    def test_original_functions_restored_verbatim(self):
        hdr = {"private.valid_indicator": ("immutable",), "public.submit_indicators": ("security definer",)}
        for name in ("private.valid_indicator", "public.submit_indicators"):
            self.assertEqual(norm(body(RB, name)), norm(body(BASE, name)), name)   # body identical to the pre-hardening definition
            head = split(fn(RB, name))[0].lower()
            for tok in ("language plpgsql", "set search_path to ''") + hdr[name]:   # header: language, security definer, search_path, volatility
                self.assertIn(tok, head, name)
            self.assertNotIn("valid_host_labels", body(RB, name)); self.assertNotIn("is_anonymous", body(RB, name)); self.assertNotIn("7301", body(RB, name))
    def test_rollback_changes_no_permissions_or_ownership(self):
        low = RB.lower()
        for bad in ("grant ", "revoke ", "owner to", "alter function", "create index", "alter table", "policy"):
            self.assertNotIn(bad, re.sub(r"--[^\n]*", "", low), bad)
        self.assertEqual(low.count("drop function"), 1); self.assertIn("drop function if exists private.valid_host_labels(text)", low)
    def test_rollback_drops_helper_after_restoring_valid_indicator(self):
        self.assertLess(RB.index("private.valid_indicator"), RB.index("drop function"))

class Migration(unittest.TestCase):
    def changed(self, name, new):
        a, b = EX[name].splitlines(), new.splitlines()
        d = list(difflib.ndiff(a, b)); return [x[2:] for x in d if x[0] == "-"], [x[2:] for x in d if x[0] == "+"]
    def test_headers_identical_to_export(self):               # signature, returns, language, security definer/invoker, volatility, search_path
        for name in ("private.valid_indicator", "public.submit_indicators"):
            self.assertEqual(split(EX[name])[0].lower(), split(fn(MIG, name))[0].lower(), name)
    def test_valid_indicator_only_two_lines_changed(self):
        rem, add = line_changes("private.valid_indicator")                 # vs the pre-hardening definition: host-label validation for domain and URL hosts, nothing else
        self.assertEqual(rem, sorted(["if p_type = 'domain' then return private.valid_domain(p_value); end if;",
                                      "if not (private.valid_domain(m[1]) or (m[1] ~ '^[0-9.]+$' and private.is_public_ip(m[1]))) then return false; end if;"]))
        self.assertEqual(add, sorted(["if p_type = 'domain' then return private.valid_domain(p_value) and private.valid_host_labels(p_value); end if;",
                                      "if not ((private.valid_domain(m[1]) and private.valid_host_labels(m[1]))",
                                      "or (m[1] ~ '^[0-9.]+$' and private.is_public_ip(m[1]))) then return false; end if;"]))
        self.assertIn("looks_like_token(seg)", body(MIG, "private.valid_indicator"))   # URL path-segment token check kept
    def test_submit_indicators_only_intended_changes(self):
        rem, add = line_changes("public.submit_indicators")                # vs the pre-hardening definition
        self.assertEqual(rem, ["if v_uid is null then raise exception 'auth_required' using errcode = '42501'; end if;"])
        self.assertEqual(add, sorted([
            "c_pending_user constant int := 100; c_pending_global constant int := 1000;",
            "if v_uid is null or private.is_anonymous() then raise exception 'auth_required' using errcode = '42501'; end if;",
            "perform pg_advisory_xact_lock(7301, 1);",
            "if (select count(*) from public.indicator_submissions where contributor_id = v_uid and status = 'pending') + v_n > c_pending_user",
            "or (select count(*) from public.indicator_submissions where status = 'pending') + v_n > c_pending_global then",
            "raise exception 'queue_full' using errcode = 'P0001';",
            "end if;"]))
        for kept in ("c_per_request constant int := 20", "c_per_hour constant int := 50", "c_per_day constant int := 200", "c_global_hour constant int := 2000",
                     "c_reject_block constant int := 10", "'rate_limited'", "'blocked'", "'too_many_items'", "'invalid_payload'"):   # existing limits untouched
            self.assertIn(kept, body(MIG, "public.submit_indicators"))
        blob = "\n".join(add)
        for need in ("private.is_anonymous()", "pg_advisory_xact_lock(7301, 1)", "c_pending_user constant int := 100", "c_pending_global constant int := 1000", "queue_full"):
            self.assertIn(need, blob)
        self.assertIn("pg_advisory_xact_lock(hashtext(v_uid::text))", fn(MIG, "public.submit_indicators"))   # per-user lock preserved
        self.assertLess(MIG.index("pg_advisory_xact_lock(hashtext"), MIG.index("pg_advisory_xact_lock(7301"))   # lock order per-user -> global
    def test_pending_cap_semantics_documented(self):
        self.assertIn("duplicates", MIG); self.assertIn("rejected as invalid", MIG)
    def test_no_permission_rls_index_or_ipv6_changes(self):
        code = re.sub(r"--[^\n]*", "", MIG).lower()
        self.assertEqual(re.findall(r"\bgrant\b[^;]*;", code), ["grant execute on function public.submit_indicators(jsonb) to authenticated;"])   # only the re-asserted authenticated grant; never anon/public\r
        self.assertEqual(re.findall(r"revoke all on function (\S+)", code), ["private.valid_host_labels(text)", "public.submit_indicators(jsonb)"])
        for bad in ("create index", "create policy", "alter table", "enable row level", "owner to", "default privileges", "create extension", "cron"):
            self.assertNotIn(bad, code)
        self.assertNotIn(r"\[", MIG.replace("[^aeiouy]", "").replace("[a-z]", ""))    # no bracketed-IPv6 regex left
        self.assertNotIn("host(m[1]", MIG)
    def test_helper_acl_matches_private_helpers(self):
        self.assertIn("from public, anon, authenticated, service_role", MIG)
        self.assertIn("{postgres=X/postgres}", MIG)
    def test_model_bigram_list_equals_sql_list(self):                       # no drift between sql_model.py and the migration
        arr = re.search(r"substr\(lbl, k, 2\) = any \(array\[(.*?)\]\)", MIG).group(1)
        self.assertEqual(re.findall(r"'([a-z]{2})'", arr), M.BIGRAMS); self.assertEqual(len(set(M.BIGRAMS)), 150)
    def test_old_vowel_heuristic_removed(self):
        self.assertNotIn("aeiouy", MIG)
    def test_only_expected_objects_created(self):
        self.assertEqual(sorted(re.findall(r"(?i)create or replace function (\S+?)\(", MIG)),
                         ["private.valid_host_labels", "private.valid_indicator", "public.submit_indicators"])

if __name__ == "__main__":
    unittest.main()
