"""Offline checks for supabase/scripts/verify_scan_expiry.sql (no database needed).

What this proves: the script is read-only, covers checks 1-18 and 21-24, guards optional objects, and its
pattern literals ACCEPT the real migration function bodies and REJECT realistic broken variants.
What it cannot prove: that PostgreSQL parses the script, or the exact pg_policies.qual deparse text (assumed below).
"""
import os
import re
import sqlite3
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFY = os.path.join(HERE, "supabase", "scripts", "verify_scan_expiry.sql")
MIGRATION = os.path.join(HERE, "supabase", "migrations", "20261028000001_scan_expiry_cleanup.sql")


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read().replace("\r\n", "\n")


def _norm(s):  # same normalisation as the SQL: lower() + collapse whitespace
    return re.sub(r"\s+", " ", s.lower())


def _patterns():
    block = _read(VERIFY).split("pat(name, re) as (values", 1)[1].split("\n),\n", 1)[0]
    return {n: r.replace("''", "'") for n, r in re.findall(r"\('([a-z_]+)',\s+'((?:[^']|'')*)'\)", block)}


def _body(fn):
    m = re.search(r"create or replace function private\.%s\(\).*?as \$\$(.*?)\$\$;" % fn, _read(MIGRATION), re.S | re.I)
    assert m, fn
    return _norm(m.group(1))


def _strip(sql):  # drop comments, dollar-quoted and single-quoted literals
    sql = re.sub(r"--[^\n]*", "", sql)
    sql = re.sub(r"\$q\$.*?\$q\$", "''", sql, flags=re.S)
    return re.sub(r"'(?:[^']|'')*'", "''", sql)


def _deletes(body):
    return body.count("delete from")


class VerifyScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = _read(VERIFY)
        cls.pat = _patterns()

    def test_read_only_single_statement(self):
        code = _strip(self.sql)
        self.assertTrue(code.lstrip().startswith("with"))
        self.assertEqual(code.count(";"), 1, "exactly one statement")
        banned = r"\b(insert|update|delete|drop|create|alter|grant|revoke|truncate|vacuum|copy|call|do|execute|perform|set|reset|begin|commit|rollback|lock|listen|notify)\b"
        self.assertIsNone(re.search(banned, code, re.I), re.search(banned, code, re.I))

    def test_dynamic_queries_are_selects_only(self):
        qs = re.findall(r"\$q\$(.*?)\$q\$", self.sql, re.S)
        self.assertEqual(len(qs), 4)
        for q in qs:
            self.assertTrue(q.strip().lower().startswith("select"), q)
            self.assertIsNone(re.search(r"\b(insert|update|delete|drop|create|alter|grant|revoke)\b", q, re.I), q)

    def test_optional_objects_only_referenced_inside_guards(self):
        code = _strip(self.sql)  # literals removed: any bare reference would abort the whole query
        for obj in ("schema_migrations", "cron.job", "job_run_details", "audit_log"):
            self.assertNotIn(obj, code, obj)
        for guard in ("to_regclass('supabase_migrations.schema_migrations')", "to_regclass('cron.job')",
                      "to_regclass('cron.job_run_details')", "to_regclass('public.audit_log')"):
            self.assertIn(guard, self.sql)

    def test_all_checks_present_and_numbered(self):
        ids = re.findall(r"select\s+(\d+),\s*'(schema|scheduler)',", self.sql)
        self.assertEqual([int(n) for n, s in ids if s == "schema"], list(range(1, 19)))
        self.assertEqual([int(n) for n, s in ids if s == "scheduler"], [21, 22, 23, 24])
        for n in (90, 91, 92):
            self.assertIn("select %d, 'summary'" % n, self.sql)

    def test_missing_objects_fail_explicitly(self):
        self.assertGreaterEqual(self.sql.count("MISSING:"), 12)
        self.assertIn("NOT INSTALLED", self.sql)
        self.assertIn("NOT OPERATIONAL", self.sql)

    def test_scheduler_is_reported_separately_and_expected_values_pinned(self):
        for s in ("'17 3 * * *'", "select private.purge_expired_scans()", "'purge-expired-scans'", "interval '36 hours'"):
            self.assertIn(s, self.sql)
        mig = _read(MIGRATION)
        self.assertIn("cron.schedule('purge-expired-scans', '17 3 * * *', 'select private.purge_expired_scans()')", mig)

    def test_patterns_accept_the_real_migration_bodies(self):
        cap, purge, p = _body("scans_cap"), _body("purge_expired_scans"), self.pat
        self.assertRegex(cap, p["cap_delete"])
        self.assertEqual(_deletes(cap), 1)
        self.assertLess(cap.index("pg_advisory_xact_lock"), cap.index("delete from"))
        for k in ("purge_select", "purge_delete", "purge_audit"):
            self.assertRegex(purge, p[k], k)
        self.assertEqual(_deletes(purge), 1)
        self.assertLess(purge.index("delete from"), purge.index("insert into public.audit_log"))

    def test_patterns_reject_broken_scans_cap(self):
        cap, p = _body("scans_cap"), self.pat
        for label, bad in {
            "deletes every user's expired rows": cap.replace("user_id = new.user_id and ", ""),
            "wrong key": cap.replace("user_id = new.user_id", "user_id <> new.user_id"),
            "no expiry filter": cap.replace(" and expires_at < now()", ""),
            "expiry reversed": cap.replace("expires_at < now()", "expires_at > now()"),
            "other schema": cap.replace("public.scans", "public.audit_log"),
        }.items():
            self.assertNotRegex(bad, p["cap_delete"], label)
        two = cap.replace("return new;", "delete from public.scans where user_id = new.user_id; return new;")
        self.assertEqual(_deletes(two), 2)  # check 9 requires exactly one DELETE

    def test_patterns_reject_broken_purge(self):
        purge, p = _body("purge_expired_scans"), self.pat
        for label, key, bad in (
            ("limit raised", "purge_select", purge.replace("limit 5000", "limit 50000")),
            ("limit removed", "purge_select", purge.replace(" limit 5000", "")),
            ("no skip locked", "purge_select", purge.replace(" skip locked", "")),
            ("no row lock", "purge_select", purge.replace(" for update skip locked", "")),
            ("not expired only", "purge_select", purge.replace("where expires_at < now()", "where true")),
            ("delete not tied to batch", "purge_delete", purge.replace("using doomed d where s.id = d.id", "where true")),
            ("heartbeat removed", "purge_audit", re.sub(r"insert into public\.audit_log.*?;", "", purge, flags=re.S)),
            ("heartbeat wrong action", "purge_audit", purge.replace("'purge_expired_scans'", "'x'")),
        ):
            self.assertNotRegex(bad, p[key], label)
        swapped = purge.replace("delete from", "XX").replace("insert into public.audit_log", "delete from").replace("XX", "insert into public.audit_log")
        self.assertGreater(swapped.index("delete from"), swapped.index("insert into public.audit_log"))  # heartbeat before delete: SQL check 17 would FAIL

    def test_policy_patterns(self):  # ASSUMED deparse format of pg_policies.qual (not observed on a live database)
        p = self.pat
        good = _norm("((user_id = ( SELECT auth.uid() AS uid)) AND (NOT ( SELECT private.is_anonymous() AS is_anonymous)) AND (expires_at > now()))")
        self.assertRegex(good, p["policy_owner"])
        self.assertRegex(good, p["policy_expiry"])
        self.assertRegex(good, p["policy_notanon"])
        self.assertNotRegex(good, p["policy_or"])
        old = _norm("((user_id = ( SELECT auth.uid() AS uid)) AND (NOT ( SELECT private.is_anonymous() AS is_anonymous)))")
        self.assertNotRegex(old, p["policy_expiry"])            # pre-migration policy must FAIL check 5
        self.assertNotRegex(_norm("(expires_at > now())"), p["policy_owner"])       # expiry alone is not ownership
        self.assertNotRegex(_norm("(true)"), p["policy_owner"])
        widened = _norm("(((user_id = ( SELECT auth.uid() AS uid)) AND (expires_at > now())) OR true)")
        self.assertRegex(widened, p["policy_or"])               # check 6 rejects an OR branch


# ---- check 11 (trigger state) is EXECUTED, not grepped: the check's own SQL expressions are extracted from the script and
# ---- evaluated in SQLite against fake pg_trigger rows. Only syntax common to both engines is used (no ::casts after removal).
def _split_top(s):
    out, depth, cur, q = [], 0, [], False
    for ch in s:
        if ch == "'":
            q = not q
        if not q:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                out.append("".join(cur).strip())
                cur = []
                continue
        cur.append(ch)
    out.append("".join(cur).strip())
    return out


def _check11():
    sql = _read(VERIFY)
    block = sql.split("union all select 11, 'schema',", 1)[1].split("union all select 12,", 1)[0]
    parts = _split_top("'schema'," + block)  # name, expected, actual, ok follow the section literal
    assert len(parts) == 5, parts
    return parts[2], parts[3], parts[4].replace("::text", "")  # expected, actual, ok (SQLite has no ::cast; ints/bools concatenate)


BEFORE_INSERT_ROW = 1 | 2 | 4  # pg_trigger.tgtype bits: ROW=1, BEFORE=2, INSERT=4


class TriggerStateCheck(unittest.TestCase):
    FCAP_OID = 4242

    def _eval(self, rows, ok_expr=None):
        _, actual, ok = _check11()
        db = sqlite3.connect(":memory:")
        db.execute("create table trg (tgtype integer, tgenabled text, tgfoid integer)")
        db.execute("create table fcap (oid integer)")
        db.execute("insert into fcap values (?)", (self.FCAP_OID,))
        db.executemany("insert into trg values (?,?,?)", rows)
        a, o = db.execute("select (%s), (%s)" % (actual.replace("::text", ""), ok_expr or ok)).fetchone()
        return a, bool(o)

    def _row(self, state, tgtype=BEFORE_INSERT_ROW, foid=None):
        return [(tgtype, state, self.FCAP_OID if foid is None else foid)]

    def test_normal_enabled_O_passes(self):
        a, ok = self._eval(self._row("O"))
        self.assertTrue(ok)
        self.assertRegex(a, r"state=O enabled-for-app-inserts=(1|true)")

    def test_always_enabled_A_passes(self):
        a, ok = self._eval(self._row("A"))
        self.assertTrue(ok)
        self.assertRegex(a, r"state=A enabled-for-app-inserts=(1|true)")

    def test_disabled_D_fails(self):
        a, ok = self._eval(self._row("D"))
        self.assertFalse(ok)
        self.assertRegex(a, r"state=D enabled-for-app-inserts=(0|false)")

    def test_replica_only_R_fails(self):
        a, ok = self._eval(self._row("R"))
        self.assertFalse(ok)
        self.assertRegex(a, r"state=R enabled-for-app-inserts=(0|false)")

    def test_missing_trigger_fails_explicitly(self):
        a, ok = self._eval([])
        self.assertFalse(ok)  # FAIL, not NULL/UNVERIFIED: coalesce(..., false)
        self.assertEqual(a, "MISSING: trigger scans_cap_trg on public.scans")

    def test_wrong_timing_event_level_or_function_fails_even_when_enabled(self):
        for label, tgtype, foid in (("AFTER INSERT row", 1 | 4, None), ("BEFORE UPDATE row", 1 | 2 | 16, None),
                                    ("BEFORE INSERT statement-level", 2 | 4, None), ("INSTEAD OF", BEFORE_INSERT_ROW | 64, None),
                                    ("other function", BEFORE_INSERT_ROW, 7)):
            _, ok = self._eval(self._row("O", tgtype, foid))
            self.assertFalse(ok, label)

    def test_old_condition_would_wrongly_pass_replica_only(self):  # proves these tests catch a regression to tgenabled <> 'D'
        _, _, ok = _check11()
        self.assertIn("tgenabled in ('O', 'A')", ok)
        weak = ok.replace("tgenabled in ('O', 'A')", "tgenabled <> 'D'")
        self.assertNotEqual(weak, ok)
        self.assertTrue(self._eval(self._row("R"), weak)[1])      # the old condition lets R through
        self.assertFalse(self._eval(self._row("R"))[1])           # the current one does not

    def test_header_states_row_92_stays_unverified(self):
        head = _read(VERIFY).split("with\npat", 1)[0]
        self.assertIn("92", head)
        self.assertIn("UNVERIFIED", head)
        self.assertNotIn("Every row must show status = PASS", head)


if __name__ == "__main__":
    unittest.main()
