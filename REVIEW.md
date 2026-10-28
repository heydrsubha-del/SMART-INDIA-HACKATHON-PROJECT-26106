# Algorithmistic — Current Security & Database Review

**Last reviewed:** 2026-10-14 (live checks). Repository re-read 2026-10-28; no live Supabase access then. Live facts marked *owner-reported* come from the owner's read-only audit (2026-10-28), not independently verified.  
**Status:** Live production hardening and follow-up performance changes are recorded here. Historical proposal and discussion remain at `docs/archive/REVIEW_supabase_hardening_2026-10.md`.

## 1. Production safety and evidence

Supabase ref `qozfyuiloitutpfthuwn` (`https://qozfyuiloitutpfthuwn.supabase.co`) is production. Treat it as production regardless of the dashboard label.

Live database checks on 2026-10-14 confirmed the production marker returns false, `rls_auto_enable()` remains attached to the enabled `ensure_rls` event trigger, API roles cannot execute that SECURITY DEFINER callback, all six public tables have RLS enabled, and anonymous/non-admin RPC smoke tests were denied without adding a contribution-log row. A temporary table smoke test confirmed automatic RLS enablement and removed the temporary table afterward.

**Never execute test-only seed, race, or rollback scripts against production.** In particular, do not run:
- `supabase/scripts/race_seed.sql`
- `supabase/scripts/race_cleanup.sql`
- `supabase/scripts/verify_caps_rollback.sql`
- `supabase/rollback/*.sql`, unless performing an explicitly approved recovery with a verified backup and reviewed recovery plan.

## 2. Versioned migrations

The repository should contain these ten versioned migrations, in order:

1. `20261012000001_helpers.sql`
2. `20261012000002_shared_indicators.sql`
3. `20261012000003_scans.sql`
4. `20261013000001_contributions.sql`
5. `20261013233236_harden_production_api_functions.sql`
6. `20261014000001_harden_submit_indicators.sql`
7. `20261015000001_owner_self_review.sql`
8. `20261015000002_optimize_rls_and_fk_indexes.sql`
9. `20261027000001_followup_hardening.sql` (owner-reported as recorded; confirm the live function body contains `withdrawn_indicator`)
10. `20261027164451_restrict_review_queue_rpc_access.sql` (owner-reported: all ten versions are recorded in production; Supabase compares versions, not file contents)

**Proposed, NOT applied:** `20261028000001_scan_expiry_cleanup.sql` (scan retention, see section 5). Rollback: `supabase/rollback/scan_expiry_down.sql`. Apply only to a test project first.

**Owner-reported production check (2026-10-28), schema:** version `20261028000001` is absent from `schema_migrations`; `scans_owner_select` has no `expires_at` condition; `scans_expires_at_idx` does not exist; the live `purge_expired_scans()` is the migration-9 version (deletes and returns a count, no `audit_log` row); its EXECUTE privileges are correct (anon, authenticated, service_role all false). So the migration has **not** run in production. Do **not** use `supabase migration repair` for this version: that records it as applied without running the SQL.

**Verification is two separate questions.** Run the read-only `supabase/scripts/verify_scan_expiry.sql` (one SELECT; missing objects show as FAIL rows, not errors):
- *Schema verification* (checks 1-18, summary row 90): migration recorded; RLS enabled and forced; the owner policy is permissive SELECT for `authenticated` with the ownership, expiry and anonymous-block predicates, no OR branch and no second permissive SELECT policy; `scans_cap()` deletes only the inserting user's expired rows after taking the per-user lock, behind a trigger whose `tgtype` is exactly 7 (BEFORE INSERT FOR EACH ROW with no extra events, so BEFORE INSERT OR UPDATE fails) and whose state is `O` (enabled) or `A` (always); disabled `D` and replica-only `R` fail (the output shows `exact-before-insert-row` and `enabled-for-app-inserts`), and clients cannot set `user_id`/`expires_at`; the index is valid on `public.scans(expires_at)`; the purge function is batch-limited (5000), uses `FOR UPDATE SKIP LOCKED`, deletes only that batch, writes the heartbeat after the delete, and is not executable by anon, authenticated, service_role or PUBLIC. These are normalised-text pattern checks on function bodies, not proof of behaviour.
- *Scheduler verification* (checks 21-24, summary row 91): `pg_cron` installed; job `purge-expired-scans` exists, is active, `17 3 * * *`, command `select private.purge_expired_scans()`; last cron run `succeeded` within 36 hours; `audit_log` heartbeat within 36 hours. A passing schema result never implies automated deletion. Current status (owner-reported): `pg_cron` is not installed, so **scheduled cleanup is NOT operational**.
- *Pass criteria:* every row in checks 1-18 and 21-24 and summary rows 90 and 91 must show PASS. Summary row 92 (BEHAVIOUR) is a constant: it is **always UNVERIFIED in this script, is not a failure, and is never cleared by the verifier**. Run the test-project suite below separately and record its result separately (see "Behaviour test log"), not through this script.
- *Behaviour* (row 92) is established only by `supabase/tests/005_followup_and_scan_expiry.sql` on a TEST project.
Uncertainties: the script has not been executed (no PostgreSQL available when written); the `pg_policies.qual` deparse format and `proconfig` rendering (`search_path=""`) are assumed, so a FAIL on checks 4-6 or 8/14 after a correct deployment means adjust the pattern, not the database. `test_verify_scan_expiry.py` runs offline: it checks the script is read-only, covers every check, guards optional objects, and that its patterns accept the migration's function bodies and reject broken variants. It also executes check 11's own SQL expressions in SQLite against fake trigger rows (`tgtype` 7 with state `O` or `A` passes; `D`, `R`, extra events such as BEFORE INSERT OR UPDATE / OR DELETE, wrong timing/event/level, wrong function and a missing trigger fail explicitly) and asserts row 92 is a literal `'UNVERIFIED'`. Scratch-copy mutation checks confirm the tests fail if the SQL regresses to `tgenabled <> 'D'`, to the loose `tgtype` bitmask, or if row 92 becomes computable.

**Offline results (2026-10-29, authoring sandbox; a copy of the repository from the supplied zip, not a git checkout, without a `fixtures/` folder):** `test_verify_scan_expiry.py` 21 tests, OK (the earlier 18 plus 3 new); `python -m compileall -q .` OK; full suite 593 tests: 0 failures and 1 error. The error is `test_model_audit.Retraining.test_independent_set_quality_floor` (`TypeError: 'NoneType' ...`), caused solely by the missing `fixtures/independent_eval.csv` (the loader returns None when the file is absent); it is a missing-fixture error, not a logic failure, and was not re-checked with the fixture present (the owner's own run was owner-reported 572 passed before these test additions). **Not verified:** PostgreSQL syntax and runtime behaviour of `verify_scan_expiry.sql` and of migration `20261028000001`; no database was available and no SQL was executed against PostgreSQL. SQLite evaluates only check 11's logic, not Postgres semantics (`pg_trigger` columns, casts).

**Behaviour test log:** `supabase/tests/005_followup_and_scan_expiry.sql` has not been run on any project. Record the date, test project ref and the "17 of 17 passed" result here once it has.

The first seven versions are already recorded in live Supabase migration history. The eighth migration's SQL was applied directly to production on 2026-10-14 and verified. Reconcile migration history read-only first: run `npx supabase migration list --linked` and `npx supabase db push --dry-run --linked`. Run `npx supabase migration repair --status applied <version> --linked` only for a version that is genuinely missing from remote history (it records state; it does not execute SQL). Per the owner-retrieved history, 20261015000002 and migrations 9 and 10 were already recorded, so no repair should be needed; confirm before running anything. Confirm no pending migrations before considering the repository/database synced.

The production-hardening migration is committed on `main` as `d3a6ed419e86db9fbf39815328d0b3fd5c692cc4` (`Harden production API functions`). Migration 10 in the repository is the corrected version (authenticated reviewer access kept, anon/PUBLIC revoked); Supabase compares versions, not contents, so confirm the live grants match it. Never edit or delete an applied migration file. Future database changes must use new timestamped migrations.

## 3. Implemented safeguards and live checks

- Community indicators remain quarantined in `indicator_submissions` until an authorized reviewer approves them.
- Admin authorization uses `app_metadata.role = admin` and AAL2/MFA; user-editable metadata is not trusted.
- Platform-owner self-review is labelled, requires a reason, gets lower confidence, and does not count as independent verification.
- `submit_indicators()` rejects missing/anonymous sessions and implements per-request, per-user and global rate limits plus pending caps of 100 per user / 1000 globally. Migration 9 adds a 500 global cap for accounts under 24h old (live status unverified).
- `is_test_project()` returns false in production, so the manual E2E harness must never treat production as a test target.
- `rls_auto_enable()` remains attached to the event trigger; EXECUTE was revoked from PUBLIC, anon, authenticated and service_role. The trigger smoke test passed.
- Live anonymous/non-admin RPC smoke tests were denied before contribution-log writes.
- Six public tables have RLS enabled; none of the current public tables lacks RLS. Sensitive server-side tables with no client policies remain intentionally deny-by-default.
- The latest performance hardening added indexes to three previously unindexed foreign keys, rewrote owner RLS predicates to cache stable helper calls per statement, and combined the two authenticated SELECT policies on `shared_indicators` without widening access. Live verification confirmed all three indexes exist, the effective policy roles/predicates are present, and advisor checks were rerun.

These checks do not prove every application workflow is correct. The Phase 4 E2E harness is designed to refuse production and must run only against an isolated test project.

## 4. Community Intelligence status

At the last count query, there were **0 verified shared indicators** and **0 pending submissions**. The verified community feed is therefore empty. Do not insert fake threat data to populate it. Keep contribution sharing opt-in and never submit raw emails, message bodies, personal identifiers, or entire forensic reports as community indicators.

## 5. Remaining advisories and limits

- `review_queue()`, `review_submission()`, and `submit_indicators()` remain authenticated-callable SECURITY DEFINER RPCs because they are application entry points requiring tightly restricted writes. Their definitions contain internal admin/MFA or submitter checks, their search path is pinned, and anon/PUBLIC execution is revoked. Supabase's authenticated SECURITY DEFINER warning is therefore an intentional architectural warning (migration 10 also grants `service_role` EXECUTE, which adds no capability: a service-role JWT fails `private.is_admin()`; the reviewer clients refuse service-role credentials), not something to silence by breaking the RPCs. Revisit if the app changes to a non-public RPC architecture.
- Leaked-password protection is disabled. Supabase's password-security docs state it is available on the **Pro plan and above**; it cannot be set with SQL. On Free it stays open: set a long minimum password length, keep MFA mandatory for administrators, and consider CAPTCHA on sign-up.
- **Scan expiry is not enforced in production** (owner-reported: `pg_cron` is not installed, so the purge function exists but nothing runs it). Plan: `20261028000001_scan_expiry_cleanup.sql` hides expired scans from their owner, deletes a user's own expired scans whenever they store a new one, batch-limits `purge_expired_scans()` (5000 rows, writes one `audit_log` heartbeat row, EXECUTE revoked from every API role including `service_role`), and schedules a daily job **only if** `pg_cron` is already installed. Inactive users' expired rows stay until a scheduler runs: enable `pg_cron` in Dashboard → Database → Extensions if the project offers it (verify; not assumed), then re-run the migration's `DO` block or run `select cron.schedule('purge-expired-scans','17 3 * * *','select private.purge_expired_scans()');` as the postgres role. Monitor with `select at, reason from public.audit_log where action='purge_expired_scans' order by at desc limit 3;` (alert if older than 2 days). Do not put a service-role key in GitHub Actions or the client to call the purge.
- Migration 11 static review (2026-10-28, not executed): all statements are transactional and idempotent (safe to re-apply); it only narrows read access and adds privileges nobody (no API role) holds; `CREATE INDEX` and `ALTER POLICY` take brief table locks on a near-empty table. The per-user purge in `scans_cap()` runs before the unique-hash and 500-row checks, so rescanning expired evidence works; it is safe only because clients cannot set `user_id` (column-level INSERT grant; verify check 12) and it relies on the `postgres` role bypassing RLS, as `review_submission` already does. Residual risks: if `pg_cron` exists but `cron.schedule` fails, the whole migration rolls back (consider an exception handler before applying); enabling `pg_cron` later does not create the job, run the `cron.schedule` command above; the purge removes at most 5000 rows per run.
- Four RLS-enabled tables have no policies; this is intentional for server-only / deny-by-default tables. Do not add permissive policies merely to silence the informational advisory.

The latest live Performance Advisor no longer reports the three unindexed foreign keys, the five RLS init-plan policies, or the duplicate authenticated `shared_indicators` SELECT policies. It now reports the three newly created indexes as unused. This is expected on a database with very little data and immediately after index creation; do not drop them solely to silence that advisory. Reevaluate usage only after meaningful production workload accumulates.

GitHub CodeQL succeeded for commit `d3a6ed4` and again for the `REVIEW.md` update. CodeQL is static analysis, not a Python test run. A full Python test-suite run and true Phase 4 E2E run were **not** independently performed during this audit; the available environment cannot clone the repo, no Supabase development branch is available, and the Phase 4 script deliberately refuses production. Earlier test counts of 31/31 SQL assertions, 40/40 Python tests, and 12/12 package-integrity tests were owner-reported and not independently rerun here. A later owner-reported full Python run (2026-10-28) was 572 passed; also not independently verified.

## 6. Proposals, tests and rollback artifacts

- `supabase/proposals/20261012_harden_submit_indicators.sql` is an earlier proposal; keep it for audit history and do not run it as another production migration.
- `supabase/proposals/20261012_harden_submit_indicators_ROLLBACK.sql` is not a general rollback for the current schema.
- `supabase/tests/*.sql` are for an isolated test database with the necessary roles and fixtures.
- Inspect `supabase/scripts/preflight_snapshot.sql` and `supabase/scripts/validation_checks.sql` before use and confirm the target project.
- `race_seed.sql`, `race_cleanup.sql`, and `verify_caps_rollback.sql` are test-only. Never run them against production.
- `supabase/rollback/*.sql` requires a verified backup, confirmed target project and reviewed recovery plan.

## 7. Safe operating rule

When in doubt, stop before executing SQL. Confirm the project ref, take a verified backup before destructive/recovery operations, prefer a non-production test project, and never apply a proposal or rollback merely because its filename sounds relevant.

## 8. Test coverage and procedure

**CI limitation (owner-reported):** when the private audit dataset is unavailable, CI excludes three corpus-dependent test modules (the modules that need `AUDIT_DIR` are `test_label_regression`, `test_package_integrity` and `test_validation_parity`; the CI workflow file was not supplied, so the exact exclusion list is unverified). `test_model_audit`'s independent-set check also needs `fixtures/independent_eval.csv`. A green CI run is therefore not a full-suite result. Run the whole suite locally with `AUDIT_DIR=<folder with the five CSV exports> python -m unittest discover -s . -p "test_*.py"`.

| Requirement | Where it is tested | Run against |
|---|---|---|
| Anonymous cannot submit / review; ordinary user cannot read queue or decide; admin without MFA refused; admin with MFA can review; admin cannot self-review; self-metadata admin ignored | `e2e_phase4.py run` | isolated TEST project, over HTTP |
| Platform-owner self-review needs a reason, is labelled `self_reviewed`, confidence 0.25, 0 independent contributors | `e2e_phase4.py run` with the optional `SIH26106_E2E_OWNER_*` variables; `supabase/tests/004_self_review.sql` (31 checks, includes audit log) | TEST project |
| Withdrawn indicator not re-verified; new-account 500 cap; scan 500 cap, retention and closed purge function | `supabase/tests/005_followup_and_scan_expiry.sql` (17 checks) | TEST project SQL editor |
| Limits, duplicates, pending caps | `supabase/tests/003_contributions.sql`, `005` | TEST project |

Not testable through the public API (they need privileged writes): withdrawn indicators, pending-cap saturation and `audit_log` contents; these are SQL-only. `005` and the optional owner block were written without a PostgreSQL server or a Supabase project available, so **neither has been executed yet**.

Manual procedure (TEST project only; production is `qozfyuiloitutpfthuwn` and must never be used):
1. Create a new Supabase project; apply all migrations in `supabase/migrations/` in order; in the TEST project only, override the marker: `create or replace function public.is_test_project() returns boolean language sql stable set search_path = pg_catalog as $$ select true $$;` (the repository migration returns false for production).
2. Enable anonymous sign-ins, TOTP MFA, and disable email confirmation. Create the reviewer user, set `app_metadata.role = 'admin'` in the dashboard (never `user_metadata`); for the optional owner test create a second such user and `insert into private.platform_owners (user_id) values ('<id>');`.
3. In a shell (never in git): `SIH26106_SUPABASE_URL`, `SIH26106_SUPABASE_ANON_KEY` (publishable key only), `SIH26106_E2E_PROJECT_REF`, `SIH26106_E2E_CONFIRM=TEST-PROJECT-ONLY:<ref>`, `SIH26106_E2E_PROD_REFS=qozfyuiloitutpfthuwn`, reviewer email/password.
4. `python e2e_phase4.py check`, then `python e2e_phase4.py enroll-mfa` (export the printed TOTP secret), then `python e2e_phase4.py run`. Exit code 0 means nothing failed or was skipped.
5. Paste `supabase/tests/004_self_review.sql` and `005_followup_and_scan_expiry.sql` into the TEST project's SQL editor; expect "31 of 31 passed" and "17 of 17 passed". Each rolls back its data.
