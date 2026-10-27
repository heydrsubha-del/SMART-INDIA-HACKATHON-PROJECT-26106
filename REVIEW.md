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
