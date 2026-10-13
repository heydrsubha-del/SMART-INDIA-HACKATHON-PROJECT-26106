# Algorithmistic — Current Security & Database Review

**Last reviewed:** 2026-10-14  
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

The repository should contain these eight versioned migrations, in order:

1. `20261012000001_helpers.sql`
2. `20261012000002_shared_indicators.sql`
3. `20261012000003_scans.sql`
4. `20261013000001_contributions.sql`
5. `20261013233236_harden_production_api_functions.sql`
6. `20261014000001_harden_submit_indicators.sql`
7. `20261015000001_owner_self_review.sql`
8. `20261015000002_optimize_rls_and_fk_indexes.sql`

The first seven versions are already recorded in live Supabase migration history. The eighth migration's SQL was applied directly to production on 2026-10-14 and verified; after adding this file to the repository, run `npx supabase migration repair --status applied 20261015000002 --linked` to reconcile migration history. That command records migration state; it does not execute the SQL. Then run `npx supabase db push --dry-run --linked` and confirm no pending migrations before considering the repository/database synced.

The production-hardening migration is committed on `main` as `d3a6ed419e86db9fbf39815328d0b3fd5c692cc4` (`Harden production API functions`). Never edit or delete an applied migration file. Future database changes must use new timestamped migrations.

## 3. Implemented safeguards and live checks

- Community indicators remain quarantined in `indicator_submissions` until an authorized reviewer approves them.
- Admin authorization uses `app_metadata.role = admin` and AAL2/MFA; user-editable metadata is not trusted.
- Platform-owner self-review is labelled, requires a reason, gets lower confidence, and does not count as independent verification.
- `submit_indicators()` rejects missing/anonymous sessions and implements per-request, per-user and global rate limits plus pending caps of 100 per user / 1000 globally.
- `is_test_project()` returns false in production, so the manual E2E harness must never treat production as a test target.
- `rls_auto_enable()` remains attached to the event trigger; EXECUTE was revoked from PUBLIC, anon, authenticated and service_role. The trigger smoke test passed.
- Live anonymous/non-admin RPC smoke tests were denied before contribution-log writes.
- Six public tables have RLS enabled; none of the current public tables lacks RLS. Sensitive server-side tables with no client policies remain intentionally deny-by-default.
- The latest performance hardening added indexes to three previously unindexed foreign keys, rewrote owner RLS predicates to cache stable helper calls per statement, and combined the two authenticated SELECT policies on `shared_indicators` without widening access. Live verification confirmed all three indexes exist, the effective policy roles/predicates are present, and advisor checks were rerun.

These checks do not prove every application workflow is correct. The Phase 4 E2E harness is designed to refuse production and must run only against an isolated test project.

## 4. Community Intelligence status

At the last count query, there were **0 verified shared indicators** and **0 pending submissions**. The verified community feed is therefore empty. Do not insert fake threat data to populate it. Keep contribution sharing opt-in and never submit raw emails, message bodies, personal identifiers, or entire forensic reports as community indicators.

## 5. Remaining advisories and limits

- `review_queue()`, `review_submission()`, and `submit_indicators()` remain authenticated-callable SECURITY DEFINER RPCs because they are application entry points requiring tightly restricted writes. Their definitions contain internal admin/MFA or submitter checks, their search path is pinned, and anon/PUBLIC execution is revoked. Supabase's authenticated SECURITY DEFINER warning is therefore an intentional architectural warning, not something to silence by breaking the RPCs. Revisit if the app changes to a non-public RPC architecture.
- Leaked-password protection is disabled. Supabase documents that feature as Pro-plan-and-above; it cannot be enabled with SQL. If the project is on Free, this advisory requires a plan upgrade or remains open. If already Pro+, enable it under Auth password security and test signup/password-change behavior.
- Four RLS-enabled tables have no policies; this is intentional for server-only / deny-by-default tables. Do not add permissive policies merely to silence the informational advisory.

The latest live Performance Advisor no longer reports the three unindexed foreign keys, the five RLS init-plan policies, or the duplicate authenticated `shared_indicators` SELECT policies. It now reports the three newly created indexes as unused. This is expected on a database with very little data and immediately after index creation; do not drop them solely to silence that advisory. Reevaluate usage only after meaningful production workload accumulates.

GitHub CodeQL succeeded for commit `d3a6ed4` and again for the `REVIEW.md` update. CodeQL is static analysis, not a Python test run. A full Python test-suite run and true Phase 4 E2E run were **not** independently performed during this audit; the available environment cannot clone the repo, no Supabase development branch is available, and the Phase 4 script deliberately refuses production. Earlier test counts of 31/31 SQL assertions, 40/40 Python tests, and 12/12 package-integrity tests were owner-reported and not independently rerun here.

## 6. Proposals, tests and rollback artifacts

- `supabase/proposals/20261012_harden_submit_indicators.sql` is an earlier proposal; keep it for audit history and do not run it as another production migration.
- `supabase/proposals/20261012_harden_submit_indicators_ROLLBACK.sql` is not a general rollback for the current schema.
- `supabase/tests/*.sql` are for an isolated test database with the necessary roles and fixtures.
- Inspect `supabase/scripts/preflight_snapshot.sql` and `supabase/scripts/validation_checks.sql` before use and confirm the target project.
- `race_seed.sql`, `race_cleanup.sql`, and `verify_caps_rollback.sql` are test-only. Never run them against production.
- `supabase/rollback/*.sql` requires a verified backup, confirmed target project and reviewed recovery plan.

## 7. Safe operating rule

When in doubt, stop before executing SQL. Confirm the project ref, take a verified backup before destructive/recovery operations, prefer a non-production test project, and never apply a proposal or rollback merely because its filename sounds relevant.
