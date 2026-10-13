# Algorithmistic — Current Security & Database Review

**Last reviewed:** 2026-10-14  
**Status:** Live production checks and the production-hardening migration are recorded here. Historical proposal and discussion remain at `docs/archive/REVIEW_supabase_hardening_2026-10.md`.

## 1. Production safety and evidence

Supabase ref `qozfyuiloitutpfthuwn` (`https://qozfyuiloitutpfthuwn.supabase.co`) is production. Treat it as production regardless of the dashboard project label.

This review includes direct read-only inspection of the live database on 2026-10-14, after applying `20261013233236_harden_production_api_functions.sql`. Live checks confirmed the production marker returns false, the RLS event trigger remains enabled, API roles cannot execute its SECURITY DEFINER callback, all six public tables have RLS enabled, and anonymous/non-admin RPC smoke tests were denied without adding a contribution-log row. The trigger smoke test created a temporary table, verified RLS was enabled, and removed that table.

**Never execute test-only seed, race, or rollback scripts against production.** In particular, do not run:
- `supabase/scripts/race_seed.sql`
- `supabase/scripts/race_cleanup.sql`
- `supabase/scripts/verify_caps_rollback.sql`
- `supabase/rollback/*.sql`, unless performing an explicitly approved recovery with a verified backup and a reviewed rollback plan.

## 2. Versioned migrations and deployment status

The repository contains these seven versioned migrations, in order:

1. `20261012000001_helpers.sql`
2. `20261012000002_shared_indicators.sql`
3. `20261012000003_scans.sql`
4. `20261013000001_contributions.sql`
5. `20261013233236_harden_production_api_functions.sql`
6. `20261014000001_harden_submit_indicators.sql`
7. `20261015000001_owner_self_review.sql`

Live Supabase migration history contains all seven versions. The production-hardening migration is committed on `main` as commit `d3a6ed419e86db9fbf39815328d0b3fd5c692cc4` (`Harden production API functions`). Migration tracking records which versions are applied; it is not a substitute for inspecting live objects.

Do not edit or delete applied migration files to tidy the repository. Make future database changes as new timestamped migrations and test them in a separate non-production Supabase project first.

## 3. Implemented safeguards and live check results

- Community indicators remain quarantined in `indicator_submissions` until an authorized reviewer approves them.
- Admin authorization checks use `app_metadata.role = admin` and an AAL2/MFA session; user-editable metadata is not trusted.
- Platform-owner self-review is explicitly marked, requires a reason, receives lower confidence, and does not count as independent verification.
- `submit_indicators()` rejects a missing/anonymous session and has per-request, per-user, global rate limits, plus pending caps of 100 per user and 1000 globally.
- `is_test_project()` returns false in production, so the manual test harness must not treat production as a test target.
- `rls_auto_enable()` remains attached to the enabled `ensure_rls` event trigger; EXECUTE was revoked from PUBLIC, anon, authenticated, and service_role. A smoke test confirmed the trigger still enables RLS on a newly created public table.
- An unauthenticated smoke test confirmed submission, review-queue, and review-submission RPC calls are refused before any contribution-log write.
- Current live inventory: six public tables, all with RLS enabled; zero public tables without RLS. Sensitive tables with RLS but no client policies are intentionally deny-by-default.

These checks do not prove every application workflow is correct. The manual Phase 4 end-to-end test is deliberately test-project-only and must only run against a separately configured test project.

## 4. Community Intelligence status

At the time of the live check, there were **0 verified shared indicators** and **0 pending submissions**. The verified community feed is therefore empty. Do not insert fake threat data to populate it. The database contained only a small amount of scan/contribution audit data; never expose raw indicator values or user identifiers unnecessarily during routine checks.

Contribution sharing must remain opt-in. Do not send raw emails, message bodies, personal identifiers, or entire forensic reports as community indicators. BEC/impersonation-specific indicator collection is a separate planned feature and is not claimed to be complete here.

## 5. Remaining advisories and limitations

The latest Supabase security advisor still reports:
- `review_queue()`, `review_submission()`, and `submit_indicators()` are authenticated-callable SECURITY DEFINER functions. Their definitions contain internal authorization checks; do not revoke their required authenticated access indiscriminately.
- Leaked-password protection is disabled. Check plan availability and Auth behavior before enabling it.
- Four RLS-enabled tables have no policies. This is intentional for server-only/deny-by-default tables; do not add policies merely to silence the informational advisory.

The performance advisor still reports three unindexed foreign keys, five auth/RLS initialization-plan suggestions, and multiple permissive SELECT policies on `shared_indicators`. These are follow-up performance items, not evidence that data isolation failed.

The GitHub CodeQL analysis for commit `d3a6ed4` completed successfully. The repository does not currently have a standard unit-test workflow in GitHub Actions. A complete Python test-suite run and a real Phase 4 E2E run were **not** performed here: the current environment cannot clone the repository, no Supabase development branch is available, and the E2E harness is specifically designed to refuse production. Do not claim full E2E coverage until it passes against an isolated test project.

Earlier test counts (31/31 SQL assertions, 40/40 Python tests, and 12/12 package-integrity tests) were owner-reported results and have not been independently rerun during this audit. The live smoke checks described above were run separately.

## 6. Proposals, tests, and rollback artifacts

- `supabase/proposals/20261012_harden_submit_indicators.sql` is an earlier standalone proposal. Keep it for audit history; **do not execute it on production as another migration**.
- `supabase/proposals/20261012_harden_submit_indicators_ROLLBACK.sql` is paired with that old proposal. It is not a general rollback for the current schema and must not be run on production.
- `supabase/tests/*.sql`: run against an isolated test database with the required roles and fixtures.
- `supabase/scripts/preflight_snapshot.sql` and `supabase/scripts/validation_checks.sql`: inspect before use and run only against an intentionally selected project.
- `supabase/scripts/race_seed.sql`, `race_cleanup.sql`, and `verify_caps_rollback.sql`: test-only scripts, never production maintenance scripts.
- `supabase/rollback/*.sql`: manual recovery artifacts. Require a verified backup, confirmed target project, and reviewed recovery plan.

## 7. Other project work

The Agentic AI MVP is a separate planned change. First audit Synapse Copilot and the analyzer pipeline; then add an isolated, feature-flagged, read-only module with bounded tool calls. Do not change scoring, authentication, database review permissions, or the BEC roadmap as part of that initial integration.

## 8. Safe operating rule

When in doubt, stop before executing SQL. Confirm the Supabase project ref, take a verified backup before destructive or recovery operations, prefer a non-production test project, and never apply a proposal or rollback merely because its filename sounds relevant.
