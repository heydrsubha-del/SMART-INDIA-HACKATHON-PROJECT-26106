# Algorithmistic — Current Security & Database Review

**Last reviewed:** 2026-10-14  
**Status:** Current operational notes. Historical proposal and discussion are preserved at `docs/archive/REVIEW_supabase_hardening_2026-10.md`.

## 1. Production safety and evidence

The repository owner identifies Supabase project ref `qozfyuiloitutpfthuwn` (`https://qozfyuiloitutpfthuwn.supabase.co`) as the **production project**, even though the dashboard/project label has previously appeared as `algorithmistic-test`. Treat it as production.

This review is based on the current repository plus results the owner reported from Supabase SQL Editor and CLI. I do not have direct database access, so reported database facts are not an independent live query.

**Never execute test-only seed, race, or rollback scripts against this production project.** In particular, do not run:
- `supabase/scripts/race_seed.sql`
- `supabase/scripts/race_cleanup.sql`
- `supabase/scripts/verify_caps_rollback.sql`
- `supabase/rollback/*.sql`, unless performing an explicitly approved recovery with a verified backup and a reviewed rollback plan.

## 2. Versioned migrations and deployment status

The repository contains these six versioned migrations, in order:

1. `20261012000001_helpers.sql`
2. `20261012000002_shared_indicators.sql`
3. `20261012000003_scans.sql`
4. `20261013000001_contributions.sql`
5. `20261014000001_harden_submit_indicators.sql`
6. `20261015000001_owner_self_review.sql`

**Owner-reported status:** the owner self-review SQL was applied in the production SQL Editor and worked in testing. Migration tracking was reconciled using `supabase migration repair`; a subsequent `supabase db push --dry-run --linked` reported that the remote database was up to date.

Important distinction: `migration repair` changes migration history; it does not execute migration SQL. A dry run reports whether the CLI sees pending migrations; it is not an independent audit of every live database object.

Do not edit or delete applied migration files to tidy the repository. Make future database changes as new timestamped migrations and test them in a separate non-production Supabase project first.

## 3. Implemented database safeguards

Based on the migration files and owner-reported test results:

- Community indicators are held in a submission queue until an authorized reviewer approves them.
- Review operations require an admin claim and an MFA-level session.
- Platform-owner self-review is explicitly marked, requires a reason, receives lower confidence, and does not count as independent verification.
- Anonymous contribution submissions are rejected by the hardened submission function.
- Per-user and global limits protect contribution volume and pending-queue size.
- Row-level security and narrowly granted RPC access are part of the database design.

The owner reported **31/31 SQL assertions** and **40/40 Python tests** passing for the self-review work. The owner later reported **12/12 tests** passing for `test_package_integrity.py`. These are reported run results, not live database results independently reproduced from this document.

## 4. Community Intelligence status

The owner reports that the Streamlit app's Supabase connection and Community Intelligence settings work.

The last production query shared showed **0 verified indicators, 0 pending indicators, and 2 withdrawn indicators** after synthetic test indicators were withdrawn. Therefore, the verified community feed is empty. Do not insert fake threat data to populate it.

Contribution sharing must remain opt-in. Do not send raw emails, message bodies, personal identifiers, or entire forensic reports as community indicators. BEC/impersonation-specific indicator collection is a separate planned feature and is not claimed to be complete here.

## 5. Proposals and old hardening files

- `supabase/migrations/20261014000001_harden_submit_indicators.sql` is the versioned migration carrying hardening logic into migration history.
- `supabase/proposals/20261012_harden_submit_indicators.sql` is an earlier standalone proposal. Keep it for audit history; **do not execute it on production as another migration**.
- `supabase/proposals/20261012_harden_submit_indicators_ROLLBACK.sql` is paired with that old proposal. It is not a general rollback for the current schema and must not be run on production.
- The abandoned contribution-log retention proposal and redundant `.diff` were removed from the active tree because the patch is already present in `contribution_client.py` and retention was not implemented or scheduled.

## 6. SQL scripts and intended use

- `supabase/tests/*.sql`: test suite; run against an isolated test database with the required roles and fixtures.
- `supabase/scripts/preflight_snapshot.sql`: read-only object/permission snapshot; inspect its target checks and run only against an intentionally selected project.
- `supabase/scripts/validation_checks.sql`: read-only validator checks. Confirm expected results match the current applied SQL version before use.
- `supabase/scripts/race_seed.sql` and `race_cleanup.sql`: test-only scripts that deliberately create/delete synthetic test rows. **Do not use against production.**
- `supabase/scripts/verify_caps_rollback.sql`: test-only cap/rollback exercise; not a production maintenance script.
- `supabase/rollback/*.sql`: manual recovery artifacts. Require a verified backup, confirmed target project, and reviewed recovery plan before use.

## 7. Remaining work and limitations

- Keep `docs/archive/REVIEW_supabase_hardening_2026-10.md` as historical audit context; this file is the current operational summary.
- Keep tests and maintenance scripts clearly labelled by environment. Check every hard-coded project ref before running any script.
- These hardening checks are not a substitute for a live audit of production function definitions, grants, RLS policies, and indexes.
- The Agentic AI MVP is a separate planned change. First audit Synapse Copilot and the analyzer pipeline; then add an isolated, feature-flagged, read-only module with bounded tool calls. Do not change scoring, authentication, database review permissions, or the BEC roadmap as part of that initial integration.

## 8. Safe operating rule

When in doubt, stop before executing SQL. Confirm the Supabase project ref, take a verified backup before destructive or recovery operations, prefer a non-production test project, and never apply a proposal or rollback merely because its filename sounds relevant.
