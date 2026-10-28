# Algorithmistic — Current Security & Database Review

**Last reviewed:** 2026-10-28 (documentation update). The last **full** production security review was on 2026-10-14. On 2026-10-28 only limited read-only Supabase checks were performed: the project list showed that only the production project remains, and the scheduled-purge query on `cron.job_run_details` returned no execution records. They do not re-verify the rest of the production configuration. Other live facts marked *owner-reported* come from the owner's own production checks (through 2026-10-28) and were not independently re-verified. The temporary isolated test project (`tmldbzsxfqqetxyzppec`) used for the latest E2E and SQL runs has been **deleted** (consistent with that project list).  
**Status:** Live production hardening, follow-up performance changes and scan-expiry cleanup (owner-reported applied) are recorded here. The first scheduled purge run is **not yet confirmed**. Historical proposal and discussion remain at `docs/archive/REVIEW_supabase_hardening_2026-10.md`.

## 1. Production safety and evidence

Supabase ref `qozfyuiloitutpfthuwn` (`https://qozfyuiloitutpfthuwn.supabase.co`) is production. Treat it as production regardless of the dashboard label.

Live database checks on 2026-10-14 confirmed the production marker returns false, `rls_auto_enable()` remains attached to the enabled `ensure_rls` event trigger, API roles cannot execute that SECURITY DEFINER callback, all six public tables have RLS enabled, and anonymous/non-admin RPC smoke tests were denied without adding a contribution-log row. A temporary table smoke test confirmed automatic RLS enablement and removed the temporary table afterward.

**Never execute test-only seed, race, or rollback scripts against production.** In particular, do not run:
- `supabase/scripts/race_seed.sql`
- `supabase/scripts/race_cleanup.sql`
- `supabase/scripts/verify_caps_rollback.sql`
- `supabase/rollback/*.sql`, unless performing an explicitly approved recovery with a verified backup and reviewed recovery plan.

## 2. Versioned migrations

The repository should contain these eleven versioned migrations, in order:

1. `20261012000001_helpers.sql`
2. `20261012000002_shared_indicators.sql`
3. `20261012000003_scans.sql`
4. `20261013000001_contributions.sql`
5. `20261013233236_harden_production_api_functions.sql`
6. `20261014000001_harden_submit_indicators.sql`
7. `20261015000001_owner_self_review.sql`
8. `20261015000002_optimize_rls_and_fk_indexes.sql`
9. `20261027000001_followup_hardening.sql` (owner-reported as recorded; confirm the live function body contains `withdrawn_indicator`)
10. `20261027164451_restrict_review_queue_rpc_access.sql` (owner-reported: recorded in production; Supabase compares versions, not file contents)
11. `20261028000001_scan_expiry_cleanup.sql` (owner-reported applied and verified, see section 5; rollback: `supabase/rollback/scan_expiry_down.sql`, never run against production without an approved recovery plan)

The first seven versions are already recorded in live Supabase migration history. The eighth migration's SQL was applied directly to production on 2026-10-14 and verified. Reconcile migration history read-only first: run `npx supabase migration list --linked` and `npx supabase db push --dry-run --linked`. Run `npx supabase migration repair --status applied <version> --linked` only for a version that is genuinely missing from remote history (it records state; it does not execute SQL). Per the owner-retrieved history, 20261015000002 and migrations 9 and 10 were already recorded, so no repair should be needed; confirm before running anything. Owner-reported (2026-10-28): version `20261028000001` was reconciled with `migration repair` (which records history only and executes no SQL; the SQL itself was applied separately and checked, section 5), `migration list --linked` shows local and remote matching through `20261028000001`, and `db push --dry-run --linked` reports `Remote database is up to date`. Not re-verified by the reviewer. Do not rerun the applied migration.

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
- **Scan expiry (migration 11).** Owner-reported as applied and verified in production (SQL checks, not a reviewer re-check):
  - the `scans_expires_at_idx` index exists;
  - `scans_owner_select` hides expired scans from their owner;
  - `private.scans_cap()` deletes the current user's own expired scans before applying the 500-row cap;
  - `private.purge_expired_scans()` deletes at most 5,000 expired rows per run and writes one `audit_log` heartbeat row (`reason` = rows deleted);
  - `has_function_privilege(..., 'execute')` returns false for each of `anon`, `authenticated` and `service_role` (false/false/false; this includes any grant inherited from `PUBLIC`). `PUBLIC` itself was not queried separately; the migration revokes it.
  
  A manual purge returned `0` with no expired scans present, so **deletion by the purge and the heartbeat row it writes have not been exercised on real expired data in production**. `supabase/tests/005_followup_and_scan_expiry.sql` passed 17/17 on the isolated test project, run through the Supabase SQL runner, with migration `20261028000001` applied, which covers purge deletion, the heartbeat, the cap and the closed privileges there; that is test-project evidence, not production evidence (see section 8). Expired rows are hidden from owners immediately but physically remain until the owner's next scan insert or the scheduled purge.
- **Scheduler (`pg_cron`).** Owner-reported (independently checked by the owner): the extension is enabled; job `purge-expired-scans` exists, schedule `17 3 * * *` (03:17 UTC / 08:47 IST), command `SELECT private.purge_expired_scans();`, active, runs as `postgres`. **Configured is not completed:** no execution history existed at the last check (the 2026-10-28 read-only query returned no `cron.job_run_details` records), so a successful scheduled run is **NOT yet confirmed**. Remaining task, after the first 03:17 UTC run: confirm `select status, return_message, start_time from cron.job_run_details order by start_time desc limit 3;` shows `succeeded`, and that `select at, reason from public.audit_log where action='purge_expired_scans' order by at desc limit 3;` shows a new heartbeat row. Alert if the newest heartbeat is older than 2 days. Do not put a service-role key in GitHub Actions or the client to call the purge.
- Four RLS-enabled tables have no policies; this is intentional for server-only / deny-by-default tables. Do not add permissive policies merely to silence the informational advisory.

The latest live Performance Advisor no longer reports the three unindexed foreign keys, the five RLS init-plan policies, or the duplicate authenticated `shared_indicators` SELECT policies. It now reports the three newly created indexes as unused. This is expected on a database with very little data and immediately after index creation; do not drop them solely to silence that advisory. Reevaluate usage only after meaningful production workload accumulates.

GitHub CodeQL succeeded for commit `d3a6ed4`. CI/CodeQL status for the later documentation and test-file commits has **not been confirmed** by the reviewer; check the GitHub Actions result for the exact commit SHA before relying on it. CodeQL is static analysis, not a Python test run. Two separate sets of results exist (section 8): the five SQL suites, executed against the isolated test project through the Supabase SQL runner (115/115 assertions passed), and the owner-run Phase 4 HTTP E2E, executed locally over HTTP against that project (42 passed, 0 failed, 0 skipped). The Phase 4 script deliberately refuses production. The **full Python suite was not rerun for the latest audit**: the earlier counts of 40/40 Python tests and 12/12 package-integrity tests, and a full Python run of 572 passed on 2026-10-28, are older owner-reported figures and must not be read as results of the latest audit.

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

**Latest isolated-test results (2026-10-28).** Both sets ran against a temporary test project (`tmldbzsxfqqetxyzppec`, now deleted), never against production. They differ in how they were run:
- **SQL suites:** executed against the test project through the Supabase SQL runner; all five passed (115/115 assertions). Synthetic test data was rolled back.
- **Phase 4 HTTP E2E:** owner-run locally (`e2e_phase4.py run`) against the test project's API; 42 passed, 0 failed, 0 skipped, as reported by the owner.

| Suite | Result |
|---|---|
| Phase 4 HTTP E2E (`e2e_phase4.py run`) | 42 passed, 0 failed, 0 skipped/inconclusive. Covered reviewer MFA, approval/rejection, self-review protection, contributor restrictions, community-intelligence retrieval, private-scan isolation and database-outage handling |
| `001_shared_indicators_rls.sql` | 17/17 |
| `002_scans_isolation.sql` | 16/16 |
| `003_contributions.sql` | 34/34 |
| `004_self_review.sql` | 31/31 |
| `005_followup_and_scan_expiry.sql` | 17/17, with migration `20261028000001` applied (an earlier run on a project without it gave 12/17, the five failures being the expiry behaviours it adds) |
| SQL total | 115/115 assertions |

Not covered by these results: the optional platform-owner HTTP E2E checks (`SIH26106_E2E_OWNER_*`) were not configured for this run; platform-owner self-review is covered only by the SQL suite `004` (31/31). The full Python suite was not rerun. Test-project results say nothing about production data: the production purge has not deleted real expired scans and the first scheduled run is unconfirmed (section 5).

**CI limitation (owner-reported):** when the private audit dataset is unavailable, CI excludes three corpus-dependent test modules (the modules that need `AUDIT_DIR` are `test_label_regression`, `test_package_integrity` and `test_validation_parity`; the CI workflow file was not supplied, so the exact exclusion list is unverified). `test_model_audit`'s independent-set check also needs `fixtures/independent_eval.csv`. A green CI run is therefore not a full-suite result. Run the whole suite locally with `AUDIT_DIR=<folder with the five CSV exports> python -m unittest discover -s . -p "test_*.py"`.

| Requirement | Where it is tested | Run against |
|---|---|---|
| Anonymous cannot submit / review; ordinary user cannot read queue or decide; admin without MFA refused; admin with MFA can review; admin cannot self-review; self-metadata admin ignored | `e2e_phase4.py run` | isolated TEST project, over HTTP |
| Platform-owner self-review needs a reason, is labelled `self_reviewed`, confidence 0.25, 0 independent contributors | `e2e_phase4.py run` with the optional `SIH26106_E2E_OWNER_*` variables; `supabase/tests/004_self_review.sql` (31 checks, includes audit log) | TEST project |
| Withdrawn indicator not re-verified; new-account 500 cap; scan 500 cap, retention and closed purge function | `supabase/tests/005_followup_and_scan_expiry.sql` (17 checks; helper `run_as` repaired 2026-10-28, it was truncated) | TEST project SQL editor |
| Limits, duplicates, pending caps | `supabase/tests/003_contributions.sql`, `005` | TEST project |

Not testable through the public API (they need privileged writes): withdrawn indicators, pending-cap saturation and `audit_log` contents; these are SQL-only. The optional owner HTTP block was not executed in the latest run; the SQL suites above are the only platform-owner evidence.

Manual procedure (TEST project only; production is `qozfyuiloitutpfthuwn` and must never be used). The previous test project has been deleted, so repeating any live E2E or SQL test requires creating a **new** isolated test project first:
1. Create a new Supabase project; apply all migrations in `supabase/migrations/` in order; in the TEST project only, override the marker: `create or replace function public.is_test_project() returns boolean language sql stable set search_path = pg_catalog as $$ select true $$;` (the repository migration returns false for production).
2. Enable anonymous sign-ins, TOTP MFA, and disable email confirmation. Create the reviewer user, set `app_metadata.role = 'admin'` in the dashboard (never `user_metadata`); for the optional owner test create a second such user and `insert into private.platform_owners (user_id) values ('<id>');`.
3. In a shell (never in git): `SIH26106_SUPABASE_URL`, `SIH26106_SUPABASE_ANON_KEY` (publishable key only), `SIH26106_E2E_PROJECT_REF`, `SIH26106_E2E_CONFIRM=TEST-PROJECT-ONLY:<ref>`, `SIH26106_E2E_PROD_REFS=qozfyuiloitutpfthuwn`, reviewer email/password.
4. `python e2e_phase4.py check`, then `python e2e_phase4.py enroll-mfa` (export the printed TOTP secret), then `python e2e_phase4.py run`. Exit code 0 means nothing failed or was skipped.
5. Paste `supabase/tests/004_self_review.sql` and `005_followup_and_scan_expiry.sql` into the TEST project's SQL editor; expect "31 of 31 passed" and "17 of 17 passed". Each rolls back its data. Never run `004` or `005` against production.


## 9. Security hardening pass (2026-10-28, local working tree on `main`)

**Scope/limits.** The supplied ZIP has **no `.git` directory**: Git history, branch and `git status` could not be inspected, and nothing was pushed. Live Supabase, Streamlit Cloud, Google/Microsoft consoles and CI were not accessed; no live testing or deployment is claimed. `bandit`/`pip-audit` could not be installed (no package access), so only `compileall`, the test suite and pattern greps were run.

**Findings and fixes (code)**
| # | Finding | Fix |
|---|---|---|
| 4 | `parse_eml` had no size/part/attachment limits; deep MIME nesting raised `RecursionError`; attachments of any size were decoded and later sent to the scanner | `email_parser.py`: 25 MB message cap (`EmailTooLargeError`), 25 attachments, 15 MB each, 40 MB aggregate (excess kept as metadata with `skipped`, never scanned or treated as clean), 200 MIME parts, 100 Received hops (oldest/origin side kept), 1M body chars, 500 links, nesting -> clean `ValueError`. Env overrides: `SIH26106_MAX_*` |
| 4/6 | Scanner had no size, count, aggregate, archive-bomb or wall-clock limits | `antivirus_scan.py`: per-file 25 MB, 25 files, 40 MB total, ZIP central-directory inspection (entries, declared size, ratio, nested archives; nothing extracted), 60 s clamd stream deadline. Blocked items return `ok: False` (never "clean"). `app.py` Antivirus panel applies a bounded budget and honours `skipped` |
| 5 | `fetch_verified(max_rows, timeout)` unclamped; page could overshoot; no response-size check | `shared_intel_client.py`: rows clamped to [0, 50000], timeout to (0, 30] s, `limit` never exceeds remaining rows, page truncated to requested size, `Content-Length` > 2 MB refused |
| 7 | No `.streamlit/config.toml` (default 200 MB upload, error details shown) | Added: XSRF on, static serving off, `maxUploadSize=25`, `showErrorDetails="none"`, viewer toolbar |

**Verified, no change needed**
- HTML injection fix is present in `app.py` (`fix_html_injection.py --check`: 0 edits pending). Regression test added; remaining `unsafe_allow_html` uses were not individually re-audited beyond that.
- Admin check = `app_metadata.role='admin'` + `aal2`, enforced inside every SECURITY DEFINER RPC; `user_metadata` unused; anon denied; `scans` RLS owner-scoped on all verbs; no client write grants on contribution tables. Static regression tests added; the SQL itself was not executed here.
- Tracebacks only render when `SIH26106_DEBUG=1`; ensure it is unset in production.
- Scan-expiry migration `20261028000001`, job `purge-expired-scans` (`17 3 * * *`): reviewed in code only; execution evidence is still the owner-reported item in section 5. Check `cron.job_run_details` and an `audit_log` row with `action='purge_expired_scans'` after the first run. No purge function was invoked.

**Files changed:** `email_parser.py`, `antivirus_scan.py`, `shared_intel_client.py`, `app.py` (Antivirus loop + import only), `.streamlit/config.toml` (new), `test_security_hardening.py` (new, 23 tests), `MANIFEST.sha256` (hash refreshed), `REVIEW.md`.

**Tests:** full `pytest` in the workspace: 595 passed, 0 failed (includes 23 new). `python -m compileall`: OK. Corpus-dependent modules ran with whatever local fixtures were in the ZIP.

**Unresolved / manual**
1. **Secret history not reviewed** (no `.git`). The ZIP contains `client_secret_462580216432-...apps.googleusercontent.com.json` and `client_secret_yandex.json` with live-looking client secrets (git-ignored, but present in the archive you shared). Treat both as exposed. Run locally: `git log --all --oneline -- 'client_secret*' '*.apps.googleusercontent.com.json'` and `git log -S'sb_secret_' --all --oneline` (and `-S'GOCSPX-'`); if hits exist, rotate and consider `git filter-repo` (not done here).
2. **Rotate** (you do this): Google Cloud Console > APIs & Services > Credentials > the OAuth client > add new secret, update Streamlit secrets, disable old. Microsoft Entra > App registrations > Certificates & secrets > new secret, delete old. Yandex OAuth app > regenerate secret. Supabase > Project Settings > API Keys: create new secret key, delete the leaked one (`sb_secret_...`); if legacy JWT keys were exposed, rotate the JWT secret. Update `.streamlit/secrets.toml`/Streamlit Cloud secrets only; never commit.
3. **Dashboard settings to check:** Supabase Auth: CAPTCHA (Turnstile/hCaptcha) for sign-up/sign-in, email-signup off if Google-only, anonymous sign-ins off, rate limits (sign-in, OTP, token refresh) at defaults or lower, minimum password length >= 12, leaked-password protection (Pro), MFA TOTP enabled, redirect URL allowlist exact-match. Streamlit Cloud: app visibility, `SIH26106_DEBUG` unset, secrets only in the Secrets panel.
4. Streamlit `maxUploadSize=25` must match `SIH26106_MAX_MESSAGE_BYTES`; the app has no per-user rate limit on analysis (platform-level only).
5. CI/CodeQL for these changes is unconfirmed.


### 9.1 Second hardening pass (2026-10-28)

Verified first: HTML-injection fix present (`fix_html_injection.py --check` = 0 pending; not duplicated). Baseline for diff/`git diff --check` was a scratch Git repo built from your ZIP (the ZIP has no `.git`), so the real branch/status could not be confirmed here.

| Finding | Fix |
|---|---|
| Rejected emails (oversized, deeply nested, wrong type) raised uncaught in `app.py` | `EmailRejectedError` base class; `analyze_bytes` shows a plain error and `st.stop()`s, no traceback. `parse_eml` also rejects non-bytes/str input and treats `MemoryError` like `RecursionError` |
| Antivirus panel counted skipped/errored files as "Clean" and showed skipped files as clean when ClamAV was down | Clean metric counts only status "Clean"; new "Not scanned / error" metric; skipped files show "Not scanned". `scan_attachments` adds `scanned` and sets `infected` only on a successful scan |
| ZIP check ignored prefixed/self-extracting archives and passed unreadable ZIPs | `inspect_zip` finds archives by header/EOCD anywhere, tolerates prefixes, **fails closed** on malformed structure or any inspector error; per-entry size (512 MB), per-entry ratio, >5 nested archives, large nested archive, entry count, total size, ratio. Metadata only; nothing extracted. Declared sizes can lie, so ClamAV/VirusTotal remain the real content scan |
| ClamAV timeout applied only to the send loop | One 60 s monotonic deadline covers connect, send and every recv (a trickling server cannot extend it); response size capped; socket always closed. VirusTotal path: see 9.3 (best-effort 120 s budget, not a strict wall-clock guarantee). `scan_bytes` converts any unexpected exception to `ok: False` |
| Shared-intel body read via `.json()` | Streamed (`stream=True`) with a strict 2 MB cap (also refuses declared `Content-Length` > 2 MB), response always closed; `max_rows` clamped 0-50,000 (NaN/inf safe), timeout clamped (0, 30] s |

**Tests (actually run, workspace):** see section 8 addendum below. New tests live in `test_security_hardening.py`; `test_shared_intel_client.py` test double gained `iter_content`/`close`/`headers` to match the streaming client.

**Not done / remaining risk:** no live penetration test; no live ClamAV/VirusTotal/Supabase run (ClamAV protocol exercised only against a local fake socket server); `bandit`/`pip-audit` unavailable offline; Streamlit buffers uploads before app code runs, so `maxUploadSize=25` (config) is the first defence; a batch of CSV rows or a mailbox with one bad message stops at the first rejected message (graceful stop, not a crash); `unsafe_allow_html` sites other than those in `fix_html_injection.py` were not re-audited.

**Credentials you must rotate manually (exposed in the archive you supplied; Git history unverified):** (1) Google OAuth client secret (`client_secret_462580216432-...apps.googleusercontent.com.json`): Google Cloud Console > APIs & Services > Credentials > add new secret, update Streamlit secrets, disable old. (2) Microsoft Entra app secret (if one was ever committed): App registrations > Certificates & secrets > new, delete old. (3) Supabase secret key (`sb_secret_...`) and, if legacy keys were exposed, the JWT secret: Project Settings > API Keys. (4) Yandex OAuth secret (`client_secret_yandex.json`): regenerate in the Yandex OAuth app. After rotating, remove any copies from history with `git filter-repo` on a fresh clone and force-push only after confirming (not done here).

**Section 8 addendum - results actually run (2026-10-28, workspace, not CI):** `python -m pytest -q`: **610 passed, 0 failed** (10 subtests passed; 39 in `test_security_hardening.py`). `python -m compileall -q .`: OK. `git diff --check` (against a scratch baseline built from the ZIP): clean. `sha256sum -c MANIFEST.sha256`: all OK. `test_contributions.py` and `test_shared_intel_client.py` test doubles were extended with `iter_content`/`close`/`headers` to match the streaming client; no assertions were weakened.

**Final verification pass (2026-10-28):** the delivered ZIP (10 files) was overlaid on a fresh extraction of your original archive in a scratch Git repo (branch `main` there only; your real repo's branch/history was NOT verified). Defect found and fixed: an attachment whose decoding raised was recorded as empty data, which `scan_bytes` treats as an empty (clean) file; it is now `skipped: decode_error` and reported "Not scanned". Results in the overlaid copy: see the final report in chat (pytest, compileall, `git diff --cached --check`, `sha256sum -c`).

### 9.2 Antivirus UI status fix (2026-10-28)

Fixed in `app.py` via the new pure helper `antivirus_scan.attachment_status()`: "Clean" is shown only for a successful scan with no detection; with no backend, ordinary attachments show "Not scanned" and risky extensions show "Potentially risky extension" (heuristic, explicitly not a malware verdict); any attachment with `skipped` metadata (size/count/aggregate limits, decode errors) shows "Not scanned" plus the actual reason regardless of scanner availability. Metrics are now separate: Detections (antivirus), Clean (scanned), Risky extension (heuristic), Not scanned / error. Regression tests: `AttachmentStatusUI` in `test_security_hardening.py` (scanner unavailable, benign and risky extensions, decode failure, skipped with scanner available, malformed outcomes).

**Actual results (final ZIP overlaid on a fresh extraction of the original archive, scratch Git repo; real repo branch/history not verified):** `pytest -q`: 618 passed, 0 failed (10 subtests passed; 46 in `test_security_hardening.py`). `compileall -q .`: OK. `git diff --cached --check`: clean (CRLF warnings only). `sha256sum -c MANIFEST.sha256`: 7/7 OK. No live scanner or deployment testing.


### 9.3 Malformed verdicts and VirusTotal deadline (2026-10-28)

1. **Verdict strictness.** `antivirus_scan._verdict()` returns a verdict only when `ok is True` and `infected` is exactly `True`/`False`. `{"ok": True}`, `infected: None`, strings, ints, lists, truthy non-bool `ok`, non-dicts all become **Scan error** (never Clean, never INFECTED) in `attachment_status()` and `scan_attachments()`. VirusTotal results are also refused as "clean" when the analysis stats are missing/empty (`_vt_stats_ok`); a cached file record without usable stats falls through to a fresh upload.
2. **VirusTotal budget.** The 120 s deadline now starts before the first request and covers lookup, upload, polling and sleeps. Each request gets a (connect <=10 s, read <=30 s) timeout capped by the remaining budget; bodies are streamed with a 2 MB cap and a deadline check per chunk; the deadline is re-checked after every network call and sleeps are clamped to the remaining time. **Limitation (not a strict wall-clock guarantee):** `requests` timeouts apply per socket operation, so one request that trickles bytes, or the single-call upload body, can overrun by up to roughly one timeout interval. A hard guarantee would need a worker thread/process with kill, or an async client; not implemented.

Tests: `MalformedVerdicts` and `VirusTotalDeadline` (fake clock; time consumed in lookup, upload, polling, body read; nearly expired deadline) in `test_security_hardening.py`.

**Actual results (all 10 intended files overlaid on a fresh extraction of the original full project in a scratch Git repo; your real repo's branch/history not verified):** `pytest -q`: **629 passed, 0 failed** (10 subtests passed; 57 in `test_security_hardening.py`). `compileall -q .`: OK. `git diff --cached --check`: clean (CRLF warnings only). `sha256sum -c MANIFEST.sha256`: 7/7 OK. No live VirusTotal/ClamAV/Supabase testing.
