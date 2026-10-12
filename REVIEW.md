# Algorithmistic hardening proposal - review pack (rev 3)
STATUS: nothing applied, nothing executed on PostgreSQL or Supabase. Target if approved: algorithmistic-test (qozfyuiloitutpfthuwn) only.
Repo: no repo files were edited. Your pasted `git status` (3 modified, 5 untracked) is unverified from here; re-run it. Only `contribution_client.queue_full.diff` (1 line, CRLF kept) touches a repo file and it changes that file's hash (MANIFEST decision below).

## Files
| File | Purpose |
|---|---|
| 20261012_harden_submit_indicators.sql | migration (3 objects) |
| 20261012_harden_submit_indicators_ROLLBACK.sql | restores exported text of 2 functions, drops helper |
| validation_checks.sql | read-only, 52 rows, NOT RUN (rev 3's 44-row version was run by you: all baseline matches) |
| preflight_snapshot.sql | read-only: owner/ACL/attributes/md5 snapshot + index evidence, NOT RUN |
| PROPOSAL_ONLY_contribution_log_retention.sql | not implemented, not scheduled |
| sql_model.py, validation_corpus.py, test_*.py | offline tests (Python model, not PostgreSQL) |

## Migration: exactly what changes
| Object | Change |
|---|---|
| NEW private.valid_host_labels(text) | applies looks_like_token to labels left of registrable domain (two-part-suffix list copied from sanitizer) + narrow readable-word exception; REVOKE from public, anon, authenticated, service_role (matches other private helpers `{postgres=X/postgres}`) |
| private.valid_indicator(text,text) | exported text, 2 lines edited: domain and URL-host paths also call valid_host_labels. Header (IMMUTABLE, invoker, search_path '') identical |
| public.submit_indicators(jsonb) | exported text + additions: `is_anonymous()` reject (same `auth_required`/42501); global advisory lock `(7301,1)` taken AFTER the per-user lock; pending caps 100/user, 1000/global -> `queue_full`. Only the one auth line is replaced; header (SECURITY DEFINER, search_path '') identical |
Unchanged: tables, indexes, RLS, all other grants, looks_like_token, valid_domain, is_public_ip, review_queue, review_submission, scans, scoring/auth/report code. CREATE OR REPLACE keeps owner and ACL; the migration issues no GRANT.
IPv6 URLs: branch REMOVED from this migration; deferred to a separate proposal (corpus row `DEFERRED_IPV6_URL`).

## Readable-subdomain rule (rev 4: vowel-ratio heuristic replaced)
Your read-only validation_checks.sql run (rev 3 corpus, 44 rows) reported actual = baseline for every row: this confirms my reading of the CURRENT exported functions, not the proposed ones. The corpus now has 52 rows, so re-run before applying (read-only).
Problem: rev 3 rejected `misunderstandings` (vowels 29%) and `straightforwardness` (4-consonant run) although Python accepts them. Both were legitimate readable labels and the vowel/consonant rules were poor discriminators.
Cause of the underlying gap: looks_like_token() rejects EVERY non-wordlike label of 16+ chars; Python only rejects those with entropy >= 3.7. Python alone, however, accepts most random letter-only strings of 16-20 chars (about 85% / 54% in my simulation), so copying Python would weaken protection.
New rule (block R inside private.valid_host_labels only; looks_like_token and URL path segments untouched). A label that looks_like_token flags is still allowed only if: letters only; 16-24 chars; not a-f only; entropy < 3.7; AND >= 65% of its adjacent letter pairs are in a fixed list of 150 common English bigrams. Digits, hyphens, UUID, JWT, hex, numeric, keyboard-walk and 25+ char labels stay rejected.
Measured offline with sql_model.py (a Python model, NOT PostgreSQL): all 45 eligible (16-24 letter) sample words/compounds accepted, but the lowest pair-coverage is 0.67 against the 0.65 threshold - a THIN margin, so expect some real readable words to be rejected (fail closed); uniformly random lowercase letters pass 0.16% / 0.03% / 0.02% / 0.01% at 16 / 18 / 20 / 24 chars (rev 3: 4.6% / 3.7% / 1.9% / 0.6%). Caveats: the 65% threshold was chosen after seeing results on my own word sample (no word list exists in the sandbox), so real-world false rejects are unmeasured; the rule is a letter-pair heuristic, not a dictionary or language check: transliterated non-English labels may pass or fail by chance (corpus has one of each); adversarial strings built from common bigrams can pass.
Parity statement: SQL-accepted labels are always a SUBSET of Python-accepted labels (entropy < 3.7 is required, fuzz-tested). The converse is NOT true; Python is not matched exactly. Intentional SQL-stricter cases: letters+digit labels, hyphenated 16+ labels, repeated-pattern letters, non-English-like letters, 25+ char labels, and all URL path segments.
DECISION: keep block R, or delete it (strict looks_like_token on labels; then every 16+ char readable label is rejected).

## Behavioral differences, Python sanitizer vs proposed SQL
| Item | Status |
|---|---|
| #1 subdomain labels | CLOSED (helper). Registrable/DGA domains stay valid. Existing pending rows with token-like subdomains will fail approval (`invalid_indicator`): reject them |
| #2 16+ char rule | SQL stricter than Python (NOT parity): paths keep the strict rule; subdomains use block R above |
| #3 truncate vs reject | INTENTIONAL: SQL never rewrites client data; Python output has no token segments so no loss |
| #4 IPv6 URL host | DEFERRED, still rejected by SQL |
| extra: `%` escapes in paths | INTENTIONAL stricter in SQL |
| extra: is_public_ip allows 6to4, Teredo, 64:ff9b:1::/48, ORCHID that Python 3.12.3 rejects | NOT FIXED (outside approved design); documented in corpus |

## Pending caps (documented behavior)
v_n counts EVERY requested item, including duplicates (ON CONFLICT DO NOTHING) and items that will be rejected as invalid. 95 pending + a 10-item request = `queue_full` even if all 10 are duplicates. The raise rolls everything back (no log row). Capacity frees only when review_submission leaves 'pending'; no withdrawal function exists in the exports. Global lock waits count toward statement_timeout (8s authenticated): contention = timeout error, not a hang.

## Indexes (reconciled, none added)
The five CSVs contain NO index list (no pg_indexes/INDEX section), so the earlier "indexes cover the queries" claim cannot be verified from these files. Evidence available is constraint-implied indexes only: indicator_submissions PK(id) and UNIQUE(contributor_id, indicator_type, value_norm) - supports the per-user pending count by contributor_id prefix; contribution_log PK(id) only. Nothing shows an index on status/created_at (global pending count, review_queue) or on contribution_log(at). The rate-limit queries already exist today; only the two pending counts are new. No index is proposed: global pending is bounded by the 1000 cap but the table also holds reviewed rows. preflight_snapshot.sql sections 2-3 would produce the evidence (needs approval); add an index only if it shows a seq scan matters.

## Rollback verification (offline, text level)
test_package_integrity.py checks against the CSV exports: rollback contains the exported text of valid_indicator and submit_indicators verbatim (so language, SECURITY DEFINER/INVOKER, IMMUTABLE, search_path are restored); rollback has no GRANT/REVOKE/OWNER/index/policy statements; helper dropped after valid_indicator is restored; migration headers equal export headers; valid_indicator differs by exactly 2 lines; submit_indicators removes exactly 1 original line.
NOT verifiable from exports: owner of valid_indicator and its ACL (absent); ownership of the others is inferred from `postgres=X/postgres` grantors. Real proof = preflight_snapshot.sql before migration vs after rollback (md5, owner, ACL must match).

## Tests
RUN offline (all pass): 33 new tests - package integrity (12), corpus vs real sanitizer + model (4), label regression/invariants (14), queue_full/anonymous client handling (3) - plus the existing 11 contribution-client and 14 shared-intel-client tests (real sanitizer, patched client). sql_model.py is a Python MODEL of the SQL; it is NOT PostgreSQL. Package integrity also checks the model's bigram list equals the list in the migration.
NOT RUN: every SQL behavior (validation_checks.sql, caps, locks, anon rejection, rollback), E2E files, manifest check.
Need migration applied + fixtures + separate approval: concurrency (parallel users vs global cap using a low-threshold isolated copy), pending caps at 100/1000, anonymous token -> auth_required (no log row), non-admin/aal1/self-review, duplicate submissions, privacy of review_queue output, DB failure handling.

## Checklist
- [ ] Re-run git status; decide MANIFEST.sha256 regeneration after the client edit
- [ ] Keep or delete readable-word block R
- [ ] Anonymous-signup client will always get auth_required after migration (flag stays "0")
- [ ] Approve running preflight_snapshot.sql + validation_checks.sql (read-only) on algorithmistic-test?
- [ ] Decide on tightening is_public_ip (separate item), IPv6 URL proposal, reviewer-signal inflation, scans.summary nesting (not in this package)
