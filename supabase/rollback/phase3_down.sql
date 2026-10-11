-- Manual rollback for Phase 3. Run only after a pg_dump. Verified rows already promoted into shared_indicators are kept.
drop function if exists public.review_submission(uuid, text, text);
drop function if exists public.review_queue(int);
drop function if exists public.submit_indicators(jsonb);
drop function if exists private.valid_indicator(text, text);
drop function if exists private.valid_domain(text);
drop function if exists private.looks_like_token(text);
drop function if exists private.is_public_ip(text);
drop table if exists public.audit_log;
drop table if exists public.indicator_allowlist;
drop table if exists public.contribution_log;
drop table if exists public.indicator_submissions;
