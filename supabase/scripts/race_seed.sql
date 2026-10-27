-- TEST-ONLY: a dedicated TEST project - NEVER production (ref qozfyuiloitutpfthuwn is PRODUCTION) ONLY.
-- This script COMMITS synthetic contribution_log rows. Clean them up with race_cleanup.sql.
-- Requires three fresh, ordinary authenticated users: A and B for the race; C owns seed rows and must NEVER sign in or submit.
-- Replace each UUID placeholder once. Never use real-user accounts.
-- Seed timestamp has a fractional-second marker (.000777) so cleanup can identify this seed without a second UUID paste.
-- Run the race within 10 minutes of the reported seed_time.
-- GUARD: aborts unless this project answers public.is_test_project() = true (production returns false).
do $guard$ begin
  if not coalesce(public.is_test_project(), false) then
    raise exception 'ABORT: not a test project (is_test_project() is not true). Never run this on production.';
  end if;
end $guard$;

DO $test$
DECLARE
    t_a text := '0dab5714-a087-4d35-af77-0cbe146dbf1a';
    t_b text := 'e3f474de-d687-4161-9e83-3d9f93d4785f';
    t_c text := 'f1e1bf60-f162-4c93-ac2f-7f2d7c47fe3d';
    v_a uuid;
    v_b uuid;
    v_c uuid;
    v_def text;
    v_hour_before bigint;
    v_need integer;
    v_seed_time timestamptz := date_trunc('second', now()) + interval '777 microseconds';
    v_log_before bigint;
    v_submissions_before bigint;
    v_seed_rows bigint;
    v_seed_sum bigint;
    v_hour_after bigint;
BEGIN
    IF t_a LIKE 'PASTE%' OR t_b LIKE 'PASTE%' OR t_c LIKE 'PASTE%' THEN
        RAISE EXCEPTION 'ABORT: paste all three disposable user UUIDs';
    END IF;

    v_a := t_a::uuid;
    v_b := t_b::uuid;
    v_c := t_c::uuid;

    IF v_a = v_b OR v_a = v_c OR v_b = v_c THEN
        RAISE EXCEPTION 'ABORT: A, B, and C must be different users';
    END IF;
    IF (SELECT count(*) FROM auth.users WHERE id IN (v_a, v_b, v_c)) <> 3 THEN
        RAISE EXCEPTION 'ABORT: one or more users not found; verify the test project';
    END IF;
    IF EXISTS (
        SELECT 1 FROM auth.users
        WHERE id IN (v_a, v_b, v_c)
          AND (is_anonymous OR coalesce(raw_app_meta_data->>'role', '') ILIKE '%admin%')
    ) THEN
        RAISE EXCEPTION 'ABORT: all three must be non-anonymous, non-admin accounts';
    END IF;
    IF EXISTS (SELECT 1 FROM public.contribution_log WHERE contributor_id IN (v_a, v_b, v_c))
       OR EXISTS (SELECT 1 FROM public.indicator_submissions WHERE contributor_id IN (v_a, v_b, v_c)) THEN
        RAISE EXCEPTION 'ABORT: A, B, and C must have zero existing contribution rows';
    END IF;

    -- Refuse to collide with a previous test seed, even if a different C UUID is supplied.
    IF EXISTS (
        SELECT 1 FROM public.contribution_log
        WHERE at > now() - interval '3 hours'
          AND mod(extract(microseconds FROM at)::bigint, 1000000) = 777
    ) THEN
        RAISE EXCEPTION 'ABORT: a seed marker already exists in the last 3 hours; inspect/clean it first';
    END IF;

    v_def := pg_get_functiondef('public.submit_indicators(jsonb)'::regprocedure);
    IF v_def NOT LIKE '%c_global_hour constant int := 2000%'
       OR v_def NOT LIKE '%c_pending_user constant int := 100%'
       OR v_def NOT LIKE '%c_pending_global constant int := 1000%'
       OR v_def NOT LIKE '%pg_advisory_xact_lock(7301, 1)%'
       OR v_def NOT LIKE '%private.is_anonymous()%' THEN
        RAISE EXCEPTION 'ABORT: applied submit_indicators() differs from the reviewed migration';
    END IF;

    -- Leave two global pending slots free so queue_full cannot be the reason for a race refusal.
    IF (SELECT count(*) FROM public.indicator_submissions WHERE status = 'pending') > 998 THEN
        RAISE EXCEPTION 'ABORT: global pending queue has fewer than two free slots';
    END IF;

    SELECT coalesce(sum(items), 0) INTO v_hour_before
    FROM public.contribution_log
    WHERE at > now() - interval '1 hour';
    IF v_hour_before > 1900 THEN
        RAISE EXCEPTION 'ABORT: global hourly total already %; safe test requires <= 1900', v_hour_before;
    END IF;

    SELECT count(*) INTO v_log_before FROM public.contribution_log;
    SELECT count(*) INTO v_submissions_before FROM public.indicator_submissions;
    v_need := 1999 - v_hour_before::integer;

    INSERT INTO public.contribution_log (contributor_id, items, at)
    SELECT v_c, 20, v_seed_time FROM generate_series(1, v_need / 20);
    IF v_need % 20 > 0 THEN
        INSERT INTO public.contribution_log (contributor_id, items, at)
        VALUES (v_c, v_need % 20, v_seed_time);
    END IF;

    SELECT count(*), coalesce(sum(items), 0)
    INTO v_seed_rows, v_seed_sum
    FROM public.contribution_log
    WHERE contributor_id = v_c AND at = v_seed_time;

    SELECT coalesce(sum(items), 0) INTO v_hour_after
    FROM public.contribution_log
    WHERE at > now() - interval '1 hour';

    IF v_seed_sum <> v_need
       OR v_hour_after <> 1999
       OR (SELECT count(*) FROM public.contribution_log) <> v_log_before + v_seed_rows
       OR (SELECT count(*) FROM public.contribution_log WHERE contributor_id = v_c) <> v_seed_rows
       OR (SELECT count(*) FROM public.indicator_submissions) <> v_submissions_before THEN
        RAISE EXCEPTION 'ABORT: seed assertions failed; transaction rolled back';
    END IF;
END
$test$;

-- No UUID placeholder needed here. Copy seed_time exactly into race_cleanup.sql.
-- Expected owners=1 and global_hour_total=1999. If this query output fails, rerun this SELECT alone.
SELECT min(at) AS seed_time,
       count(*) AS seed_rows,
       sum(items) AS seed_items,
       count(DISTINCT contributor_id) AS owners,
       (SELECT coalesce(sum(items), 0)
        FROM public.contribution_log
        WHERE at > now() - interval '1 hour') AS global_hour_total
FROM public.contribution_log
WHERE at > now() - interval '3 hours'
  AND mod(extract(microseconds FROM at)::bigint, 1000000) = 777;
