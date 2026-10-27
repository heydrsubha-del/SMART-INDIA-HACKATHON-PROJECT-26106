-- TEST-ONLY: a dedicated TEST project - NEVER production (ref qozfyuiloitutpfthuwn is PRODUCTION) ONLY.
-- This cleanup removes only the exact synthetic seed rows and the two named race submissions/logs.
-- Paste the same three disposable UUIDs used in race_seed.sql, plus its exact seed_time.
-- All checks occur before any delete. Any unexpected row or count mismatch aborts and rolls back the entire DO statement.
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
    t_seed text := '2026-10-11 23:40:33.000777+00';
    v_a uuid;
    v_b uuid;
    v_c uuid;
    v_seed timestamptz;
    v_end timestamptz;
    v_seed_rows bigint;
    v_seed_sum bigint;
    v_bad bigint;
    v_sub_before bigint;
    v_log_before bigint;
    v_deleted_sub bigint;
    v_deleted_log_c bigint;
    v_deleted_log_ab bigint;
    v_left bigint;
BEGIN
    IF t_a LIKE 'PASTE%' OR t_b LIKE 'PASTE%' OR t_c LIKE 'PASTE%' OR t_seed LIKE 'PASTE%' THEN
        RAISE EXCEPTION 'ABORT: paste A/B/C UUIDs and the exact seed_time';
    END IF;

    v_a := t_a::uuid;
    v_b := t_b::uuid;
    v_c := t_c::uuid;
    v_seed := t_seed::timestamptz;
    v_end := v_seed + interval '30 minutes';

    IF mod(extract(microseconds FROM v_seed)::bigint, 1000000) <> 777 THEN
        RAISE EXCEPTION 'ABORT: seed_time is missing the expected .000777 marker';
    END IF;
    IF v_seed > now() + interval '10 seconds' OR v_seed < now() - interval '48 hours' THEN
        RAISE EXCEPTION 'ABORT: seed_time is in the future or older than 48 hours';
    END IF;
    IF v_a = v_b OR v_a = v_c OR v_b = v_c THEN
        RAISE EXCEPTION 'ABORT: A, B, and C must be different users';
    END IF;
    IF (SELECT count(*) FROM auth.users WHERE id IN (v_a, v_b, v_c)) <> 3 THEN
        RAISE EXCEPTION 'ABORT: one or more users not found; verify the test project';
    END IF;

    -- Require identifiable seed rows. C must never have submissions or any non-seed log rows.
    SELECT count(*), coalesce(sum(items), 0)
      INTO v_seed_rows, v_seed_sum
    FROM public.contribution_log
    WHERE contributor_id = v_c AND at = v_seed;
    IF v_seed_rows = 0 OR v_seed_sum < 99 OR v_seed_sum > 1999 THEN
        RAISE EXCEPTION 'ABORT: expected seed rows not found at the supplied timestamp; nothing deleted';
    END IF;

    -- Every submission belonging to A/B/C must match the one permitted pending race row in the time window.
    SELECT count(*) INTO v_bad
    FROM public.indicator_submissions s
    WHERE s.contributor_id IN (v_a, v_b, v_c)
      AND NOT (
          s.indicator_type = 'domain'
          AND s.claimed_verdict = 'suspicious'
          AND s.status = 'pending'
          AND s.created_at >= v_seed
          AND s.created_at <= v_end
          AND ((s.contributor_id = v_a AND s.value_norm = 'tango.example.com')
            OR (s.contributor_id = v_b AND s.value_norm = 'uniform.example.com'))
      );
    IF v_bad <> 0 THEN
        RAISE EXCEPTION 'ABORT: % unexpected submission row(s) owned by A/B/C; nothing deleted', v_bad;
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.indicator_submissions
        WHERE contributor_id IN (v_a, v_b)
        GROUP BY contributor_id HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'ABORT: more than one submission exists for a race user; nothing deleted';
    END IF;

    -- C may own only seed rows at the exact marker. A/B may own only one item=1 log row within the race window.
    SELECT count(*) INTO v_bad
    FROM public.contribution_log l
    WHERE l.contributor_id IN (v_a, v_b, v_c)
      AND NOT (
          (l.contributor_id = v_c AND l.at = v_seed AND l.items BETWEEN 1 AND 20)
          OR (l.contributor_id IN (v_a, v_b) AND l.items = 1 AND l.at >= v_seed AND l.at <= v_end)
      );
    IF v_bad <> 0 THEN
        RAISE EXCEPTION 'ABORT: % unexpected contribution-log row(s) owned by A/B/C; nothing deleted', v_bad;
    END IF;
    IF (SELECT count(*) FROM public.contribution_log WHERE contributor_id = v_c AND at = v_seed AND items <> 20) > 1
       OR EXISTS (
           SELECT 1 FROM public.contribution_log
           WHERE contributor_id IN (v_a, v_b)
           GROUP BY contributor_id HAVING count(*) > 1
       ) THEN
        RAISE EXCEPTION 'ABORT: log rows do not match the expected seed/race shape; nothing deleted';
    END IF;

    SELECT count(*) INTO v_sub_before
    FROM public.indicator_submissions
    WHERE contributor_id IN (v_a, v_b);
    SELECT count(*) INTO v_log_before
    FROM public.contribution_log
    WHERE contributor_id IN (v_a, v_b, v_c);

    DELETE FROM public.indicator_submissions s
    WHERE s.indicator_type = 'domain'
      AND s.claimed_verdict = 'suspicious'
      AND s.status = 'pending'
      AND s.created_at >= v_seed AND s.created_at <= v_end
      AND ((s.contributor_id = v_a AND s.value_norm = 'tango.example.com')
        OR (s.contributor_id = v_b AND s.value_norm = 'uniform.example.com'));
    GET DIAGNOSTICS v_deleted_sub = ROW_COUNT;

    DELETE FROM public.contribution_log l
    WHERE l.contributor_id = v_c AND l.at = v_seed AND l.items BETWEEN 1 AND 20;
    GET DIAGNOSTICS v_deleted_log_c = ROW_COUNT;

    DELETE FROM public.contribution_log l
    WHERE l.contributor_id IN (v_a, v_b)
      AND l.items = 1 AND l.at >= v_seed AND l.at <= v_end;
    GET DIAGNOSTICS v_deleted_log_ab = ROW_COUNT;

    SELECT count(*) INTO v_left
    FROM (
        SELECT 1 FROM public.indicator_submissions WHERE contributor_id IN (v_a, v_b, v_c)
        UNION ALL
        SELECT 1 FROM public.contribution_log WHERE contributor_id IN (v_a, v_b, v_c)
    ) remaining;

    IF v_deleted_sub <> v_sub_before
       OR v_deleted_log_c + v_deleted_log_ab <> v_log_before
       OR v_left <> 0 THEN
        RAISE EXCEPTION 'ABORT: cleanup mismatch (deleted % submissions/% logs; expected %/%; % rows remain); rolled back',
            v_deleted_sub, v_deleted_log_c + v_deleted_log_ab, v_sub_before, v_log_before, v_left;
    END IF;

    RAISE NOTICE 'Cleanup complete: deleted % race submission(s) and % contribution-log row(s).',
        v_deleted_sub, v_deleted_log_c + v_deleted_log_ab;
END
$test$;
