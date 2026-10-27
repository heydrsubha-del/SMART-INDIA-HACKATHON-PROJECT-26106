-- TEST-ONLY. Project a dedicated TEST project - NEVER production (ref qozfyuiloitutpfthuwn is PRODUCTION) ONLY. NOT EXECUTED.
--
-- ONE statement (a single DO block), no BEGIN/COMMIT, no top-level DDL:
--   * Each scenario (T1..T4) runs in its own sub-block and ends with a sentinel error (SQLSTATE ZZ001) that rolls back that
--     scenario's database changes. Results are kept in a PL/pgSQL variable, which survives a sub-block rollback.
--   * The block ends with an UNCAUGHT RAISE EXCEPTION, so PostgreSQL aborts the statement and rolls back everything else.
--     Any earlier error (guard, FK, constraint) also aborts and rolls back everything.
--   * The helper functions are created with EXECUTE inside the block (transactional DDL), so they roll back too.
-- Only non-transactional side effect: id sequence values consumed by the seed inserts are NOT returned (gaps only).
--
-- BEFORE RUNNING: SQL Editor role = postgres; dashboard project = a dedicated TEST project - NEVER production (ref qozfyuiloitutpfthuwn is PRODUCTION);
-- paste the disposable user's UUID below. The report arrives as an ERROR message starting "REPORT". That is intentional.

do $t$
declare
  v_txt text := 'PASTE-DISPOSABLE-TEST-USER-UUID-HERE';
  v_uid uuid; v_def text; v_anon text;
  v_pu bigint; v_pg bigint; v_hu bigint; v_du bigint; v_hg bigint; v_need int;
  v_cnt bigint; v_cnt2 bigint; v_locks bigint; v_ok boolean;
  v_b_sub bigint; v_b_log bigint; v_rep text := ''; v_fail int;
begin
  if not coalesce(public.is_test_project(), false) then raise exception 'ABORT: not a test project (is_test_project() is not true)'; end if;
  -- ---------- guards (any failure aborts and rolls back everything) ----------
  if v_txt like 'PASTE%' then raise exception 'ABORT: paste the disposable user UUID into v_txt'; end if;
  v_uid := v_txt::uuid;
  if not exists (select 1 from auth.users where id = v_uid) then raise exception 'ABORT: user not found - wrong project?'; end if;
  if exists (select 1 from auth.users where id = v_uid and (is_anonymous or coalesce(raw_app_meta_data->>'role','') ilike '%admin%')) then
    raise exception 'ABORT: user must be a normal, non-anonymous, non-admin account'; end if;

  v_def := pg_get_functiondef('public.submit_indicators(jsonb)'::regprocedure);
  if v_def not like '%c_pending_user constant int := 100%' or v_def not like '%c_pending_global constant int := 1000%'
     or v_def not like '%c_global_hour constant int := 2000%' or v_def not like '%pg_advisory_xact_lock(7301, 1)%'
     or v_def not like '%private.is_anonymous()%' then
    raise exception 'ABORT: applied submit_indicators() differs from the reviewed definition'; end if;
  v_anon := pg_get_functiondef('private.is_anonymous()'::regprocedure);

  select coalesce(sum(items),0) into v_hu from public.contribution_log where contributor_id = v_uid and at > now() - interval '1 hour';
  select coalesce(sum(items),0) into v_du from public.contribution_log where contributor_id = v_uid and at > now() - interval '1 day';
  if v_hu > 30 or v_du > 150 then raise exception 'ABORT: user lacks per-hour/day headroom (hour=%, day=%)', v_hu, v_du; end if;
  if (select count(*) from public.indicator_submissions where contributor_id = v_uid and status = 'rejected'
        and reviewed_at > now() - interval '30 days') >= 5 then raise exception 'ABORT: user is near the rejection block'; end if;
  if exists (select 1 from public.indicator_submissions where value_norm like 'zz-capseed-%'
             or (contributor_id = v_uid and value_norm in ('alpha.example.com','bravo.example.com','charlie.example.com','delta.example.com',
                 'echo.example.com','foxtrot.example.com','golf.example.com','hotel.example.com','india.example.com','juliet.example.com',
                 'kilo.example.com','lima.example.com'))) then
    raise exception 'ABORT: pre-existing rows collide with test values'; end if;

  select count(*) into v_pu from public.indicator_submissions where contributor_id = v_uid and status = 'pending';
  select count(*) into v_pg from public.indicator_submissions where status = 'pending';
  if v_pu > 85 or v_pg - v_pu > 850 then raise exception 'ABORT: too many pending rows already (user=%, global=%)', v_pu, v_pg; end if;
  select coalesce(sum(items),0) into v_hg from public.contribution_log where at > now() - interval '1 hour';
  if v_hg > 1900 then raise exception 'ABORT: global hourly log already %', v_hg; end if;

  select count(*) into v_b_sub from public.indicator_submissions;
  select count(*) into v_b_log from public.contribution_log;

  -- ---------- helpers (created inside the transaction; rolled back with it) ----------
  execute $h$
    create function pg_temp.items(p_from int, p_n int) returns jsonb language sql as
    $f$ select jsonb_agg(jsonb_build_object('indicator_type', 'domain',
          'value_norm', (array['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet','kilo','lima'])[i] || '.example.com',
          'claimed_verdict', 'suspicious'))
        from generate_series(p_from, p_from + p_n - 1) as i $f$ $h$;
  execute $h$
    create function pg_temp.line(p_test text, p_exp text, p_act text) returns text language sql immutable as
    $f$ select format('%s | expected=%s | actual=%s | %s', p_test, p_exp, p_act, case when p_exp = p_act then 'PASS' else 'FAIL' end) || E'\n' $f$ $h$;
  -- Calls submit_indicators as role 'authenticated' with simulated JWT claims. The role is always reset before returning.
  execute $h$
    create function pg_temp.sub(p_uid uuid, p_anon boolean, p_items jsonb) returns text language plpgsql as
    $f$
    declare r jsonb; v text;
    begin
      perform set_config('request.jwt.claims', case when p_uid is null then '{}'
              else jsonb_build_object('sub', p_uid, 'role', 'authenticated', 'is_anonymous', p_anon)::text end, true);
      perform set_config('request.jwt.claim.sub', coalesce(p_uid::text, ''), true);
      set local role authenticated;
      begin
        r := public.submit_indicators(p_items);
        v := format('accepted=%s dup=%s rej=%s', r->>'accepted', r->>'duplicates', r->>'rejected');
      exception when others then
        v := 'ERR:' || sqlerrm;
      end;
      reset role;
      return v;
    end $f$ $h$;

  -- ---------- T1: per-user pending cap (+ T5a lock presence) ----------
  begin
    insert into public.indicator_submissions(contributor_id, indicator_type, value_norm, claimed_verdict)
      select v_uid, 'domain', 'zz-capseed-' || gen_random_uuid()::text || '.invalid', 'suspicious' from generate_series(1, 90 - v_pu::int);
    v_rep := v_rep || pg_temp.line('T1a user pending=90, submit 11 -> refused', 'ERR:queue_full', pg_temp.sub(v_uid, false, pg_temp.items(1, 11)));
    v_rep := v_rep || pg_temp.line('T1b user pending=90, submit 10 (=100) -> accepted', 'accepted=10 dup=0 rej=0', pg_temp.sub(v_uid, false, pg_temp.items(1, 10)));
    select count(*) into v_locks from pg_locks where locktype = 'advisory' and pid = pg_backend_pid() and granted
       and classid = 7301::oid and objid = 1::oid and objsubid = 2;
    v_rep := v_rep || pg_temp.line('T5a global advisory lock (7301,1) held after submit', '1', v_locks::text);
    select count(*) into v_locks from pg_locks where locktype = 'advisory' and pid = pg_backend_pid() and granted and objsubid = 1;
    v_rep := v_rep || pg_temp.line('T5a per-contributor advisory lock held after submit', 'true', (v_locks >= 1)::text);
    v_rep := v_rep || pg_temp.line('T1c user pending=100, submit 1 new -> refused', 'ERR:queue_full', pg_temp.sub(v_uid, false, pg_temp.items(11, 1)));
    v_rep := v_rep || pg_temp.line('T1d user pending=100, submit 1 duplicate -> refused (conservative by design)', 'ERR:queue_full', pg_temp.sub(v_uid, false, pg_temp.items(1, 1)));
    select count(*) into v_cnt from public.indicator_submissions where contributor_id = v_uid and status = 'pending';
    v_rep := v_rep || pg_temp.line('T1e user pending count still 100 (refusals rolled back)', '100', v_cnt::text);
    raise exception 'scenario rollback' using errcode = 'ZZ001';
  exception when sqlstate 'ZZ001' then null;
  end;
  if (select count(*) from public.indicator_submissions) <> v_b_sub or (select count(*) from public.contribution_log) <> v_b_log then
    raise exception 'ABORT: T1 rollback did not restore the baseline'; end if;

  -- ---------- T2: global pending cap (seed rows owned by random UUIDs need the FK bypass) ----------
  begin
    v_ok := true;
    begin
      set local session_replication_role = replica;
      insert into public.indicator_submissions(contributor_id, indicator_type, value_norm, claimed_verdict)
        select gen_random_uuid(), 'domain', 'zz-capseed-' || gen_random_uuid()::text || '.invalid', 'suspicious' from generate_series(1, 990 - v_pg::int);
      set local session_replication_role = origin;
    exception when others then
      v_ok := false;
      v_rep := v_rep || pg_temp.line('T2 seeding (FK bypass)', 'available', 'SKIPPED: ' || sqlerrm);
    end;
    if v_ok then
      v_rep := v_rep || pg_temp.line('T2a global pending=990, submit 11 -> refused', 'ERR:queue_full', pg_temp.sub(v_uid, false, pg_temp.items(1, 11)));
      v_rep := v_rep || pg_temp.line('T2b global pending=990, submit 10 (=1000) -> accepted', 'accepted=10 dup=0 rej=0', pg_temp.sub(v_uid, false, pg_temp.items(1, 10)));
      v_rep := v_rep || pg_temp.line('T2c global pending=1000, submit 1 -> refused', 'ERR:queue_full', pg_temp.sub(v_uid, false, pg_temp.items(11, 1)));
      select count(*) into v_cnt from public.indicator_submissions where contributor_id = v_uid and status = 'pending';
      v_rep := v_rep || pg_temp.line('T2d user own pending < 100 (global cap was the trigger)', 'true', (v_cnt < 100)::text);
    end if;
    raise exception 'scenario rollback' using errcode = 'ZZ001';
  exception when sqlstate 'ZZ001' then null;
  end;
  if (select count(*) from public.indicator_submissions) <> v_b_sub or (select count(*) from public.contribution_log) <> v_b_log then
    raise exception 'ABORT: T2 rollback did not restore the baseline'; end if;

  -- ---------- T3: global hourly rate limit ----------
  begin
    v_ok := true;
    v_need := 1990 - v_hg::int;
    begin
      set local session_replication_role = replica;
      insert into public.contribution_log(contributor_id, items, at) select gen_random_uuid(), 20, now() from generate_series(1, v_need / 20);
      if v_need % 20 > 0 then insert into public.contribution_log(contributor_id, items, at) values (gen_random_uuid(), v_need % 20, now()); end if;
      set local session_replication_role = origin;
    exception when others then
      v_ok := false;
      v_rep := v_rep || pg_temp.line('T3 seeding', 'available', 'SKIPPED: ' || sqlerrm);
    end;
    if v_ok then
      v_rep := v_rep || pg_temp.line('T3a global hour=1990, submit 11 -> refused', 'ERR:rate_limited', pg_temp.sub(v_uid, false, pg_temp.items(1, 11)));
      v_rep := v_rep || pg_temp.line('T3b global hour=1990, submit 10 (=2000) -> accepted', 'accepted=10 dup=0 rej=0', pg_temp.sub(v_uid, false, pg_temp.items(1, 10)));
      v_rep := v_rep || pg_temp.line('T3c global hour=2000, submit 1 -> refused', 'ERR:rate_limited', pg_temp.sub(v_uid, false, pg_temp.items(11, 1)));
      select coalesce(sum(items),0) into v_cnt from public.contribution_log where at > now() - interval '1 hour';
      v_rep := v_rep || pg_temp.line('T3d global hourly sum is exactly 2000', '2000', v_cnt::text);
    end if;
    raise exception 'scenario rollback' using errcode = 'ZZ001';
  exception when sqlstate 'ZZ001' then null;
  end;
  if (select count(*) from public.indicator_submissions) <> v_b_sub or (select count(*) from public.contribution_log) <> v_b_log then
    raise exception 'ABORT: T3 rollback did not restore the baseline'; end if;

  -- ---------- T4: anonymous / missing session ----------
  begin
    select count(*) into v_cnt from public.contribution_log;
    if v_anon not ilike '%jwt%' then
      v_rep := v_rep || pg_temp.line('T4 precondition', 'is_anonymous() reads the JWT', 'INCONCLUSIVE: its source does not mention jwt; review private.is_anonymous()');
    end if;
    v_rep := v_rep || pg_temp.line('T4a anonymous claims, real uid -> refused', 'ERR:auth_required', pg_temp.sub(v_uid, true, pg_temp.items(1, 1)));
    v_rep := v_rep || pg_temp.line('T4b no session -> refused', 'ERR:auth_required', pg_temp.sub(null, false, pg_temp.items(1, 1)));
    select count(*) into v_cnt2 from public.contribution_log;
    v_rep := v_rep || pg_temp.line('T4c refused calls wrote no log row', v_cnt::text, v_cnt2::text);
    v_rep := v_rep || pg_temp.line('T4d control: normal claims -> accepted', 'accepted=1 dup=0 rej=0', pg_temp.sub(v_uid, false, pg_temp.items(1, 1)));
    raise exception 'scenario rollback' using errcode = 'ZZ001';
  exception when sqlstate 'ZZ001' then null;
  end;
  if (select count(*) from public.indicator_submissions) <> v_b_sub or (select count(*) from public.contribution_log) <> v_b_log then
    raise exception 'ABORT: T4 rollback did not restore the baseline'; end if;

  -- ---------- report: uncaught raise => the whole statement rolls back ----------
  v_fail := (length(v_rep) - length(replace(v_rep, '| FAIL', ''))) / length('| FAIL');
  raise exception E'REPORT (everything rolled back by design)\nnot-passing: % check(s)\n%', v_fail, v_rep;
end $t$;
