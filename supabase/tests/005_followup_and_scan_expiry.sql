-- Behavioural test for 20261027000001_followup_hardening.sql and 20261028000001_scan_expiry_cleanup.sql.
-- RUN IN A TEST/DISPOSABLE PROJECT ONLY, never production. SQL Editor friendly; same harness as 004_self_review.sql:
-- all synthetic data lives in one sub-transaction ended by a deliberate RAISE (full rollback); helpers live in pg_temp.
-- Expected: 17 rows with passed = true plus a SUMMARY row "17 of 17 passed". Not yet executed anywhere (no PostgreSQL in the authoring sandbox).

create or replace function pg_temp.add(r jsonb, p_test text, p_got text, p_want text) returns jsonb
language sql as $$
  select r || jsonb_build_array(jsonb_build_object(
    'n',      jsonb_array_length(r) + 1,
    'passed', coalesce((p_got is not distinct from p_want) or (right(p_want, 1) = '*' and left(p_got, length(p_want) - 1) = left(p_want, length(p_want) - 1)), false),
    'test',   p_test,
    'detail', 'got=' || coalesce(p_got, 'NULL') || ' want=' || p_want));
$$;

-- Run one statement as an API role with a realistic Supabase JWT, return its scalar result or 'err:<sqlstate>:<message>'.
create or replace function pg_temp.run_as(p_uid uuid, p_role text, p_aal text, p_admin boolean, p_sql text,
                               p_app jsonb default '{}', p_user jsonb default '{}') returns text
language plpgsql as $$
declare v_out text;
begin
  perform set_config('request.jwt.claims', jsonb_build_object(
      'sub', p_uid, 'role', p_role, 'aal', p_aal, 'is_anonymous', false,
      'app_metadata',  case when p_admin then jsonb_build_object('provider', 'email', 'role', 'admin') else jsonb_build_object('provider', 'email') end || p_app,
      'user_metadata', p_user)::text, true);
  perform set_config('request.jwt.claim.sub', coalesce(p_uid::text, ''), true);
  execute format('set local role %I', p_role);
  begin
    execute p_sql into v_out;
  exception when others then
    v_out := 'err:' || sqlstate || ':' || sqlerrm;
  end;
  reset role;
  return v_out;
end $$;

create or replace function pg_temp.run_tests() returns table (n int, passed boolean, test text, detail text)
language plpgsql as $fn$
declare
  c_admin constant uuid := '00000000-0000-0000-0000-0000000000b1';   -- ordinary administrator
  c_con   constant uuid := '00000000-0000-0000-0000-0000000000b2';   -- contributor of the withdrawn-indicator submissions
  c_con2  constant uuid := '00000000-0000-0000-0000-0000000000b3';
  c_fill  constant uuid := '00000000-0000-0000-0000-0000000000b4';   -- owns the filler pending rows
  c_new   constant uuid := '00000000-0000-0000-0000-0000000000b5';   -- account younger than 24h
  c_old   constant uuid := '00000000-0000-0000-0000-0000000000b6';   -- account older than 24h
  c_scan  constant uuid := '00000000-0000-0000-0000-0000000000b7';
  c_cap   constant uuid := '00000000-0000-0000-0000-0000000000b8';
  c_x1    constant uuid := '00000000-0000-0000-0000-0000000000b9';
  c_x2    constant uuid := '00000000-0000-0000-0000-0000000000ba';
  s_wd    constant uuid := '00000000-0000-0000-0002-000000000001';
  s_wd2   constant uuid := '00000000-0000-0000-0002-000000000002';
  items10 constant text := $q$select public.submit_indicators((select jsonb_agg(jsonb_build_object('indicator_type','domain','value_norm','x'||chr(96+g)||'.example.org','claimed_verdict','suspicious')) from generate_series(1,10) g)) ->> 'accepted'$q$;
  ins     constant text := 'with i as (insert into public.scans (evidence_hash, summary) values (%L, ''{}'') returning 1) select count(*)::text from i';
  r jsonb := '[]'::jsonb;
  v text;
begin
  begin
    insert into auth.users (id, aud, role, email, created_at) values
      (c_admin, 'authenticated', 'authenticated', 'adm2@example.invalid', now()),
      (c_con,   'authenticated', 'authenticated', 'con@example.invalid', now()),
      (c_con2,  'authenticated', 'authenticated', 'con2@example.invalid', now()),
      (c_fill,  'authenticated', 'authenticated', 'fill@example.invalid', now()),
      (c_new,   'authenticated', 'authenticated', 'new@example.invalid', now()),
      (c_old,   'authenticated', 'authenticated', 'old@example.invalid', now() - interval '48 hours'),
      (c_scan,  'authenticated', 'authenticated', 'scan@example.invalid', now()),
      (c_cap,   'authenticated', 'authenticated', 'cap@example.invalid', now()),
      (c_x1,    'authenticated', 'authenticated', 'x1@example.invalid', now()),
      (c_x2,    'authenticated', 'authenticated', 'x2@example.invalid', now());

    -- A) withdrawn indicators are never silently re-verified
    insert into public.shared_indicators (indicator_type, value_norm, verdict, confidence, status, contributor_count, source, reviewed_at)
      values ('domain', 'wd.example.org', 'malicious', 0.50, 'withdrawn', 1, 'community', now());
    insert into public.indicator_submissions (id, contributor_id, indicator_type, value_norm, claimed_verdict) values
      (s_wd,  c_con,  'domain', 'wd.example.org', 'malicious'),
      (s_wd2, c_con2, 'domain', 'wd.example.org', 'malicious');
    r := pg_temp.add(r, '01 approving a submission for a withdrawn indicator is refused',
      pg_temp.run_as(c_admin, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_wd, 'approve', null)), 'err:P0001:withdrawn_indicator');
    select (select status from public.shared_indicators where value_norm = 'wd.example.org') || '/' ||
           (select status from public.indicator_submissions where id = s_wd) || '/' ||
           (select count(*) from public.audit_log where target = s_wd)::text into v;
    r := pg_temp.add(r, '02 the refusal changes nothing (still withdrawn, still pending, no audit row)', v, 'withdrawn/pending/0');
    r := pg_temp.add(r, '03 rejecting a submission for a withdrawn indicator is still allowed',
      pg_temp.run_as(c_admin, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_wd2, 'reject', 'e2e')), 'rejected');

    -- B) pending caps: accounts under 24h cannot push the global queue past 500
    insert into public.indicator_submissions (contributor_id, indicator_type, value_norm, claimed_verdict)
      select c_fill, 'domain', 'fill' || g || '.example.org', 'malicious' from generate_series(1, 495) g;
    r := pg_temp.add(r, '04 account younger than 24h is refused above 500 global pending (queue_full)',
      pg_temp.run_as(c_new, 'authenticated', 'aal1', false, items10), 'err:P0001:queue_full');
    r := pg_temp.add(r, '05 established account may still submit below the 1000 global cap',
      pg_temp.run_as(c_old, 'authenticated', 'aal1', false, items10), '10');

    -- C) scan retention
    insert into public.scans (user_id, evidence_hash, summary) values (c_scan, repeat('a', 64), '{}');
    insert into public.scans (user_id, evidence_hash, summary, expires_at) values (c_scan, repeat('b', 64), '{}', now() - interval '1 day');
    r := pg_temp.add(r, '06 owner no longer sees an expired scan',
      pg_temp.run_as(c_scan, 'authenticated', 'aal1', false, 'select count(*)::text from public.scans'), '1');
    r := pg_temp.add(r, '07 owner can store a new scan',
      pg_temp.run_as(c_scan, 'authenticated', 'aal1', false, format(ins, repeat('c', 64))), '1');
    select count(*)::text into v from public.scans where user_id = c_scan and expires_at < now();
    r := pg_temp.add(r, '08 that insert deleted the owner''s own expired scans', v, '0');
    insert into public.scans (user_id, evidence_hash, summary, expires_at) values (c_scan, repeat('d', 64), '{}', now() - interval '1 day');
    r := pg_temp.add(r, '09 re-scanning expired evidence is not blocked by the unique hash',
      pg_temp.run_as(c_scan, 'authenticated', 'aal1', false, format(ins, repeat('d', 64))), '1');
    insert into public.scans (user_id, evidence_hash, summary) select c_cap, md5(g::text) || md5(g::text), '{}' from generate_series(1, 499) g;
    insert into public.scans (user_id, evidence_hash, summary, expires_at) values (c_cap, repeat('e', 64), '{}', now() - interval '1 day');
    r := pg_temp.add(r, '10 the 500 cap counts only live scans (499 live + 1 expired still accepts one)',
      pg_temp.run_as(c_cap, 'authenticated', 'aal1', false, format(ins, repeat('f', 64))), '1');
    r := pg_temp.add(r, '11 the 500 cap is still enforced',
      pg_temp.run_as(c_cap, 'authenticated', 'aal1', false, format(ins, repeat('9', 64))), 'err:P0001:scan_limit');

    -- D) the purge function is closed to every API role
    r := pg_temp.add(r, '12 anon cannot run the purge', pg_temp.run_as(null, 'anon', 'aal1', false, 'select private.purge_expired_scans()::text'), 'err:42501:*');
    r := pg_temp.add(r, '13 authenticated cannot run the purge', pg_temp.run_as(c_scan, 'authenticated', 'aal1', false, 'select private.purge_expired_scans()::text'), 'err:42501:*');
    r := pg_temp.add(r, '14 service_role cannot run the purge', pg_temp.run_as(null, 'service_role', 'aal1', false, 'select private.purge_expired_scans()::text'), 'err:42501:*');

    -- E) the purge itself (privileged editor role; one expired row for each of three different users)
    insert into public.scans (user_id, evidence_hash, summary, expires_at) values
      (c_x1, repeat('1', 64), '{}', now() - interval '2 days'), (c_x2, repeat('2', 64), '{}', now() - interval '2 days'),
      (c_old, repeat('3', 64), '{}', now() - interval '2 days');
    select (private.purge_expired_scans() >= 3)::text into v;
    r := pg_temp.add(r, '15 purge deletes expired scans (at least the 3 seeded)', v, 'true');
    select count(*)::text into v from public.scans where expires_at < now();
    r := pg_temp.add(r, '16 no expired scans remain', v, '0');
    select count(*)::text into v from public.audit_log where action = 'purge_expired_scans' and at >= now();
    r := pg_temp.add(r, '17 the purge wrote exactly one audit heartbeat row', v, '1');

    raise exception 'test_rollback' using errcode = 'P0990';
  exception when sqlstate 'P0990' then
    null;
  end;

  return query
    select 0, jsonb_array_length(r) = 17 and not exists (select 1 from jsonb_array_elements(r) e where not (e ->> 'passed')::boolean),
           'SUMMARY', (select count(*) from jsonb_array_elements(r) e where (e ->> 'passed')::boolean)::text || ' of 17 passed (' || jsonb_array_length(r)::text || ' ran)'
    union all
    select (e ->> 'n')::int, (e ->> 'passed')::boolean, e ->> 'test', e ->> 'detail' from jsonb_array_elements(r) e
    order by 1;
exception when others then
  return query
    select 0, false, 'ABORTED: ' || sqlstate, sqlerrm
    union all
    select (e ->> 'n')::int, (e ->> 'passed')::boolean, e ->> 'test', e ->> 'detail' from jsonb_array_elements(r) e
    order by 1;
end $fn$;

select * from pg_temp.run_tests();
