-- Behavioural test for 20261015000001_owner_self_review.sql.  RUN IN A TEST/DISPOSABLE PROJECT ONLY, never production.
-- Works in the Supabase SQL Editor: no Docker, no pgTAP, no persistent writes.
--   * Everything below runs as the editor's privileged role (postgres). Direct audit_log / shared_indicators checks use that role,
--     so audit_log stays closed to authenticated/anon (no grant is added or needed).
--   * review_submission() is called through pg_temp.run_as(), which does SET LOCAL ROLE authenticated + realistic JWT claims
--     and always RESET ROLEs afterwards, so role switching can never get out of order.
--   * All synthetic data is created inside one plpgsql BEGIN..EXCEPTION block that ends in a deliberate RAISE, which ROLLS BACK
--     every row (users, owner entry, submissions, indicators, audit rows). The result table is built in memory so it survives.
--   * The three helper functions live in pg_temp and vanish when the session ends.
-- Expected: 31 rows with passed = true plus a SUMMARY row (n = 0) reading "31 of 31 passed".

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
  c_owner constant uuid := '00000000-0000-0000-0000-0000000000a1';   -- platform owner (listed in private.platform_owners)
  c_admin constant uuid := '00000000-0000-0000-0000-0000000000a2';   -- ordinary administrator
  c_con_c constant uuid := '00000000-0000-0000-0000-0000000000a3';   -- independent contributors
  c_con_x constant uuid := '00000000-0000-0000-0000-0000000000a4';
  s_ok  constant uuid := '00000000-0000-0000-0001-000000000001';     -- owner's own submissions
  s_rej constant uuid := '00000000-0000-0000-0001-000000000002';
  s_nr  constant uuid := '00000000-0000-0000-0001-000000000003';
  s_al  constant uuid := '00000000-0000-0000-0001-000000000004';
  s_ip  constant uuid := '00000000-0000-0000-0001-000000000005';
  s_dup constant uuid := '00000000-0000-0000-0001-000000000006';
  s_adm constant uuid := '00000000-0000-0000-0001-000000000007';     -- ordinary admin's own submission
  s_oth constant uuid := '00000000-0000-0000-0001-000000000008';     -- someone else's submission
  s_upx constant uuid := '00000000-0000-0000-0001-000000000009';
  s_upo constant uuid := '00000000-0000-0000-0001-000000000010';
  c_reason constant text := 'a long enough reason';
  r jsonb := '[]'::jsonb;
  v text;
begin
  begin   -- sub-transaction: everything inside is rolled back by the RAISE at its end
    insert into auth.users (id, aud, role, email) values
      (c_owner, 'authenticated', 'authenticated', 'owner@example.invalid'),
      (c_admin, 'authenticated', 'authenticated', 'admin@example.invalid'),
      (c_con_c, 'authenticated', 'authenticated', 'c@example.invalid'),
      (c_con_x, 'authenticated', 'authenticated', 'x@example.invalid');
    insert into private.platform_owners (user_id) values (c_owner);
    insert into public.indicator_submissions (id, contributor_id, indicator_type, value_norm, claimed_verdict) values
      (s_ok,  c_owner, 'domain', 'ownok.example.org',       'malicious'),
      (s_rej, c_owner, 'domain', 'ownrej.example.org',      'malicious'),
      (s_nr,  c_owner, 'domain', 'ownnoreason.example.org', 'malicious'),
      (s_al,  c_owner, 'domain', 'login.google.com',        'malicious'),
      (s_ip,  c_owner, 'ip',     '10.0.0.5',                'malicious'),
      (s_dup, c_owner, 'domain', 'dup.example.org',         'malicious'),
      (s_adm, c_admin, 'domain', 'admown.example.org',      'malicious'),
      (s_oth, c_con_c, 'domain', 'others.example.org',      'malicious'),
      (gen_random_uuid(), c_con_c, 'domain', 'dup.example.org', 'malicious'),
      (s_upx, c_con_x, 'domain', 'upx.example.org',         'malicious'),
      (s_upo, c_owner, 'domain', 'upx.example.org',         'malicious');
    insert into public.shared_indicators (indicator_type, value_norm, verdict, confidence, status, contributor_count, source, reviewed_by, reviewed_at)
      values ('domain', 'dup.example.org', 'malicious', 0.50, 'verified', 1, 'community', c_admin, now());

    -- ordinary administrator: restriction preserved
    r := pg_temp.add(r, '01 ordinary admin cannot self-review (even with a reason)',
      pg_temp.run_as(c_admin, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_adm, 'approve', c_reason)), 'err:P0001:self_review');
    r := pg_temp.add(r, '02 client-supplied owner flags in JWT metadata are ignored',
      pg_temp.run_as(c_admin, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_adm, 'approve', c_reason),
                     '{"is_platform_owner": true, "role_owner": true}', '{"role": "owner", "is_platform_owner": true}'), 'err:P0001:self_review');

    -- owner without MFA / without admin role
    r := pg_temp.add(r, '03 owner without MFA (aal1) is refused',
      pg_temp.run_as(c_owner, 'authenticated', 'aal1', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_ok, 'approve', c_reason)), 'err:42501:*');
    r := pg_temp.add(r, '04 owner without app_metadata admin role is refused',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', false, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_ok, 'approve', c_reason)), 'err:42501:*');

    -- owner: reason is mandatory
    r := pg_temp.add(r, '05 self-review with missing reason is refused',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_nr, 'approve', null)), 'err:P0001:reason_required');
    r := pg_temp.add(r, '06 self-review with empty reason is refused',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_nr, 'approve', '')), 'err:P0001:reason_required');
    r := pg_temp.add(r, '07 self-review with whitespace-only reason is refused',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_nr, 'approve', '   ')), 'err:P0001:reason_required');
    r := pg_temp.add(r, '08 self-review with a too-short reason is refused',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_nr, 'approve', 'too short')), 'err:P0001:reason_required');
    select count(*)::text into v from public.audit_log where target = s_nr;
    r := pg_temp.add(r, '09 refused self-reviews leave no audit row', v, '0');

    -- owner: authorized self-approve, labelling and audit trail
    r := pg_temp.add(r, '10 owner can self-approve with a reason',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_ok, 'approve', 'owner verified manually')), 'approved');
    select review_kind || '/' || confidence::text || '/' || contributor_count::text into v from public.shared_indicators where value_norm = 'ownok.example.org';
    r := pg_temp.add(r, '11 self-approved intel is labelled self_reviewed, confidence 0.25, zero independent contributors', v, 'self_reviewed/0.25/0');
    select action || '/' || decision || '/' || reason || '/' || self_review::text || '/' || actor::text into v from public.audit_log where target = s_ok;
    r := pg_temp.add(r, '12 audit row records action, decision, reason, self-review flag and actor', v, 'self_approve/approve/owner verified manually/true/' || c_owner::text);
    select (at is not null)::text into v from public.audit_log where target = s_ok;
    r := pg_temp.add(r, '13 audit row is timestamped', v, 'true');
    r := pg_temp.add(r, '14 self_reviewed label is publicly readable (anon)',
      pg_temp.run_as(null, 'anon', 'aal1', false, 'select review_kind from public.shared_indicators where value_norm = ''ownok.example.org'''), 'self_reviewed');

    -- owner: self-reject
    r := pg_temp.add(r, '15 owner can self-reject with a reason',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_rej, 'reject', 'owner rejects own entry')), 'rejected');
    select action || '/' || self_review::text into v from public.audit_log where target = s_rej;
    r := pg_temp.add(r, '16 self-reject is audited as self_reject / self_review = true', v, 'self_reject/true');
    select count(*)::text into v from public.shared_indicators where value_norm = 'ownrej.example.org';
    r := pg_temp.add(r, '17 self-rejected indicator is never published', v, '0');

    -- existing protections still enforced on the self-review path
    r := pg_temp.add(r, '18 allowlist still enforced on self-review',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_al, 'approve', c_reason)), 'err:P0001:allowlisted');
    r := pg_temp.add(r, '19 indicator validation still enforced on self-review',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_ip, 'approve', c_reason)), 'err:P0001:invalid_indicator');
    r := pg_temp.add(r, '20 already-reviewed submission is still blocked',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_ok, 'approve', c_reason)), 'err:P0001:already_reviewed');
    r := pg_temp.add(r, '21 invalid decision is still refused',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_nr, 'maybe', c_reason)), 'err:P0001:invalid_decision');

    -- never downgrade independent verification
    r := pg_temp.add(r, '22 self-approval of an already independently verified indicator succeeds',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_dup, 'approve', 'duplicate of verified intel')), 'approved');
    select review_kind || '/' || confidence::text || '/' || reviewed_by::text into v from public.shared_indicators where value_norm = 'dup.example.org';
    r := pg_temp.add(r, '23 independent verification is not downgraded or overwritten', v, 'independent/0.50/' || c_admin::text);

    -- owner reviewing someone else = ordinary review
    r := pg_temp.add(r, '24 owner reviewing another contributor is an ordinary review',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_oth, 'approve', null)), 'approved');
    select a.action || '/' || a.self_review::text || '/' || s.review_kind into v
      from public.audit_log a, public.shared_indicators s where a.target = s_oth and s.value_norm = 'others.example.org';
    r := pg_temp.add(r, '25 ordinary review is not flagged as self-review', v, 'approve/false/independent');

    -- independent review upgrades a self-reviewed indicator
    r := pg_temp.add(r, '26 owner self-approves upx.example.org',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_upo, 'approve', 'self check first')), 'approved');
    r := pg_temp.add(r, '27 independent admin approves the same indicator',
      pg_temp.run_as(c_admin, 'authenticated', 'aal2', true, format('select public.review_submission(%L::uuid,%L,%L) ->> ''status''', s_upx, 'approve', null)), 'approved');
    select review_kind || '/' || confidence::text into v from public.shared_indicators where value_norm = 'upx.example.org';
    r := pg_temp.add(r, '28 independent approval upgrades a self-reviewed indicator', v, 'independent/0.50');

    -- owner list and owner check are closed to clients
    r := pg_temp.add(r, '29 clients cannot read the owner list',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, 'select count(*)::text from private.platform_owners'), 'err:42501:*');
    r := pg_temp.add(r, '30 clients cannot add owners',
      pg_temp.run_as(c_admin, 'authenticated', 'aal2', true, format('with i as (insert into private.platform_owners (user_id) values (%L) returning 1) select count(*)::text from i', c_admin)), 'err:42501:*');
    r := pg_temp.add(r, '31 clients cannot call the owner check directly',
      pg_temp.run_as(c_owner, 'authenticated', 'aal2', true, 'select private.is_platform_owner()::text'), 'err:42501:*');

    raise exception 'test_rollback' using errcode = 'P0990';   -- discard all synthetic data
  exception when sqlstate 'P0990' then
    null;
  end;

  return query
    select 0, jsonb_array_length(r) = 31 and not exists (select 1 from jsonb_array_elements(r) e where not (e ->> 'passed')::boolean),
           'SUMMARY', (select count(*) from jsonb_array_elements(r) e where (e ->> 'passed')::boolean)::text || ' of 31 passed (' || jsonb_array_length(r)::text || ' ran)'
    union all
    select (e ->> 'n')::int, (e ->> 'passed')::boolean, e ->> 'test', e ->> 'detail' from jsonb_array_elements(r) e
    order by 1;
exception when others then   -- setup/unexpected failure: show what ran plus the error
  return query
    select 0, false, 'ABORTED: ' || sqlstate, sqlerrm
    union all
    select (e ->> 'n')::int, (e ->> 'passed')::boolean, e ->> 'test', e ->> 'detail' from jsonb_array_elements(r) e
    order by 1;
end $fn$;

select * from pg_temp.run_tests();
