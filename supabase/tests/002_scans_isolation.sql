-- pgTAP: users cannot access each other's private scans. Run with: supabase test db
begin;
select plan(16);

insert into auth.users (id, aud, role, email) values
  ('00000000-0000-0000-0000-00000000000a', 'authenticated', 'authenticated', 'user-a@example.test'),
  ('00000000-0000-0000-0000-00000000000b', 'authenticated', 'authenticated', 'user-b@example.test'),
  ('00000000-0000-0000-0000-00000000000c', 'authenticated', 'authenticated', 'admin-c@example.test');
insert into public.scans (id, user_id, evidence_hash, summary) values
  ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000000a', repeat('a', 64), '{"score": 10}'),
  ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-00000000000b', repeat('b', 64), '{"score": 90}');

-- anonymous (no session)
set local role anon;
select throws_ok($$select * from public.scans$$, '42501', null, 'anon has no access to scans');

-- user A
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000a","role":"authenticated","aal":"aal1"}', true);
select is((select count(*)::int from public.scans), 1, 'A sees only own scans');
select is((select count(*)::int from public.scans where id = '00000000-0000-0000-0000-0000000000b1'), 0, 'A cannot see B by id');
select lives_ok($$insert into public.scans (evidence_hash, summary) values (repeat('c', 64), '{"score": 5}')$$, 'A can insert own scan');
select throws_ok($$insert into public.scans (user_id, evidence_hash, summary) values ('00000000-0000-0000-0000-00000000000b', repeat('d', 64), '{}')$$, '42501', null, 'A cannot choose user_id (insert as B)');
select lives_ok($$update public.scans set summary = '{"hacked": true}' where id = '00000000-0000-0000-0000-0000000000b1'$$, 'A update on B row runs but matches nothing');
select throws_ok($$update public.scans set user_id = '00000000-0000-0000-0000-00000000000b' where id = '00000000-0000-0000-0000-0000000000a1'$$, '42501', null, 'A cannot reassign user_id');
select lives_ok($$delete from public.scans where id = '00000000-0000-0000-0000-0000000000b1'$$, 'A delete on B row runs but matches nothing');
select throws_ok($$insert into public.scans (evidence_hash, summary) values (repeat('e', 64), '{"body": "hello"}')$$, '23514', null, 'summary with email-content key is rejected');
select throws_ok($$insert into public.scans (evidence_hash, summary) values (repeat('f', 64), jsonb_build_object('note', repeat('x', 9000)))$$, '23514', null, 'oversized summary is rejected');

-- user B
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000b","role":"authenticated","aal":"aal1"}', true);
select is((select count(*)::int from public.scans), 1, 'B sees only own scans');

-- anonymous sign-in session (authenticated role, is_anonymous = true), same sub as A
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000a","role":"authenticated","aal":"aal1","is_anonymous":true}', true);
select is((select count(*)::int from public.scans), 0, 'anonymous sign-in session reads nothing');
select throws_ok($$insert into public.scans (evidence_hash, summary) values (repeat('9', 64), '{}')$$, '42501', null, 'anonymous sign-in session cannot insert');

-- admin (MFA) still has no access to private scans
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000c","role":"authenticated","aal":"aal2","app_metadata":{"role":"admin"}}', true);
select is((select count(*)::int from public.scans), 0, 'admin cannot read private scans');

-- owner-level checks of what the attempts above did
reset role;
select is((select summary ->> 'score' from public.scans where id = '00000000-0000-0000-0000-0000000000b1'), '90', 'B row unchanged and not deleted');
select columns_are('public', 'scans', array['id', 'user_id', 'evidence_hash', 'summary', 'created_at', 'expires_at'], 'scans stores no email-content columns');

select * from finish();
rollback;
