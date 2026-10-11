-- pgTAP: shared_indicators access rules. Run with: supabase test db
begin;
select plan(17);

insert into public.shared_indicators (id, indicator_type, value_norm, verdict, status, reviewed_at) values
  ('00000000-0000-0000-0000-0000000000a1', 'domain', 'verified.example.net', 'malicious', 'verified', now()),
  ('00000000-0000-0000-0000-0000000000a2', 'domain', 'pending.example.net', 'suspicious', 'pending', null),
  ('00000000-0000-0000-0000-0000000000a3', 'domain', 'withdrawn.example.net', 'malicious', 'withdrawn', now());

-- anonymous (no session)
set local role anon;
select is((select count(*)::int from public.shared_indicators), 1, 'anon sees only verified rows');
select lives_ok($$select value_norm, verdict from public.shared_indicators$$, 'anon can read public columns');
select throws_ok($$select reviewed_by from public.shared_indicators$$, '42501', null, 'anon cannot read reviewer identity');
select throws_ok($$insert into public.shared_indicators (indicator_type, value_norm, verdict) values ('domain', 'x.example.org', 'malicious')$$, '42501', null, 'anon cannot insert');
select throws_ok($$update public.shared_indicators set verdict = 'suspicious'$$, '42501', null, 'anon cannot update');
select throws_ok($$delete from public.shared_indicators$$, '42501', null, 'anon cannot delete');

-- ordinary signed-in user
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-0000000000b1","role":"authenticated","aal":"aal1"}', true);
select is((select count(*)::int from public.shared_indicators), 1, 'user sees only verified rows');
select throws_ok($$insert into public.shared_indicators (indicator_type, value_norm, verdict) values ('domain', 'x.example.org', 'malicious')$$, '42501', null, 'user cannot insert');

-- admin claims: only app_metadata + aal2 counts
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-0000000000b1","role":"authenticated","aal":"aal2","user_metadata":{"role":"admin"}}', true);
select is((select count(*)::int from public.shared_indicators), 1, 'user_metadata admin claim is ignored');
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-0000000000b1","role":"authenticated","aal":"aal1","app_metadata":{"role":"admin"}}', true);
select is((select count(*)::int from public.shared_indicators), 1, 'admin without MFA sees only verified rows');
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-0000000000b1","role":"authenticated","aal":"aal2","app_metadata":{"role":"admin"}}', true);
select is((select count(*)::int from public.shared_indicators), 3, 'admin with MFA sees all rows');
select throws_ok($$insert into public.shared_indicators (indicator_type, value_norm, verdict) values ('domain', 'x.example.org', 'malicious')$$, '42501', null, 'admin cannot write through the client API');

-- table constraints (checked as the table owner)
reset role;
select throws_ok($$insert into public.shared_indicators (indicator_type, value_norm, verdict) values ('domain', 'a@b.example.org', 'malicious')$$, '23514', null, 'rejects @');
select throws_ok($$insert into public.shared_indicators (indicator_type, value_norm, verdict) values ('url', 'http://x.example.org/a?t=1', 'malicious')$$, '23514', null, 'rejects query string');
select throws_ok($$insert into public.shared_indicators (indicator_type, value_norm, verdict) values ('url', 'http://x.example.org/a#f', 'malicious')$$, '23514', null, 'rejects fragment');
select throws_ok($$insert into public.shared_indicators (indicator_type, value_norm, verdict) values ('email', 'x.example.org', 'malicious')$$, '23514', null, 'rejects unknown type');
select throws_ok($$insert into public.shared_indicators (indicator_type, value_norm, verdict, status) values ('domain', 'y.example.org', 'malicious', 'verified')$$, '23514', null, 'verified requires a review');

select * from finish();
rollback;
