-- pgTAP: Phase 3 contributions. Run in the test project only. Everything rolls back at the end.
begin;
select plan(29);

insert into auth.users (id, aud, role, email) values
  ('00000000-0000-0000-0000-00000000000a', 'authenticated', 'authenticated', 'user-a@example.test'),
  ('00000000-0000-0000-0000-00000000000b', 'authenticated', 'authenticated', 'user-b@example.test'),
  ('00000000-0000-0000-0000-00000000000c', 'authenticated', 'authenticated', 'reviewer@example.test'),
  ('00000000-0000-0000-0000-00000000000d', 'authenticated', 'authenticated', 'user-d@example.test');
-- B already has one pending submission for an allowlisted provider (used by the allowlist test)
insert into public.indicator_submissions (contributor_id, indicator_type, value_norm, claimed_verdict)
  values ('00000000-0000-0000-0000-00000000000b', 'domain', 'login.google.com', 'malicious');
-- D has ten rejected submissions in the last 30 days (spam history)
insert into public.indicator_submissions (contributor_id, indicator_type, value_norm, claimed_verdict, status, reviewed_at)
  select '00000000-0000-0000-0000-00000000000d', 'domain', 'spam' || g || '.example.org', 'malicious', 'rejected', now() from generate_series(1, 10) g;

-- 1. no session at all
set local role anon;
select throws_ok($$select public.submit_indicators('[]'::jsonb)$$, '42501', null, 'anon without a session cannot submit');

-- user A (Supabase anonymous sign-in)
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000a","role":"authenticated","aal":"aal1","is_anonymous":true}', true);
select is((select public.submit_indicators($$[{"indicator_type":"domain","value_norm":"evil.example.net","claimed_verdict":"malicious","status":"verified","contributor_id":"00000000-0000-0000-0000-00000000000b"},{"indicator_type":"url","value_norm":"http://evil.example.net/login","claimed_verdict":"suspicious"},{"indicator_type":"url","value_norm":"http://evil.example.net/x?t=1","claimed_verdict":"suspicious"},{"indicator_type":"domain","value_norm":"someone@example.com","claimed_verdict":"malicious"},{"indicator_type":"ip","value_norm":"10.0.0.5","claimed_verdict":"malicious"},{"indicator_type":"url","value_norm":"http://evil.example.net/aB3xK9pQ2mZ7vL1nR8tY4wC6","claimed_verdict":"malicious"}]$$::jsonb)),
  '{"accepted":2,"duplicates":0,"rejected":4}'::jsonb, 'valid items accepted; email, query string, private IP and token path rejected');
reset role;
select is((select count(*)::int from public.indicator_submissions where contributor_id = '00000000-0000-0000-0000-00000000000a' and status = 'pending'), 2, 'accepted items are pending and owned by the caller');
select is((select count(*)::int from public.indicator_submissions where contributor_id = '00000000-0000-0000-0000-00000000000b' and value_norm = 'evil.example.net'), 0, 'client-supplied contributor_id and status are ignored');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000a","role":"authenticated","aal":"aal1","is_anonymous":true}', true);
select is((select public.submit_indicators('[{"indicator_type":"domain","value_norm":"evil.example.net","claimed_verdict":"malicious"}]'::jsonb)), '{"accepted":0,"duplicates":1,"rejected":0}'::jsonb, 'duplicate submission is not stored twice');
select throws_ok($$insert into public.indicator_submissions (contributor_id, indicator_type, value_norm, claimed_verdict) values ('00000000-0000-0000-0000-00000000000a', 'domain', 'direct.example.org', 'malicious')$$, '42501', null, 'direct insert is denied');
select throws_ok($$update public.indicator_submissions set status = 'approved'$$, '42501', null, 'contributors cannot change status');
select is((select count(*)::int from public.indicator_submissions), 2, 'A reads only own submissions');

-- user B
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000b","role":"authenticated","aal":"aal1","is_anonymous":true}', true);
select is((select count(*)::int from public.indicator_submissions), 1, 'B reads only own submissions');
select throws_ok($$select public.submit_indicators((select jsonb_agg(jsonb_build_object('indicator_type','domain','value_norm','d'||g||'.example.org','claimed_verdict','suspicious')) from generate_series(1,21) g))$$, 'P0001', 'too_many_items', 'more than 20 items per request is refused');
reset role;
insert into public.contribution_log (contributor_id, items) values ('00000000-0000-0000-0000-00000000000b', 50);
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000b","role":"authenticated","aal":"aal1","is_anonymous":true}', true);
select throws_ok($$select public.submit_indicators('[{"indicator_type":"domain","value_norm":"fresh.example.org","claimed_verdict":"suspicious"}]'::jsonb)$$, 'P0001', 'rate_limited', 'hourly limit is enforced');

-- user D (repeatedly rejected)
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000d","role":"authenticated","aal":"aal1","is_anonymous":true}', true);
select throws_ok($$select public.submit_indicators('[{"indicator_type":"domain","value_norm":"fresh.example.org","claimed_verdict":"suspicious"}]'::jsonb)$$, 'P0001', 'blocked', 'contributors with many rejections are blocked');

-- unauthorized review attempts
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000a","role":"authenticated","aal":"aal1","is_anonymous":true}', true);
select throws_ok($$select * from public.review_queue(10)$$, '42501', null, 'non-admin cannot read the review queue');
select throws_ok($$select public.review_submission(gen_random_uuid(), 'approve', null)$$, '42501', null, 'non-admin cannot approve');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000a","role":"authenticated","aal":"aal2","user_metadata":{"role":"admin"}}', true);
select throws_ok($$select * from public.review_queue(10)$$, '42501', null, 'user_metadata admin claim is ignored');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000c","role":"authenticated","aal":"aal1","app_metadata":{"role":"admin"}}', true);
select throws_ok($$select * from public.review_queue(10)$$, '42501', null, 'admin without MFA is refused');

-- reviewer (app_metadata admin + MFA)
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000c","role":"authenticated","aal":"aal2","app_metadata":{"role":"admin"}}', true);
select is((select count(*)::int from public.review_queue(50)), 3, 'reviewer sees the 3 pending submissions');
select ok(not exists (select 1 from jsonb_object_keys(to_jsonb((select q from public.review_queue(1) q limit 1))) k where k = 'contributor_id'), 'queue never exposes contributor identity');
select is((select public.review_submission((select id from public.review_queue(50) where value_norm = 'evil.example.net' limit 1), 'approve', 'looks right') ->> 'status'), 'approved', 'reviewer can approve');

-- verified-only retrieval
reset role;
set local role anon;
select is((select count(*)::int from public.shared_indicators where value_norm = 'evil.example.net'), 1, 'approved indicator is publicly readable');
select is((select count(*)::int from public.shared_indicators where value_norm = 'http://evil.example.net/login'), 0, 'pending indicator is not public');
reset role;
do $$ begin perform set_config('test.done_id', (select id::text from public.indicator_submissions where value_norm = 'evil.example.net' and contributor_id = '00000000-0000-0000-0000-00000000000a'), false); end $$;
select is((select status || '/' || source || '/' || reviewed_by::text from public.shared_indicators where value_norm = 'evil.example.net'), 'verified/community/00000000-0000-0000-0000-00000000000c', 'promotion recorded reviewer, source and status server-side');
select is((select status || '/' || (promoted_id is not null)::text from public.indicator_submissions where value_norm = 'evil.example.net' and contributor_id = '00000000-0000-0000-0000-00000000000a'), 'approved/true', 'submission linked to the promoted record');

reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000c","role":"authenticated","aal":"aal2","app_metadata":{"role":"admin"}}', true);
select is((select public.review_submission((select id from public.review_queue(50) where value_norm = 'http://evil.example.net/login' limit 1), 'reject', 'spam') ->> 'status'), 'rejected', 'reviewer can reject');
reset role;
select is((select count(*)::int from public.shared_indicators where value_norm = 'http://evil.example.net/login'), 0, 'rejected indicator never becomes verified');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-00000000000c","role":"authenticated","aal":"aal2","app_metadata":{"role":"admin"}}', true);
select throws_ok($$select public.review_submission(current_setting('test.done_id')::uuid, 'approve', null)$$, 'P0001', 'already_reviewed', 'a reviewed submission cannot be reviewed again');
select throws_ok($$select public.review_submission((select id from public.review_queue(50) where value_norm = 'login.google.com' limit 1), 'approve', null)$$, 'P0001', 'allowlisted', 'allowlisted providers cannot be promoted');

select is((select public.submit_indicators('[{"indicator_type":"domain","value_norm":"own.example.org","claimed_verdict":"suspicious"}]'::jsonb) ->> 'accepted'), '1', 'a reviewer can also contribute');
select throws_ok($$select public.review_submission((select id from public.review_queue(50) where value_norm = 'own.example.org' limit 1), 'approve', null)$$, 'P0001', 'self_review', 'a reviewer cannot approve their own submission');

select * from finish();
rollback;
