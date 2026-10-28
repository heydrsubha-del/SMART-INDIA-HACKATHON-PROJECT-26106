-- READ-ONLY: one SELECT statement, no DDL/DML, nothing is created, changed or executed except catalog reads and
-- guarded dynamic SELECTs (query_to_xml) on optional objects. Safe on any project, including production.
-- Run as the postgres role in the SQL editor. PASS criteria: every schema row (1-18) and every scheduler row (21-24) must show
-- PASS, and summary rows 90 and 91 must show PASS. Summary row 92 (BEHAVIOUR) deliberately stays UNVERIFIED: this script cannot
-- establish behaviour, so it only clears after supabase/tests/005_followup_and_scan_expiry.sql passes on a separate TEST project.
--   checks 1-18   SCHEMA verification: did 20261028000001_scan_expiry_cleanup.sql take effect? (structure/pattern checks)
--   checks 21-24  SCHEDULER verification: is automated deletion actually running? (pg_cron job, last run, heartbeat)
-- A function existing does NOT mean cleanup is automated: read the "SCHEDULED CLEANUP" summary row separately.
-- Missing objects produce FAIL rows (never an abort). UNVERIFIED = could not be established reliably.
-- LIMITS: function-body checks are normalised-text pattern matches, not proof of behaviour. Behaviour is proven only by
-- supabase/tests/005_followup_and_scan_expiry.sql on a TEST project. Pattern literals below are unit-tested against the
-- migration text by test_verify_scan_expiry.py; the pg_policies.qual deparse format is assumed, not observed (see REVIEW.md).
with
pat(name, re) as (values
  ('policy_owner',   'user_id = (\( ?select )?auth\.uid\(\)'),
  ('policy_expiry',  'expires_at > now\(\)'),
  ('policy_notanon', 'not \( ?select private\.is_anonymous\(\)'),
  ('policy_or',      ' or '),
  ('cap_delete',     'delete from public\.scans where user_id = new\.user_id and expires_at < now\(\);'),
  ('purge_select',   'select id from public\.scans where expires_at < now\(\) order by expires_at limit 5000 for update skip locked'),
  ('purge_delete',   'delete from public\.scans s using doomed d where s\.id = d\.id;'),
  ('purge_audit',    'insert into public\.audit_log \(actor, action, reason\) values \(null, ''purge_expired_scans'', n::text\);')
),
sc    as (select to_regclass('public.scans') as oid),
rls   as (select c.relrowsecurity as en, c.relforcerowsecurity as fo from pg_class c where c.oid = (select oid from sc)),
pol   as (select p.permissive, p.cmd, p.roles, regexp_replace(lower(p.qual), '\s+', ' ', 'g') as qn
            from pg_policies p where p.schemaname = 'public' and p.tablename = 'scans' and p.policyname = 'scans_owner_select'),
nsel  as (select count(*) as n from pg_policies
           where schemaname = 'public' and tablename = 'scans' and permissive = 'PERMISSIVE' and cmd in ('SELECT', 'ALL')),
fcap  as (select p.oid, p.prosecdef, p.proconfig, p.prorettype, p.pronargs, regexp_replace(lower(p.prosrc), '\s+', ' ', 'g') as body
            from pg_proc p where p.oid = to_regprocedure('private.scans_cap()')::oid),
fpg   as (select p.oid, p.prosecdef, p.proconfig, p.prorettype, p.pronargs, regexp_replace(lower(p.prosrc), '\s+', ' ', 'g') as body
            from pg_proc p where p.oid = to_regprocedure('private.purge_expired_scans()')::oid),
trg   as (select t.tgtype, t.tgenabled, t.tgfoid from pg_trigger t
           where t.tgrelid = (select oid from sc) and t.tgname = 'scans_cap_trg' and not t.tgisinternal),
idx   as (select x.indisvalid, x.indisready, x.indnatts, (x.indpred is null) as full_idx, (x.indexprs is null) as plain_idx,
                 a.attname, nt.nspname as tns, t.relname as trel
            from pg_class i
            join pg_namespace ni on ni.oid = i.relnamespace
            join pg_index x on x.indexrelid = i.oid
            join pg_class t on t.oid = x.indrelid
            join pg_namespace nt on nt.oid = t.relnamespace
            left join pg_attribute a on a.attrelid = t.oid and a.attnum = x.indkey[0]
           where i.relname = 'scans_expires_at_idx' and ni.nspname = 'public'),
hist  as (select to_regclass('supabase_migrations.schema_migrations') is not null as present,
                 case when to_regclass('supabase_migrations.schema_migrations') is null then null
                      else ((xpath('/row/c/text()', query_to_xml(
                             $q$select count(*)::text as c from supabase_migrations.schema_migrations where version = '20261028000001'$q$,
                             false, true, '')))[1])::text end as c),
ext   as (select exists (select 1 from pg_extension where extname = 'pg_cron') as inst,
                 to_regclass('cron.job') is not null as has_job, to_regclass('cron.job_run_details') is not null as has_runs),
job   as (select case when to_regclass('cron.job') is null then null
                      else ((xpath('/row/j/text()', query_to_xml(
                             $q$select concat_ws('|', active::text, schedule, command) as j from cron.job where jobname = 'purge-expired-scans' order by jobid limit 1$q$,
                             false, true, '')))[1])::text end as j),
run   as (select case when to_regclass('cron.job_run_details') is null or to_regclass('cron.job') is null then null
                      else ((xpath('/row/r/text()', query_to_xml(
                             $q$select concat_ws('|', d.status, d.start_time::text) as r from cron.job_run_details d join cron.job j on j.jobid = d.jobid where j.jobname = 'purge-expired-scans' order by d.start_time desc limit 1$q$,
                             false, true, '')))[1])::text end as r),
hb    as (select case when to_regclass('public.audit_log') is null then null
                      else ((xpath('/row/m/text()', query_to_xml(
                             $q$select max(at)::text as m from public.audit_log where action = 'purge_expired_scans'$q$,
                             false, true, '')))[1])::text end as m),
checks(n, section, check_name, expected, actual, ok) as (
  select 1, 'schema', 'migration 20261028000001 recorded in schema_migrations', 'recorded',
         case when not (select present from hist) then 'MISSING: supabase_migrations.schema_migrations not found'
              when (select c from hist) is null then 'could not read migration history'
              when (select c from hist)::int = 0 then 'MISSING: version 20261028000001 is NOT recorded'
              else 'recorded' end,
         case when not (select present from hist) then false
              when (select c from hist) is null then null
              else (select c from hist)::int > 0 end
  union all select 2, 'schema', 'RLS enabled and forced on public.scans', 'enabled=true forced=true',
         coalesce((select 'enabled=' || en::text || ' forced=' || fo::text from rls), 'MISSING: table public.scans'),
         coalesce((select en and fo from rls), false)
  union all select 3, 'schema', 'policy scans_owner_select is permissive SELECT for authenticated only', 'PERMISSIVE/SELECT/{authenticated}',
         coalesce((select permissive || '/' || cmd || '/' || roles::text from pol), 'MISSING: policy scans_owner_select'),
         coalesce((select permissive = 'PERMISSIVE' and cmd = 'SELECT' and roles = '{authenticated}'::name[] from pol), false)
  union all select 4, 'schema', 'policy enforces ownership (user_id = auth.uid())', 'ownership predicate present',
         coalesce((select left(qn, 200) from pol), 'MISSING: policy scans_owner_select'),
         coalesce((select qn ~ (select re from pat where name = 'policy_owner') from pol), false)
  union all select 5, 'schema', 'policy hides expired rows (expires_at > now())', 'expiry predicate present',
         coalesce((select left(qn, 200) from pol), 'MISSING: policy scans_owner_select'),
         coalesce((select qn ~ (select re from pat where name = 'policy_expiry') from pol), false)
  union all select 6, 'schema', 'policy keeps the anonymous-session block and has no OR branch', 'not-anonymous present, no OR',
         coalesce((select 'anon-block=' || (qn ~ (select re from pat where name = 'policy_notanon'))::text ||
                          ' has-or=' || (qn ~ (select re from pat where name = 'policy_or'))::text from pol), 'MISSING: policy scans_owner_select'),
         coalesce((select qn ~ (select re from pat where name = 'policy_notanon') and qn !~ (select re from pat where name = 'policy_or') from pol), false)
  union all select 7, 'schema', 'exactly one permissive SELECT/ALL policy on public.scans (no widening)', '1',
         (select n::text from nsel), (select n = 1 from nsel)
  union all select 8, 'schema', 'scans_cap(): SECURITY DEFINER, search_path pinned empty, returns trigger',
         'secdef=true pinned=true trigger=true',
         coalesce((select 'secdef=' || prosecdef::text || ' pinned=' || coalesce((proconfig @> array['search_path=""'])::text, 'false') ||
                          ' trigger=' || (prorettype = 'trigger'::regtype)::text from fcap), 'MISSING: function private.scans_cap()'),
         coalesce((select prosecdef and coalesce(proconfig @> array['search_path=""'], false) and prorettype = 'trigger'::regtype from fcap), false)
  union all select 9, 'schema', 'scans_cap() deletes only the inserting user''s own expired rows (single DELETE)',
         'one DELETE ... where user_id = new.user_id and expires_at < now()',
         coalesce((select 'pattern=' || (body ~ (select re from pat where name = 'cap_delete'))::text ||
                          ' deletes=' || ((length(body) - length(replace(body, 'delete from', ''))) / length('delete from'))::text from fcap),
                  'MISSING: function private.scans_cap()'),
         coalesce((select body ~ (select re from pat where name = 'cap_delete')
                      and (length(body) - length(replace(body, 'delete from', ''))) / length('delete from') = 1 from fcap), false)
  union all select 10, 'schema', 'scans_cap() takes the per-user advisory lock before deleting', 'lock before delete',
         coalesce((select 'lock-pos=' || position('pg_advisory_xact_lock' in body)::text || ' delete-pos=' || position('delete from' in body)::text from fcap),
                  'MISSING: function private.scans_cap()'),
         coalesce((select position('pg_advisory_xact_lock' in body) > 0 and position('pg_advisory_xact_lock' in body) < position('delete from' in body) from fcap), false)
  union all select 11, 'schema', 'trigger scans_cap_trg: enabled BEFORE INSERT FOR EACH ROW calling scans_cap()', 'before/insert/row, state O or A (enabled for ordinary application inserts), right function',
         coalesce((select 'tgtype=' || tgtype::text || ' state=' || tgenabled::text ||
                          ' enabled-for-app-inserts=' || (tgenabled in ('O', 'A'))::text ||
                          ' before-insert-row=' || ((tgtype & 1) = 1 and (tgtype & 2) = 2 and (tgtype & 4) = 4 and (tgtype & 64) = 0)::text ||
                          ' calls-scans_cap=' || (tgfoid = (select oid from fcap))::text from trg),
                  'MISSING: trigger scans_cap_trg on public.scans'),
         coalesce((select (tgtype & 1) = 1 and (tgtype & 2) = 2 and (tgtype & 4) = 4 and (tgtype & 64) = 0
                      and tgenabled in ('O', 'A') and tgfoid = (select oid from fcap) from trg), false)
  union all select 12, 'schema', 'authenticated cannot set user_id or expires_at (column INSERT/UPDATE privileges)', 'false/false/false/false',
         case when (select oid from sc) is null then 'MISSING: table public.scans'
              else has_column_privilege('authenticated', (select oid from sc)::oid, 'user_id', 'INSERT')::text || '/' ||
                   has_column_privilege('authenticated', (select oid from sc)::oid, 'user_id', 'UPDATE')::text || '/' ||
                   has_column_privilege('authenticated', (select oid from sc)::oid, 'expires_at', 'INSERT')::text || '/' ||
                   has_column_privilege('authenticated', (select oid from sc)::oid, 'expires_at', 'UPDATE')::text end,
         case when (select oid from sc) is null then false
              else not (has_column_privilege('authenticated', (select oid from sc)::oid, 'user_id', 'INSERT')
                     or has_column_privilege('authenticated', (select oid from sc)::oid, 'user_id', 'UPDATE')
                     or has_column_privilege('authenticated', (select oid from sc)::oid, 'expires_at', 'INSERT')
                     or has_column_privilege('authenticated', (select oid from sc)::oid, 'expires_at', 'UPDATE')) end
  union all select 13, 'schema', 'index scans_expires_at_idx is a valid plain index on public.scans(expires_at)', 'public.scans(expires_at), valid',
         coalesce((select tns || '.' || trel || '(' || coalesce(attname::text, '?') || ') natts=' || indnatts::text || ' valid=' || (indisvalid and indisready)::text from idx),
                  'MISSING: index public.scans_expires_at_idx'),
         coalesce((select tns = 'public' and trel = 'scans' and attname = 'expires_at' and indnatts = 1
                      and indisvalid and indisready and full_idx and plain_idx from idx), false)
  union all select 14, 'schema', 'purge_expired_scans(): no args, returns integer, SECURITY DEFINER, search_path pinned empty',
         'args=0 integer secdef=true pinned=true',
         coalesce((select 'args=' || pronargs::text || ' integer=' || (prorettype = 'integer'::regtype)::text || ' secdef=' || prosecdef::text ||
                          ' pinned=' || coalesce((proconfig @> array['search_path=""'])::text, 'false') from fpg),
                  'MISSING: function private.purge_expired_scans()'),
         coalesce((select pronargs = 0 and prorettype = 'integer'::regtype and prosecdef and coalesce(proconfig @> array['search_path=""'], false) from fpg), false)
  union all select 15, 'schema', 'purge selects only expired rows, ordered, LIMIT 5000, FOR UPDATE SKIP LOCKED', 'pattern matches',
         coalesce((select 'pattern=' || (body ~ (select re from pat where name = 'purge_select'))::text from fpg), 'MISSING: function private.purge_expired_scans()'),
         coalesce((select body ~ (select re from pat where name = 'purge_select') from fpg), false)
  union all select 16, 'schema', 'purge deletes only from public.scans, only the locked batch (single DELETE)', 'one DELETE joined to the batch',
         coalesce((select 'pattern=' || (body ~ (select re from pat where name = 'purge_delete'))::text ||
                          ' deletes=' || ((length(body) - length(replace(body, 'delete from', ''))) / length('delete from'))::text from fpg),
                  'MISSING: function private.purge_expired_scans()'),
         coalesce((select body ~ (select re from pat where name = 'purge_delete')
                      and (length(body) - length(replace(body, 'delete from', ''))) / length('delete from') = 1 from fpg), false)
  union all select 17, 'schema', 'purge writes the audit_log heartbeat after the delete', 'heartbeat insert after delete',
         coalesce((select 'pattern=' || (body ~ (select re from pat where name = 'purge_audit'))::text ||
                          ' delete-pos=' || position('delete from' in body)::text || ' audit-pos=' || position('insert into public.audit_log' in body)::text from fpg),
                  'MISSING: function private.purge_expired_scans()'),
         coalesce((select body ~ (select re from pat where name = 'purge_audit')
                      and position('delete from' in body) > 0
                      and position('delete from' in body) < position('insert into public.audit_log' in body) from fpg), false)
  union all select 18, 'schema', 'purge EXECUTE is denied to anon / authenticated / service_role / PUBLIC', 'false/false/false/false',
         case when (select oid from fpg) is null then 'MISSING: function private.purge_expired_scans()'
              else coalesce(case when exists (select 1 from pg_roles where rolname = 'anon') then has_function_privilege('anon', (select oid from fpg), 'execute')::text end, 'no-role') || '/' ||
                   coalesce(case when exists (select 1 from pg_roles where rolname = 'authenticated') then has_function_privilege('authenticated', (select oid from fpg), 'execute')::text end, 'no-role') || '/' ||
                   coalesce(case when exists (select 1 from pg_roles where rolname = 'service_role') then has_function_privilege('service_role', (select oid from fpg), 'execute')::text end, 'no-role') || '/' ||
                   (exists (select 1 from pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                             where p.oid = (select oid from fpg) and a.grantee = 0 and a.privilege_type = 'EXECUTE'))::text end,
         case when (select oid from fpg) is null then false
              else not (coalesce(case when exists (select 1 from pg_roles where rolname = 'anon') then has_function_privilege('anon', (select oid from fpg), 'execute') end, false)
                     or coalesce(case when exists (select 1 from pg_roles where rolname = 'authenticated') then has_function_privilege('authenticated', (select oid from fpg), 'execute') end, false)
                     or coalesce(case when exists (select 1 from pg_roles where rolname = 'service_role') then has_function_privilege('service_role', (select oid from fpg), 'execute') end, false)
                     or exists (select 1 from pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                                 where p.oid = (select oid from fpg) and a.grantee = 0 and a.privilege_type = 'EXECUTE')) end
  -- ---------------------------------------------------------------- scheduler (separate from schema)
  union all select 21, 'scheduler', 'pg_cron extension installed', 'installed',
         case when (select inst from ext) then 'installed' else 'NOT INSTALLED: no scheduler exists' end, (select inst from ext)
  union all select 22, 'scheduler', 'job purge-expired-scans exists, is active, schedule ''17 3 * * *'', command purge_expired_scans()',
         'active=true | 17 3 * * * | select private.purge_expired_scans()',
         case when not (select has_job from ext) then 'NOT AVAILABLE: cron.job not found (pg_cron not installed)'
              when (select j from job) is null then 'MISSING: job purge-expired-scans not found'
              else (select j from job) end,
         case when not (select has_job from ext) then false
              when (select j from job) is null then false
              else split_part((select j from job), '|', 1) = 'true'
                   and split_part((select j from job), '|', 2) = '17 3 * * *'
                   and lower(btrim(split_part((select j from job), '|', 3), ' ;' || chr(10))) = 'select private.purge_expired_scans()' end
  union all select 23, 'scheduler', 'last cron run succeeded within 36 hours', 'succeeded, < 36h ago',
         case when not (select has_runs from ext) then 'NOT AVAILABLE: cron.job_run_details not found'
              when (select r from run) is null then 'NO RUN RECORDED (expected only if the job was created < 24h ago)'
              else (select r from run) end,
         case when not (select has_runs from ext) then false
              when (select r from run) is null then false
              else split_part((select r from run), '|', 1) = 'succeeded'
                   and split_part((select r from run), '|', 2)::timestamptz > now() - interval '36 hours' end
  union all select 24, 'scheduler', 'audit_log purge heartbeat written within 36 hours', 'heartbeat < 36h ago',
         case when (select m from hb) is null then 'NO HEARTBEAT ROW (purge has never run, or audit_log missing)' else (select m from hb) end,
         case when (select m from hb) is null then false else (select m from hb)::timestamptz > now() - interval '36 hours' end
)
select n, section, check_name, expected, actual,
       case when ok is null then 'UNVERIFIED' when ok then 'PASS' else 'FAIL' end as status
  from checks
union all
select 90, 'summary', 'SCHEMA VERIFICATION (checks 1-18)', 'all PASS',
       count(*) filter (where ok)::text || ' pass / ' || count(*) filter (where ok is false)::text || ' fail / ' || count(*) filter (where ok is null)::text || ' unverified',
       case when count(*) filter (where ok is distinct from true) = 0 then 'PASS'
            when count(*) filter (where ok is false) > 0 then 'FAIL' else 'UNVERIFIED' end
  from checks where section = 'schema'
union all
select 91, 'summary', 'SCHEDULED CLEANUP (checks 21-24): is automated deletion operational?', 'all PASS',
       case when count(*) filter (where ok is distinct from true) = 0 then 'operational (job active, ran recently, heartbeat fresh)'
            else 'NOT OPERATIONAL: expired scans are not deleted automatically (opportunistic per-user purge only)' end,
       case when count(*) filter (where ok is distinct from true) = 0 then 'PASS' else 'FAIL' end
  from checks where section = 'scheduler'
union all
select 92, 'summary', 'BEHAVIOUR (what the schema checks cannot prove)', 'tested on a TEST project',
       'not established by this script: run supabase/tests/005_followup_and_scan_expiry.sql on a TEST project', 'UNVERIFIED'
order by n;
