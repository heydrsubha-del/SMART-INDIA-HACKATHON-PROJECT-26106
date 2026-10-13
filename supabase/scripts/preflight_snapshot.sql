-- READ-ONLY snapshot queries. NOT RUN. Only for algorithmistic-test, after approval. Run BEFORE the migration, AFTER the migration, and AFTER a rollback.
-- 1) Attributes / owner / ACL / definition hash of the functions involved. After a rollback every row for the 3 original functions must equal the
--    BEFORE snapshot (owner, security_definer, volatility, config, acl, def_md5); private.valid_host_labels must be gone.
select n.nspname as schema, p.proname, pg_get_function_identity_arguments(p.oid) as args,
       pg_get_userbyid(p.proowner) as owner, p.prosecdef as security_definer, p.provolatile as volatility,
       p.proconfig as config, p.proacl::text as acl, md5(pg_get_functiondef(p.oid)) as def_md5
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where (n.nspname, p.proname) in (('public','submit_indicators'),('private','valid_indicator'),('private','valid_host_labels'),
                                 ('private','looks_like_token'),('private','valid_domain'),('private','is_public_ip'))
order by 1, 2;
-- 2) Index evidence (no index list was in the audit exports). Used only to decide whether the pending-count queries need an index.
select schemaname, tablename, indexname, indexdef from pg_indexes
where schemaname = 'public' and tablename in ('indicator_submissions','contribution_log') order by tablename, indexname;
-- 3) Table sizes for that decision.
select relname, reltuples::bigint as approx_rows from pg_class where oid in ('public.indicator_submissions'::regclass, 'public.contribution_log'::regclass);
