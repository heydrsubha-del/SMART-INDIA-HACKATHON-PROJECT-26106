-- Verification checks for 20261121211425_harden_rpc_facades_and_internal_rls.sql.
-- Run only after applying the migration, in the project being verified.
DO $verify$
DECLARE
  v_count integer;
  v_sig regprocedure;
BEGIN
  -- Public RPC facade functions must be invoker functions, never SECURITY DEFINER.
  FOREACH v_sig IN ARRAY ARRAY[
    'public.review_queue(integer)'::regprocedure,
    'public.review_submission(uuid,text,text)'::regprocedure,
    'public.submit_indicators(jsonb)'::regprocedure
  ] LOOP
    IF (SELECT prosecdef FROM pg_proc WHERE oid = v_sig) THEN
      RAISE EXCEPTION 'Public RPC % is still SECURITY DEFINER', v_sig;
    END IF;
    IF NOT has_function_privilege('authenticated', v_sig, 'EXECUTE') THEN
      RAISE EXCEPTION 'authenticated cannot execute public RPC %', v_sig;
    END IF;
    IF has_function_privilege('anon', v_sig, 'EXECUTE') THEN
      RAISE EXCEPTION 'anon can execute public RPC %', v_sig;
    END IF;
  END LOOP;

  -- Private implementations remain SECURITY DEFINER, with explicit role grants only.
  FOREACH v_sig IN ARRAY ARRAY[
    'private.review_queue(integer)'::regprocedure,
    'private.review_submission(uuid,text,text)'::regprocedure,
    'private.submit_indicators(jsonb)'::regprocedure
  ] LOOP
    IF NOT (SELECT prosecdef FROM pg_proc WHERE oid = v_sig) THEN
      RAISE EXCEPTION 'Private implementation % lost SECURITY DEFINER', v_sig;
    END IF;
    IF NOT has_function_privilege('authenticated', v_sig, 'EXECUTE') THEN
      RAISE EXCEPTION 'authenticated cannot execute private implementation %', v_sig;
    END IF;
    IF has_function_privilege('anon', v_sig, 'EXECUTE') THEN
      RAISE EXCEPTION 'anon can execute private implementation %', v_sig;
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM pg_proc p
      WHERE p.oid = v_sig AND coalesce(array_to_string(p.proconfig, ','), '') LIKE '%search_path=""%'
    ) THEN
      RAISE EXCEPTION 'Private implementation % lost empty search_path', v_sig;
    END IF;
  END LOOP;

  IF has_schema_privilege('anon', 'private', 'USAGE') THEN
    RAISE EXCEPTION 'anon still has USAGE on private schema';
  END IF;
  IF NOT has_schema_privilege('authenticated', 'private', 'USAGE') THEN
    RAISE EXCEPTION 'authenticated lacks USAGE on private schema';
  END IF;
  IF NOT has_schema_privilege('service_role', 'private', 'USAGE') THEN
    RAISE EXCEPTION 'service_role lacks USAGE on private schema';
  END IF;

  -- Each internal table needs a restrictive, false, all-commands API-deny policy.
  SELECT count(*) INTO v_count
  FROM pg_policy p
  JOIN pg_class c ON c.oid = p.polrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE (n.nspname, c.relname, p.polname) IN (
    ('private', 'platform_owners', 'platform_owners_deny_api'),
    ('public', 'audit_log', 'audit_log_deny_api'),
    ('public', 'contribution_log', 'contribution_log_deny_api'),
    ('public', 'indicator_allowlist', 'indicator_allowlist_deny_api')
  )
    AND NOT p.polpermissive
    AND p.polcmd = '*'
    AND pg_get_expr(p.polqual, p.polrelid) IN ('false', '(false)')
    AND pg_get_expr(p.polwithcheck, p.polrelid) IN ('false', '(false)');
  IF v_count <> 4 THEN
    RAISE EXCEPTION 'Expected 4 restrictive deny policies, found %', v_count;
  END IF;

  -- Explicitly ensure API roles still have no table-level access to these records.
  IF has_table_privilege('anon', 'private.platform_owners', 'SELECT')
     OR has_table_privilege('anon', 'private.platform_owners', 'INSERT')
     OR has_table_privilege('anon', 'private.platform_owners', 'UPDATE')
     OR has_table_privilege('anon', 'private.platform_owners', 'DELETE')
     OR has_table_privilege('authenticated', 'private.platform_owners', 'SELECT')
     OR has_table_privilege('authenticated', 'private.platform_owners', 'INSERT')
     OR has_table_privilege('authenticated', 'private.platform_owners', 'UPDATE')
     OR has_table_privilege('authenticated', 'private.platform_owners', 'DELETE')
     OR has_table_privilege('anon', 'public.audit_log', 'SELECT')
     OR has_table_privilege('anon', 'public.audit_log', 'INSERT')
     OR has_table_privilege('anon', 'public.audit_log', 'UPDATE')
     OR has_table_privilege('anon', 'public.audit_log', 'DELETE')
     OR has_table_privilege('authenticated', 'public.audit_log', 'SELECT')
     OR has_table_privilege('authenticated', 'public.audit_log', 'INSERT')
     OR has_table_privilege('authenticated', 'public.audit_log', 'UPDATE')
     OR has_table_privilege('authenticated', 'public.audit_log', 'DELETE')
     OR has_table_privilege('anon', 'public.contribution_log', 'SELECT')
     OR has_table_privilege('anon', 'public.contribution_log', 'INSERT')
     OR has_table_privilege('anon', 'public.contribution_log', 'UPDATE')
     OR has_table_privilege('anon', 'public.contribution_log', 'DELETE')
     OR has_table_privilege('authenticated', 'public.contribution_log', 'SELECT')
     OR has_table_privilege('authenticated', 'public.contribution_log', 'INSERT')
     OR has_table_privilege('authenticated', 'public.contribution_log', 'UPDATE')
     OR has_table_privilege('authenticated', 'public.contribution_log', 'DELETE')
     OR has_table_privilege('anon', 'public.indicator_allowlist', 'SELECT')
     OR has_table_privilege('anon', 'public.indicator_allowlist', 'INSERT')
     OR has_table_privilege('anon', 'public.indicator_allowlist', 'UPDATE')
     OR has_table_privilege('anon', 'public.indicator_allowlist', 'DELETE')
     OR has_table_privilege('authenticated', 'public.indicator_allowlist', 'SELECT')
     OR has_table_privilege('authenticated', 'public.indicator_allowlist', 'INSERT')
     OR has_table_privilege('authenticated', 'public.indicator_allowlist', 'UPDATE')
     OR has_table_privilege('authenticated', 'public.indicator_allowlist', 'DELETE') THEN
    RAISE EXCEPTION 'An API role has table privileges on an internal table';
  END IF;
END
$verify$;

SELECT 'security advisory hardening verification passed' AS result;
