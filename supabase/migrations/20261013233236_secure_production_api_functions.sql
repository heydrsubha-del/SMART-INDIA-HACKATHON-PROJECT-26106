-- Production-only hardening for Algorithmistic.
-- This project is production: the E2E harness must abort here, never treat it as a test target.
-- Dedicated test projects must explicitly configure their own test marker separately.
create or replace function public.is_test_project()
returns boolean
language sql
stable
set search_path = pg_catalog
as $$ select false $$;

-- This SECURITY DEFINER function exists only as an event-trigger callback.
-- Preserve the event trigger itself; remove API-role EXECUTE grants only.
do $migration$
begin
  if to_regprocedure('public.rls_auto_enable()') is not null then
    execute 'revoke execute on function public.rls_auto_enable() from public, anon, authenticated, service_role';
  end if;
end
$migration$;
