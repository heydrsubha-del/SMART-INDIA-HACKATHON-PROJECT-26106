-- Phase 1 / 1 of 3: helpers and safe defaults. No data, no API-exposed objects.
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to anon, authenticated;     -- needed so RLS policies can call the helpers; 'private' is not an API-exposed schema

-- Admin = role in app_metadata (users cannot edit it) AND a multi-factor session. user_metadata is never trusted.
create or replace function private.is_admin() returns boolean
language sql stable set search_path = '' as $$
  select coalesce((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)
     and coalesce(auth.jwt() ->> 'aal', '') = 'aal2';
$$;

-- Anonymous sign-in sessions are low-trust and never own private history.
create or replace function private.is_anonymous() returns boolean
language sql stable set search_path = '' as $$
  select coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false);
$$;

create or replace function private.set_updated_at() returns trigger
language plpgsql set search_path = '' as $$
begin new.updated_at := now(); return new; end $$;

revoke all on function private.is_admin(), private.is_anonymous() from public;
grant execute on function private.is_admin(), private.is_anonymous() to anon, authenticated;

-- New tables in public start with NO access for API roles; each migration grants exactly what it needs.
alter default privileges in schema public revoke all on tables from anon, authenticated;
