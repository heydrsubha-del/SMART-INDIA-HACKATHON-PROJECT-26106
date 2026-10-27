-- Rollback for 20261028000001_scan_expiry_cleanup.sql. Needs a confirmed target project and a reviewed recovery plan.
do $$ begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    if exists (select 1 from cron.job where jobname = 'purge-expired-scans') then perform cron.unschedule('purge-expired-scans'); end if;
  end if;
end $$;
alter policy scans_owner_select on public.scans
  using (user_id = (select auth.uid()) and not (select private.is_anonymous()));
create or replace function private.scans_cap() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  perform pg_advisory_xact_lock(hashtext('scans:' || new.user_id::text));
  if (select count(*) from public.scans where user_id = new.user_id) >= 500 then
    raise exception 'scan_limit' using errcode = 'P0001';
  end if;
  return new;
end $$;
create or replace function private.purge_expired_scans() returns integer
language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
  delete from public.scans where expires_at < now();
  get diagnostics n = row_count;
  return n;
end $$;
drop index if exists public.scans_expires_at_idx;
-- ACLs unchanged by CREATE OR REPLACE (still no API-role EXECUTE). Existing audit_log 'purge_expired_scans' rows are kept.
