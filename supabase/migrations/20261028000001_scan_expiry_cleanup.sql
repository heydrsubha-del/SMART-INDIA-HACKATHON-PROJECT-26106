-- Scan retention (ADDITIVE; no applied migration is edited). Works WITHOUT a scheduler and WITHOUT pg_cron:
--  1) expired scans are invisible to their owner immediately (policy only narrows access);
--  2) a user's own expired scans are deleted whenever that user stores a new scan (also frees the 500-row cap and the unique-hash slot);
--  3) private.purge_expired_scans() is batch-limited, writes one audit_log heartbeat row per run, and is executable by NO API role;
--  4) a daily job is created ONLY IF the pg_cron extension is already installed (no-op otherwise).
-- Prerequisite: 20261027000001_followup_hardening.sql (defines scans_cap and purge_expired_scans). Not executed anywhere yet.

create index if not exists scans_expires_at_idx on public.scans (expires_at);

alter policy scans_owner_select on public.scans
  using (user_id = (select auth.uid()) and not (select private.is_anonymous()) and expires_at > now());

create or replace function private.scans_cap() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  perform pg_advisory_xact_lock(hashtext('scans:' || new.user_id::text));
  delete from public.scans where user_id = new.user_id and expires_at < now();   -- retention: runs before the unique/cap checks
  if (select count(*) from public.scans where user_id = new.user_id) >= 500 then
    raise exception 'scan_limit' using errcode = 'P0001';
  end if;
  return new;
end $$;
revoke all on function private.scans_cap() from public, anon, authenticated, service_role;

create or replace function private.purge_expired_scans() returns integer
language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
  with doomed as (
    select id from public.scans where expires_at < now() order by expires_at limit 5000 for update skip locked)
  delete from public.scans s using doomed d where s.id = d.id;
  get diagnostics n = row_count;
  insert into public.audit_log (actor, action, reason) values (null, 'purge_expired_scans', n::text);   -- heartbeat: reason = rows deleted
  return n;
end $$;
revoke all on function private.purge_expired_scans() from public, anon, authenticated, service_role;

-- Optional scheduler: only if pg_cron is ALREADY installed. Nested IFs so cron.job is never planned when the extension is absent.
do $cron$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    if not exists (select 1 from cron.job where jobname = 'purge-expired-scans') then
      perform cron.schedule('purge-expired-scans', '17 3 * * *', 'select private.purge_expired_scans()');
    end if;
  end if;
end $cron$;
