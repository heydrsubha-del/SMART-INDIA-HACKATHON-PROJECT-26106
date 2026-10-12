-- PROPOSAL ONLY - NOT IMPLEMENTED, NOT SCHEDULED. pg_cron is not installed; nothing here runs by itself.
-- Bounded purge: contribution_log rows older than 7 days (quota windows need only 1 day). Run manually or from an approved scheduler.
create or replace function private.purge_contribution_log(p_batch int default 1000)
 returns int language plpgsql security invoker set search_path to '' as $f$
declare n int;
begin
  with d as (select id from public.contribution_log where at < now() - interval '7 days'
             order by id limit least(greatest(coalesce(p_batch,1000),1),5000) for update skip locked)
  delete from public.contribution_log c using d where c.id = d.id;
  get diagnostics n = row_count; return n;
end $f$;
revoke all on function private.purge_contribution_log(int) from public, anon, authenticated;
