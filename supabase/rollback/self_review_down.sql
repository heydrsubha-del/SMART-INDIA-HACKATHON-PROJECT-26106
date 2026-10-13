-- Manual rollback for 20261015000001_owner_self_review.sql. Run only after a pg_dump.
-- Restores the original review_submission (self-review blocked for everyone). Self-reviewed rows already published stay;
-- audit_log keeps its extra columns' data until dropped below.
create or replace function public.review_submission(p_id uuid, p_decision text, p_note text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid(); v_sub public.indicator_submissions%rowtype;
  v_host text; v_shared uuid; v_n int;
begin
  if v_uid is null or not private.is_admin() then raise exception 'forbidden' using errcode = '42501'; end if;
  if coalesce(p_decision, '') not in ('approve', 'reject') then raise exception 'invalid_decision' using errcode = 'P0001'; end if;
  if p_note is not null and char_length(p_note) > 200 then raise exception 'note_too_long' using errcode = 'P0001'; end if;

  select * into v_sub from public.indicator_submissions where id = p_id for update;
  if not found then raise exception 'not_found' using errcode = 'P0001'; end if;
  if v_sub.status <> 'pending' then raise exception 'already_reviewed' using errcode = 'P0001'; end if;
  if v_sub.contributor_id = v_uid then raise exception 'self_review' using errcode = 'P0001'; end if;   -- reviewers cannot approve their own submissions

  if p_decision = 'reject' then
    update public.indicator_submissions
       set status = 'rejected', reviewed_by = v_uid, reviewed_at = now(), review_note = p_note where id = p_id;
    insert into public.audit_log (actor, action, target) values (v_uid, 'reject', p_id);
    return jsonb_build_object('status', 'rejected');
  end if;

  if not private.valid_indicator(v_sub.indicator_type, v_sub.value_norm) then raise exception 'invalid_indicator' using errcode = 'P0001'; end if;
  v_host := case v_sub.indicator_type when 'domain' then v_sub.value_norm
                                      when 'url' then substring(v_sub.value_norm from '^https?://([^/]+)') end;
  if exists (select 1 from public.indicator_allowlist a
              where (a.indicator_type = 'domain' and v_host is not null and (v_host = a.value_norm or v_host like '%.' || a.value_norm))
                 or (a.indicator_type = 'ip' and v_sub.indicator_type = 'ip' and v_sub.value_norm = a.value_norm)) then
    raise exception 'allowlisted' using errcode = 'P0001';
  end if;

  select count(distinct contributor_id) into v_n from public.indicator_submissions
    where indicator_type = v_sub.indicator_type and value_norm = v_sub.value_norm;
  insert into public.shared_indicators (indicator_type, value_norm, verdict, confidence, status, contributor_count, source, reviewed_by, reviewed_at)
    values (v_sub.indicator_type, v_sub.value_norm, v_sub.claimed_verdict, 0.50, 'verified', v_n, 'community', v_uid, now())
    on conflict (indicator_type, value_norm) do update
      set status = 'verified', contributor_count = excluded.contributor_count,
          reviewed_by = excluded.reviewed_by, reviewed_at = excluded.reviewed_at, last_seen = now()
    returning id into v_shared;
  update public.indicator_submissions
     set status = 'approved', reviewed_by = v_uid, reviewed_at = now(), review_note = p_note, promoted_id = v_shared where id = p_id;
  insert into public.audit_log (actor, action, target) values (v_uid, 'approve', p_id);
  return jsonb_build_object('status', 'approved', 'shared_id', v_shared);
end $$;

revoke all on function public.review_submission(uuid, text, text) from public, anon;
grant execute on function public.review_submission(uuid, text, text) to authenticated;
drop function if exists private.is_platform_owner();
drop table if exists private.platform_owners;
alter table public.audit_log drop constraint if exists audit_log_self_reason_chk, drop constraint if exists audit_log_decision_chk;
alter table public.audit_log drop column if exists self_review, drop column if exists reason, drop column if exists decision;
-- Drop review_kind only after deciding what to do with self_reviewed rows (e.g. set status = 'withdrawn' first).
-- alter table public.shared_indicators drop column review_kind;
