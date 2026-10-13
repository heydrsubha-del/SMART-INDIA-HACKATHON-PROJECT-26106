-- Audited platform-owner self-review. ADDITIVE: no applied migration is edited. Not executed anywhere; review before deploying.
-- Ordinary admins keep the self_review block. Only a user listed in private.platform_owners (writable by no API role) who is
-- ALSO an admin on an aal2 session may review their own submission, and only with a reason. Self-reviewed intel is labelled
-- review_kind = 'self_reviewed', gets lower confidence, and never counts as independent verification.
-- After applying, add the owner by hand (SQL editor / postgres role), NOT in this file:
--   insert into private.platform_owners (user_id) values ('<owner auth.users id>');

-- ---------------------------------------------------------------- trusted owner list (server-side only)
create table if not exists private.platform_owners (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  granted_at timestamptz not null default now()
);
alter table private.platform_owners enable row level security;
alter table private.platform_owners force row level security;          -- no policies: deny by default
revoke all on private.platform_owners from public, anon, authenticated;

-- Owner = admin (app_metadata.role) + aal2 + listed here. Runs as definer so API roles need no table access; not callable by clients.
create or replace function private.is_platform_owner() returns boolean
language sql stable security definer set search_path = '' as $$
  select private.is_admin() and exists (select 1 from private.platform_owners o where o.user_id = auth.uid());
$$;
revoke all on function private.is_platform_owner() from public, anon, authenticated;

-- ---------------------------------------------------------------- audit trail columns
alter table public.audit_log
  add column if not exists decision    text,
  add column if not exists reason      text,
  add column if not exists self_review boolean not null default false;
alter table public.audit_log
  add constraint audit_log_decision_chk    check (decision is null or decision in ('approve', 'reject')),
  add constraint audit_log_self_reason_chk check (not self_review or (reason is not null and char_length(btrim(reason)) >= 10));

-- ---------------------------------------------------------------- label on published intel
alter table public.shared_indicators
  add column if not exists review_kind text not null default 'independent' check (review_kind in ('independent', 'self_reviewed'));
grant select (review_kind) on public.shared_indicators to anon, authenticated;   -- consumers can tell the two apart

-- ---------------------------------------------------------------- review_submission (same signature, grants unchanged)
create or replace function public.review_submission(p_id uuid, p_decision text, p_note text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid(); v_sub public.indicator_submissions%rowtype;
  v_host text; v_shared uuid; v_n int;
  v_self boolean := false; v_reason text; v_kind text; v_existing text;
  c_reason_min constant int := 10;
begin
  if v_uid is null or not private.is_admin() then raise exception 'forbidden' using errcode = '42501'; end if;
  if coalesce(p_decision, '') not in ('approve', 'reject') then raise exception 'invalid_decision' using errcode = 'P0001'; end if;
  if p_note is not null and char_length(p_note) > 200 then raise exception 'note_too_long' using errcode = 'P0001'; end if;

  select * into v_sub from public.indicator_submissions where id = p_id for update;
  if not found then raise exception 'not_found' using errcode = 'P0001'; end if;
  if v_sub.status <> 'pending' then raise exception 'already_reviewed' using errcode = 'P0001'; end if;

  if v_sub.contributor_id = v_uid then
    if not private.is_platform_owner() then raise exception 'self_review' using errcode = 'P0001'; end if;   -- ordinary admins: unchanged
    v_reason := btrim(coalesce(p_note, ''));
    if char_length(v_reason) < c_reason_min then raise exception 'reason_required' using errcode = 'P0001'; end if;
    v_self := true;
  end if;

  if p_decision = 'reject' then
    update public.indicator_submissions
       set status = 'rejected', reviewed_by = v_uid, reviewed_at = now(), review_note = p_note where id = p_id;
    insert into public.audit_log (actor, action, target, decision, reason, self_review)
      values (v_uid, case when v_self then 'self_reject' else 'reject' end, p_id, 'reject', case when v_self then v_reason else p_note end, v_self);
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

  v_kind := case when v_self then 'self_reviewed' else 'independent' end;
  -- A self-reviewer's own submission is not independent evidence, so it is excluded from the count.
  select count(distinct contributor_id) into v_n from public.indicator_submissions
    where indicator_type = v_sub.indicator_type and value_norm = v_sub.value_norm and (not v_self or contributor_id <> v_uid);

  if v_self then   -- never downgrade or overwrite an already independently verified indicator; just link the submission to it
    select id, review_kind into v_shared, v_existing from public.shared_indicators
      where indicator_type = v_sub.indicator_type and value_norm = v_sub.value_norm and status = 'verified' and review_kind = 'independent' for update;
  end if;
  if v_shared is null then
    insert into public.shared_indicators as t (indicator_type, value_norm, verdict, confidence, status, contributor_count, source, reviewed_by, reviewed_at, review_kind)
      values (v_sub.indicator_type, v_sub.value_norm, v_sub.claimed_verdict, case when v_self then 0.25 else 0.50 end, 'verified', v_n, 'community', v_uid, now(), v_kind)
      on conflict (indicator_type, value_norm) do update
        set status = 'verified', contributor_count = excluded.contributor_count, review_kind = excluded.review_kind,
            confidence = case when excluded.review_kind = 'self_reviewed' or t.review_kind = 'self_reviewed' then excluded.confidence else t.confidence end,
            reviewed_by = excluded.reviewed_by, reviewed_at = excluded.reviewed_at, last_seen = now()
      returning id into v_shared;
  end if;
  update public.indicator_submissions
     set status = 'approved', reviewed_by = v_uid, reviewed_at = now(), review_note = p_note, promoted_id = v_shared where id = p_id;
  insert into public.audit_log (actor, action, target, decision, reason, self_review)
    values (v_uid, case when v_self then 'self_approve' else 'approve' end, p_id, 'approve', case when v_self then v_reason else p_note end, v_self);
  return jsonb_build_object('status', 'approved', 'shared_id', v_shared);
end $$;

revoke all on function public.review_submission(uuid, text, text) from public, anon;
grant execute on function public.review_submission(uuid, text, text) to authenticated;
