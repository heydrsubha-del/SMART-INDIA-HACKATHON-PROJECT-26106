-- Follow-up hardening (additive; applied migrations are NOT edited). Review, then apply with the normal migration flow. NOT executed anywhere yet.
-- 1) review_submission(): refuses to re-verify a 'withdrawn' shared indicator (error 'withdrawn_indicator').
-- 2) submit_indicators(): accounts < 24h old cannot raise the global pending queue above 500 (stops sign-up bursts filling all 1000 slots).
-- 3) scans: per-user row cap (500), recursive forbidden-key check (NOT VALID: new/updated rows only; run VALIDATE after cleaning old rows),
--    and private.purge_expired_scans() to enforce expires_at (schedule it, see bottom).

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

  -- FOLLOW-UP: a withdrawn indicator is never silently re-verified (withdrawal needs an explicit trusted-tooling decision to reverse).
  if exists (select 1 from public.shared_indicators w
              where w.indicator_type = v_sub.indicator_type and w.value_norm = v_sub.value_norm and w.status = 'withdrawn') then
    raise exception 'withdrawn_indicator' using errcode = 'P0001';
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

CREATE OR REPLACE FUNCTION public.submit_indicators(p_items jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_uid uuid := auth.uid();
  v_item jsonb; v_type text; v_value text; v_verdict text; v_log bigint;
  v_n int; v_accepted int := 0; v_dups int := 0; v_rejected int := 0;
  c_per_request constant int := 20;  c_per_hour constant int := 50;  c_per_day constant int := 200;
  c_global_hour constant int := 2000; c_reject_block constant int := 10;
  c_pending_user constant int := 100; c_pending_global constant int := 1000;
  c_pending_global_new constant int := 500; c_new_account interval := interval '24 hours';   -- FOLLOW-UP
  v_created timestamptz;
begin
  -- CHANGED: anonymous Supabase sessions are refused with the same code/errcode as a missing session.
  if v_uid is null or private.is_anonymous() then raise exception 'auth_required' using errcode = '42501'; end if;
  -- LOCK ORDER (always): 1) per-contributor, 2) global. No other function takes either lock (review_submission only row-locks), so no deadlock cycle.
  perform pg_advisory_xact_lock(hashtext(v_uid::text));            -- serialise one contributor's calls
  if p_items is null or jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) < 1 then
    raise exception 'invalid_payload' using errcode = 'P0001';
  end if;
  v_n := jsonb_array_length(p_items);
  if v_n > c_per_request then raise exception 'too_many_items' using errcode = 'P0001'; end if;
  if (select count(*) from public.indicator_submissions
        where contributor_id = v_uid and status = 'rejected' and reviewed_at > now() - interval '30 days') >= c_reject_block then
    raise exception 'blocked' using errcode = 'P0001';
  end if;
  -- NEW: 2) global lock (two-int key form = separate key space from the per-user one-bigint locks). Held to end of transaction.
  --      Waiting for it counts toward statement_timeout (8s for authenticated): contention surfaces as a timeout error, not a hang.
  perform pg_advisory_xact_lock(7301, 1);
  if coalesce((select sum(items) from public.contribution_log where contributor_id = v_uid and at > now() - interval '1 hour'), 0) + v_n > c_per_hour
     or coalesce((select sum(items) from public.contribution_log where contributor_id = v_uid and at > now() - interval '1 day'), 0) + v_n > c_per_day
     or coalesce((select sum(items) from public.contribution_log where at > now() - interval '1 hour'), 0) + v_n > c_global_hour then
    raise exception 'rate_limited' using errcode = 'P0001';
  end if;
  -- NEW: pending caps. CONSERVATIVE BY DESIGN: v_n is every item in the request, including duplicates (ON CONFLICT DO NOTHING)
  -- and items that will later be rejected as invalid, so e.g. 95 pending + a 10-item request is queue_full even if all 10 are duplicates.
  -- The raise rolls back the whole call (no contribution_log row, no submissions). Capacity is freed only when review_submission moves a row out of 'pending'
  -- (no withdrawal function exists in the exports).
  if (select count(*) from public.indicator_submissions where contributor_id = v_uid and status = 'pending') + v_n > c_pending_user
     or (select count(*) from public.indicator_submissions where status = 'pending') + v_n > c_pending_global then
    raise exception 'queue_full' using errcode = 'P0001';
  end if;
  -- FOLLOW-UP: accounts younger than 24h cannot push the GLOBAL pending queue past 500, so a burst of fresh sign-ups cannot
  -- fill all 1000 slots and lock out established contributors. Established accounts keep the full 1000.
  select u.created_at into v_created from auth.users u where u.id = v_uid;
  if coalesce(v_created, now()) > now() - c_new_account
     and (select count(*) from public.indicator_submissions where status = 'pending') + v_n > c_pending_global_new then
    raise exception 'queue_full' using errcode = 'P0001';
  end if;
  insert into public.contribution_log (contributor_id, items) values (v_uid, v_n) returning id into v_log;

  for v_item in select * from jsonb_array_elements(p_items) loop
    -- Only these three fields are ever read. Any client-supplied status, identity or verification claim is ignored.
    if jsonb_typeof(v_item) <> 'object' then v_rejected := v_rejected + 1; continue; end if;
    v_type := v_item ->> 'indicator_type'; v_value := v_item ->> 'value_norm'; v_verdict := v_item ->> 'claimed_verdict';
    if coalesce(v_type, '') not in ('url', 'domain', 'ip', 'hash') or coalesce(v_verdict, '') not in ('malicious', 'suspicious')
       or not private.valid_indicator(v_type, v_value) then
      v_rejected := v_rejected + 1; continue;
    end if;
    insert into public.indicator_submissions (contributor_id, indicator_type, value_norm, claimed_verdict)
      values (v_uid, v_type, v_value, v_verdict)
      on conflict (contributor_id, indicator_type, value_norm) do nothing;
    if found then v_accepted := v_accepted + 1; else v_dups := v_dups + 1; end if;
  end loop;

  update public.contribution_log set accepted = v_accepted where id = v_log;
  return jsonb_build_object('accepted', v_accepted, 'duplicates', v_dups, 'rejected', v_rejected);
end $function$;

-- ---------------------------------------------------------------- scans: recursive PII-key check
create or replace function private.json_has_forbidden_keys(j jsonb) returns boolean
language plpgsql immutable set search_path = '' as $$
declare k text; v jsonb;
begin
  if jsonb_typeof(j) = 'object' then
    for k, v in select * from jsonb_each(j) loop
      if lower(k) in ('body','subject','text','full_text','from','to','raw','email','report','html','content','message','sender','recipient','address','phone')
         or private.json_has_forbidden_keys(v) then return true; end if;
    end loop;
  elsif jsonb_typeof(j) = 'array' then
    for v in select * from jsonb_array_elements(j) loop
      if private.json_has_forbidden_keys(v) then return true; end if;
    end loop;
  end if;
  return false;
end $$;
revoke all on function private.json_has_forbidden_keys(jsonb) from public, anon, authenticated;
grant execute on function private.json_has_forbidden_keys(jsonb) to authenticated;   -- evaluated in the caller's context by the CHECK constraint

alter table public.scans drop constraint if exists scans_summary_nested_keys_chk;
alter table public.scans add constraint scans_summary_nested_keys_chk
  check (not private.json_has_forbidden_keys(summary)) not valid;
-- After confirming no legacy rows violate it:  alter table public.scans validate constraint scans_summary_nested_keys_chk;

-- ---------------------------------------------------------------- scans: per-user cap
create or replace function private.scans_cap() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  perform pg_advisory_xact_lock(hashtext('scans:' || new.user_id::text));
  if (select count(*) from public.scans where user_id = new.user_id) >= 500 then
    raise exception 'scan_limit' using errcode = 'P0001';
  end if;
  return new;
end $$;
revoke all on function private.scans_cap() from public, anon, authenticated;
drop trigger if exists scans_cap_trg on public.scans;
create trigger scans_cap_trg before insert on public.scans for each row execute function private.scans_cap();

-- ---------------------------------------------------------------- scans: enforce expires_at
create or replace function private.purge_expired_scans() returns integer
language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
  delete from public.scans where expires_at < now();
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function private.purge_expired_scans() from public, anon, authenticated;
-- Schedule daily (requires the pg_cron extension, enable it in Dashboard > Database > Extensions, then run ONCE):
--   select cron.schedule('purge-expired-scans', '17 3 * * *', $$select private.purge_expired_scans()$$);

revoke all on function public.review_submission(uuid, text, text) from public, anon;
grant execute on function public.review_submission(uuid, text, text) to authenticated;
revoke all on function public.submit_indicators(jsonb) from public, anon;
grant execute on function public.submit_indicators(jsonb) to authenticated;
