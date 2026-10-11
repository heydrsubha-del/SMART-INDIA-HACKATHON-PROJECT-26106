-- Phase 3: opt-in contributions. Quarantine first; promotion only by an authorized reviewer, server-side.
-- Clients get NO direct write access to any of these tables. All writes go through the SECURITY DEFINER functions
-- below, which re-validate everything and take identity/status from the database, never from the caller.

-- ---------------------------------------------------------------- tables
create table public.indicator_submissions (
  id              uuid primary key default gen_random_uuid(),
  contributor_id  uuid not null references auth.users (id) on delete cascade,
  indicator_type  text not null check (indicator_type in ('url', 'domain', 'ip', 'hash')),
  value_norm      text not null check (char_length(value_norm) between 3 and 512 and value_norm !~ '[@?#%[:space:]]'),
  claimed_verdict text not null check (claimed_verdict in ('malicious', 'suspicious')),
  status          text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  created_at      timestamptz not null default now(),
  reviewed_by     uuid references auth.users (id) on delete set null,
  reviewed_at     timestamptz,
  review_note     text check (char_length(review_note) <= 200),
  promoted_id     uuid references public.shared_indicators (id) on delete set null,
  unique (contributor_id, indicator_type, value_norm),
  check (status = 'pending' or reviewed_at is not null)
);
create index indicator_submissions_status_idx  on public.indicator_submissions (status, created_at);
create index indicator_submissions_contrib_idx on public.indicator_submissions (contributor_id, status, reviewed_at);
create index indicator_submissions_value_idx   on public.indicator_submissions (indicator_type, value_norm);

-- One row per submit call (counts every item, valid or not) so spam of invalid payloads is rate-limited too.
create table public.contribution_log (
  id             bigint generated always as identity primary key,
  contributor_id uuid not null,
  items          integer not null check (items >= 0),
  accepted       integer not null default 0,
  at             timestamptz not null default now()
);
create index contribution_log_contrib_idx on public.contribution_log (contributor_id, at);
create index contribution_log_at_idx      on public.contribution_log (at);

-- Indicators reviewers may never promote (extend with the service role in trusted tooling).
create table public.indicator_allowlist (
  indicator_type text not null check (indicator_type in ('domain', 'ip')),
  value_norm     text not null,
  reason         text,
  primary key (indicator_type, value_norm)
);
insert into public.indicator_allowlist (indicator_type, value_norm, reason) values
  ('domain', 'google.com', 'major provider (seed)'), ('domain', 'microsoft.com', 'major provider (seed)'),
  ('domain', 'apple.com', 'major provider (seed)'),  ('domain', 'amazon.com', 'major provider (seed)'),
  ('domain', 'github.com', 'major provider (seed)');

create table public.audit_log (
  id     bigint generated always as identity primary key,
  actor  uuid,
  action text not null,
  target uuid,
  at     timestamptz not null default now()
);

-- ---------------------------------------------------------------- RLS and grants (deny by default)
alter table public.indicator_submissions enable row level security;
alter table public.indicator_submissions force row level security;
alter table public.contribution_log      enable row level security;
alter table public.contribution_log      force row level security;
alter table public.indicator_allowlist   enable row level security;
alter table public.indicator_allowlist   force row level security;
alter table public.audit_log             enable row level security;
alter table public.audit_log             force row level security;

revoke all on public.indicator_submissions, public.contribution_log, public.indicator_allowlist, public.audit_log
  from public, anon, authenticated;

-- A contributor may read the status of their OWN submissions only. No client insert/update/delete exists.
grant select (id, indicator_type, value_norm, status, created_at) on public.indicator_submissions to authenticated;
create policy submissions_owner_read on public.indicator_submissions
  for select to authenticated using (contributor_id = auth.uid());

-- ---------------------------------------------------------------- strict validation (backstop behind the Python sanitizer)
create or replace function private.is_public_ip(p_ip text) returns boolean
language plpgsql immutable set search_path = '' as $$
declare v inet;
begin
  begin v := p_ip::inet; exception when others then return false; end;
  if masklen(v) <> (case family(v) when 4 then 32 else 128 end) then return false; end if;
  return not (v <<= any (array['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
    '203.0.113.0/24', '224.0.0.0/3', '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '2001:db8::/32',
    'fc00::/7', 'fe80::/10', 'ff00::/8']::inet[]));
end $$;

create or replace function private.looks_like_token(p_seg text) returns boolean
language plpgsql immutable set search_path = '' as $$
declare wordlike boolean; letters int; digits int;
begin
  if p_seg is null or p_seg = '' then return false; end if;
  if char_length(p_seg) > 64 or p_seg ~ '[@=%]' then return true; end if;
  if p_seg ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     or p_seg ~ '^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$' then return true; end if;
  if p_seg ~* '^[0-9a-f]{16,}$' or (p_seg ~ '^[0-9]+$' and char_length(p_seg) >= 8) then return true; end if;
  select coalesce(bool_and((t.p ~ '^[A-Za-z]+$' and char_length(t.p) <= 14) or (t.p ~ '^[0-9]+$' and char_length(t.p) <= 4)), true)
    into wordlike from unnest(regexp_split_to_array(p_seg, '[-_.]')) as t(p) where t.p <> '';
  if wordlike then return false; end if;
  letters := char_length(regexp_replace(p_seg, '[^A-Za-z]', '', 'g'));
  digits  := char_length(regexp_replace(p_seg, '[^0-9]', '', 'g'));
  return (char_length(p_seg) >= 12 and digits >= 3 and letters >= 3) or char_length(p_seg) >= 16;
end $$;

create or replace function private.valid_domain(p_d text) returns boolean
language sql immutable set search_path = '' as $$
  select p_d ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}|xn--[a-z0-9-]{1,59})$'
     and char_length(p_d) <= 253
     and p_d !~ '\.(local|localhost|internal|lan|home|corp|intranet|invalid|test|arpa|onion)$';
$$;

create or replace function private.valid_indicator(p_type text, p_value text) returns boolean
language plpgsql immutable set search_path = '' as $$
declare m text[]; seg text;
begin
  if p_value is null or char_length(p_value) not between 3 and 512 or p_value ~ '[@?#%[:space:]]' then return false; end if;
  if p_type = 'hash'   then return p_value ~ '^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$'; end if;
  if p_type = 'ip'     then return private.is_public_ip(p_value); end if;
  if p_type = 'domain' then return private.valid_domain(p_value); end if;
  if p_type = 'url' then
    m := regexp_match(p_value, '^https?://([a-z0-9.-]+)((/[A-Za-z0-9._~-]*)*)$');   -- no port, userinfo, query, fragment or escapes
    if m is null then return false; end if;
    if not (private.valid_domain(m[1]) or (m[1] ~ '^[0-9.]+$' and private.is_public_ip(m[1]))) then return false; end if;
    for seg in select t.s from unnest(string_to_array(m[2], '/')) as t(s) loop
      if seg <> '' and private.looks_like_token(seg) then return false; end if;
    end loop;
    return true;
  end if;
  return false;
end $$;

revoke all on function private.is_public_ip(text), private.looks_like_token(text),
  private.valid_domain(text), private.valid_indicator(text, text) from public, anon, authenticated;

-- ---------------------------------------------------------------- submit (quarantine only)
create or replace function public.submit_indicators(p_items jsonb) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_item jsonb; v_type text; v_value text; v_verdict text; v_log bigint;
  v_n int; v_accepted int := 0; v_dups int := 0; v_rejected int := 0;
  c_per_request constant int := 20;  c_per_hour constant int := 50;  c_per_day constant int := 200;
  c_global_hour constant int := 2000; c_reject_block constant int := 10;
begin
  if v_uid is null then raise exception 'auth_required' using errcode = '42501'; end if;
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
  if coalesce((select sum(items) from public.contribution_log where contributor_id = v_uid and at > now() - interval '1 hour'), 0) + v_n > c_per_hour
     or coalesce((select sum(items) from public.contribution_log where contributor_id = v_uid and at > now() - interval '1 day'), 0) + v_n > c_per_day
     or coalesce((select sum(items) from public.contribution_log where at > now() - interval '1 hour'), 0) + v_n > c_global_hour then
    raise exception 'rate_limited' using errcode = 'P0001';
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
end $$;

-- ---------------------------------------------------------------- review (admin + MFA only; promotion happens here)
create or replace function public.review_queue(p_limit int default 50)
returns table (id uuid, indicator_type text, value_norm text, claimed_verdict text, created_at timestamptz, distinct_contributors bigint)
language plpgsql security definer set search_path = '' as $$
begin
  if not private.is_admin() then raise exception 'forbidden' using errcode = '42501'; end if;
  return query
    select s.id, s.indicator_type, s.value_norm, s.claimed_verdict, s.created_at,
           (select count(distinct x.contributor_id) from public.indicator_submissions x
              where x.indicator_type = s.indicator_type and x.value_norm = s.value_norm)
      from public.indicator_submissions s
     where s.status = 'pending'
     order by s.created_at
     limit least(greatest(coalesce(p_limit, 50), 1), 200);              -- contributor identity is never returned
end $$;

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

-- Only signed-in sessions (including Supabase anonymous sign-ins) may call these; reviewers are checked inside.
revoke all on function public.submit_indicators(jsonb), public.review_queue(int), public.review_submission(uuid, text, text)
  from public, anon;
grant execute on function public.submit_indicators(jsonb), public.review_queue(int), public.review_submission(uuid, text, text)
  to authenticated;
