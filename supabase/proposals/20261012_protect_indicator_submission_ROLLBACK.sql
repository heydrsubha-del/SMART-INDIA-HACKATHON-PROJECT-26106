-- PROPOSED ROLLBACK - NOT APPLIED. Function text below is copied programmatically from the audit exports (query.csv, query__1_.csv).
-- CREATE OR REPLACE keeps owner and ACL, and the migration issues no GRANT, so nothing here touches permissions.
-- (valid_indicator's ACL is not in the exports; submit_indicators' ACL is {postgres=X/postgres,authenticated=X/postgres,service_role=X/postgres}.)
-- Run preflight_snapshot.sql before the migration and after this rollback; the md5/ACL columns must match.
begin;
CREATE OR REPLACE FUNCTION private.valid_indicator(p_type text, p_value text)
 RETURNS boolean
 LANGUAGE plpgsql
 IMMUTABLE
 SET search_path TO ''
AS $function$
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
end $function$;

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
end $function$;

-- remove the new helper only after valid_indicator no longer references it
drop function if exists private.valid_host_labels(text);
commit;
