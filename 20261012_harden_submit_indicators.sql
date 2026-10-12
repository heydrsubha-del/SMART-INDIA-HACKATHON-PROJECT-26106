-- PROPOSED - NOT APPLIED. Only ever for project algorithmistic-test (qozfyuiloitutpfthuwn). NOT executed on any PostgreSQL instance.
-- Objects: NEW private.valid_host_labels(text); REPLACED private.valid_indicator(text,text); REPLACED public.submit_indicators(jsonb).
-- Not touched: tables, indexes, RLS, grants (apart from REVOKE on the new helper), looks_like_token, valid_domain, is_public_ip,
-- review_queue, review_submission, scans. No IPv6-URL support here (deferred to a separate proposal).
begin;
-- A) NEW helper: applies the existing private.looks_like_token() to every label LEFT of the registrable domain, like
--    indicator_sanitizer._clean_host. Registrable label(s) are not checked (random/DGA domains stay valid). Applies to domain and URL hosts only.
--    Two-part-suffix list = copy of indicator_sanitizer._TWO_PART_SUFFIXES: keep both lists in sync.
--    private.looks_like_token() itself is NOT modified (URL path segments keep today's stricter rule).
create or replace function private.valid_host_labels(p_d text)
 returns boolean
 language plpgsql
 immutable
 set search_path to ''
as $function$
declare l text[]; n int; keep int; i int; lbl text;
begin
  if p_d is null then return false; end if;
  l := string_to_array(p_d, '.'); n := coalesce(array_length(l, 1), 0);
  if n < 2 then return false; end if;
  keep := case when (l[n-1] || '.' || l[n]) = any (array['co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.in','co.jp','com.br','com.cn','co.nz','co.za','com.mx','com.tr','com.sg','com.hk']) then 3 else 2 end;
  for i in 1 .. n - keep loop
    lbl := l[i];
    if private.looks_like_token(lbl) then
      -- R) READABLE-WORD EXCEPTION (separable block: delete this whole `if` to make labels strictly follow looks_like_token).
      -- looks_like_token() rejects EVERY non-wordlike label of 16+ chars; Python only rejects those with entropy >= 3.7.
      -- A flagged label is still allowed only if ALL hold: letters only, 16-24 chars, not hex-only (a-f), Shannon entropy < 3.7 bits/char
      -- (so SQL-accepted labels are a SUBSET of Python-accepted ones; the converse is NOT true and parity is not claimed), and at least 65 percent of its
      -- adjacent letter pairs are among 150 very common English bigrams (random strings hit ~15 percent of pairs by chance; English words/compounds 70-95).
      -- Digits, hyphens, UUIDs, base64/JWT-like, hex, numeric, keyboard-walk/random letters and 25+ char labels stay rejected. Non-English
      -- transliterated words may pass or fail by chance of their letter pairs; this is a heuristic, not a dictionary.
      if not (lbl ~ '^[a-z]+$' and lbl !~ '^[a-f]+$' and char_length(lbl) between 16 and 24
              and (select count(*) from generate_series(1, char_length(lbl) - 1) as k
                    where substr(lbl, k, 2) = any (array['th','he','in','er','an','re','on','at','en','nd','ti','es','or','te','of','ed','is','it','al','ar','st','to','nt','ng','se','ha','as','ou','io','le','ve','co','me','de','hi','ri','ro','ic','ne','ea','ra','ce','li','ch','ll','be','ma','si','om','ur','ca','el','ta','la','ns','di','fo','ho','pe','ec','pr','no','ct','us','ac','ot','il','tr','ly','nc','et','ut','ss','so','rs','un','lo','wa','ge','ie','wh','ee','wi','em','ad','ol','rt','po','we','na','ul','ni','ts','mo','ow','pa','im','mi','ai','sh','ir','su','id','os','iv','ia','am','fi','ci','vi','pl','ig','tu','ev','ld','ry','mp','fe','bl','ab','gh','ty','op','wo','sa','ay','ex','ke','fr','oo','av','ag','if','ap','gr','od','bo','sp','rd','do','uc','bu','ei','ov','by','rm','ep','tt','ew','ga'])) * 100 >= 65 * (char_length(lbl) - 1)
              and (select coalesce(-sum((g.c::float8 / t.n) * (ln(g.c::float8 / t.n) / ln(2::float8))), 0)
                     from (select count(*) as c from regexp_split_to_table(lbl, '') as x group by x) g
                     cross join (select char_length(lbl) as n) t) < 3.7) then
        return false;
      end if;
    end if;
  end loop;
  return true;
end $function$;
revoke all on function private.valid_host_labels(text) from public, anon, authenticated, service_role;   -- existing private helpers have ACL {postgres=X/postgres} only

-- B) valid_indicator(): exported definition with exactly two marked edits (same signature, language, IMMUTABLE, search_path; owner/ACL preserved by CREATE OR REPLACE).
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
  if p_type = 'domain' then return private.valid_domain(p_value) and private.valid_host_labels(p_value); end if;   -- CHANGED
  if p_type = 'url' then
    m := regexp_match(p_value, '^https?://([a-z0-9.-]+)((/[A-Za-z0-9._~-]*)*)$');   -- no port, userinfo, query, fragment or escapes
    if m is null then return false; end if;
    if not ((private.valid_domain(m[1]) and private.valid_host_labels(m[1]))                                    -- CHANGED
            or (m[1] ~ '^[0-9.]+$' and private.is_public_ip(m[1]))) then return false; end if;
    for seg in select t.s from unnest(string_to_array(m[2], '/')) as t(s) loop
      if seg <> '' and private.looks_like_token(seg) then return false; end if;
    end loop;
    return true;
  end if;
  return false;
end $function$;

-- C) submit_indicators(): exported definition + additions only (anon reject, global advisory lock, pending caps 100/user + 1000/global). Validation is inherited from B.
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
  c_pending_user constant int := 100; c_pending_global constant int := 1000;   -- NEW
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

commit;
