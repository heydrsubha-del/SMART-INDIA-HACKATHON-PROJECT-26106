-- Phase 1 / 3 of 3: private per-user scan summaries. Summary only: no body, subject, addresses or report text.
create table public.scans (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null default auth.uid() references auth.users (id) on delete cascade,
  evidence_hash text not null check (evidence_hash ~ '^[0-9a-f]{64}$'),
  summary       jsonb not null default '{}'::jsonb
                check (jsonb_typeof(summary) = 'object'
                       and pg_column_size(summary) <= 8192
                       and not (summary ?| array['body', 'subject', 'text', 'full_text', 'from', 'to', 'raw', 'email', 'report'])),
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null default now() + interval '90 days',
  unique (user_id, evidence_hash)
);

create index scans_user_created_idx on public.scans (user_id, created_at desc);

alter table public.scans enable row level security;
alter table public.scans force row level security;

-- user_id is never client-settable: it defaults to auth.uid() on insert and cannot be updated.
revoke all on public.scans from public, anon, authenticated;
grant select on public.scans to authenticated;
grant insert (evidence_hash, summary) on public.scans to authenticated;
grant update (summary) on public.scans to authenticated;
grant delete on public.scans to authenticated;

create policy scans_owner_select on public.scans for select to authenticated
  using (user_id = auth.uid() and not private.is_anonymous());
create policy scans_owner_insert on public.scans for insert to authenticated
  with check (user_id = auth.uid() and not private.is_anonymous());
create policy scans_owner_update on public.scans for update to authenticated
  using (user_id = auth.uid() and not private.is_anonymous())
  with check (user_id = auth.uid() and not private.is_anonymous());
create policy scans_owner_delete on public.scans for delete to authenticated
  using (user_id = auth.uid() and not private.is_anonymous());
-- No admin policy on purpose: admins use aggregate views (later phase) or the service role, never raw private scans.
