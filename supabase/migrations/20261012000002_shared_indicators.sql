-- Phase 1 / 2 of 3: verified shared threat intelligence. Sanitized indicators only; no email content, no personal data.
create table public.shared_indicators (
  id                uuid primary key default gen_random_uuid(),
  indicator_type    text not null check (indicator_type in ('url', 'domain', 'ip', 'hash')),
  value_norm        text not null check (char_length(value_norm) between 3 and 512 and value_norm !~ '[@?#[:space:]]'),
  verdict           text not null check (verdict in ('malicious', 'suspicious')),
  confidence        numeric(3, 2) not null default 0.50 check (confidence between 0 and 1),
  status            text not null default 'pending' check (status in ('pending', 'verified', 'withdrawn')),
  contributor_count integer not null default 0 check (contributor_count >= 0),
  source            text not null default 'community' check (source in ('community', 'analyst')),
  reviewed_by       uuid references auth.users (id) on delete set null,
  reviewed_at       timestamptz,
  first_seen        timestamptz not null default now(),
  last_seen         timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  unique (indicator_type, value_norm),
  check (status <> 'verified' or reviewed_at is not null)      -- nothing is public without a review
);

create index shared_indicators_verified_idx on public.shared_indicators (updated_at) where status = 'verified';

create trigger shared_indicators_updated_at before update on public.shared_indicators
  for each row execute function private.set_updated_at();

alter table public.shared_indicators enable row level security;
alter table public.shared_indicators force row level security;

-- Clients may only SELECT, and only these columns (reviewer identity and review time stay private).
-- All writes (promotion, withdrawal) come from trusted server-side tooling using the service role, never from a client.
revoke all on public.shared_indicators from public, anon, authenticated;
grant select (id, indicator_type, value_norm, verdict, confidence, status, contributor_count, last_seen, updated_at)
  on public.shared_indicators to anon, authenticated;

create policy shared_indicators_read_verified on public.shared_indicators
  for select to anon, authenticated using (status = 'verified');

create policy shared_indicators_admin_read on public.shared_indicators
  for select to authenticated using (private.is_admin());
