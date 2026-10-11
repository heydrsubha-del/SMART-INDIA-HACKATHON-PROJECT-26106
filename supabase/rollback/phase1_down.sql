-- Manual rollback for Phase 1 (Supabase has no automatic down migrations). Run only after a pg_dump.
drop table if exists public.scans;
drop table if exists public.shared_indicators;
drop function if exists private.set_updated_at();
drop function if exists private.is_anonymous();
drop function if exists private.is_admin();
drop schema if exists private;
-- Default privileges changed in migration 1 are left as is (safer); restore manually only if you need the old defaults.
