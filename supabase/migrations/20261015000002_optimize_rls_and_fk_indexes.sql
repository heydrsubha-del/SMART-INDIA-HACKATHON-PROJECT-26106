-- Safe performance hardening for Algorithmistic production.
-- Applied directly to the production database on 2026-10-14; reconcile this
-- migration version with Supabase CLI history after adding this file to main.

-- Cover foreign keys previously reported as unindexed by Supabase.
CREATE INDEX IF NOT EXISTS indicator_submissions_promoted_id_idx
  ON public.indicator_submissions (promoted_id);
CREATE INDEX IF NOT EXISTS indicator_submissions_reviewed_by_idx
  ON public.indicator_submissions (reviewed_by);
CREATE INDEX IF NOT EXISTS shared_indicators_reviewed_by_idx
  ON public.shared_indicators (reviewed_by);

-- Stable auth/helper calls are evaluated once per statement, not per row.
ALTER POLICY scans_owner_select ON public.scans
  USING ((user_id = (SELECT auth.uid())) AND (NOT (SELECT private.is_anonymous())));

ALTER POLICY scans_owner_insert ON public.scans
  WITH CHECK ((user_id = (SELECT auth.uid())) AND (NOT (SELECT private.is_anonymous())));

ALTER POLICY scans_owner_update ON public.scans
  USING ((user_id = (SELECT auth.uid())) AND (NOT (SELECT private.is_anonymous())))
  WITH CHECK ((user_id = (SELECT auth.uid())) AND (NOT (SELECT private.is_anonymous())));

ALTER POLICY scans_owner_delete ON public.scans
  USING ((user_id = (SELECT auth.uid())) AND (NOT (SELECT private.is_anonymous())));

ALTER POLICY submissions_owner_read ON public.indicator_submissions
  USING (contributor_id = (SELECT auth.uid()));

-- Keep the anonymous feed limited to verified records. Authenticated readers
-- use one equivalent combined policy: verified records for everyone signed in,
-- plus other statuses only for authorized admin/AAL2 sessions.
ALTER POLICY shared_indicators_read_verified ON public.shared_indicators TO anon;
DROP POLICY IF EXISTS shared_indicators_admin_read ON public.shared_indicators;
DROP POLICY IF EXISTS shared_indicators_authenticated_read ON public.shared_indicators;
CREATE POLICY shared_indicators_authenticated_read
  ON public.shared_indicators
  FOR SELECT
  TO authenticated
  USING ((status = 'verified'::text) OR (SELECT private.is_admin()));
