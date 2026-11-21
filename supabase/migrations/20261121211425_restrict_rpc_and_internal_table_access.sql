-- Algorithmistic production hardening.
-- Keep the existing public RPC names and their authorization behaviour, but move
-- SECURITY DEFINER implementations into the non-public `private` schema.
-- Add restrictive deny policies to internal tables so future permissive-policy
-- mistakes cannot accidentally expose them to anon/authenticated API roles.
-- Leaked-password protection is intentionally not changed (Free-plan limitation).

-- Fail closed if a target function is missing or a private implementation name
-- already exists. This prevents an accidental overwrite of an unrelated object.
DO $guard$
BEGIN
  IF to_regprocedure('public.review_queue(integer)') IS NULL
     OR to_regprocedure('public.review_submission(uuid,text,text)') IS NULL
     OR to_regprocedure('public.submit_indicators(jsonb)') IS NULL THEN
    RAISE EXCEPTION 'Expected public Algorithmistic RPC function is missing; aborting hardening migration';
  END IF;

  IF to_regprocedure('private.review_queue(integer)') IS NOT NULL
     OR to_regprocedure('private.review_submission(uuid,text,text)') IS NOT NULL
     OR to_regprocedure('private.submit_indicators(jsonb)') IS NOT NULL THEN
    RAISE EXCEPTION 'Private RPC implementation name already exists; inspect before applying hardening migration';
  END IF;
END
$guard$;

-- A private SECURITY DEFINER implementation is only callable through a role
-- with the explicit grants below. `anon` loses all access to the private schema.
REVOKE USAGE ON SCHEMA private FROM PUBLIC, anon;
GRANT USAGE ON SCHEMA private TO authenticated, service_role;

-- Move the exact production-verified implementations; ALTER FUNCTION preserves
-- their owner, body, security settings, defaults, and function identity.
ALTER FUNCTION public.review_queue(integer) SET SCHEMA private;
ALTER FUNCTION public.review_submission(uuid, text, text) SET SCHEMA private;
ALTER FUNCTION public.submit_indicators(jsonb) SET SCHEMA private;

-- Reassert the private implementation ACLs explicitly. The implementations
-- retain their existing SECURITY DEFINER + empty search_path protections and
-- enforce admin+AAL2 or authenticated/non-anonymous authorization internally.
REVOKE ALL ON FUNCTION private.review_queue(integer) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION private.review_submission(uuid, text, text) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION private.submit_indicators(jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.review_queue(integer) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.review_submission(uuid, text, text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.submit_indicators(jsonb) TO authenticated, service_role;

-- Public RPC facades preserve the exact endpoint names, parameter names,
-- defaults, result types, and return shapes consumed by the existing client.
-- They execute as invoker; privileged work remains inside the private routines.
CREATE OR REPLACE FUNCTION public.review_queue(p_limit integer DEFAULT 50)
RETURNS TABLE (
  id uuid,
  indicator_type text,
  value_norm text,
  claimed_verdict text,
  created_at timestamp with time zone,
  distinct_contributors bigint
)
LANGUAGE sql
SECURITY INVOKER
SET search_path TO ''
AS $wrapper$
  SELECT * FROM private.review_queue(p_limit);
$wrapper$;

CREATE OR REPLACE FUNCTION public.review_submission(
  p_id uuid,
  p_decision text,
  p_note text DEFAULT NULL::text
)
RETURNS jsonb
LANGUAGE sql
SECURITY INVOKER
SET search_path TO ''
AS $wrapper$
  SELECT private.review_submission(p_id, p_decision, p_note);
$wrapper$;

CREATE OR REPLACE FUNCTION public.submit_indicators(p_items jsonb)
RETURNS jsonb
LANGUAGE sql
SECURITY INVOKER
SET search_path TO ''
AS $wrapper$
  SELECT private.submit_indicators(p_items);
$wrapper$;

-- New SQL functions receive EXECUTE for PUBLIC by default; remove it explicitly.
REVOKE ALL ON FUNCTION public.review_queue(integer) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.review_submission(uuid, text, text) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.submit_indicators(jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.review_queue(integer) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.review_submission(uuid, text, text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.submit_indicators(jsonb) TO authenticated, service_role;

COMMENT ON FUNCTION public.review_queue(integer) IS
  'Public invoker facade; privileged reviewer query is implemented in private.review_queue.';
COMMENT ON FUNCTION public.review_submission(uuid, text, text) IS
  'Public invoker facade; admin/AAL2 authorization and review logic are implemented in private.review_submission.';
COMMENT ON FUNCTION public.submit_indicators(jsonb) IS
  'Public invoker facade; authenticated/non-anonymous checks and contribution limits are implemented in private.submit_indicators.';

-- These tables are internal implementation state. Their existing design is
-- deny-by-default: no anon/authenticated table grants and no permissive RLS
-- policies. Restrictive FALSE policies make that intent explicit and continue
-- denying API roles even if a permissive policy is accidentally added later.
REVOKE ALL ON TABLE private.platform_owners FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.audit_log FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.contribution_log FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.indicator_allowlist FROM PUBLIC, anon, authenticated;

DROP POLICY IF EXISTS platform_owners_deny_api ON private.platform_owners;
CREATE POLICY platform_owners_deny_api
  ON private.platform_owners
  AS RESTRICTIVE FOR ALL TO anon, authenticated
  USING (false) WITH CHECK (false);

DROP POLICY IF EXISTS audit_log_deny_api ON public.audit_log;
CREATE POLICY audit_log_deny_api
  ON public.audit_log
  AS RESTRICTIVE FOR ALL TO anon, authenticated
  USING (false) WITH CHECK (false);

DROP POLICY IF EXISTS contribution_log_deny_api ON public.contribution_log;
CREATE POLICY contribution_log_deny_api
  ON public.contribution_log
  AS RESTRICTIVE FOR ALL TO anon, authenticated
  USING (false) WITH CHECK (false);

DROP POLICY IF EXISTS indicator_allowlist_deny_api ON public.indicator_allowlist;
CREATE POLICY indicator_allowlist_deny_api
  ON public.indicator_allowlist
  AS RESTRICTIVE FOR ALL TO anon, authenticated
  USING (false) WITH CHECK (false);

COMMENT ON POLICY platform_owners_deny_api ON private.platform_owners IS
  'Restrictive deny rule: platform owner grants are server-side only.';
COMMENT ON POLICY audit_log_deny_api ON public.audit_log IS
  'Restrictive deny rule: audit records are internal and not accessible through user API roles.';
COMMENT ON POLICY contribution_log_deny_api ON public.contribution_log IS
  'Restrictive deny rule: rate-limit and contribution accounting are internal.';
COMMENT ON POLICY indicator_allowlist_deny_api ON public.indicator_allowlist IS
  'Restrictive deny rule: allowlist maintenance is trusted-tooling only.';

-- Preserve indexes currently reported as unused: they support FK maintenance
-- and the expiry-purge path; low-volume statistics are not a safe drop signal.
COMMENT ON INDEX public.indicator_submissions_promoted_id_idx IS
  'Retained for indicator_submissions.promoted_id foreign-key maintenance.';
COMMENT ON INDEX public.indicator_submissions_reviewed_by_idx IS
  'Retained for indicator_submissions.reviewed_by foreign-key maintenance.';
COMMENT ON INDEX public.shared_indicators_reviewed_by_idx IS
  'Retained for shared_indicators.reviewed_by foreign-key maintenance.';
COMMENT ON INDEX public.scans_expires_at_idx IS
  'Retained for private.purge_expired_scans expiry cleanup.';

-- Refresh PostgREST so the unchanged public RPC endpoints are visible immediately.
NOTIFY pgrst, 'reload schema';
