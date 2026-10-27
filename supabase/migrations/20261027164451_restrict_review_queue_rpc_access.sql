-- Keep review queue callable by authenticated reviewers; private.is_admin() enforces admin + MFA.
-- The reviewer client uses the authenticated user's JWT and deliberately refuses service-role credentials.
REVOKE EXECUTE ON FUNCTION public.review_queue(integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.review_queue(integer) TO authenticated, service_role;

-- Keep community submissions available to signed-in users, never anonymous callers.
REVOKE EXECUTE ON FUNCTION public.submit_indicators(jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.submit_indicators(jsonb) TO authenticated, service_role;

-- Review decisions have an internal admin + MFA check; no anonymous/public execution.
REVOKE EXECUTE ON FUNCTION public.review_submission(uuid, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.review_submission(uuid, text, text) TO authenticated, service_role;
