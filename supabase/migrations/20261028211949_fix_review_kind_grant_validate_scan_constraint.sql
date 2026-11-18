-- Migration: Fix review_kind access and validate scans constraint
-- NOTE: Reconstructed from verified production state; this is not the recovered
-- original migration file.

-- Allow anon and authenticated clients to read the review classification.
GRANT SELECT (review_kind)
ON public.shared_indicators
TO anon, authenticated;

-- Validate the existing scans summary nested-keys constraint.
ALTER TABLE public.scans
VALIDATE CONSTRAINT scans_summary_nested_keys_chk;
