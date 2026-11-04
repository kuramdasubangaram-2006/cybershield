-- Run once in the CyberShield Supabase SQL Editor before deploying this update.
-- Stores structured findings only; uploaded file contents and pasted log text are not stored.

ALTER TABLE public.scans
    ADD COLUMN IF NOT EXISTS analysis_details TEXT NOT NULL DEFAULT '{}';
