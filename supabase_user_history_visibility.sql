-- Run once in the CyberShield Supabase SQL Editor before deploying the matching app update.
-- User-cleared scans are hidden from that User's account but remain visible to Admins.

ALTER TABLE public.scans
    ADD COLUMN IF NOT EXISTS user_hidden_at TIMESTAMPTZ;
