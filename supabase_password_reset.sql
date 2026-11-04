-- Run once in Supabase SQL Editor before deploying the password-recovery update.

CREATE TABLE IF NOT EXISTS public.password_reset_codes (
    user_id BIGINT PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    requested_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE public.password_reset_codes ENABLE ROW LEVEL SECURITY;
