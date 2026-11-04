-- Run this once in the CyberShield Supabase SQL Editor.
-- Every five minutes, delete scan history older than 24 hours for User accounts.
-- Admin account scans are kept until an Admin clears them manually.

CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.schedule(
    'cybershield-user-scan-retention',
    '*/5 * * * *',
    $job$
        DELETE FROM public.scans AS scan
        USING public.users AS account
        WHERE account.id = scan.user_id
          AND account.role = 'user'
          AND scan.created_at < NOW() - INTERVAL '24 hours';
    $job$
);

-- Keep scheduler run history bounded as well.
SELECT cron.schedule(
    'cybershield-cron-history-cleanup',
    '0 0 * * *',
    $job$
        DELETE FROM cron.job_run_details
        WHERE end_time < NOW() - INTERVAL '7 days';
    $job$
);
