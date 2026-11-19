-- ============================================================================
-- OSP-67: Scheduled 30-Day Data Retention Purge (`pg_cron`) & Audit Logging
-- Epic E10 — Authentication & Access Control (FR-B-06, NFR-SEC-06, AC-28)
--
-- Scope (OSP-67 ONLY):
--   - Add optional `metadata` JSONB summary column to `public.audit_logs`
--   - Create `public.purge_expired_records()` SECURITY DEFINER function
--     (deletes `rescuer_observations` first, then `victim_records` > 30 days)
--   - Write immutable `RETENTION_PURGE` summary entry into `public.audit_logs`
--   - Restrict execution to `pg_cron` / `service_role` (revoke from PUBLIC/anon/authenticated)
--   - Enable `pg_cron` and schedule daily `purge-expired-records-daily` (`0 3 * * *` UTC)
--   - Note: `audit_logs` immutability triggers belong to OSP-65; Android Room purge belongs to E8.
-- ============================================================================

-- 1. Backwards-compatible structured metadata column for purge deletion counts
ALTER TABLE public.audit_logs
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 2. Retention Purge Function (30-day clock from record `created_at`)
CREATE OR REPLACE FUNCTION public.purge_expired_records()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_cutoff TIMESTAMPTZ := now() - interval '30 days';
  v_observations_deleted INTEGER := 0;
  v_victims_deleted INTEGER := 0;
  v_total_deleted INTEGER := 0;
  v_summary JSONB;
  v_audit_log_id UUID;
BEGIN
  -- Delete observations before victim_records to stay compatible with future E8 FK constraints
  DELETE FROM public.rescuer_observations
   WHERE created_at < v_cutoff;
  GET DIAGNOSTICS v_observations_deleted = ROW_COUNT;

  DELETE FROM public.victim_records
   WHERE created_at < v_cutoff;
  GET DIAGNOSTICS v_victims_deleted = ROW_COUNT;

  v_total_deleted := v_observations_deleted + v_victims_deleted;

  v_summary := jsonb_build_object(
    'retention_days', 30,
    'cutoff_at', v_cutoff,
    'rescuer_observations_deleted', v_observations_deleted,
    'victim_records_deleted', v_victims_deleted,
    'total_deleted', v_total_deleted
  );

  INSERT INTO public.audit_logs (
    actor_user_id,
    actor_role,
    device_id,
    action_type,
    target_record_id,
    metadata
  )
  VALUES (
    NULL,
    NULL,
    NULL,
    'RETENTION_PURGE',
    NULL,
    v_summary
  )
  RETURNING id INTO v_audit_log_id;

  RETURN v_summary || jsonb_build_object('audit_log_id', v_audit_log_id);
END;
$$;

-- 3. Restrict direct RPC execution from unprivileged clients
REVOKE ALL ON FUNCTION public.purge_expired_records() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.purge_expired_records() FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.purge_expired_records() TO service_role;

-- 4. Enable pg_cron and idempotently schedule daily 03:00 UTC purge
CREATE EXTENSION IF NOT EXISTS pg_cron;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM cron.job
     WHERE jobname = 'purge-expired-records-daily'
  ) THEN
    PERFORM cron.unschedule('purge-expired-records-daily');
  END IF;

  PERFORM cron.schedule(
    'purge-expired-records-daily',
    '0 3 * * *',
    'SELECT public.purge_expired_records();'
  );
END
$$;
