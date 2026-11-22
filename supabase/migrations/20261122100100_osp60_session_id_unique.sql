-- ============================================================================
-- OSP-60 (optional, needs team approval): one session_id -> at most one user_devices row
--
-- The OSP-58 schema indexes user_devices.session_id but does not make it unique.
-- bind_device_session() already clears duplicates before binding; this partial unique index
-- is a second safety net: a duplicate binding fails loudly at bind time instead of making
-- the OSP-61 guard answer 500 on every later request.
--
-- Safe for existing data: Supabase session ids are unique per auth session, and NULL
-- (unbound / logged out) rows are excluded by the WHERE clause.
--
-- Kept in its own migration so it can be dropped from the PR if OSP-58's owner disagrees.
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS user_devices_session_id_unique
  ON public.user_devices (session_id)
  WHERE session_id IS NOT NULL;
