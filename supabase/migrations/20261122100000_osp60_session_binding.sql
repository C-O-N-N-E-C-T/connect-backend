-- ============================================================================
-- OSP-60: Session binding RPCs for POST /api/v1/auth/session and /auth/logout
-- Epic E10 — Authentication & Access Control (FR-R-15, FR-D-01, FR-B-06)
--
-- Scope (OSP-60 ONLY):
--   - public.bind_device_session(...)    revocation check + device upsert + LOGIN audit
--   - public.unbind_device_session(...)  clear session binding + LOGOUT audit
--   - public.record_login_rejected(...)  LOGIN_REJECTED audit for ACCOUNT_DISABLED logins
--   - EXECUTE only for service_role (the backend); never anon / authenticated
--
-- Why RPCs: supabase-js has no client-side transactions. Each function body runs in ONE
-- transaction, so "device bound but no audit row" (or the reverse) cannot happen.
--
-- Notes:
--   - Tables come from OSP-58; this migration does not change them.
--   - bind/unbind are SECURITY INVOKER: the caller is service_role, which already bypasses
--     RLS on public tables, so no definer rights are needed.
--   - record_login_rejected is SECURITY DEFINER because it reads auth.users, which
--     service_role cannot SELECT on Supabase (same pattern as OSP-67 purge_expired_records).
--   - audit_logs immutability triggers belong to OSP-65.
-- ============================================================================


-- 1. Bind the access token's session_id to the (user_id, device_id) row --------------------
--
-- Returns jsonb:
--   {"status": "BOUND", "authenticated_at": "<timestamptz>"}  on success
--   {"status": "DEVICE_REVOKED"}                               when the device is revoked
--
-- p_user_id and p_session_id MUST come from the verified JWT claims (sub, session_id),
-- never from the request body. The backend enforces that; this function trusts its caller.
CREATE OR REPLACE FUNCTION public.bind_device_session(
  p_user_id UUID,
  p_role public.app_role,
  p_device_id UUID,
  p_device_name TEXT,
  p_session_id UUID
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
  v_now TIMESTAMPTZ := now();
  v_is_revoked BOOLEAN;
  v_rows INTEGER := 0;
BEGIN
  -- 1a. Lock the existing device row (if any) so an admin revoking this device at the same
  --     moment cannot slip between this check and the upsert below.
  SELECT is_device_revoked
    INTO v_is_revoked
    FROM public.user_devices
   WHERE user_id = p_user_id
     AND device_id = p_device_id
     FOR UPDATE;

  -- 1b. Revoked device: write the rejected attempt and stop. The row is NOT modified.
  IF v_is_revoked IS TRUE THEN
    INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, metadata)
    VALUES (
      p_user_id,
      p_role,
      p_device_id,
      'LOGIN_REJECTED',
      jsonb_build_object('reason', 'DEVICE_REVOKED')
    );
    RETURN jsonb_build_object('status', 'DEVICE_REVOKED');
  END IF;

  -- 1c. One session -> at most one device row. If this session_id is still bound to another
  --     row (e.g. the same token was sent with a different device_id), clear it there first.
  --     Otherwise the OSP-61 guard's maybeSingle() would see two rows and answer 500.
  UPDATE public.user_devices
     SET session_id = NULL
   WHERE session_id = p_session_id
     AND NOT (user_id = p_user_id AND device_id = p_device_id);

  -- 1d. Upsert on (user_id, device_id). On re-login Supabase issues a NEW session_id, which
  --     replaces the old one, so tokens of the old session get SESSION_NOT_BOUND afterwards.
  --     IMPORTANT: is_device_revoked / device_revoked_at are never written here, so a revoked
  --     device can never "un-revoke" itself by logging in again. The WHERE clause also covers
  --     a row that was inserted and revoked concurrently after step 1a found nothing.
  INSERT INTO public.user_devices (user_id, device_id, device_name, session_id, last_login_at)
  VALUES (p_user_id, p_device_id, p_device_name, p_session_id, v_now)
  ON CONFLICT (user_id, device_id) DO UPDATE
     SET device_name = EXCLUDED.device_name,
         session_id = EXCLUDED.session_id,
         last_login_at = EXCLUDED.last_login_at
   WHERE public.user_devices.is_device_revoked = false;
  GET DIAGNOSTICS v_rows = ROW_COUNT;

  -- Nothing written: the conflicting row is revoked (concurrent revoke). Treat as revoked.
  IF v_rows = 0 THEN
    INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, metadata)
    VALUES (
      p_user_id,
      p_role,
      p_device_id,
      'LOGIN_REJECTED',
      jsonb_build_object('reason', 'DEVICE_REVOKED')
    );
    RETURN jsonb_build_object('status', 'DEVICE_REVOKED');
  END IF;

  -- 1e. LOGIN audit row in the same transaction as the binding.
  INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, metadata)
  VALUES (
    p_user_id,
    p_role,
    p_device_id,
    'LOGIN',
    jsonb_build_object('session_id', p_session_id)
  );

  -- authenticated_at = last_login_at; the backend derives the 72 h offline grant from it.
  RETURN jsonb_build_object('status', 'BOUND', 'authenticated_at', v_now);
END;
$$;


-- 2. Clear the binding of the current session (logout) -----------------------------------
--
-- Matches on BOTH user_id and session_id (values from req.auth, set by the OSP-61 guard).
-- The device row itself stays: device history and revocation state are kept.
CREATE OR REPLACE FUNCTION public.unbind_device_session(
  p_user_id UUID,
  p_role public.app_role,
  p_device_id UUID,
  p_session_id UUID
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public
AS $$
BEGIN
  UPDATE public.user_devices
     SET session_id = NULL
   WHERE user_id = p_user_id
     AND session_id = p_session_id;

  INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, metadata)
  VALUES (
    p_user_id,
    p_role,
    p_device_id,
    'LOGOUT',
    jsonb_build_object('session_id', p_session_id)
  );
END;
$$;


-- 3. Audit a login rejected with ACCOUNT_DISABLED -----------------------------------------
--
-- Only called for VERIFIED tokens (the user is known). 401 / 400 attempts are not audited,
-- so unauthenticated callers cannot flood audit_logs.
-- actor_user_id references auth.users: if the user was deleted after the token was issued,
-- the id is kept only in metadata so the insert cannot fail on the foreign key.
-- SECURITY DEFINER: service_role has no SELECT on auth.users in Supabase, so the EXISTS check
-- runs with the owner's rights. Safe because EXECUTE is limited to service_role (section 4)
-- and search_path is pinned.
CREATE OR REPLACE FUNCTION public.record_login_rejected(
  p_user_id UUID,
  p_role public.app_role,
  p_device_id UUID,
  p_reason TEXT
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, metadata)
  VALUES (
    CASE WHEN EXISTS (SELECT 1 FROM auth.users WHERE id = p_user_id) THEN p_user_id END,
    p_role,
    p_device_id,
    'LOGIN_REJECTED',
    jsonb_build_object('reason', p_reason, 'user_id', p_user_id)
  );
END;
$$;


-- 4. Privileges ---------------------------------------------------------------------------
-- CRITICAL: Supabase grants EXECUTE on new public functions to anon and authenticated by
-- default. Without these REVOKEs any signed-in user could call the RPCs through PostgREST
-- and bind or unbind arbitrary sessions. Only the backend (service_role) may execute them.
REVOKE ALL ON FUNCTION public.bind_device_session(UUID, public.app_role, UUID, TEXT, UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.bind_device_session(UUID, public.app_role, UUID, TEXT, UUID) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bind_device_session(UUID, public.app_role, UUID, TEXT, UUID) TO service_role;

REVOKE ALL ON FUNCTION public.unbind_device_session(UUID, public.app_role, UUID, UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.unbind_device_session(UUID, public.app_role, UUID, UUID) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.unbind_device_session(UUID, public.app_role, UUID, UUID) TO service_role;

REVOKE ALL ON FUNCTION public.record_login_rejected(UUID, public.app_role, UUID, TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.record_login_rejected(UUID, public.app_role, UUID, TEXT) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_login_rejected(UUID, public.app_role, UUID, TEXT) TO service_role;
