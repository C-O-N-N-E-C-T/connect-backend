-- =========================================================================================
-- OSP-66: Administrator API database functions (FR-B-06, NFR-SEC-06, AC: device/global revoke)
-- =========================================================================================
-- Every state change and its audit_logs row happen in ONE function call (one transaction),
-- the same pattern as OSP-60 bind_device_session and OSP-65 sync_observation_audited.
-- If the audit INSERT fails, the state change is rolled back too.
--
-- Session revocation deletes rows from auth.sessions, which service_role cannot touch directly.
-- These functions are SECURITY DEFINER (owned by the migration owner) with a pinned
-- search_path, and EXECUTE is granted to service_role only.
--
-- Deliberate: admin_revoke_device keeps user_devices.session_id. The OSP-61 guard looks a
-- device up BY session_id; clearing it would make the next call answer SESSION_NOT_BOUND
-- instead of the required DEVICE_REVOKED.
-- =========================================================================================


-- 1. Delete one auth session (helper, called by the functions below) -----------------------
CREATE OR REPLACE FUNCTION public.admin_revoke_session(p_session_id UUID)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_session_id IS NULL THEN
    RETURN;
  END IF;
  DELETE FROM auth.sessions WHERE id = p_session_id;
END;
$$;


-- 2. Create the profile of an account that was just created in Auth -----------------------
CREATE OR REPLACE FUNCTION public.admin_create_user_profile(
  p_actor_user_id UUID,
  p_actor_role public.app_role,
  p_actor_device_id UUID,
  p_user_id UUID,
  p_role public.app_role,
  p_full_name TEXT
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  INSERT INTO public.user_profiles (id, full_name, role, is_active)
  VALUES (p_user_id, p_full_name, p_role, true);

  INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, target_record_id, metadata)
  VALUES (
    p_actor_user_id,
    p_actor_role,
    p_actor_device_id,
    'USER_CREATED',
    p_user_id,
    jsonb_build_object('role', p_role)
  );

  RETURN jsonb_build_object('status', 'CREATED');
END;
$$;


-- 3. Single-device revoke ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.admin_revoke_device(
  p_actor_user_id UUID,
  p_actor_role public.app_role,
  p_actor_device_id UUID,
  p_user_id UUID,
  p_device_id UUID
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_is_revoked BOOLEAN;
  v_session_id UUID;
BEGIN
  -- Lock the row so a concurrent login cannot re-bind the device while it is being revoked.
  SELECT d.is_device_revoked, d.session_id
    INTO v_is_revoked, v_session_id
    FROM public.user_devices AS d
   WHERE d.user_id = p_user_id
     AND d.device_id = p_device_id
     FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('status', 'NOT_FOUND');
  END IF;

  IF v_is_revoked IS TRUE THEN
    -- Idempotent: nothing changes, nothing is audited.
    RETURN jsonb_build_object('status', 'ALREADY_REVOKED');
  END IF;

  -- session_id is intentionally NOT cleared (see the header of this migration).
  UPDATE public.user_devices AS d
     SET is_device_revoked = true,
         device_revoked_at = now()
   WHERE d.user_id = p_user_id
     AND d.device_id = p_device_id;

  PERFORM public.admin_revoke_session(v_session_id);

  INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, target_record_id, metadata)
  VALUES (
    p_actor_user_id,
    p_actor_role,
    p_actor_device_id,
    'DEVICE_REVOKED',
    p_user_id,
    jsonb_build_object('revoked_device_id', p_device_id)
  );

  RETURN jsonb_build_object('status', 'REVOKED');
END;
$$;


-- 4. Global revoke: disable the account and delete every session ----------------------------
CREATE OR REPLACE FUNCTION public.admin_disable_user(
  p_actor_user_id UUID,
  p_actor_role public.app_role,
  p_actor_device_id UUID,
  p_user_id UUID
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM 1 FROM public.user_profiles AS p WHERE p.id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('status', 'NOT_FOUND');
  END IF;

  UPDATE public.user_profiles AS p
     SET is_active = false,
         all_sessions_revoked_at = now()
   WHERE p.id = p_user_id;

  DELETE FROM auth.sessions WHERE user_id = p_user_id;

  INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, target_record_id, metadata)
  VALUES (
    p_actor_user_id,
    p_actor_role,
    p_actor_device_id,
    'ACCOUNT_DISABLED',
    p_user_id,
    jsonb_build_object('reason', 'ADMIN_GLOBAL_REVOKE')
  );

  RETURN jsonb_build_object('status', 'DISABLED');
END;
$$;


-- 5. Reactivate a disabled account ----------------------------------------------------------
-- all_sessions_revoked_at is NOT cleared: tokens issued before the disable stay invalid,
-- so the user must sign in again to get a working session.
CREATE OR REPLACE FUNCTION public.admin_activate_user(
  p_actor_user_id UUID,
  p_actor_role public.app_role,
  p_actor_device_id UUID,
  p_user_id UUID
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM 1 FROM public.user_profiles AS p WHERE p.id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('status', 'NOT_FOUND');
  END IF;

  UPDATE public.user_profiles AS p
     SET is_active = true
   WHERE p.id = p_user_id;

  INSERT INTO public.audit_logs (actor_user_id, actor_role, device_id, action_type, target_record_id, metadata)
  VALUES (
    p_actor_user_id,
    p_actor_role,
    p_actor_device_id,
    'USER_REACTIVATED',
    p_user_id,
    '{}'::jsonb
  );

  RETURN jsonb_build_object('status', 'ACTIVATED');
END;
$$;


-- 6. User list with e-mail (auth.users is not readable by service_role directly) -----------
CREATE OR REPLACE FUNCTION public.admin_list_users(p_limit INTEGER, p_offset INTEGER)
RETURNS TABLE (
  id UUID,
  email TEXT,
  full_name TEXT,
  role public.app_role,
  is_active BOOLEAN,
  created_at TIMESTAMPTZ,
  all_sessions_revoked_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT p.id,
         u.email::text,
         p.full_name,
         p.role,
         p.is_active,
         p.created_at,
         p.all_sessions_revoked_at
    FROM public.user_profiles AS p
    LEFT JOIN auth.users AS u ON u.id = p.id
   ORDER BY p.created_at DESC, p.id
   LIMIT p_limit
  OFFSET p_offset;
$$;


-- 7. Privileges: service_role (the backend) only --------------------------------------------
REVOKE ALL ON FUNCTION public.admin_revoke_session(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_revoke_session(UUID) TO service_role;

REVOKE ALL ON FUNCTION public.admin_create_user_profile(UUID, public.app_role, UUID, UUID, public.app_role, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_create_user_profile(UUID, public.app_role, UUID, UUID, public.app_role, TEXT)
  TO service_role;

REVOKE ALL ON FUNCTION public.admin_revoke_device(UUID, public.app_role, UUID, UUID, UUID)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_revoke_device(UUID, public.app_role, UUID, UUID, UUID)
  TO service_role;

REVOKE ALL ON FUNCTION public.admin_disable_user(UUID, public.app_role, UUID, UUID)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_disable_user(UUID, public.app_role, UUID, UUID)
  TO service_role;

REVOKE ALL ON FUNCTION public.admin_activate_user(UUID, public.app_role, UUID, UUID)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_activate_user(UUID, public.app_role, UUID, UUID)
  TO service_role;

REVOKE ALL ON FUNCTION public.admin_list_users(INTEGER, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_list_users(INTEGER, INTEGER) TO service_role;
