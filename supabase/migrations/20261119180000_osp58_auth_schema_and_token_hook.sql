-- ============================================================================
-- OSP-58: Core Auth Schema, Device Binding, Audit Skeleton, Stubs & JWT Hook
-- Epic E10 — Authentication & Access Control (Supabase Auth)
--
-- Scope (OSP-58 ONLY):
--   - public.app_role enum ('rescuer', 'coordinator', 'administrator')
--   - public.user_profiles
--   - public.user_devices (with UNIQUE(user_id, device_id))
--   - public.audit_logs (skeleton with nullable actor/target columns)
--   - public.victim_records & public.rescuer_observations (minimal STUB tables)
--   - Enable Row Level Security on all new tables (policies added in OSP-63)
--   - public.custom_access_token_hook (injects `user_role` from user_profiles)
-- ============================================================================

-- 1. Application Role Enum
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_type t
      JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE t.typname = 'app_role'
       AND n.nspname = 'public'
  ) THEN
    CREATE TYPE public.app_role AS ENUM (
      'rescuer',
      'coordinator',
      'administrator'
    );
  END IF;
END
$$;

-- 2. User Profiles (1:1 with auth.users; source of truth for RBAC & global revocation)
CREATE TABLE IF NOT EXISTS public.user_profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT,
  role public.app_role NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  all_sessions_revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3. User Devices (device binding & single-device revocation)
CREATE TABLE IF NOT EXISTS public.user_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  device_id UUID NOT NULL,
  device_name TEXT,
  session_id UUID,
  last_login_at TIMESTAMPTZ,
  is_device_revoked BOOLEAN NOT NULL DEFAULT false,
  device_revoked_at TIMESTAMPTZ,
  CONSTRAINT user_devices_user_id_device_id_key UNIQUE (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_user_devices_user_id
  ON public.user_devices (user_id);

CREATE INDEX IF NOT EXISTS idx_user_devices_session_id
  ON public.user_devices (session_id);

-- 4. Audit Logs Skeleton (actor/device/target columns nullable for system & list events)
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  actor_role public.app_role,
  device_id UUID,
  action_type TEXT NOT NULL,
  target_record_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
  ON public.audit_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_user_id
  ON public.audit_logs (actor_user_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_action_type
  ON public.audit_logs (action_type);

-- 5. Minimal STUB Tables for E8/E9 RBAC, RLS, Audit & 30-day Retention Tests
CREATE TABLE IF NOT EXISTS public.victim_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_victim_records_created_at
  ON public.victim_records (created_at);

CREATE TABLE IF NOT EXISTS public.rescuer_observations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_rescuer_observations_created_at
  ON public.rescuer_observations (created_at);

-- 6. Deny-by-Default RLS Guard (policies are defined in OSP-63)
ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.victim_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rescuer_observations ENABLE ROW LEVEL SECURITY;

-- 7. Custom Access Token Hook (reads active role strictly from public.user_profiles)
CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_claims jsonb;
  v_user_id uuid;
  v_role public.app_role;
BEGIN
  v_claims := COALESCE(event -> 'claims', '{}'::jsonb);
  v_claims := v_claims - 'user_role';

  IF NULLIF(event ->> 'user_id', '') IS NOT NULL THEN
    v_user_id := (event ->> 'user_id')::uuid;

    SELECT up.role
      INTO v_role
      FROM public.user_profiles AS up
     WHERE up.id = v_user_id
       AND up.is_active = true;
  END IF;

  IF v_role IS NOT NULL THEN
    v_claims := jsonb_set(v_claims, '{user_role}', to_jsonb(v_role::text), true);
  ELSE
    v_claims := jsonb_set(v_claims, '{user_role}', 'null'::jsonb, true);
  END IF;

  RETURN jsonb_set(event, '{claims}', v_claims, true);
END;
$$;

GRANT USAGE ON SCHEMA public TO supabase_auth_admin;
REVOKE ALL ON FUNCTION public.custom_access_token_hook(jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) TO supabase_auth_admin;
