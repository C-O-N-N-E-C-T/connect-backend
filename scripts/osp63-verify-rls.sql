-- =========================================================================================
-- OSP-63: behavioural check of the RLS acceptance criteria. LOCAL SUPABASE ONLY.
--
--   npx supabase start            # or: npx supabase db reset
--   docker exec -i supabase_db_connect-backend psql -U postgres -v ON_ERROR_STOP=1 \
--     < scripts/osp63-verify-rls.sql
--
-- Everything runs in ONE transaction that is rolled back at the end: the two test users,
-- their profiles/devices and the victim/audit rows are never kept. Each check prints
-- "PASS ..." as a NOTICE; the first failing check raises "FAIL ..." and stops the script.
-- Roles are switched with SET ROLE + request.jwt.claims, which is exactly what PostgREST does
-- for a supabase-js request carrying that JWT.
-- =========================================================================================

BEGIN;

-- Test fixtures (as postgres) ---------------------------------------------------------------
-- A = coordinator, B = rescuer. Fixed UUIDs so the checks below can refer to them.
INSERT INTO auth.users (id, aud, role, email)
VALUES ('00000000-0000-4000-a000-00000000000a', 'authenticated', 'authenticated', 'osp63-a@example.test'),
       ('00000000-0000-4000-a000-00000000000b', 'authenticated', 'authenticated', 'osp63-b@example.test');

INSERT INTO public.user_profiles (id, full_name, role, is_active)
VALUES ('00000000-0000-4000-a000-00000000000a', 'OSP-63 A', 'coordinator', true),
       ('00000000-0000-4000-a000-00000000000b', 'OSP-63 B', 'rescuer', true);

INSERT INTO public.user_devices (user_id, device_id, device_name)
VALUES ('00000000-0000-4000-a000-00000000000a', gen_random_uuid(), 'A phone'),
       ('00000000-0000-4000-a000-00000000000b', gen_random_uuid(), 'B phone');

INSERT INTO public.victim_records (created_by, payload)
VALUES ('00000000-0000-4000-a000-00000000000b', '{"osp63": true}');
INSERT INTO public.rescuer_observations (created_by, payload)
VALUES ('00000000-0000-4000-a000-00000000000b', '{"osp63": true}');
INSERT INTO public.audit_logs (actor_user_id, actor_role, action_type)
VALUES ('00000000-0000-4000-a000-00000000000a', 'coordinator', 'OSP63_TEST');


-- Helpers (temporary, dropped with the session) ---------------------------------------------
-- Switch to a client role the way PostgREST does. p_sub NULL = anon request.
CREATE FUNCTION pg_temp.become(p_role text, p_sub uuid, p_user_role text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  PERFORM set_config('request.jwt.claims',
    jsonb_strip_nulls(jsonb_build_object('role', p_role, 'sub', p_sub, 'user_role', p_user_role))::text,
    true);
  PERFORM set_config('request.jwt.claim.sub', COALESCE(p_sub::text, ''), true);
  EXECUTE format('SET LOCAL ROLE %I', p_role);
END;
$$;

CREATE FUNCTION pg_temp.back_to_postgres()
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  RESET ROLE;
  PERFORM set_config('request.jwt.claims', '', true);
  PERFORM set_config('request.jwt.claim.sub', '', true);
END;
$$;

-- The query must run and return exactly p_expected rows.
CREATE FUNCTION pg_temp.expect_rows(p_label text, p_role text, p_sub uuid, p_user_role text,
                                    p_sql text, p_expected bigint)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  v_n bigint;
BEGIN
  PERFORM pg_temp.become(p_role, p_sub, p_user_role);
  EXECUTE format('SELECT count(*) FROM (%s) AS q', p_sql) INTO v_n;
  PERFORM pg_temp.back_to_postgres();
  IF v_n IS DISTINCT FROM p_expected THEN
    RAISE EXCEPTION 'FAIL % — expected % row(s), got %', p_label, p_expected, v_n;
  END IF;
  RAISE NOTICE 'PASS % (% row(s))', p_label, v_n;
END;
$$;

-- The statement must fail with "permission denied" (SQLSTATE 42501).
CREATE FUNCTION pg_temp.expect_denied(p_label text, p_role text, p_sub uuid, p_user_role text,
                                      p_sql text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  BEGIN
    PERFORM pg_temp.become(p_role, p_sub, p_user_role);
    EXECUTE p_sql;
  EXCEPTION
    WHEN insufficient_privilege THEN
      -- The sub-transaction rollback also undid SET LOCAL ROLE.
      -- Only a TABLE privilege error counts; e.g. "permission denied for function
      -- is_active_user" would mean the policy itself is broken.
      IF SQLERRM NOT LIKE 'permission denied for table %' THEN
        RAISE EXCEPTION 'FAIL % — unexpected 42501: %', p_label, SQLERRM;
      END IF;
      RAISE NOTICE 'PASS % (%)', p_label, SQLERRM;
      RETURN;
  END;
  PERFORM pg_temp.back_to_postgres();
  RAISE EXCEPTION 'FAIL % — statement was allowed', p_label;
END;
$$;

-- Client roles must be able to call the helpers (they live in this session's pg_temp schema).
DO $$
BEGIN
  EXECUTE format('GRANT USAGE ON SCHEMA %s TO anon, authenticated, service_role',
                 pg_my_temp_schema()::regnamespace);
END
$$;


-- AC-1: RLS is enabled on 100% of public tables ----------------------------------------------
DO $$
DECLARE
  v_off text;
BEGIN
  SELECT string_agg(c.relname, ', ') INTO v_off
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relrowsecurity;
  IF v_off IS NOT NULL THEN
    RAISE EXCEPTION 'FAIL AC-1 — RLS off on: %', v_off;
  END IF;
  RAISE NOTICE 'PASS AC-1 RLS enabled on every public table';
END
$$;


-- AC-2: direct client queries on victim/audit tables get nothing -----------------------------
SELECT pg_temp.expect_denied('AC-2 anon SELECT victim_records', 'anon', NULL, NULL,
  'SELECT * FROM public.victim_records');
SELECT pg_temp.expect_denied('AC-2 coordinator SELECT victim_records', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'SELECT * FROM public.victim_records');
SELECT pg_temp.expect_denied('AC-2 coordinator SELECT rescuer_observations', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'SELECT * FROM public.rescuer_observations');
SELECT pg_temp.expect_denied('AC-2 anon SELECT audit_logs', 'anon', NULL, NULL,
  'SELECT * FROM public.audit_logs');
SELECT pg_temp.expect_rows('AC-2 coordinator SELECT audit_logs', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'SELECT * FROM public.audit_logs', 0);

-- Writes and TRUNCATE (TRUNCATE ignores RLS, only privileges stop it)
SELECT pg_temp.expect_denied('coordinator INSERT victim_records', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator',
  $q$INSERT INTO public.victim_records (payload) VALUES ('{}')$q$);
SELECT pg_temp.expect_denied('coordinator TRUNCATE victim_records', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'TRUNCATE public.victim_records');
SELECT pg_temp.expect_denied('anon TRUNCATE rescuer_observations', 'anon', NULL, NULL,
  'TRUNCATE public.rescuer_observations');
SELECT pg_temp.expect_denied('coordinator INSERT audit_logs', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator',
  $q$INSERT INTO public.audit_logs (action_type) VALUES ('FORGED')$q$);
SELECT pg_temp.expect_denied('coordinator TRUNCATE audit_logs', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'TRUNCATE public.audit_logs');


-- AC-3: self-read only, and only while active -------------------------------------------------
SELECT pg_temp.expect_rows('AC-3 A reads own profile', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'SELECT * FROM public.user_profiles', 1);
SELECT pg_temp.expect_rows('AC-3 A reads own devices', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'SELECT * FROM public.user_devices', 1);
SELECT pg_temp.expect_rows('AC-3 A cannot read B''s profile', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator',
  $q$SELECT * FROM public.user_profiles WHERE id = '00000000-0000-4000-a000-00000000000b'$q$, 0);
SELECT pg_temp.expect_rows('AC-3 A cannot read B''s devices', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator',
  $q$SELECT * FROM public.user_devices WHERE user_id = '00000000-0000-4000-a000-00000000000b'$q$, 0);
SELECT pg_temp.expect_rows('AC-3 B reads own profile', 'authenticated',
  '00000000-0000-4000-a000-00000000000b', 'rescuer', 'SELECT * FROM public.user_profiles', 1);
SELECT pg_temp.expect_denied('anon SELECT user_profiles', 'anon', NULL, NULL,
  'SELECT * FROM public.user_profiles');
SELECT pg_temp.expect_denied('anon SELECT user_devices', 'anon', NULL, NULL,
  'SELECT * FROM public.user_devices');

-- No client writes on profile/devices
SELECT pg_temp.expect_denied('A UPDATE own profile (role escalation)', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator',
  $q$UPDATE public.user_profiles SET role = 'administrator' WHERE id = '00000000-0000-4000-a000-00000000000a'$q$);
SELECT pg_temp.expect_denied('A INSERT profile', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator',
  $q$INSERT INTO public.user_profiles (id, role) VALUES ('00000000-0000-4000-a000-00000000000a', 'administrator')$q$);
SELECT pg_temp.expect_denied('A DELETE own device', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator',
  $q$DELETE FROM public.user_devices WHERE user_id = '00000000-0000-4000-a000-00000000000a'$q$);
SELECT pg_temp.expect_denied('A UPDATE own device (un-revoke)', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator',
  $q$UPDATE public.user_devices SET is_device_revoked = false WHERE user_id = '00000000-0000-4000-a000-00000000000a'$q$);
SELECT pg_temp.expect_denied('A TRUNCATE user_devices', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'TRUNCATE public.user_devices');

-- Deactivate A (as postgres, like the OSP-66 admin_disable_user would)
UPDATE public.user_profiles SET is_active = false WHERE id = '00000000-0000-4000-a000-00000000000a';

SELECT pg_temp.expect_rows('AC-3 inactive A cannot read own profile', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'SELECT * FROM public.user_profiles', 0);
SELECT pg_temp.expect_rows('AC-3 inactive A cannot read own devices', 'authenticated',
  '00000000-0000-4000-a000-00000000000a', 'coordinator', 'SELECT * FROM public.user_devices', 0);
SELECT pg_temp.expect_rows('AC-3 B (still active) still reads own profile', 'authenticated',
  '00000000-0000-4000-a000-00000000000b', 'rescuer', 'SELECT * FROM public.user_profiles', 1);


-- Helper privileges and backend (service_role) path -------------------------------------------
DO $$
BEGIN
  IF has_function_privilege('anon', 'public.is_active_user()', 'EXECUTE') THEN
    RAISE EXCEPTION 'FAIL anon can execute is_active_user()';
  END IF;
  IF NOT has_function_privilege('authenticated', 'public.is_active_user()', 'EXECUTE') THEN
    RAISE EXCEPTION 'FAIL authenticated cannot execute is_active_user()';
  END IF;
  RAISE NOTICE 'PASS is_active_user(): authenticated EXECUTE yes, anon no';
END
$$;

SELECT pg_temp.expect_rows('backend service_role reads victim_records', 'service_role', NULL, NULL,
  $q$SELECT * FROM public.victim_records WHERE payload ->> 'osp63' = 'true'$q$, 1);
SELECT pg_temp.expect_rows('backend service_role reads all profiles', 'service_role', NULL, NULL,
  $q$SELECT * FROM public.user_profiles WHERE id IN ('00000000-0000-4000-a000-00000000000a', '00000000-0000-4000-a000-00000000000b')$q$, 2);
SELECT pg_temp.expect_rows('backend service_role reads audit_logs', 'service_role', NULL, NULL,
  $q$SELECT * FROM public.audit_logs WHERE action_type = 'OSP63_TEST'$q$, 1);

-- Backend write path: a SECURITY INVOKER RPC called by service_role still works.
DO $$
DECLARE
  v_result jsonb;
BEGIN
  SET LOCAL ROLE service_role;
  v_result := public.bind_device_session('00000000-0000-4000-a000-00000000000b', 'rescuer',
                                         gen_random_uuid(), 'osp63', gen_random_uuid());
  RESET ROLE;
  IF v_result ->> 'status' IS DISTINCT FROM 'BOUND' THEN
    RAISE EXCEPTION 'FAIL service_role bind_device_session — got %', v_result;
  END IF;
  RAISE NOTICE 'PASS backend service_role bind_device_session (BOUND)';
END
$$;

-- Login path: the custom access token hook still reads the role (active) / null (inactive).
-- Run as supabase_auth_admin when this session may switch to it (e.g. psql -U supabase_admin);
-- otherwise as the function owner, which exercises the same SECURITY DEFINER body.
DO $$
DECLARE
  v_can_switch boolean := pg_has_role(current_user, 'supabase_auth_admin', 'MEMBER');
  v_active text;
  v_inactive text;
BEGIN
  IF v_can_switch THEN
    SET LOCAL ROLE supabase_auth_admin;
  END IF;
  v_active := public.custom_access_token_hook(
    '{"user_id": "00000000-0000-4000-a000-00000000000b", "claims": {}}') #>> '{claims,user_role}';
  v_inactive := public.custom_access_token_hook(
    '{"user_id": "00000000-0000-4000-a000-00000000000a", "claims": {}}') #>> '{claims,user_role}';
  RESET ROLE;
  IF v_active IS DISTINCT FROM 'rescuer' OR v_inactive IS NOT NULL THEN
    RAISE EXCEPTION 'FAIL token hook — active: %, inactive: %', v_active, v_inactive;
  END IF;
  RAISE NOTICE 'PASS token hook (as %): active -> rescuer, inactive -> null',
    CASE WHEN v_can_switch THEN 'supabase_auth_admin' ELSE 'owner' END;
END
$$;

DO $$ BEGIN RAISE NOTICE 'OSP-63: ALL CHECKS PASSED'; END $$;

ROLLBACK;
