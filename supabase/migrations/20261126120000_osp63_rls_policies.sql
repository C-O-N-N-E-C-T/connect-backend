-- =========================================================================================
-- OSP-63: Deny-by-default PostgreSQL RLS (FR-B-06, NFR-SEC-06, AC-28 | TID: SCRT-3-1)
-- =========================================================================================
-- OSP-58 enabled RLS on every table and left them without policies. This migration adds the
-- only client-facing read paths and closes everything else:
--
--   victim_records, rescuer_observations, audit_logs
--     -> NO policy for anon or authenticated (deny-by-default). Only the backend
--        (service_role, BYPASSRLS) reads them, so the OSP-65 view audit cannot be skipped by a
--        direct supabase-js query.
--   user_profiles, user_devices
--     -> authenticated may SELECT only its own row, and only while its profile is active
--        (public.is_active_user()). No client INSERT/UPDATE/DELETE.
--
-- Table privileges are narrowed as a second lock behind RLS. Supabase grants ALL (including
-- TRUNCATE, which RLS does not check) on new public tables to anon and authenticated.
--   - victim_records, rescuer_observations: ALL revoked -> direct queries get "permission denied".
--   - user_profiles, user_devices: authenticated keeps SELECT only; anon gets nothing.
--   - audit_logs: unchanged. OSP-65 already allows authenticated SELECT only; with no policy it
--     returns 0 rows.
--   - service_role privileges are not touched.
--
-- No FORCE ROW LEVEL SECURITY: the token hook and the SECURITY DEFINER functions of OSP-60/65/
-- 66/67 rely on the table owner bypassing RLS.
-- =========================================================================================


-- 1. Helper: is the caller's profile active? ----------------------------------------------
-- SECURITY DEFINER so it reads user_profiles as the owner: no RLS recursion when it is used
-- inside the user_profiles policy, and it also works from the user_devices policy.
-- Unlike the RPCs of OSP-60/65/66, authenticated MUST keep EXECUTE: a policy expression runs
-- with the privileges of the querying role, so without it every self-read would fail with
-- "permission denied for function is_active_user".
CREATE OR REPLACE FUNCTION public.is_active_user()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.user_profiles AS up
     WHERE up.id = auth.uid()
       AND up.is_active = true
  );
$$;

REVOKE ALL ON FUNCTION public.is_active_user() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_active_user() TO authenticated;


-- 2. Self-read policies (SELECT only, authenticated only) ---------------------------------
-- (SELECT ...) wrappers let Postgres evaluate auth.uid() and the helper once per statement
-- instead of once per row.
DROP POLICY IF EXISTS user_profiles_select_own_active ON public.user_profiles;
CREATE POLICY user_profiles_select_own_active
  ON public.user_profiles
  FOR SELECT
  TO authenticated
  USING (
    id = (SELECT auth.uid())
    AND (SELECT public.is_active_user())
  );

DROP POLICY IF EXISTS user_devices_select_own_active ON public.user_devices;
CREATE POLICY user_devices_select_own_active
  ON public.user_devices
  FOR SELECT
  TO authenticated
  USING (
    user_id = (SELECT auth.uid())
    AND (SELECT public.is_active_user())
  );

-- victim_records, rescuer_observations, audit_logs: deliberately NO policy (deny-by-default).


-- 3. Table privileges (second lock behind RLS) --------------------------------------------
REVOKE ALL ON public.victim_records FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.rescuer_observations FROM PUBLIC, anon, authenticated;

-- REVOKE ALL then GRANT SELECT (not a list of privileges) so nothing is left behind, e.g.
-- MAINTAIN, which ALL includes from Postgres 17.
REVOKE ALL ON public.user_profiles FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.user_profiles TO authenticated;

REVOKE ALL ON public.user_devices FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.user_devices TO authenticated;


-- 4. Guard: RLS must be enabled on 100% of public tables ----------------------------------
-- Fails the migration (and rolls it back) if any table in the public schema has RLS off, if a
-- client-facing policy exists on a deny-by-default table, if a client role still holds a
-- privilege on victim_records/rescuer_observations, or if a public view would bypass RLS.
-- Failing loudly is deliberate: a table nobody has reviewed must not stay open to clients.
DO $$
DECLARE
  v_missing text;
  v_policies text;
  v_views text;
  v_table text;
  v_role text;
BEGIN
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
    INTO v_missing
    FROM pg_class AS c
    JOIN pg_namespace AS n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public'
     AND c.relkind IN ('r', 'p')
     AND NOT c.relrowsecurity;

  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'OSP-63: RLS is not enabled on public table(s): %', v_missing;
  END IF;

  SELECT string_agg(tablename || '.' || policyname, ', ')
    INTO v_policies
    FROM pg_policies
   WHERE schemaname = 'public'
     AND tablename IN ('victim_records', 'rescuer_observations', 'audit_logs')
     AND roles && ARRAY['public', 'anon', 'authenticated']::name[];

  IF v_policies IS NOT NULL THEN
    RAISE EXCEPTION 'OSP-63: deny-by-default tables must have no policy, found: %', v_policies;
  END IF;

  FOREACH v_table IN ARRAY ARRAY['public.victim_records', 'public.rescuer_observations'] LOOP
    FOREACH v_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
      IF has_table_privilege(v_role, v_table, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE') THEN
        RAISE EXCEPTION 'OSP-63: % still has a privilege on %', v_role, v_table;
      END IF;
    END LOOP;
  END LOOP;

  -- A view runs with its owner's rights unless security_invoker is set, so a plain view over
  -- victim_records would hand the rows to anon. No views exist today; keep it that way.
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
    INTO v_views
    FROM pg_class AS c
    JOIN pg_namespace AS n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public'
     AND c.relkind IN ('v', 'm')
     AND NOT COALESCE('security_invoker=true' = ANY (c.reloptions), false);

  IF v_views IS NOT NULL THEN
    RAISE EXCEPTION 'OSP-63: public view(s) without security_invoker bypass RLS: %', v_views;
  END IF;
END
$$;
