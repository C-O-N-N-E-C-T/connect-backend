# OSP-63: Deny-by-default PostgreSQL RLS

Scope: Row Level Security and table privileges for every table in the `public` schema.
Depends on: OSP-58 (tables, RLS enabled without policies). Works with: OSP-65 (audit log), OSP-66 (admin functions).
Migration: `supabase/migrations/20261126120000_osp63_rls_policies.sql`.

## 1. Why

The Supabase anon key ships in every web and mobile build. With it plus a user's JWT, anyone can query the database directly through PostgREST (`supabase.from('victim_records').select()`), bypassing the backend. The OSP-65 view audit is written by the backend, so such a direct read would leave no audit row. OSP-63 makes the database itself refuse those queries.

## 2. Access matrix

| Table | `anon` | `authenticated` | `service_role` (backend) |
|---|---|---|---|
| `victim_records` | permission denied | permission denied | full (bypasses RLS) |
| `rescuer_observations` | permission denied | permission denied | full |
| `audit_logs` | permission denied | SELECT → **0 rows** (no policy) | SELECT, INSERT (OSP-65) |
| `user_profiles` | permission denied | SELECT **own row only, only while `is_active`** | full |
| `user_devices` | permission denied | SELECT **own rows only, only while `is_active`** | full |

No client role can INSERT, UPDATE, DELETE or TRUNCATE any table.

## 3. Acceptance criteria and how they are met

| AC | How |
|---|---|
| RLS is enabled on 100% of `public` tables | OSP-58 enables it on all five tables. The migration ends with a guard that fails (and rolls back) if any `public` table has `relrowsecurity = false`. A static test checks that every `CREATE TABLE public.*` in any migration has a matching `ENABLE ROW LEVEL SECURITY`. |
| Direct anon / coordinator query on `victim_records` or `audit_logs` → 0 rows / permission denied | No policy for `anon`/`authenticated` on the three deny-by-default tables; the guard fails if one is ever added. `victim_records` and `rescuer_observations` additionally have ALL privileges revoked → permission denied. `audit_logs` keeps the OSP-65 SELECT grant → 0 rows. |
| A user reads only their own profile/device rows, and 0 rows once `is_active = false` | Policies `user_profiles_select_own_active` and `user_devices_select_own_active`: `FOR SELECT TO authenticated USING (<owner column> = auth.uid() AND public.is_active_user())`. |

## 4. Decisions

- **`public.is_active_user()` is executable by `authenticated`.** Every other RPC in this repo revokes EXECUTE from `authenticated`. This helper must not: policy expressions run with the privileges of the querying role, so without the grant every self-read fails with `permission denied for function is_active_user`. It is `SECURITY DEFINER` with `search_path = ''` and only returns a boolean about the caller's own profile. Running as the owner also prevents RLS recursion when the `user_profiles` policy reads `user_profiles`.
- **Privileges are a second lock behind RLS.** Supabase grants ALL privileges on new `public` tables to `anon` and `authenticated`, including TRUNCATE. RLS does not check TRUNCATE. Revoking the privileges closes that gap. It also keeps the tables closed if someone later adds a permissive policy by mistake.
- **`audit_logs` privileges are unchanged.** OSP-65 documents `authenticated` SELECT "subject to RLS". With no policy that returns 0 rows, which the AC accepts.
- **No `FORCE ROW LEVEL SECURITY`.** The custom access token hook and the SECURITY DEFINER functions of OSP-60/65/66/67 run as the table owner and rely on the owner bypassing RLS.
- **The backend is unaffected.** Every table access in `src/` uses `supabaseAdmin` (service_role, `BYPASSRLS`). connect-web and connect-mobile make no direct table queries.
- **Future tables:** a new `public` table must `ENABLE ROW LEVEL SECURITY` in its own migration. The static test in `tests/osp63-rls.test.ts` fails if it does not. The database guard in this migration runs only once, when this migration is applied. Default privileges for future tables are not changed here, so a new table still needs its own REVOKEs. The static regexes only recognise the `public.<table>` form; the database guard is the real check.
- **Views:** a view runs with its owner's rights unless `security_invoker = true` is set, so a plain view over `victim_records` would hand the rows to `anon`. The guard rejects any `public` view or materialized view without `security_invoker`. No views exist today.

## 5. Tests

`tests/osp63-rls.test.ts` checks the SQL statically, in the same style as the other migration tests: helper definition and grants, policy shape, no policy on the deny-by-default tables in any migration, privilege revokes, the 100% guard, and no FORCE RLS. These tests cannot prove the behaviour. Section 6 does that.

## 6. Verification (local Supabase only, never the hosted project)

```bash
npx supabase start          # or: npx supabase db reset
docker exec -i supabase_db_connect-backend psql -U postgres -v ON_ERROR_STOP=1 -q -t \
  < scripts/osp63-verify-rls.sql
```

The script runs in one transaction and rolls it back, so no test data is kept. It creates two users (A = coordinator, B = rescuer), switches roles exactly as PostgREST does (`SET ROLE` + `request.jwt.claims`), and prints `PASS …` per check. The first failure stops it with `FAIL …`. It covers:

- AC-1: no `public` table with RLS off.
- AC-2: anon and coordinator SELECT on `victim_records`/`rescuer_observations` → permission denied; coordinator on `audit_logs` → 0 rows; INSERT/TRUNCATE denied.
- AC-3: A and B read only their own profile/devices. Every write, including role escalation and device un-revoke, is denied. After `is_active = false`, A reads 0 rows while B is unaffected.
- `audit_logs`: client INSERT/TRUNCATE denied.
- `is_active_user()` grants, the service_role (backend) read path and a SECURITY INVOKER RPC (`bind_device_session`).
- The custom access token hook still returns `user_role` for an active profile and `null` for an inactive one. It runs as `supabase_auth_admin` when psql is started with `-U supabase_admin`, otherwise as the owner.

A denied check passes only on `permission denied for table …`. Any other 42501 (e.g. on `is_active_user`) fails it.

Result on 2026-11-26 (Supabase CLI 3.2.0, Postgres 15): all 32 checks passed, both as `postgres` and as `supabase_admin`. Two negative controls were also run: granting `victim_records` back to `authenticated`, and adding a `USING (true)` policy. Both made the script fail as expected. The migration guard was also tested on its own: a plain view over `victim_records`, and a leftover `anon` grant on `rescuer_observations`, each made the migration fail.

An HTTP check through PostgREST with a signed `authenticated` JWT (`user_role = coordinator`) gave the same result: `victim_records`/`rescuer_observations` 403 `42501`; `audit_logs` 200 with 0 rows; own profile/device 1 row; PATCH own role 403; after deactivation 0 rows.

Not covered: a real email/password sign-in through local GoTrue. With the current `config.toml` (`[auth.email] enable_signup = false`), the local Auth server answers `email_provider_disabled`. That setting predates OSP-63 and is not changed here. The token hook was exercised directly instead (see above).

## 7. Applying to the hosted project

Applying the migration to the hosted project is done by the team after review, with `supabase db push` or by running the migration in the SQL editor. Run this read-only query in the SQL editor **before and after** applying:

```sql
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND NOT c.relrowsecurity;  -- expect 0 rows
```

**Before:** if it returns any table, for example one created in Studio or by an extension, the migration's guard will raise and the whole migration will be rolled back. Decide first what to do with that table: enable RLS on it, or drop it. **After:** it must return 0 rows. Also confirm the revokes (expect `false` in every column):

```sql
SELECT has_table_privilege('anon', 'public.victim_records', 'SELECT')          AS anon_victims,
       has_table_privilege('authenticated', 'public.victim_records', 'SELECT') AS auth_victims,
       has_table_privilege('authenticated', 'public.user_profiles', 'UPDATE')  AS auth_profile_update;
```

If the migration is run in the SQL editor instead of `supabase db push`, Supabase does not record it as applied. Record it with `supabase migration repair --status applied 20261126120000` so that a later `db push` does not try to apply it again. Running it again would be harmless anyway, because the migration is idempotent.

Do not run `scripts/osp63-verify-rls.sql` on the hosted project. It inserts test users, even though it rolls them back.

---

## Türkçe özet

- **Hassas tablolar** (`victim_records`, `rescuer_observations`, `audit_logs`) istemcilere tamamen kapalı. Policy yok. İlk ikisinde yetkiler de geri alındı (permission denied). `audit_logs` OSP-65'teki gibi kaldı (0 satır).
- **`user_profiles` / `user_devices`**: Giriş yapmış kullanıcı yalnızca kendi satırını, yalnızca hesabı aktifken okuyabilir. Yazma ve TRUNCATE yetkisi yok.
- **`is_active_user()`** fonksiyonunun `authenticated` için çalıştırma yetkisi bilerek açık bırakıldı. Policy'ler sorguyu atan rolün yetkisiyle çalışır.
- Backend `service_role` kullandığı için etkilenmez.
- Doğrulama yalnızca yerel Supabase'de `scripts/osp63-verify-rls.sql` ile yapılır. 2026-11-26'da 32 kontrolün hepsi geçti. Token hook ve backend RPC'leri de etkilenmedi.
- Hosted projeye uygulamadan **önce** bölüm 7'deki salt-okunur sorgu çalıştırılmalı. RLS'i kapalı bir tablo varsa migration hata verip tamamen geri alınır.
