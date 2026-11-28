# OSP-68: AC-19 / AC-28 integration tests (local Supabase only)

Automated end-to-end checks of AC-19 (authentication, role matrix, revocation) and AC-28 (audit
log, 30-day purge, RLS). They use the real Express app (in process, `supertest`, no fakes) and
the **local Docker Supabase** (GoTrue, PostgREST, Postgres with all migrations applied).

> **LOCAL ONLY.** These tests create users, revoke devices and call `purge_expired_records()`.
> They must never run against the hosted project. A guard stops the whole suite before any
> request if the Supabase API or DB host is not `127.0.0.1` / `localhost` (see section 3).

## 1. How to run

```bash
npx supabase start          # Docker must be running
npm run test:integration    # vitest.integration.config.ts, tests/integration/**
npx supabase stop
```

`npm test` does **not** run these tests (`tests/integration/**` is excluded in `vitest.config.ts`).
Only the guard's unit test (`tests/osp68-local-guard.test.ts`) runs there.

Test counts (2026-11-28): **87 integration tests** (`osp68-ac19-auth` 63, `osp68-ac28-audit` 12,
`osp68-ac28-rls` 12) and **475 unit tests** in `npm test`, including the guard's unit test.

Files run one after another (`fileParallelism: false`): they share one database and one GoTrue
rate limit, and the purge affects whole tables.

## 2. Traceability

| Jira item | Test (file › describe › test) |
|---|---|
| 1. Missing / malformed / expired JWT → 401 `UNAUTHENTICATED` | `osp68-ac19-auth` › *AC-19 / OSP-61* — 10 credential kinds (no header, empty Bearer, wrong scheme, garbage, forged payload, swapped signature, `alg: none`, wrong HS256 secret, **expired but validly signed**) plus the anon and service_role keys, each against all 16 `/api/v1` endpoints (every protected route, `POST /auth/session`, an unknown path). Status, body and `WWW-Authenticate: Bearer` are checked. Two control tests prove the same tokens/signing are accepted when valid. |
| 2. Full role matrix | `osp68-ac19-auth` › *AC-19 / OSP-62* — 14 endpoints × 3 roles with real users. Includes administrator → 403 `ROLE_FORBIDDEN` on override (**FR-D-06**) and assignments (**FR-D-07**), and an extra check that the rejected override changed nothing and wrote no audit row. `POST /admin/users` (create a rescuer): administrator → 201 (profile and `USER_CREATED` audit row checked), coordinator and rescuer → 403 `ROLE_FORBIDDEN`. With `role: administrator` every role gets 403. Unique emails are used, and a created user is added to the cleanup list before any assertion. |
| 2. Role matrix: `POST /auth/logout` | `osp68-ac19-auth` › *AC-19 / OSP-60* — every role → 204 with an empty body; the same token then gets 403 `SESSION_NOT_BOUND`; a `LOGOUT` audit row is written; the device row stays with `session_id = null`. This block is deliberately the **last** one in the file. It ends the base sessions, and no later test uses them (vitest runs tests in definition order). |
| 3. Revocation → 403 on the next request with an unexpired token | `osp68-ac19-auth` › *AC-19 / OSP-66* — single-device revoke via the admin API → `DEVICE_REVOKED` (the user's other device keeps working, the revoked device cannot be re-bound); `revoke-all` via the admin API → `ACCOUNT_DISABLED`; `is_active=false` and `all_sessions_revoked_at` alone → `ACCOUNT_DISABLED`. |
| 4a. Audit row for victim GET / POST / PATCH | `osp68-ac28-audit` › *AC-28 / FR-B-06* — `GET /victims` (exactly one `VICTIM_LIST_VIEW`), `GET /victims/:id` (`VICTIM_VIEW`), `PATCH …/override` (`VICTIM_UPDATE`, reason text not copied), `POST /sync` (`OBSERVATION_SYNC`); failed requests write no row. |
| 4b. `service_role` cannot UPDATE / DELETE audit rows | `osp68-ac28-audit` › *AC-28 / NFR-SEC-06* — UPDATE, DELETE and UPSERT with the service_role key → `42501`, row unchanged; anon/authenticated INSERT → `42501`; TRUNCATE (see section 5). |
| 4c. 30-day purge | `osp68-ac28-audit` › *30-day retention purge* — rows 31 days old are deleted, rows 29 days old and new rows stay, the `RETENTION_PURGE` audit row holds the counts; anon/authenticated cannot call the RPC. |
| 4d. RLS (OSP-63) | `osp68-ac28-rls` — anon: all five tables → permission denied. Authenticated (real user JWT straight to PostgREST): victim tables → permission denied, `audit_logs` → 0 rows, own profile/device only, no writes, 0 own rows after `is_active=false`. |
| Bonus: rate limit (OSP-64) | `osp68-ac19-auth` › *AC-19 / OSP-64* — the 11th `/api/v1/auth/*` request from one IP → 429; other IPs and `GET /auth/me` are not affected. |
| 5. Android DB encryption | **Out of scope** (decided by the team): it depends on E8 (Room + SQLCipher), which does not exist yet. To be tested together with E8. |

The HTTPS part of AC-19 (NFR-SEC-02, 426 in production) is covered by the unit test
`tests/osp64-security.test.ts`. The integration run uses `NODE_ENV=test`.

## 3. Safety: local values only, never `.env`

- `tests/integration/global-setup.ts` reads the URL and keys from `npx supabase status -o json`
  and runs `assertLocalUrl` on the API and DB URLs. If a check fails, vitest stops before
  loading any test file. An optional `INTEGRATION_SUPABASE_URL` is checked **before** the CLI
  is called. Example: `INTEGRATION_SUPABASE_URL=https://example.supabase.co npm run test:integration`
  exits with code 1 and prints `REFUSING TO RUN`.
- `src/config/env.ts` calls `dotenv.config()`, which never overwrites variables that are already
  set. `tests/integration/setup-env.ts` sets **every** key of the env schema to the local
  values before the app is imported. It then compares the app's own `env` object with those
  values and aborts on any difference. Values from `.env` or the shell (`SUPABASE_URL=…`) are
  therefore never used.
- Run outside `npm run test:integration` (no globalSetup), `requireProvidedConfig` in
  `helpers.ts` / `setup-env.ts` stops with a clear `[OSP-68] … run via npm run test:integration`
  error. This happens before the app (and with it `.env`) is loaded, because the test files import
  `src/app.js` dynamically, after the helpers.
- Keys are never printed.

## 4. Technical notes

- **Sign-in:** local GoTrue rejects email/password sign-in (`email_provider_disabled`, because
  `[auth.email] enable_signup = false` in `config.toml`). The tests do not change that setting.
  Instead they create the user with the admin API, generate a magic link (no email is sent) and
  call `verifyOtp`. The result is a real session: an ES256 access token whose `session_id` is a
  row in `auth.sessions`, with the token hook applied.
- **Expired token:** local Supabase signs with ES256 (JWKS). The private key is not exposed, and
  `jwt_expiry` is 3600 s. Local GoTrue also accepts the legacy HS256 `JWT_SECRET`, so the test
  takes the real claims of a bound session and re-signs them with HS256 (Node `crypto`), with
  `exp` in the past. `getClaims` rejects it as expired. A control test signs the same claims the
  same way with a future `exp` and gets 200. That shows the signature is valid and only `exp`
  was rejected.
- **Revocation and ES256:** `getClaims` verifies ES256 tokens locally against JWKS, so a token
  whose `auth.sessions` row was deleted by the admin functions still reaches the guard. The guard
  then answers `DEVICE_REVOKED` / `ACCOUNT_DISABLED`, as AC-19 requires. With HS256 tokens,
  `getClaims` calls `getUser` instead. After the session is deleted that call fails with
  `AuthSessionMissingError`, and the guard answers 401 instead of 403 (checked by hand on
  2026-11-28). The hosted project must therefore use asymmetric signing keys for AC-19 to hold there.
- **Rate limit:** the tests set `TRUST_PROXY=1` (an env setting, not a code change) and give
  each client its own `X-Forwarded-For` IP. The 10/min/IP limit then never blocks unrelated
  tests. The limit itself is tested separately. GoTrue's own verify limit (burst 30, then about
  6 per minute) can answer 429 after many back-to-back runs. `signIn` then waits 10 s and retries,
  but within a total wait budget of **60 s per process** (one test file,
  `SIGN_IN_WAIT_BUDGET_MS`). When the budget is used up it stops with a clear error ("wait about a
  minute and run again"). The timeouts are set above the budget, so that error appears instead of
  a generic vitest timeout: `testTimeout` 90 s (the revocation tests open their own users) and
  `hookTimeout` 120 s (`beforeAll` opens 3 users).

## 5. Test data and what stays in the local database

- Users get emails like `osp68-<tag>-<random>@example.test`. `afterAll` deletes the users they
  created. Devices and profiles go with them (`ON DELETE CASCADE`). The tests also delete the
  victim and observation rows they created. `audit_logs` has no foreign key to users (OSP-65),
  so audit rows do not block the delete.
- **Audit rows stay.** `audit_logs` is append-only, so every run leaves its rows (`LOGIN`,
  `VICTIM_*`, `DEVICE_REVOKED`, `RETENTION_PURGE`, …) in the **local** database. For a clean state,
  run `npx supabase db reset` (local only).
- Leftover check: `SELECT count(*) FROM auth.users WHERE email LIKE 'osp68-%';` should return 0.
- TRUNCATE cannot be expressed through PostgREST/supabase-js. The test runs it with `psql` inside
  the local DB container (`docker exec supabase_db_connect-backend …`), inside a transaction that
  is rolled back. As `service_role` it gets `permission denied`. As the table owner, the OSP-65
  trigger blocks it. `scripts/osp63-verify-rls.sql` covers TRUNCATE by clients.
- The purge deletes **every** victim/observation row older than 30 days in the local database,
  not only the test rows.

---

## Türkçe özet

- `npx supabase start` → `npm run test:integration` → `npx supabase stop`. `npm test` bu testleri çalıştırmaz.
- **Yalnızca yerel:** API ya da DB host'u `127.0.0.1`/`localhost` değilse paket hiç başlamaz.
  Anahtarlar `supabase status` çıktısından okunur. `.env` ve kabuktaki `SUPABASE_*` değerleri kullanılmaz.
- AC-19 (401 / rol matrisi / iptal) ve AC-28 (audit / değiştirilemezlik / 30 gün / RLS) maddeleri
  bölüm 2'deki tabloda testlere eşlenmiştir. Rol matrisinde `POST /admin/users` ve `/auth/logout` da vardır.
- 87 entegrasyon testi (63 + 12 + 12) ve 475 birim testi var.
- GoTrue 429 verirse `signIn` dosya başına en fazla 60 sn bekler, sonra açık bir hatayla durur
  (`testTimeout` 90 sn, `hookTimeout` 120 sn).
- Entegrasyon config'i dışında çalıştırılırsa `requireProvidedConfig`, uygulama ve `.env` yüklenmeden açık bir hatayla durdurur.
- Madde 5 (Android DB şifreleme) kapsam dışıdır. E8 (Room + SQLCipher) ile birlikte test edilecek.
- Test kullanıcıları ve kayıtları silinir. Audit satırları append-only olduğu için yerel DB'de
  kalır. Temiz durum için `npx supabase db reset` (yalnızca yerel) çalıştırılır.
