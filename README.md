# connect-backend

Node.js + Express + TypeScript backend API and Supabase CLI migrations for the **CONNECT** offline-first earthquake search-and-rescue coordination system (**Epic E10 — Authentication & Access Control**).

## Quick Start

1. **Install Node.js & dependencies:**
   Requires **Node.js `26.x` Active LTS** (fallback `24.x`; see `.nvmrc`).
   ```bash
   npm ci
   npx supabase --version
   ```
2. **Configure & verify environment variables:**
   ```bash
   cp .env.example .env
   ```
   Fill in `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, and `DATABASE_URL` in `.env` (never commit `.env`), then verify your local setup:
   ```bash
   node scripts/check-env.mjs
   ```
3. **Run in development mode:**
   ```bash
   npm run dev
   ```
4. **Seed pre-provisioned accounts (`OSP-59`, idempotent):**
   Fill `SEED_*` email and password variables in `.env`, then run:
   ```bash
   npm run seed
   ```
   This provisions the `'administrator'`, `'coordinator'`, and `'rescuer'` accounts via Supabase Auth Admin API (`email_confirm: true`, `app_metadata.role`) and upserts their `public.user_profiles` rows. Re-running `npm run seed` produces no duplicates or errors.
5. **Run tests & typecheck:**
   ```bash
   npm run typecheck
   npm test
   ```

## Environment Variables

| Variable | Local (`development`) | Render (`production`) | Purpose |
| --- | --- | --- | --- |
| `NODE_ENV` | `development` | `production` | Enables HTTPS enforcement (`426 HTTPS_REQUIRED` for plain HTTP) and hides internal error details. |
| `PORT` | `3000` | Set by Render | HTTP port the server listens on. |
| `CORS_ORIGIN` | `http://localhost:5173` | Web Coordination Dashboard URL | The only origin allowed by CORS. |
| `TRUST_PROXY` | `0` | `1` | Number of reverse-proxy hops in front of the app. Needed so HTTPS detection and per-IP rate limiting see the real client. Leave `0` when no proxy is present. |
| `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `DATABASE_URL` | Local/dev project | Production project | Supabase and database connection. Never expose the service role key to clients. |

## Security Behavior

- **HTTPS (NFR-SEC-02, AC-19):** In production, plain HTTP requests are rejected with `426 Upgrade Required`. TLS is terminated by Render, not by the app.
- **HSTS:** Responses include `Strict-Transport-Security` with a one-year max-age and `includeSubDomains`.
- **CORS:** Only `CORS_ORIGIN` receives an `Access-Control-Allow-Origin` header.
- **Rate limiting:** `/api/v1/auth/*` allows 10 requests per minute per client IP. Exceeding it returns `429 RATE_LIMITED`. The counter is in memory, so it applies per running instance. Exception: `GET /api/v1/auth/me` (OSP-70 dashboard session check) is not counted.

## Auth Endpoints (OSP-60)

| Endpoint | Guarded | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/session` | No (verifies the token itself) | Called right after Supabase sign-in with `{device_id, device_name}`. Binds the token's `session_id` to the device, writes a `LOGIN` audit row and returns `{user_id, role, device_id}`, plus a 72 h unsigned `offline_mission_grant` for rescuers. |
| `POST /api/v1/auth/logout` | Yes | Clears this session's device binding and writes a `LOGOUT` audit row. `204`, no body. Call it before Supabase `signOut()`. |
| `GET /api/v1/auth/me` | Yes | OSP-70 lightweight session check for the web dashboard. `200` `{user_id, role, device_id}` with `Cache-Control: no-store`; no audit row. A revoked device/account gets the guard's `403`. Exempt from the `/api/v1/auth/*` rate limit (exact `GET` only). |

Until `/auth/session` succeeds, every guarded request with that token gets `403 SESSION_NOT_BOUND`. Full contract and error codes: [docs/osp-60-auth-session.md](docs/osp-60-auth-session.md).

## Administrator Endpoints (OSP-66)

All of these require a token whose user has `role = 'administrator'`. Other roles get `403 ROLE_FORBIDDEN`.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/admin/users?limit&offset` | List accounts (paged, newest first). |
| `POST /api/v1/admin/users` | Create a `rescuer` or `coordinator` account. `administrator` is refused with `403 ROLE_FORBIDDEN`. |
| `GET /api/v1/admin/users/:id/devices` | Devices of a user. Session ids are never returned. |
| `POST /api/v1/admin/users/:id/devices/:deviceId/revoke` | Revoke one device. Its next call gets `403 DEVICE_REVOKED`; other devices are unaffected. |
| `POST /api/v1/admin/users/:id/revoke-all` | Disable the account and delete all its sessions. Its calls get `403 ACCOUNT_DISABLED`. Refused for your own account (`409`). |
| `POST /api/v1/admin/users/:id/reactivate` | Re-enable a disabled account. Tokens issued before the disable stay invalid. |
| `GET /api/v1/admin/audit-logs` | Filter by `action_type`, `actor_user_id`, `target_record_id`, `from`, `to`; paged. |

Design, database functions and the manual verification steps: [docs/osp-66-admin-api.md](docs/osp-66-admin-api.md).

## Deployment (Render)

1. **Create a Web Service** in Render from this repository (Node runtime, `26.x` or `24.x` to match `.nvmrc`).
2. **Build command:** `npm ci && npm run build`
3. **Start command:** `npm start`
4. **Environment variables:** Add the production values from the table above in the Render dashboard. Set `NODE_ENV=production` and `TRUST_PROXY=1`. Do not upload `.env`.
5. **Verify after the first deploy:**
   ```bash
   # Plain HTTP must be rejected (expect 426 HTTPS_REQUIRED)
   curl -i http://<your-service>.onrender.com/api/v1/health

   # HTTPS must work and send HSTS (expect 200 and Strict-Transport-Security)
   curl -I https://<your-service>.onrender.com/api/v1/health
   ```

## Documentation
- [Supabase Project & Auth Settings (`docs/supabase-settings.md`)](./docs/supabase-settings.md)
- [Deny-by-default RLS and table privileges, OSP-63 (`docs/osp-63-rls.md`)](./docs/osp-63-rls.md)
