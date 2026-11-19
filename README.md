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

## Documentation
- [Supabase Project & Auth Settings (`docs/supabase-settings.md`)](./docs/supabase-settings.md)
