# connect-backend

Node.js + Express + TypeScript backend API and Supabase CLI migrations for the **CONNECT** offline-first earthquake search-and-rescue coordination system (**Epic E10 — Authentication & Access Control**).

## Quick Start

1. **Install dependencies:**
   ```bash
   npm install
   ```
2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Fill in `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` in `.env` (never commit `.env`).
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
