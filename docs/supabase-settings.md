# Supabase Project & Authentication Settings (`OSP-57`)

This document specifies the locked Supabase Cloud and local CLI (`supabase/config.toml`) configuration for the **CONNECT** project (**Epic E10 — Authentication & Access Control**, issues `OSP-57..76`).

---

## 1. Cloud Project & Data Residency (EU Region / KVKK Note)

- **Cloud Region:** Provision the Supabase project in an **EU region** (recommended: **`eu-central-1` — Frankfurt, Germany** or `eu-west-1` — Ireland) for low latency to Turkey and GDPR-aligned infrastructure controls.
- **KVKK Art. 9 Compliance Note (Out-of-Prototype Scope):**
  - During earthquake search-and-rescue operations, victim SOS packets may optionally carry user-consented medical metadata (blood type, chronic conditions, accessibility status).
  - Under Turkish Personal Data Protection Law (**KVKK Article 9**), special-category health data in a production deployment requires explicit legal basis and/or domestic hosting/cross-border transfer safeguards evaluated with legal counsel and AFAD/public authorities outside the scope of this academic prototype.

---

## 2. Locked Authentication & Token Settings (`SCRT-1`, `SCRT-4-1`, `WAPP-1`)

All teammates and environments **must** keep the following settings identical between `supabase/config.toml` and the Supabase Cloud Dashboard (**Authentication → Settings / Providers / Auth**):

| Setting | Config Key (`supabase/config.toml`) | Required Value | Rationale |
| :--- | :--- | :--- | :--- |
| **Public Sign-Up** | `auth.enable_signup` | `false` (`Disabled`) | Self-registration is forbidden. Accounts (`rescuer`, `coordinator`, `administrator`) are provisioned strictly by the System Administrator (`OSP-59` seed / `OSP-66` Admin API). |
| **Anonymous Sign-Ins** | `auth.enable_anonymous_sign_ins` | `false` (`Disabled`) | Android Victim & Relay modes operate 100% offline with zero authentication (`AC-01`). |
| **JWT Access Token Expiry** | `auth.jwt_expiry` | `3600` (`1 hour`) | Short-lived online access tokens; offline field continuity for rescuers is governed separately by the 72-hour `OfflineMissionGrant` (`OSP-60`, `OSP-73`). |
| **Refresh Token Rotation** | `auth.enable_refresh_token_rotation` | `true` (`Enabled`) | Prevents replay of stolen refresh tokens. |
| **Refresh Reuse Detection** | `auth.refresh_token_reuse_interval` | `10` (`10 seconds`) | Automatically invalidates the session family if a rotated refresh token is reused outside the 10-second grace window. |
| **Minimum Password Length** | `auth.minimum_password_length` | `10` | Enforces at least 10 characters for all provisioned accounts. |
| **Password Complexity** | `auth.password_requirements` | `"lower_upper_letters_digits_symbols"` | Requires lowercase, uppercase letters, digits, and symbols (strictly satisfies and strengthens the `letters + digits` baseline). |
| **Email Confirmation** | `auth.email.enable_confirmations` | `true` (`email_confirm: true` on Admin create) | Admin-created accounts are marked confirmed upon creation via `supabase.auth.admin.createUser({ email_confirm: true })`. |

---

## 3. Single Login Flow & Username / Email Convention (`SCRT-1`)

1. **Client-First Authentication:**
   - Web (`connect-web`) and Android (`connect-mobile`) authenticate directly against Supabase Auth using `signInWithPassword` via `@supabase/supabase-js` or `supabase-kt`.
   - There is **no** `POST /api/v1/auth/login` password proxy endpoint on the backend.
2. **Backend Session Binding (`OSP-60`):**
   - Immediately after receiving the Supabase session, the client calls `POST /api/v1/auth/session` with `Authorization: Bearer <access_token>` and `{ device_id, device_name }` to bind the JWT `session_id` to `public.user_devices` and (for `'rescuer'`) obtain the 72-hour `OfflineMissionGrant`.
3. **Username / Email Format (`SCRT-1`):**
   - Provisioned accounts use institutional email addresses or deterministic internal pseudo-emails (`<username>@connect.internal`, e.g., `admin@connect.internal`, `coordinator@connect.internal`, `rescuer@connect.internal`) created with `email_confirm: true`.

---

## 4. Environment Variable & Secret Hygiene

> **CRITICAL SECURITY RULE:** All three GitHub repositories (`connect-backend`, `connect-web`, `connect-mobile`) are **Public**.

- **Never** commit `.env` or `local.properties` to Git.
- **Never** place `SUPABASE_SERVICE_ROLE_KEY` in `connect-web` or `connect-mobile`. Only `connect-backend` may hold `SUPABASE_SERVICE_ROLE_KEY`.
- Copy `.env.example` to `.env` locally and fill in the credentials from **Supabase Dashboard → Project Settings → API**:
  - `SUPABASE_URL`: Project URL (`https://<project-ref>.supabase.co`)
  - `SUPABASE_ANON_KEY`: `anon` `public` key
  - `SUPABASE_SERVICE_ROLE_KEY`: `service_role` `secret` key (**backend only**)

---

## 5. Custom Access Token Hook (`OSP-58`)

Once migration `OSP-58` is applied, enable the **Custom Access Token Hook** (`public.custom_access_token_hook`) in **Supabase Dashboard → Authentication → Hooks (Beta)** (or in `supabase/config.toml` under `[auth.hook.custom_access_token]`). This hook reads `role` from `public.user_profiles` and injects it as `user_role` into the JWT claims—never trusting client-mutable `raw_user_meta_data`.
