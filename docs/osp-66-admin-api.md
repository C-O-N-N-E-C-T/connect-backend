# OSP-66: Administrator API

Scope: `/api/v1/admin/*`, reachable only with `role = 'administrator'`.
Depends on: OSP-58 (tables, token hook), OSP-61 (guard), OSP-62 (`requireRole`), OSP-65 (audit log).

## 1. Endpoints

| Method | Path | Behaviour | Success | Errors |
|---|---|---|---|---|
| GET | `/admin/users?limit&offset` | List profiles with email (paged, newest first) | 200 `{ users, limit, offset }` | 400 bad paging |
| POST | `/admin/users` | Create a `rescuer` or `coordinator` account | 201 `{ user }` | 400 invalid body, **403 `ROLE_FORBIDDEN` for `administrator`**, 409 duplicate email |
| GET | `/admin/users/:id/devices` | Devices of a user (no session ids) | 200 `{ devices }` | 404 unknown user |
| POST | `/admin/users/:id/devices/:deviceId/revoke` | Single-device revoke | 200 `{ status }` | 404 unknown device |
| POST | `/admin/users/:id/revoke-all` | Global revoke: disable + ban + delete all sessions | 200 `{ user }` | 404, 409 when targeting self |
| POST | `/admin/users/:id/reactivate` | Re-enable a disabled account | 200 `{ user }` | 404 |
| GET | `/admin/audit-logs?...` | Filtered, paged audit rows | 200 `{ logs, limit, offset }` | 400 invalid filter |

Every route: `requireAuth` (guard) -> `requireRole('administrator')` -> validation -> store.
Other roles get `403 ROLE_FORBIDDEN` before any validation or database call.

## 2. Acceptance criteria and how they are met

**AC1 - single-device revoke blocks the next call from that device with `403 DEVICE_REVOKED`, other devices keep working.**
The revoke function sets `is_device_revoked = true` and `device_revoked_at = now()`, and deletes that
device's `auth.sessions` row. It deliberately keeps `user_devices.session_id`, because the guard
looks the device up *by session_id*. Clearing it would turn the answer into `SESSION_NOT_BOUND`.
Other devices have their own `session_id`, so they are untouched.

**AC2 - global revoke blocks all sessions with `403 ACCOUNT_DISABLED` and blocks new sign-ins.**
The disable function sets `is_active = false`, `all_sessions_revoked_at = now()` and deletes every
`auth.sessions` row of the user. The guard checks the profile *before* the device, so the answer is
`ACCOUNT_DISABLED`. Then `auth.admin.updateUserById(id, { ban_duration: '876000h' })` blocks new sign-ins.
Order: database first. If the ban call fails, the account is still disabled in the database (the guard
blocks it immediately) and the request answers 500 so the admin retries.

**AC3 - creating an `administrator` returns `403 ROLE_FORBIDDEN`.**
Checked before any Auth or database call, so nothing is created.

## 3. Database (migration `20261123130000_osp66_admin_api.sql`)

All functions are `SECURITY DEFINER` with `search_path = ''`, touch `auth.*` only through their own body,
and are executable by `service_role` alone (`REVOKE` from `PUBLIC`, `anon`, `authenticated`).

| Function | Does, atomically (one transaction) |
|---|---|
| `admin_revoke_session(session_id)` | Deletes that row from `auth.sessions`. Helper, service_role only. |
| `admin_create_user_profile(...)` | Inserts `user_profiles` and the `USER_CREATED` audit row. |
| `admin_revoke_device(...)` | Locks the device row, sets revoke columns, calls `admin_revoke_session`, writes `DEVICE_REVOKED`. Idempotent: a second call writes nothing. |
| `admin_disable_user(...)` | Locks the profile, sets `is_active=false` and `all_sessions_revoked_at`, deletes the user's sessions, writes `ACCOUNT_DISABLED`. |
| `admin_activate_user(...)` | Sets `is_active=true`, writes `USER_REACTIVATED`. `all_sessions_revoked_at` is kept, so tokens issued before the disable stay invalid. |
| `admin_list_users(limit, offset)` | Joins `user_profiles` with `auth.users` for the email. |

Audit rows use the actor from the guard (`req.auth`), never from the body. Targets: `target_record_id`
is the affected **user** id; the device id goes into `metadata`.

## 4. Decisions

- **Self-targeting:** disabling your own account is refused with `409 CONFLICT`. Not in the ticket,
  added because it would lock the only administrator out.
- **Audit scope:** only state changes write a row. A repeated revoke writes nothing.
- **Passwords:** minimum 10 characters, maximum 72 (bcrypt input limit). Complexity is enforced by
  Supabase (`auth.password_requirements`).
- **Email confirmation:** admin-created accounts are confirmed immediately (`email_confirm: true`), as in the seed.
- **Compensation:** if the profile + audit step fails after the Auth user was created, the Auth user is
  deleted again and the request answers 500.

## 5. Tests

Unit/API tests use in-memory stores and a fake Auth admin port. Real Supabase is spied and must not be
called (same pattern as the OSP-65 tests). A shared in-memory directory drives both the admin store and
the real guard, so AC1 and AC2 are verified end to end through the guard.

Database behaviour is checked statically (migration tests) and must be run against a local Supabase
before merge (see section 6).

## 6. Manual verification (local Supabase only, never production)

```
supabase start
supabase db reset                       # applies every migration in order
```

Then call the endpoints with an administrator token against `http://localhost:3000`.
