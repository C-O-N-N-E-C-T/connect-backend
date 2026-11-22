/**
 * OSP-60 test fakes: one in-memory "database" shared by
 *   - the OSP-61 guard's dbClient (`from(...).select().eq().maybeSingle()` reads), and
 *   - an in-memory SessionStore that mirrors the OSP-60 SQL functions (writes).
 * Because both use the same tables, a test can bind a session through /auth/session and then
 * prove that the guard accepts the same token on a protected route. No network, no Supabase.
 */
import type { Request, Response } from 'express';
import { AuthInvalidJwtError } from '@supabase/supabase-js';
import { vi } from 'vitest';
import { createApp } from '../../src/app.js';
import type { AuthGuardDeps } from '../../src/middleware/auth.js';
import type { BindSessionResult, SessionStore } from '../../src/services/session-store.js';
import type { AppRole, AuditLog, UserDevice, UserProfile } from '../../src/types/database.js';

export const USER_ID = '11111111-1111-4111-8111-111111111111';
export const OTHER_USER_ID = '22222222-2222-4222-8222-222222222222';
export const SESSION_ID = '33333333-3333-4333-8333-333333333333';
export const NEW_SESSION_ID = '66666666-6666-4666-8666-666666666666';
export const DEVICE_ID = '44444444-4444-4444-8444-444444444444';
export const OTHER_DEVICE_ID = '55555555-5555-4555-8555-555555555555';

/** Token strings the fake getClaims accepts; anything else is an invalid JWT. */
export const TOKEN = 'token.session.one';
export const NEW_TOKEN = 'token.session.two';
export const OTHER_USER_TOKEN = 'token.other.user';

/** Fixed DB clock (what now() returns inside bind_device_session). */
export const NOW_ISO = '2026-11-22T10:00:00.000Z';
export const IAT_SECONDS = Date.parse(NOW_ISO) / 1000 - 60;

export interface FakeTables {
  user_profiles: UserProfile[];
  user_devices: UserDevice[];
  audit_logs: Array<Pick<AuditLog, 'actor_user_id' | 'actor_role' | 'device_id' | 'action_type' | 'metadata'>>;
}

export interface FakeWorld {
  tables: FakeTables;
  /** token -> JWT claims returned by the fake getClaims. */
  tokens: Map<string, Record<string, unknown>>;
  getClaims: ReturnType<typeof vi.fn>;
  store: SessionStore & {
    bindSession: ReturnType<typeof vi.fn>;
    unbindSession: ReturnType<typeof vi.fn>;
    recordRejectedLogin: ReturnType<typeof vi.fn>;
  };
  deps: AuthGuardDeps;
}

export function profile(overrides: Partial<UserProfile> = {}): UserProfile {
  return {
    id: USER_ID,
    full_name: 'Test Rescuer',
    role: 'rescuer',
    is_active: true,
    all_sessions_revoked_at: null,
    created_at: '2026-11-01T00:00:00+00:00',
    ...overrides,
  };
}

export function device(overrides: Partial<UserDevice> = {}): UserDevice {
  return {
    id: `row-${Math.random().toString(16).slice(2)}`,
    user_id: USER_ID,
    device_id: DEVICE_ID,
    device_name: 'Old name',
    session_id: null,
    last_login_at: null,
    is_device_revoked: false,
    device_revoked_at: null,
    ...overrides,
  };
}

export function claims(sub: string, sessionId: string, overrides: Record<string, unknown> = {}) {
  return {
    sub,
    session_id: sessionId,
    iat: IAT_SECONDS,
    exp: IAT_SECONDS + 3600,
    aud: 'authenticated',
    // Must be ignored: the role always comes from user_profiles.
    user_role: 'administrator',
    ...overrides,
  };
}

export function createFakeWorld(): FakeWorld {
  const tables: FakeTables = {
    user_profiles: [profile()],
    user_devices: [],
    audit_logs: [],
  };

  const tokens = new Map<string, Record<string, unknown>>([
    [TOKEN, claims(USER_ID, SESSION_ID)],
    [NEW_TOKEN, claims(USER_ID, NEW_SESSION_ID)],
    [OTHER_USER_TOKEN, claims(OTHER_USER_ID, '77777777-7777-4777-8777-777777777777')],
  ]);

  const getClaims = vi.fn(async (token: string) => {
    const value = tokens.get(token);
    if (!value) return { data: null, error: new AuthInvalidJwtError('Invalid JWT') };
    return { data: { claims: value, header: { alg: 'ES256' }, signature: new Uint8Array() }, error: null };
  });

  // Read side (guard): same minimal PostgREST builder as tests/osp61-auth-guard.test.ts.
  const from = (table: string) => {
    const filters: Array<[string, unknown]> = [];
    const builder = {
      select: (_columns: string) => builder,
      eq: (column: string, value: unknown) => {
        filters.push([column, value]);
        return builder;
      },
      maybeSingle: async () => {
        const rows = ((tables[table as keyof FakeTables] ?? []) as object[]).filter((row) =>
          filters.every(([column, value]) => (row as Record<string, unknown>)[column] === value),
        );
        if (rows.length > 1) return { data: null, error: { message: 'multiple rows returned' } };
        return { data: rows[0] ?? null, error: null };
      },
    };
    return builder;
  };

  // Write side: mirrors supabase/migrations/20261122100000_osp60_session_binding.sql.
  const store = {
    bindSession: vi.fn(async (input): Promise<BindSessionResult> => {
      const existing = tables.user_devices.find(
        (row) => row.user_id === input.user_id && row.device_id === input.device_id,
      );
      if (existing?.is_device_revoked) {
        tables.audit_logs.push({
          actor_user_id: input.user_id,
          actor_role: input.role,
          device_id: input.device_id,
          action_type: 'LOGIN_REJECTED',
          metadata: { reason: 'DEVICE_REVOKED' },
        });
        return { status: 'DEVICE_REVOKED' };
      }
      for (const row of tables.user_devices) {
        if (row.session_id === input.session_id && row !== existing) row.session_id = null;
      }
      if (existing) {
        existing.device_name = input.device_name;
        existing.session_id = input.session_id;
        existing.last_login_at = NOW_ISO;
      } else {
        tables.user_devices.push(
          device({
            user_id: input.user_id,
            device_id: input.device_id,
            device_name: input.device_name,
            session_id: input.session_id,
            last_login_at: NOW_ISO,
          }),
        );
      }
      tables.audit_logs.push({
        actor_user_id: input.user_id,
        actor_role: input.role,
        device_id: input.device_id,
        action_type: 'LOGIN',
        metadata: { session_id: input.session_id },
      });
      // Postgres jsonb renders timestamptz with an offset, not "Z".
      return { status: 'BOUND', authenticated_at: '2026-11-22T10:00:00+00:00' };
    }),
    unbindSession: vi.fn(async (input) => {
      for (const row of tables.user_devices) {
        if (row.user_id === input.user_id && row.session_id === input.session_id) row.session_id = null;
      }
      tables.audit_logs.push({
        actor_user_id: input.user_id,
        actor_role: input.role,
        device_id: input.device_id,
        action_type: 'LOGOUT',
        metadata: { session_id: input.session_id },
      });
    }),
    recordRejectedLogin: vi.fn(async (input) => {
      tables.audit_logs.push({
        actor_user_id: input.user_id,
        actor_role: input.role as AppRole | null,
        device_id: input.device_id,
        action_type: 'LOGIN_REJECTED',
        metadata: { reason: input.reason, user_id: input.user_id },
      });
    }),
  } as FakeWorld['store'];

  const deps = {
    authClient: { auth: { getClaims } },
    dbClient: { from },
  } as unknown as AuthGuardDeps;

  return { tables, tokens, getClaims, store, deps };
}

/**
 * Real app wired to the fakes. A fresh app per call also gives a fresh auth rate-limit budget
 * (10/min). `GET /api/v1/test/whoami` is a test-only protected route that echoes req.auth.
 */
export function createTestApp(world: FakeWorld) {
  return createApp({
    authGuardDeps: world.deps,
    sessionStore: world.store,
    registerProtectedRoutes: (router) => {
      router.get('/test/whoami', (req: Request, res: Response) => {
        res.status(200).json({ auth: req.auth });
      });
    },
  });
}
