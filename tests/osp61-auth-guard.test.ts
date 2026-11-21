import express, { type Request, type Response } from 'express';
import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app, errorHandler } from '../src/app.js';
import { createSupabaseRequestClient } from '../src/config/supabase.js';
import {
  createRequireAuth,
  extractBearerToken,
  type AuthGuardDeps,
} from '../src/middleware/auth.js';
import type { UserDevice, UserProfile } from '../src/types/database.js';

// ---------------------------------------------------------------------------
// Fakes: getClaims + a minimal in-memory PostgREST query builder
// (from(table).select(cols).eq(col, val)...maybeSingle()), no network or database.
// ---------------------------------------------------------------------------

const USER_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_USER_ID = '22222222-2222-4222-8222-222222222222';
const SESSION_ID = '33333333-3333-4333-8333-333333333333';
const DEVICE_ID = '44444444-4444-4444-8444-444444444444';
const OTHER_DEVICE_ID = '55555555-5555-4555-8555-555555555555';
const OTHER_SESSION_ID = '66666666-6666-4666-8666-666666666666';
const TOKEN = 'valid.test.token';

// 2026-11-21T10:00:00Z in epoch seconds
const REVOKED_AT_ISO = '2026-11-21T10:00:00+00:00';
const REVOKED_AT_SECONDS = Date.parse(REVOKED_AT_ISO) / 1000;

interface FakeDb {
  tables: { user_profiles: UserProfile[]; user_devices: UserDevice[] };
  failOn: Set<string>;
  queries: Array<{ table: string; filters: Array<[string, unknown]> }>;
}

function createFakeDbClient(db: FakeDb): AuthGuardDeps['dbClient'] {
  const from = (table: string) => {
    const filters: Array<[string, unknown]> = [];
    const builder = {
      select: (_columns: string) => builder,
      eq: (column: string, value: unknown) => {
        filters.push([column, value]);
        return builder;
      },
      maybeSingle: async () => {
        db.queries.push({ table, filters: [...filters] });
        if (db.failOn.has(table)) {
          return { data: null, error: { message: `relation "${table}" secret internal detail` } };
        }
        const tableRows: ReadonlyArray<object> = db.tables[table as keyof FakeDb['tables']] ?? [];
        const rows = tableRows.filter((row) =>
          filters.every(([column, value]) => (row as Record<string, unknown>)[column] === value),
        );
        if (rows.length > 1) {
          return { data: null, error: { message: 'multiple rows returned' } };
        }
        return { data: rows[0] ?? null, error: null };
      },
    };
    return builder;
  };
  return { from } as unknown as AuthGuardDeps['dbClient'];
}

function profile(overrides: Partial<UserProfile> = {}): UserProfile {
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

function device(overrides: Partial<UserDevice> = {}): UserDevice {
  return {
    id: '77777777-7777-4777-8777-777777777777',
    user_id: USER_ID,
    device_id: DEVICE_ID,
    device_name: 'Test phone',
    session_id: SESSION_ID,
    last_login_at: '2026-11-21T09:00:00+00:00',
    is_device_revoked: false,
    device_revoked_at: null,
    ...overrides,
  };
}

function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: USER_ID,
    session_id: SESSION_ID,
    iat: REVOKED_AT_SECONDS + 60,
    exp: REVOKED_AT_SECONDS + 3660,
    role: 'authenticated',
    // The JWT role claim must be ignored in favour of user_profiles.role.
    user_role: 'administrator',
    ...overrides,
  };
}

let db: FakeDb;
let getClaims: ReturnType<typeof vi.fn>;

function claimsOk(value: Record<string, unknown>) {
  return { data: { claims: value, header: { alg: 'ES256' }, signature: new Uint8Array() }, error: null };
}

function buildTestApp(authClient?: AuthGuardDeps['authClient']) {
  const testApp = express();
  const requireAuth = createRequireAuth({
    authClient: authClient ?? ({ auth: { getClaims } } as unknown as AuthGuardDeps['authClient']),
    dbClient: createFakeDbClient(db),
  });
  testApp.get('/protected', requireAuth, (req: Request, res: Response) => {
    res.status(200).json({ auth: req.auth });
  });
  testApp.use(errorHandler);
  return testApp;
}

const callProtected = (headers: Record<string, string> = { Authorization: `Bearer ${TOKEN}` }) =>
  request(buildTestApp()).get('/protected').set(headers);

function expectError(
  res: request.Response,
  status: number,
  errorCode: string,
) {
  expect(res.status).toBe(status);
  expect(res.body).toEqual({ error_code: errorCode, message: expect.any(String) });
  expect(Object.keys(res.body).sort()).toEqual(['error_code', 'message']);
}

beforeEach(() => {
  db = {
    tables: { user_profiles: [profile()], user_devices: [device()] },
    failOn: new Set(),
    queries: [],
  };
  getClaims = vi.fn(async (token: string) =>
    token === TOKEN
      ? claimsOk(claims())
      : { data: null, error: { name: 'AuthInvalidJwtError', message: 'Invalid JWT' } },
  );
});

describe('OSP-61: Bearer header parsing', () => {
  it('extractBearerToken accepts only "Bearer <token>" (scheme case-insensitive)', () => {
    expect(extractBearerToken('Bearer abc')).toBe('abc');
    expect(extractBearerToken('bearer abc')).toBe('abc');
    expect(extractBearerToken(undefined)).toBeNull();
    expect(extractBearerToken('')).toBeNull();
    expect(extractBearerToken('Bearer')).toBeNull();
    expect(extractBearerToken('Bearer ')).toBeNull();
    expect(extractBearerToken('Bearer  abc')).toBeNull();
    expect(extractBearerToken('Bearer abc def')).toBeNull();
    expect(extractBearerToken('Basic abc')).toBeNull();
    expect(extractBearerToken('abc')).toBeNull();
  });

  it('401 UNAUTHENTICATED without an Authorization header', async () => {
    expectError(await callProtected({}), 401, 'UNAUTHENTICATED');
    expect(getClaims).not.toHaveBeenCalled();
  });

  it('401 UNAUTHENTICATED for a non-Bearer scheme', async () => {
    expectError(await callProtected({ Authorization: `Basic ${TOKEN}` }), 401, 'UNAUTHENTICATED');
    expect(getClaims).not.toHaveBeenCalled();
  });

  it('401 UNAUTHENTICATED for an empty Bearer token', async () => {
    expectError(await callProtected({ Authorization: 'Bearer ' }), 401, 'UNAUTHENTICATED');
    expectError(await callProtected({ Authorization: 'Bearer' }), 401, 'UNAUTHENTICATED');
    expect(getClaims).not.toHaveBeenCalled();
  });

  it('passes the raw token to getClaims explicitly', async () => {
    await callProtected({ Authorization: `bearer ${TOKEN}` });
    expect(getClaims).toHaveBeenCalledWith(TOKEN);
  });
});

describe('OSP-61: token verification (getClaims)', () => {
  it('401 UNAUTHENTICATED when getClaims returns an error', async () => {
    expectError(await callProtected({ Authorization: 'Bearer forged.token.value' }), 401, 'UNAUTHENTICATED');
    expect(db.queries).toHaveLength(0);
  });

  it('401 UNAUTHENTICATED when getClaims returns null data without an error', async () => {
    getClaims.mockResolvedValueOnce({ data: null, error: null });
    expectError(await callProtected(), 401, 'UNAUTHENTICATED');
  });

  it('401 UNAUTHENTICATED when getClaims throws', async () => {
    getClaims.mockRejectedValueOnce(new SyntaxError('Unexpected token in JSON'));
    expectError(await callProtected(), 401, 'UNAUTHENTICATED');
  });

  it('401 UNAUTHENTICATED for an expired token (getClaims error)', async () => {
    getClaims.mockResolvedValueOnce({
      data: null,
      error: { name: 'AuthInvalidJwtError', message: 'JWT has expired' },
    });
    expectError(await callProtected(), 401, 'UNAUTHENTICATED');
  });

  it.each(['sub', 'session_id', 'iat'])('401 UNAUTHENTICATED when the %s claim is missing', async (claim) => {
    const value = claims();
    delete value[claim];
    getClaims.mockResolvedValueOnce(claimsOk(value));
    expectError(await callProtected(), 401, 'UNAUTHENTICATED');
    expect(db.queries).toHaveLength(0);
  });

  it.each([
    ['sub', 12345],
    ['sub', 'not-a-uuid'],
    ['session_id', ''],
    ['session_id', 'not-a-uuid'],
    ['iat', '1790000000'],
  ])('401 UNAUTHENTICATED when the %s claim is ill-typed (%s)', async (claim, bad) => {
    getClaims.mockResolvedValueOnce(claimsOk(claims({ [claim]: bad })));
    expectError(await callProtected(), 401, 'UNAUTHENTICATED');
    expect(db.queries).toHaveLength(0);
  });

  describe('with the real auth-js getClaims (no network reached)', () => {
    const realVerifier = createSupabaseRequestClient();
    const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

    it('401 UNAUTHENTICATED for a malformed token that makes getClaims throw', async () => {
      const res = await request(buildTestApp(realVerifier))
        .get('/protected')
        .set('Authorization', 'Bearer aaa.bbb.ccc');
      expectError(res, 401, 'UNAUTHENTICATED');
    });

    it('401 UNAUTHENTICATED for a non-JWT token', async () => {
      const res = await request(buildTestApp(realVerifier))
        .get('/protected')
        .set('Authorization', 'Bearer not-a-jwt');
      expectError(res, 401, 'UNAUTHENTICATED');
    });

    it('401 UNAUTHENTICATED for an expired token (rejected locally by the exp check)', async () => {
      const nowSeconds = Math.floor(Date.now() / 1000);
      const expired = [
        b64({ alg: 'ES256', kid: 'test-kid', typ: 'JWT' }),
        b64(claims({ iat: nowSeconds - 7200, exp: nowSeconds - 3600 })),
        Buffer.from('signature').toString('base64url'),
      ].join('.');
      const res = await request(buildTestApp(realVerifier))
        .get('/protected')
        .set('Authorization', `Bearer ${expired}`);
      expectError(res, 401, 'UNAUTHENTICATED');
      expect(db.queries).toHaveLength(0);
    });
  });
});

describe('OSP-61: account state (user_profiles)', () => {
  it('403 ACCOUNT_DISABLED when the profile row is missing', async () => {
    db.tables.user_profiles = [];
    expectError(await callProtected(), 403, 'ACCOUNT_DISABLED');
  });

  it('403 ACCOUNT_DISABLED when is_active is false', async () => {
    db.tables.user_profiles = [profile({ is_active: false })];
    expectError(await callProtected(), 403, 'ACCOUNT_DISABLED');
  });

  it('403 ACCOUNT_DISABLED when iat == all_sessions_revoked_at', async () => {
    db.tables.user_profiles = [profile({ all_sessions_revoked_at: REVOKED_AT_ISO })];
    getClaims.mockResolvedValueOnce(claimsOk(claims({ iat: REVOKED_AT_SECONDS })));
    expectError(await callProtected(), 403, 'ACCOUNT_DISABLED');
  });

  it('403 ACCOUNT_DISABLED when iat < all_sessions_revoked_at', async () => {
    db.tables.user_profiles = [profile({ all_sessions_revoked_at: REVOKED_AT_ISO })];
    getClaims.mockResolvedValueOnce(claimsOk(claims({ iat: REVOKED_AT_SECONDS - 1 })));
    expectError(await callProtected(), 403, 'ACCOUNT_DISABLED');
  });

  it('403 ACCOUNT_DISABLED when the token was issued in the same second, before a sub-second revocation', async () => {
    // Revoked at 10:00:00.500; iat 10:00:00 (token issued at 10:00:00.xxx, floored).
    db.tables.user_profiles = [profile({ all_sessions_revoked_at: '2026-11-21T10:00:00.500123+00:00' })];
    getClaims.mockResolvedValueOnce(claimsOk(claims({ iat: REVOKED_AT_SECONDS })));
    expectError(await callProtected(), 403, 'ACCOUNT_DISABLED');
  });

  it('passes when iat > all_sessions_revoked_at', async () => {
    db.tables.user_profiles = [profile({ all_sessions_revoked_at: REVOKED_AT_ISO })];
    getClaims.mockResolvedValueOnce(claimsOk(claims({ iat: REVOKED_AT_SECONDS + 1 })));
    const res = await callProtected();
    expect(res.status).toBe(200);
  });

  it('500 INTERNAL_ERROR (fail closed) when all_sessions_revoked_at is unparseable', async () => {
    db.tables.user_profiles = [profile({ all_sessions_revoked_at: 'garbage' })];
    expectError(await callProtected(), 500, 'INTERNAL_ERROR');
  });

  it('500 INTERNAL_ERROR without internal details when the profile query fails', async () => {
    db.failOn.add('user_profiles');
    const res = await callProtected();
    expectError(res, 500, 'INTERNAL_ERROR');
    expect(JSON.stringify(res.body)).not.toContain('secret internal detail');
  });
});

describe('OSP-61: device binding (user_devices)', () => {
  it('403 SESSION_NOT_BOUND when no device row matches the session_id claim', async () => {
    db.tables.user_devices = [device({ session_id: OTHER_SESSION_ID })];
    expectError(await callProtected(), 403, 'SESSION_NOT_BOUND');
  });

  it('403 SESSION_NOT_BOUND when the session is bound to a device of another user', async () => {
    db.tables.user_devices = [device({ user_id: OTHER_USER_ID })];
    expectError(await callProtected(), 403, 'SESSION_NOT_BOUND');
  });

  it('403 DEVICE_REVOKED when the bound device is revoked', async () => {
    db.tables.user_devices = [
      device({ is_device_revoked: true, device_revoked_at: '2026-11-21T11:00:00+00:00' }),
    ];
    expectError(await callProtected(), 403, 'DEVICE_REVOKED');
  });

  it('ACCOUNT_DISABLED takes precedence over device checks', async () => {
    db.tables.user_profiles = [profile({ is_active: false })];
    db.tables.user_devices = [device({ is_device_revoked: true })];
    expectError(await callProtected(), 403, 'ACCOUNT_DISABLED');
    expect(db.queries.map((q) => q.table)).toEqual(['user_profiles']);
  });

  it('500 INTERNAL_ERROR without internal details when the device query fails', async () => {
    db.failOn.add('user_devices');
    const res = await callProtected();
    expectError(res, 500, 'INTERNAL_ERROR');
    expect(JSON.stringify(res.body)).not.toContain('secret internal detail');
  });

  it('500 INTERNAL_ERROR (fail closed) when one session_id is bound to several device rows', async () => {
    db.tables.user_devices = [device(), device({ device_id: OTHER_DEVICE_ID })];
    expectError(await callProtected(), 500, 'INTERNAL_ERROR');
  });

  it('spoofed X-Device-Id / X-Session-Id headers do not change the outcome', async () => {
    db.tables.user_devices = [
      device({ is_device_revoked: true }),
      device({ device_id: OTHER_DEVICE_ID, session_id: OTHER_SESSION_ID }),
    ];
    const spoofed = {
      Authorization: `Bearer ${TOKEN}`,
      'X-Device-Id': OTHER_DEVICE_ID,
      'X-Session-Id': OTHER_SESSION_ID,
    };
    expectError(await callProtected(spoofed), 403, 'DEVICE_REVOKED');

    db.tables.user_devices = [device(), device({ device_id: OTHER_DEVICE_ID, session_id: OTHER_SESSION_ID })];
    const ok = await callProtected(spoofed);
    expect(ok.status).toBe(200);
    expect(ok.body.auth.device_id).toBe(DEVICE_ID);
    expect(ok.body.auth.session_id).toBe(SESSION_ID);
  });
});

describe('OSP-61: success', () => {
  it('attaches { user_id, role (from DB), device_id, session_id } and calls next()', async () => {
    const res = await callProtected();
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      auth: { user_id: USER_ID, role: 'rescuer', device_id: DEVICE_ID, session_id: SESSION_ID },
    });
    // Queries use only the verified claims.
    expect(db.queries).toEqual([
      { table: 'user_profiles', filters: [['id', USER_ID]] },
      { table: 'user_devices', filters: [['session_id', SESSION_ID], ['user_id', USER_ID]] },
    ]);
  });

  it('re-checks the database on every request: revoking the device rejects the very next request', async () => {
    const testApp = buildTestApp();
    const first = await request(testApp).get('/protected').set('Authorization', `Bearer ${TOKEN}`);
    expect(first.status).toBe(200);

    db.tables.user_devices = [device({ is_device_revoked: true })];
    const second = await request(testApp).get('/protected').set('Authorization', `Bearer ${TOKEN}`);
    expectError(second, 403, 'DEVICE_REVOKED');
  });
});

// Real app: no Authorization header is sent, so the guard rejects before any network call.
// Keep the number of /api/v1/auth/* requests in this file below the rate limit (10/min).
describe('OSP-61: guard mounting in the real app', () => {
  it('GET /api/v1/health is public', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
  });

  it('POST /api/v1/auth/session is not guarded (404 until OSP-60 adds the route)', async () => {
    const res = await request(app).post('/api/v1/auth/session');
    expectError(res, 404, 'NOT_FOUND');
  });

  it.each([
    ['post', '/api/v1/auth/session-evil'],
    ['post', '/api/v1/auth/sessionX'],
    ['post', '/api/v1/auth/session/'],
    ['post', '/api/v1/auth/session/extra'],
    ['get', '/api/v1/auth/session'],
    ['post', '/api/v1/auth/logout'],
    ['get', '/api/v1/whatever'],
    ['post', '/api/v1/health'],
    ['get', '/api/v1'],
  ] as const)('%s %s is guarded (401)', async (method, path) => {
    const res = await request(app)[method](path);
    expectError(res, 401, 'UNAUTHENTICATED');
    // The OSP-64 auth rate limiter runs before the guard on /api/v1/auth/*.
    if (path.startsWith('/api/v1/auth/')) {
      expect(res.headers['ratelimit-limit']).toBe('10');
    }
  });

  it('paths outside /api/v1 still return 404', async () => {
    expectError(await request(app).get('/whatever'), 404, 'NOT_FOUND');
    expectError(await request(app).get('/api/v2/whatever'), 404, 'NOT_FOUND');
    expectError(await request(app).get('/api/v1x/whatever'), 404, 'NOT_FOUND');
  });

  it('GET /health stays public', async () => {
    expect((await request(app).get('/health')).status).toBe(200);
  });
});
