import express, { type Request, type Response } from 'express';
import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp, errorHandler } from '../src/app.js';
import { env } from '../src/config/env.js';
import {
  AuthApiError,
  AuthInvalidJwtError,
  AuthRetryableFetchError,
  AuthSessionMissingError,
  AuthUnknownError,
} from '@supabase/supabase-js';
import { createTokenVerifierClient } from '../src/config/supabase.js';
import {
  createAuthGuard,
  createRequireAuth,
  extractBearerToken,
  verifyAccessToken,
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
    aud: 'authenticated',
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
    const realVerifier = createTokenVerifierClient();
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

// Real app (createApp). A fresh app per test gives a fresh auth rate-limit budget.
// Without an Authorization header the default guard rejects before any network call.
describe('OSP-61: guard mounting in the real app', () => {
  it('GET and HEAD /api/v1/health are public', async () => {
    expect((await request(createApp()).get('/api/v1/health')).status).toBe(200);
    expect((await request(createApp()).head('/api/v1/health')).status).toBe(200);
  });

  it('POST /api/v1/auth/session is not guarded (404 placeholder until OSP-60)', async () => {
    const res = await request(createApp()).post('/api/v1/auth/session?x=1');
    expectError(res, 404, 'NOT_FOUND');
    expect(res.headers['www-authenticate']).toBeUndefined();
  });

  it.each([
    ['post', '/api/v1/auth/session-evil'],
    ['post', '/api/v1/auth/sessionX'],
    ['post', '/api/v1/auth/session/'],
    ['post', '/api/v1/auth/session/extra'],
    ['post', '/API/V1/AUTH/SESSION'],
    ['post', '/api/v1/auth/Session'],
    ['post', '/api/v1/auth/%73ession'],
    ['post', '/api/v1//auth/session'],
    ['post', '/api/v1/auth//session'],
    ['post', '/api/v1/auth/session%2F'],
    ['post', '/api/v1/auth/session/../../admin'],
    ['get', '/api/v1/auth/session'],
    ['post', '/api/v1/auth/logout'],
    ['get', '/api/v1/whatever'],
    ['post', '/api/v1/health'],
    ['get', '/api/v1/health/'],
    ['get', '/API/V1/HEALTH'],
    ['get', '/api/v1'],
  ] as const)('%s %s is guarded (401)', async (method, path) => {
    const res = await request(createApp())[method](path);
    expectError(res, 401, 'UNAUTHENTICATED');
    expect(res.headers['www-authenticate']).toBe('Bearer');
    // The OSP-64 auth rate limiter runs before the guard on /api/v1/auth/*.
    if (path.toLowerCase().startsWith('/api/v1/auth/')) {
      expect(res.headers['ratelimit-limit']).toBe('10');
    }
  });

  it('paths outside /api/v1 still return 404', async () => {
    const testApp = createApp();
    expectError(await request(testApp).get('/whatever'), 404, 'NOT_FOUND');
    expectError(await request(testApp).get('/api/v2/whatever'), 404, 'NOT_FOUND');
    expectError(await request(testApp).get('/api/v1x/whatever'), 404, 'NOT_FOUND');
  });

  it('GET /health stays public', async () => {
    expect((await request(createApp()).get('/health')).status).toBe(200);
  });

  it('CORS preflight to a guarded path is answered before the guard', async () => {
    const res = await request(createApp())
      .options('/api/v1/whatever')
      .set('Origin', env.CORS_ORIGIN)
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'authorization,content-type');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe(env.CORS_ORIGIN);
  });

  it('401 responses to the allowed origin carry CORS headers so browsers can read them', async () => {
    const res = await request(createApp()).get('/api/v1/whatever').set('Origin', env.CORS_ORIGIN);
    expect(res.status).toBe(401);
    expect(res.headers['access-control-allow-origin']).toBe(env.CORS_ORIGIN);
  });
});

describe('OSP-61 R4/R9: protected router extension point and real-app success path', () => {
  function appWithFakes() {
    return createApp({
      authGuardDeps: {
        authClient: { auth: { getClaims } } as unknown as AuthGuardDeps['authClient'],
        dbClient: createFakeDbClient(db),
      },
      registerProtectedRoutes: (router) => {
        router.get('/test/whoami', (req: Request, res: Response) => {
          res.status(200).json({ auth: req.auth });
        });
        router.post('/test/echo', (req: Request, res: Response) => {
          res.status(200).json({ body: req.body, auth: req.auth });
        });
      },
    });
  }

  it('a route registered on the protected router is unreachable without a token', async () => {
    const res = await request(appWithFakes()).get('/api/v1/test/whoami');
    expectError(res, 401, 'UNAUTHENTICATED');
    expect(getClaims).not.toHaveBeenCalled();
  });

  it('the default app guards the protected router too (no fakes)', async () => {
    const res = await request(
      createApp({
        registerProtectedRoutes: (router) => {
          router.get('/test/open', (_req: Request, res: Response) => {
            res.status(200).json({ reached: true });
          });
        },
      }),
    ).get('/api/v1/test/open');
    expectError(res, 401, 'UNAUTHENTICATED');
  });

  it('success through the real app attaches req.auth with the role from the DB', async () => {
    const res = await request(appWithFakes())
      .get('/api/v1/test/whoami')
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      auth: { user_id: USER_ID, role: 'rescuer', device_id: DEVICE_ID, session_id: SESSION_ID },
    });
  });

  it.each([
    ['ACCOUNT_DISABLED', () => (db.tables.user_profiles = [profile({ is_active: false })])],
    ['SESSION_NOT_BOUND', () => (db.tables.user_devices = [])],
    ['DEVICE_REVOKED', () => (db.tables.user_devices = [device({ is_device_revoked: true })])],
  ])('403 %s through the real app', async (code, arrange) => {
    arrange();
    const res = await request(appWithFakes())
      .get('/api/v1/test/whoami')
      .set('Authorization', `Bearer ${TOKEN}`);
    expectError(res, 403, code);
  });

  it('authenticated request to an unknown /api/v1 path gets 404', async () => {
    const res = await request(appWithFakes())
      .get('/api/v1/does-not-exist')
      .set('Authorization', `Bearer ${TOKEN}`);
    expectError(res, 404, 'NOT_FOUND');
  });

  it('protected routes receive a parsed JSON body after authentication', async () => {
    const res = await request(appWithFakes())
      .post('/api/v1/test/echo')
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ hello: 'world' });
    expect(res.status).toBe(200);
    expect(res.body.body).toEqual({ hello: 'world' });
    expect(res.body.auth.user_id).toBe(USER_ID);
  });
});

describe('OSP-61 R3: body parsing runs after the guard; parser errors -> 400', () => {
  const bigBody = JSON.stringify({ data: 'x'.repeat(1024 * 1024 + 10) });

  function appWithFakes() {
    return createApp({
      authGuardDeps: {
        authClient: { auth: { getClaims } } as unknown as AuthGuardDeps['authClient'],
        dbClient: createFakeDbClient(db),
      },
      registerProtectedRoutes: (router) => {
        router.post('/test/echo', (req: Request, res: Response) => {
          res.status(200).json({ body: req.body });
        });
      },
    });
  }

  it.each([
    ['malformed JSON', '{bad'],
    ['oversized JSON', bigBody],
  ])('no token + %s on a guarded path -> 401, not 500', async (_name, body) => {
    const res = await request(createApp())
      .post('/api/v1/victims')
      .set('Content-Type', 'application/json')
      .send(body);
    expectError(res, 401, 'UNAUTHENTICATED');
  });

  it.each([
    ['malformed JSON', 'application/json', '{bad'],
    ['oversized JSON', 'application/json', bigBody],
    ['unsupported charset', 'application/json; charset=latin1', '{"a":1}'],
  ])('authenticated + %s -> 400 VALIDATION_ERROR without parser details', async (_name, type, body) => {
    const res = await request(appWithFakes())
      .post('/api/v1/test/echo')
      .set('Authorization', `Bearer ${TOKEN}`)
      .set('Content-Type', type)
      .send(body);
    expectError(res, 400, 'VALIDATION_ERROR');
    expect(res.body.message).not.toMatch(/JSON|position|entity|charset/i);
  });

  it('public POST /api/v1/auth/session still parses JSON (malformed -> 400, valid -> placeholder 404)', async () => {
    const testApp = createApp();
    const bad = await request(testApp)
      .post('/api/v1/auth/session')
      .set('Content-Type', 'application/json')
      .send('{bad');
    expectError(bad, 400, 'VALIDATION_ERROR');

    const ok = await request(testApp)
      .post('/api/v1/auth/session')
      .send({ device_id: DEVICE_ID, device_name: 'phone' });
    expectError(ok, 404, 'NOT_FOUND');
  });
});

// ---------------------------------------------------------------------------
// Review fixes R1, R7, R10, R11, R13
// ---------------------------------------------------------------------------

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Unexpired, unsigned test token: the real getClaims must still ask the Auth server about it. */
function unverifiedToken(header: Record<string, unknown>, payload: Record<string, unknown> = {}) {
  return [
    b64url(header),
    b64url(claims({ iat: nowSeconds() - 10, exp: nowSeconds() + 3600, ...payload })),
    Buffer.from('signature').toString('base64url'),
  ].join('.');
}

const jsonResponse = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('OSP-61 R1: Auth service unavailable -> 500, token rejected -> 401 (fake getClaims)', () => {
  it.each([
    ['AuthRetryableFetchError (network, status 0)', new AuthRetryableFetchError('fetch failed', 0)],
    ['AuthRetryableFetchError (503)', new AuthRetryableFetchError('Service Unavailable', 503)],
    ['AuthApiError 429', new AuthApiError('rate limited', 429, 'over_request_rate_limit')],
    ['AuthApiError 500', new AuthApiError('server error', 500, undefined)],
    ['AuthApiError 507', new AuthApiError('insufficient storage', 507, undefined)],
  ])('returned %s -> 500 INTERNAL_ERROR', async (_name, error) => {
    getClaims.mockResolvedValueOnce({ data: null, error });
    const res = await callProtected();
    expectError(res, 500, 'INTERNAL_ERROR');
    expect(res.headers['www-authenticate']).toBeUndefined();
    expect(db.queries).toHaveLength(0);
  });

  it('thrown AuthRetryableFetchError -> 500 INTERNAL_ERROR', async () => {
    getClaims.mockRejectedValueOnce(new AuthRetryableFetchError('fetch failed', 0));
    expectError(await callProtected(), 500, 'INTERNAL_ERROR');
  });

  it.each([
    ['AuthInvalidJwtError', new AuthInvalidJwtError('Invalid JWT signature')],
    ['AuthApiError 401', new AuthApiError('invalid JWT', 401, 'bad_jwt')],
    ['AuthApiError 403', new AuthApiError('forbidden', 403, 'bad_jwt')],
    ['AuthApiError 400', new AuthApiError('bad request', 400, undefined)],
    ['AuthSessionMissingError', new AuthSessionMissingError()],
    ['AuthUnknownError', new AuthUnknownError('unparseable', new SyntaxError('x'))],
  ])('returned %s -> 401 UNAUTHENTICATED', async (_name, error) => {
    getClaims.mockResolvedValueOnce({ data: null, error });
    expectError(await callProtected(), 401, 'UNAUTHENTICATED');
  });
});

describe('OSP-61 R1: classification through the real auth-js getClaims (fake fetch)', () => {
  const hsToken = () => unverifiedToken({ alg: 'HS256', typ: 'JWT' });
  const esToken = () => unverifiedToken({ alg: 'ES256', kid: 'unknown-kid', typ: 'JWT' });

  function appWithFetch(fakeFetch: typeof fetch, timeoutMs?: number) {
    return buildTestApp(createTokenVerifierClient({ fetch: fakeFetch, timeoutMs }));
  }

  async function call(fakeFetch: typeof fetch, token = hsToken(), timeoutMs?: number) {
    return request(appWithFetch(fakeFetch, timeoutMs))
      .get('/protected')
      .set('Authorization', `Bearer ${token}`);
  }

  it('getUser fallback: Auth server accepts the token -> claims trusted -> 200', async () => {
    const fakeFetch = vi.fn(async () => jsonResponse(200, { id: USER_ID, aud: 'authenticated' }));
    const res = await call(fakeFetch as unknown as typeof fetch);
    expect(res.status).toBe(200);
    expect(res.body.auth.user_id).toBe(USER_ID);
    const [url, init] = fakeFetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(String(url)).toMatch(/\/auth\/v1\/user$/);
    expect(new Headers(init.headers).get('Authorization')).toMatch(/^Bearer /);
  });

  it.each([
    ['network error (fetch rejects)', async () => Promise.reject(new TypeError('fetch failed'))],
    ['503 JSON', async () => jsonResponse(503, { message: 'unavailable' })],
    ['502 HTML', async () => new Response('<html>bad gateway</html>', { status: 502 })],
    ['429 JSON', async () => jsonResponse(429, { code: 'over_request_rate_limit', message: 'slow down' })],
  ])('getUser fallback: %s -> 500 INTERNAL_ERROR', async (_name, impl) => {
    expectError(await call(vi.fn(impl) as unknown as typeof fetch), 500, 'INTERNAL_ERROR');
  });

  it.each([
    ['401 bad_jwt', async () => jsonResponse(401, { code: 'bad_jwt', message: 'invalid JWT' })],
    ['403 bad_jwt', async () => jsonResponse(403, { code: 'bad_jwt', message: 'invalid JWT' })],
    ['403 session_not_found', async () =>
      jsonResponse(403, { code: 'session_not_found', message: 'Session not found' })],
  ])('getUser fallback: %s -> 401 UNAUTHENTICATED', async (_name, impl) => {
    const res = await call(vi.fn(impl) as unknown as typeof fetch);
    expectError(res, 401, 'UNAUTHENTICATED');
    expect(res.headers['www-authenticate']).toBe('Bearer');
  });

  it('timeout of a hung Auth server -> 500 INTERNAL_ERROR', async () => {
    const hang = vi.fn(
      (_input: unknown, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal?.reason));
        }),
    );
    const res = await call(hang as unknown as typeof fetch, hsToken(), 50);
    expectError(res, 500, 'INTERNAL_ERROR');
  });

  // Unique kid: the JWKS cache in auth-js is process-wide.
  const ALG_TEST_KID = 'osp61-alg-test-kid';
  const jwksWithKid = async () =>
    jsonResponse(200, {
      keys: [{ kid: ALG_TEST_KID, kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA', alg: 'ES256' }],
    });

  it.each(['none', 'PS512', 'EdDSA'])(
    'alg %s with a kid present in JWKS -> rejected locally -> 401 UNAUTHENTICATED',
    async (alg) => {
      const fakeFetch = vi.fn(jwksWithKid);
      const res = await call(
        fakeFetch as unknown as typeof fetch,
        unverifiedToken({ alg, kid: ALG_TEST_KID, typ: 'JWT' }),
      );
      expectError(res, 401, 'UNAUTHENTICATED');
      for (const [url] of fakeFetch.mock.calls as unknown as Array<[string]>) {
        expect(String(url)).not.toMatch(/\/auth\/v1\/user$/);
      }
    },
  );

  it('alg none without kid -> getUser fallback rejects -> 401 UNAUTHENTICATED', async () => {
    const fakeFetch = vi.fn(async () => jsonResponse(401, { code: 'bad_jwt', message: 'invalid JWT' }));
    const res = await call(fakeFetch as unknown as typeof fetch, unverifiedToken({ alg: 'none', typ: 'JWT' }));
    expectError(res, 401, 'UNAUTHENTICATED');
    expect(String((fakeFetch.mock.calls[0] as unknown as [string])[0])).toMatch(/\/auth\/v1\/user$/);
  });

  it('JWKS endpoint 503 (asymmetric token) -> 500 INTERNAL_ERROR', async () => {
    const fakeFetch = vi.fn(async () => jsonResponse(503, { message: 'unavailable' }));
    const res = await call(fakeFetch as unknown as typeof fetch, esToken());
    expectError(res, 500, 'INTERNAL_ERROR');
    expect(String((fakeFetch.mock.calls[0] as unknown as [string])[0])).toMatch(
      /\/\.well-known\/jwks\.json$/,
    );
  });
});

describe('OSP-61 R7: aud claim must be "authenticated"', () => {
  it.each([
    ['missing', undefined],
    ['anon', 'anon'],
    ['service_role', 'service_role'],
    ['array without authenticated', ['other']],
    ['number', 1],
  ])('aud %s -> 401 UNAUTHENTICATED', async (_name, aud) => {
    const value = claims({ aud });
    if (aud === undefined) delete value.aud;
    getClaims.mockResolvedValueOnce(claimsOk(value));
    expectError(await callProtected(), 401, 'UNAUTHENTICATED');
    expect(db.queries).toHaveLength(0);
  });

  it('aud as an array containing "authenticated" is accepted', async () => {
    getClaims.mockResolvedValueOnce(claimsOk(claims({ aud: ['authenticated'] })));
    expect((await callProtected()).status).toBe(200);
  });
});

describe('OSP-61 R13: WWW-Authenticate on 401 only', () => {
  it('401 responses carry WWW-Authenticate: Bearer', async () => {
    expect((await callProtected({})).headers['www-authenticate']).toBe('Bearer');
    expect(
      (await callProtected({ Authorization: 'Bearer forged.token.value' })).headers['www-authenticate'],
    ).toBe('Bearer');
  });

  it('403 and 200 responses do not', async () => {
    db.tables.user_profiles = [profile({ is_active: false })];
    expect((await callProtected()).headers['www-authenticate']).toBeUndefined();
    db.tables.user_profiles = [profile()];
    expect((await callProtected()).headers['www-authenticate']).toBeUndefined();
  });
});

describe('OSP-61 R10: reusable verification stages', () => {
  it('verifyAccessToken returns the verified claims', async () => {
    const guard = createAuthGuard({
      authClient: { auth: { getClaims } } as unknown as AuthGuardDeps['authClient'],
      dbClient: createFakeDbClient(db),
    });
    await expect(guard.verifyAccessToken(TOKEN)).resolves.toMatchObject({
      sub: USER_ID,
      session_id: SESSION_ID,
      aud: 'authenticated',
    });
    await expect(guard.verifyAccessToken('forged')).rejects.toMatchObject({
      statusCode: 401,
      errorCode: 'UNAUTHENTICATED',
    });
    await expect(guard.verifyAuthorizationHeader(undefined)).rejects.toMatchObject({ statusCode: 401 });
    await expect(guard.loadActiveProfile(await guard.verifyAccessToken(TOKEN))).resolves.toMatchObject({
      role: 'rescuer',
    });
  });

  it('the default verifyAccessToken rejects garbage locally (no network)', async () => {
    await expect(verifyAccessToken('not-a-jwt')).rejects.toMatchObject({ statusCode: 401 });
  });
});

describe('OSP-61 R11: errors after successful authentication are not swallowed', () => {
  it('an error thrown by next() rejects the middleware promise (Express forwards it)', async () => {
    const requireAuth = createRequireAuth({
      authClient: { auth: { getClaims } } as unknown as AuthGuardDeps['authClient'],
      dbClient: createFakeDbClient(db),
    });
    const req = { headers: { authorization: `Bearer ${TOKEN}` } } as unknown as Request;
    const res = { set: vi.fn() } as unknown as Response;
    const next = vi.fn(() => {
      throw new Error('downstream boom');
    });
    const result = requireAuth(req, res, next) as unknown;
    expect(result).toBeInstanceOf(Promise);
    await expect(result).rejects.toThrow('downstream boom');
    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });
});
