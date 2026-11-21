import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthGuardDeps } from '../src/middleware/auth.js';

// Wrap (not replace) the real router factory so the test can see which guard createApp passes.
vi.mock('../src/routes/api-v1.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/routes/api-v1.js')>();
  return { ...original, createPublicApiRouter: vi.fn(original.createPublicApiRouter) };
});

const { createApp } = await import('../src/app.js');
const { defaultAuthGuard } = await import('../src/middleware/auth.js');
const { createPublicApiRouter } = await import('../src/routes/api-v1.js');
const createPublicApiRouterMock = vi.mocked(createPublicApiRouter);

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = '33333333-3333-4333-8333-333333333333';
const TOKEN = 'valid.test.token';

function fakeDeps() {
  const getClaims = vi.fn(async () => ({
    data: {
      claims: { sub: USER_ID, session_id: SESSION_ID, iat: 1_790_000_000, aud: 'authenticated' },
      header: { alg: 'ES256' },
      signature: new Uint8Array(),
    },
    error: null,
  }));
  const maybeSingle = vi.fn(async () => ({
    data: { role: 'coordinator', is_active: true, all_sessions_revoked_at: null },
    error: null,
  }));
  const builder = { select: () => builder, eq: () => builder, maybeSingle };
  const from = vi.fn(() => builder);
  const deps = {
    authClient: { auth: { getClaims } },
    dbClient: { from },
  } as unknown as AuthGuardDeps;
  return { deps, getClaims, from };
}

beforeEach(() => {
  createPublicApiRouterMock.mockClear();
});

describe('OSP-61 F1: createApp feeds the same guard deps to the public router', () => {
  it('createApp() without options passes the single default guard instance', () => {
    createApp();
    expect(createPublicApiRouterMock).toHaveBeenCalledTimes(1);
    expect(createPublicApiRouterMock.mock.calls[0]?.[0]).toBe(defaultAuthGuard);
  });

  it('createApp({ authGuardDeps }) gives the public router a guard bound to the injected fakes', async () => {
    const { deps, getClaims, from } = fakeDeps();
    createApp({ authGuardDeps: deps });
    const auth = createPublicApiRouterMock.mock.calls[0]?.[0];
    expect(auth).toBeDefined();
    expect(auth).not.toBe(defaultAuthGuard);

    // What the OSP-60 session handler will call: verification + account check hit the fakes.
    const claims = await auth!.verifyAuthorizationHeader(`Bearer ${TOKEN}`);
    expect(getClaims).toHaveBeenCalledWith(TOKEN);
    await expect(auth!.loadActiveProfile(claims)).resolves.toMatchObject({ role: 'coordinator' });
    expect(from).toHaveBeenCalledWith('user_profiles');
  });

  it('the guard on the protected mount uses the same injected fakes', async () => {
    const { deps, getClaims } = fakeDeps();
    const res = await request(createApp({ authGuardDeps: deps }))
      .get('/api/v1/anything')
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(getClaims).toHaveBeenCalledWith(TOKEN);
    // The fake returns the profile-shaped row for the device query too (no user_id) -> not bound.
    expect(res.status).toBe(403);
    expect(res.body.error_code).toBe('SESSION_NOT_BOUND');
  });

  it('public routes keep working (health 200, session placeholder 404, no token needed)', async () => {
    const { deps, getClaims } = fakeDeps();
    const testApp = createApp({ authGuardDeps: deps });
    expect((await request(testApp).get('/api/v1/health')).status).toBe(200);
    expect((await request(testApp).post('/api/v1/auth/session')).status).toBe(404);
    expect(getClaims).not.toHaveBeenCalled();
  });
});
