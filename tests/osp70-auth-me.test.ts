import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  DEVICE_ID,
  SESSION_ID,
  TOKEN,
  USER_ID,
  createFakeWorld,
  createTestApp,
  device,
  profile,
  type FakeWorld,
} from './helpers/osp60-fakes.js';

let world: FakeWorld;

beforeEach(() => {
  world = createFakeWorld();
  // A session that /auth/session already bound.
  world.tables.user_devices = [device({ session_id: SESSION_ID, last_login_at: '2026-11-22T09:00:00+00:00' })];
});

const me = (token: string | null = TOKEN, path = '/api/v1/auth/me') => {
  const req = request(createTestApp(world)).get(path);
  if (token !== null) req.set('Authorization', `Bearer ${token}`);
  return req;
};

function expectError(res: request.Response, status: number, code: string) {
  expect(res.status).toBe(status);
  expect(res.body).toEqual({ error_code: code, message: expect.any(String) });
}

describe('OSP-70 GET /api/v1/auth/me', () => {
  it('bound session -> 200 with exactly user_id, role, device_id and no-store', async () => {
    const res = await me();

    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(Object.keys(res.body).sort()).toEqual(['device_id', 'role', 'user_id']);
    expect(res.body).toEqual({ user_id: USER_ID, role: 'rescuer', device_id: DEVICE_ID });
    expect(JSON.stringify(res.body)).not.toContain(SESSION_ID);
    expect(res.body).not.toHaveProperty('session_id');
  });

  it('role comes from the database profile, not the JWT', async () => {
    world.tables.user_profiles = [profile({ role: 'coordinator' })];
    const res = await me();

    expect(res.status).toBe(200);
    expect(res.body.role).toBe('coordinator');
  });

  it('writes no audit row and touches no session/device row', async () => {
    const devicesBefore = structuredClone(world.tables.user_devices);
    await me();

    expect(world.tables.audit_logs).toEqual([]);
    expect(world.store.bindSession).not.toHaveBeenCalled();
    expect(world.store.unbindSession).not.toHaveBeenCalled();
    expect(world.store.recordRejectedLogin).not.toHaveBeenCalled();
    expect(world.tables.user_devices).toEqual(devicesBefore);
  });

  it('no token -> 401 UNAUTHENTICATED with WWW-Authenticate', async () => {
    const res = await me(null);

    expectError(res, 401, 'UNAUTHENTICATED');
    expect(res.headers['www-authenticate']).toBe('Bearer');
    expect(world.tables.audit_logs).toEqual([]);
  });

  it('invalid / expired token -> 401 UNAUTHENTICATED with WWW-Authenticate', async () => {
    const res = await me('expired.token');

    expectError(res, 401, 'UNAUTHENTICATED');
    expect(res.headers['www-authenticate']).toBe('Bearer');
  });

  it.each([
    ['is_active = false', () => [profile({ is_active: false })]],
    ['profile missing', () => []],
  ])('%s -> 403 ACCOUNT_DISABLED', async (_name, rows) => {
    world.tables.user_profiles = rows();
    expectError(await me(), 403, 'ACCOUNT_DISABLED');
    expect(world.tables.audit_logs).toEqual([]);
  });

  it('token issued before all_sessions_revoked_at -> 403 ACCOUNT_DISABLED', async () => {
    world.tables.user_profiles = [profile({ all_sessions_revoked_at: '2099-01-01T00:00:00+00:00' })];
    expectError(await me(), 403, 'ACCOUNT_DISABLED');
  });

  it('unbound session -> 403 SESSION_NOT_BOUND', async () => {
    world.tables.user_devices = [device({ session_id: null })];
    expectError(await me(), 403, 'SESSION_NOT_BOUND');
  });

  it('revoked device -> 403 DEVICE_REVOKED', async () => {
    world.tables.user_devices = [device({ session_id: SESSION_ID, is_device_revoked: true })];
    expectError(await me(), 403, 'DEVICE_REVOKED');
    expect(world.tables.audit_logs).toEqual([]);
  });

  it.each(['post', 'put', 'patch', 'delete'] as const)(
    '%s /api/v1/auth/me is not a route (guarded, then 404), handler not reached',
    async (method) => {
      const res = await request(createTestApp(world))[method]('/api/v1/auth/me').set('Authorization', `Bearer ${TOKEN}`);
      expectError(res, 404, 'NOT_FOUND');
    },
  );

  it('non-GET without a token -> 401 from the guard', async () => {
    expectError(await request(createTestApp(world)).post('/api/v1/auth/me'), 401, 'UNAUTHENTICATED');
  });

  it('trailing slash and upper case behave like the other protected routes (current behaviour)', async () => {
    const slash = await me(TOKEN, '/api/v1/auth/me/');
    const upper = await me(TOKEN, '/API/V1/AUTH/ME');
    expect(slash.status).toBe(200);
    expect(upper.status).toBe(200);
    // Same behaviour as an existing protected route.
    const logoutSlash = await request(createTestApp(world))
      .post('/api/v1/auth/logout/')
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(logoutSlash.status).toBe(204);
  });
});
