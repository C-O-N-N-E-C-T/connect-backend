import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  DEVICE_ID,
  NEW_SESSION_ID,
  OTHER_DEVICE_ID,
  OTHER_USER_ID,
  SESSION_ID,
  TOKEN,
  USER_ID,
  createFakeWorld,
  createTestApp,
  device,
  type FakeWorld,
} from './helpers/osp60-fakes.js';

let world: FakeWorld;

beforeEach(() => {
  world = createFakeWorld();
  // A session that /auth/session already bound.
  world.tables.user_devices = [device({ session_id: SESSION_ID, last_login_at: '2026-11-22T09:00:00+00:00' })];
});

const logout = (token: string | null = TOKEN, app = createTestApp(world)) => {
  const req = request(app).post('/api/v1/auth/logout');
  if (token !== null) req.set('Authorization', `Bearer ${token}`);
  return req;
};

function expectError(res: request.Response, status: number, code: string) {
  expect(res.status).toBe(status);
  expect(res.body).toEqual({ error_code: code, message: expect.any(String) });
}

describe('OSP-60 POST /api/v1/auth/logout', () => {
  it('bound session -> 204, binding cleared, LOGOUT audit; same token then SESSION_NOT_BOUND (handoff test 6)', async () => {
    const app = createTestApp(world);
    const res = await logout(TOKEN, app);

    expect(res.status).toBe(204);
    expect(res.text).toBe('');
    expect(world.tables.user_devices[0]).toMatchObject({ device_id: DEVICE_ID, session_id: null });
    expect(world.tables.audit_logs).toEqual([
      expect.objectContaining({
        actor_user_id: USER_ID,
        actor_role: 'rescuer',
        device_id: DEVICE_ID,
        action_type: 'LOGOUT',
      }),
    ]);

    const after = await request(app).get('/api/v1/test/whoami').set('Authorization', `Bearer ${TOKEN}`);
    expectError(after, 403, 'SESSION_NOT_BOUND');
  });

  it('uses req.auth from the guard, not the body', async () => {
    await request(createTestApp(world))
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ user_id: OTHER_USER_ID, session_id: NEW_SESSION_ID });

    expect(world.store.unbindSession).toHaveBeenCalledWith({
      user_id: USER_ID,
      role: 'rescuer',
      device_id: DEVICE_ID,
      session_id: SESSION_ID,
    });
  });

  it('keeps the device row (only session_id is cleared) and touches no other rows', async () => {
    world.tables.user_devices.push(
      device({ device_id: OTHER_DEVICE_ID, session_id: NEW_SESSION_ID }),
      device({ user_id: OTHER_USER_ID, session_id: '88888888-8888-4888-8888-888888888888' }),
    );
    await logout();

    expect(world.tables.user_devices).toHaveLength(3);
    expect(world.tables.user_devices.map((row) => row.session_id)).toEqual([
      null,
      NEW_SESSION_ID,
      '88888888-8888-4888-8888-888888888888',
    ]);
  });

  it('no token -> 401 from the guard, handler not reached, nothing audited (handoff test 7)', async () => {
    const res = await logout(null);

    expectError(res, 401, 'UNAUTHENTICATED');
    expect(res.headers['www-authenticate']).toBe('Bearer');
    expect(world.store.unbindSession).not.toHaveBeenCalled();
    expect(world.tables.audit_logs).toEqual([]);
  });

  it('expired / invalid token -> 401, no LOGOUT row (agreed AC reading: authenticated calls only)', async () => {
    expectError(await logout('expired.token'), 401, 'UNAUTHENTICATED');
    expect(world.tables.audit_logs).toEqual([]);
  });

  it('revoked device -> 403 DEVICE_REVOKED from the guard', async () => {
    world.tables.user_devices = [device({ session_id: SESSION_ID, is_device_revoked: true })];
    expectError(await logout(), 403, 'DEVICE_REVOKED');
    expect(world.store.unbindSession).not.toHaveBeenCalled();
  });

  it('store failure -> 500 INTERNAL_ERROR', async () => {
    world.store.unbindSession.mockRejectedValueOnce(new Error('db down'));
    expectError(await logout(), 500, 'INTERNAL_ERROR');
  });

  it('GET /api/v1/auth/logout is not a route (guarded, then 404)', async () => {
    const res = await request(createTestApp(world)).get('/api/v1/auth/logout').set('Authorization', `Bearer ${TOKEN}`);
    expectError(res, 404, 'NOT_FOUND');
  });
});
