import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { OFFLINE_GRANT_TTL_MS } from '../src/services/offline-grant.js';
import {
  DEVICE_ID,
  NEW_SESSION_ID,
  NEW_TOKEN,
  OTHER_DEVICE_ID,
  OTHER_USER_ID,
  SESSION_ID,
  TOKEN,
  USER_ID,
  claims,
  createFakeWorld,
  createTestApp,
  device,
  profile,
  type FakeWorld,
} from './helpers/osp60-fakes.js';

let world: FakeWorld;

beforeEach(() => {
  world = createFakeWorld();
});

const BODY = { device_id: DEVICE_ID, device_name: 'Samsung SM-A546B' };
/** Sentinel: send the request without any body (`undefined` would pick the default BODY). */
const NO_BODY = Symbol('no body');

function postSession(token: string | null = TOKEN, body: unknown = BODY, app = createTestApp(world)) {
  const req = request(app).post('/api/v1/auth/session');
  if (token !== null) req.set('Authorization', `Bearer ${token}`);
  return body === NO_BODY ? req : req.send(body as object);
}

const whoami = (token: string, app = createTestApp(world)) =>
  request(app).get('/api/v1/test/whoami').set('Authorization', `Bearer ${token}`);

function expectError(res: request.Response, status: number, code: string) {
  expect(res.status).toBe(status);
  expect(res.body).toEqual({ error_code: code, message: expect.any(String) });
}

// ---------------------------------------------------------------------------------------
describe('OSP-60 POST /api/v1/auth/session: success', () => {
  it('rescuer -> 200 with role, device and a 72 h unsigned offline_mission_grant', async () => {
    const res = await postSession();

    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toEqual({
      user_id: USER_ID,
      role: 'rescuer',
      device_id: DEVICE_ID,
      offline_mission_grant: {
        user_id: USER_ID,
        device_id: DEVICE_ID,
        authenticated_at: '2026-11-22T10:00:00.000Z',
        expires_at: '2026-11-25T10:00:00.000Z',
      },
    });
    const grant = res.body.offline_mission_grant;
    expect(Date.parse(grant.expires_at) - Date.parse(grant.authenticated_at)).toBe(OFFLINE_GRANT_TTL_MS);
    // ISO-8601 with an offset (Android rejects timestamps without one).
    expect(grant.authenticated_at).toMatch(/Z$/);
  });

  it('binds the token session_id claim unchanged to the (user_id, device_id) row', async () => {
    await postSession();

    expect(world.tables.user_devices).toHaveLength(1);
    expect(world.tables.user_devices[0]).toMatchObject({
      user_id: USER_ID,
      device_id: DEVICE_ID,
      device_name: 'Samsung SM-A546B',
      session_id: SESSION_ID,
      is_device_revoked: false,
    });
    expect(world.store.bindSession).toHaveBeenCalledWith({
      user_id: USER_ID,
      role: 'rescuer',
      device_id: DEVICE_ID,
      device_name: 'Samsung SM-A546B',
      session_id: SESSION_ID,
    });
  });

  it('writes one LOGIN audit row', async () => {
    await postSession();
    expect(world.tables.audit_logs).toEqual([
      expect.objectContaining({
        actor_user_id: USER_ID,
        actor_role: 'rescuer',
        device_id: DEVICE_ID,
        action_type: 'LOGIN',
      }),
    ]);
  });

  it.each(['coordinator', 'administrator'] as const)('%s -> 200 without a grant', async (role) => {
    world.tables.user_profiles = [profile({ role })];
    const res = await postSession();

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ user_id: USER_ID, role, device_id: DEVICE_ID });
    expect(res.body).not.toHaveProperty('offline_mission_grant');
  });

  it('role comes from user_profiles, not from the JWT user_role claim', async () => {
    // The fake token carries user_role: 'administrator'; the profile says rescuer.
    const res = await postSession();
    expect(res.body.role).toBe('rescuer');
  });

  it('ignores user_id / session_id sent in the body (identity only from the token)', async () => {
    const res = await postSession(TOKEN, { ...BODY, user_id: OTHER_USER_ID, session_id: NEW_SESSION_ID });

    expect(res.status).toBe(200);
    expect(res.body.user_id).toBe(USER_ID);
    expect(world.tables.user_devices[0]).toMatchObject({ user_id: USER_ID, session_id: SESSION_ID });
  });

  it('trims device_name', async () => {
    await postSession(TOKEN, { device_id: DEVICE_ID, device_name: '  Pixel 8  ' });
    expect(world.tables.user_devices[0]?.device_name).toBe('Pixel 8');
  });
});

// ---------------------------------------------------------------------------------------
describe('OSP-60 POST /api/v1/auth/session: errors', () => {
  it('no Authorization header -> 401 UNAUTHENTICATED with WWW-Authenticate, nothing written', async () => {
    const res = await postSession(null);

    expectError(res, 401, 'UNAUTHENTICATED');
    expect(res.headers['www-authenticate']).toBe('Bearer');
    expect(world.getClaims).not.toHaveBeenCalled();
    expect(world.store.bindSession).not.toHaveBeenCalled();
    expect(world.tables.audit_logs).toEqual([]);
  });

  it('invalid / expired token -> 401, not audited', async () => {
    const res = await postSession('not.a.valid.token');

    expectError(res, 401, 'UNAUTHENTICATED');
    expect(res.headers['www-authenticate']).toBe('Bearer');
    expect(world.tables.audit_logs).toEqual([]);
  });

  it('token is checked before the body: no token + invalid body -> 401, not 400', async () => {
    expectError(await postSession(null, { device_id: 'nope' }), 401, 'UNAUTHENTICATED');
  });

  it.each([
    ['missing body', NO_BODY],
    ['empty object', {}],
    ['device_id not a UUID', { device_id: 'abc', device_name: 'phone' }],
    ['device_name missing', { device_id: DEVICE_ID }],
    ['device_name empty after trim', { device_id: DEVICE_ID, device_name: '   ' }],
    ['device_name over 100 chars', { device_id: DEVICE_ID, device_name: 'x'.repeat(101) }],
    ['device_name not a string', { device_id: DEVICE_ID, device_name: 42 }],
  ])('%s -> 400 VALIDATION_ERROR, not audited', async (_name, body) => {
    const res = await postSession(TOKEN, body);

    expectError(res, 400, 'VALIDATION_ERROR');
    expect(world.store.bindSession).not.toHaveBeenCalled();
    expect(world.tables.audit_logs).toEqual([]);
  });

  it('device_name of exactly 100 chars is accepted', async () => {
    expect((await postSession(TOKEN, { device_id: DEVICE_ID, device_name: 'x'.repeat(100) })).status).toBe(200);
  });

  it.each([
    ['is_active = false', () => [profile({ is_active: false })]],
    ['profile missing', () => []],
  ])('%s -> 403 ACCOUNT_DISABLED + LOGIN_REJECTED audit, no binding', async (_name, rows) => {
    world.tables.user_profiles = rows();
    const res = await postSession();

    expectError(res, 403, 'ACCOUNT_DISABLED');
    expect(world.store.bindSession).not.toHaveBeenCalled();
    expect(world.tables.user_devices).toEqual([]);
    expect(world.tables.audit_logs).toEqual([
      expect.objectContaining({
        actor_user_id: USER_ID,
        device_id: DEVICE_ID,
        action_type: 'LOGIN_REJECTED',
        metadata: expect.objectContaining({ reason: 'ACCOUNT_DISABLED' }),
      }),
    ]);
  });

  it('token issued before all_sessions_revoked_at -> 403 ACCOUNT_DISABLED (handoff test 5)', async () => {
    const revokedAt = new Date((claims(USER_ID, SESSION_ID).iat + 1) * 1000).toISOString();
    world.tables.user_profiles = [profile({ all_sessions_revoked_at: revokedAt })];

    expectError(await postSession(), 403, 'ACCOUNT_DISABLED');
    expect(world.tables.user_devices).toEqual([]);
  });

  it('a failing LOGIN_REJECTED audit write still answers 403 (not 500)', async () => {
    world.tables.user_profiles = [profile({ is_active: false })];
    world.store.recordRejectedLogin.mockRejectedValueOnce(new Error('db down'));

    expectError(await postSession(), 403, 'ACCOUNT_DISABLED');
  });

  it('revoked device -> 403 DEVICE_REVOKED, row stays revoked and unbound (handoff test 3)', async () => {
    world.tables.user_devices = [
      device({ is_device_revoked: true, device_revoked_at: '2026-11-21T00:00:00+00:00' }),
    ];
    const res = await postSession();

    expectError(res, 403, 'DEVICE_REVOKED');
    expect(world.tables.user_devices).toEqual([
      expect.objectContaining({
        is_device_revoked: true,
        device_revoked_at: '2026-11-21T00:00:00+00:00',
        session_id: null,
        device_name: 'Old name',
      }),
    ]);
    expect(world.tables.audit_logs).toEqual([
      expect.objectContaining({ action_type: 'LOGIN_REJECTED', metadata: { reason: 'DEVICE_REVOKED' } }),
    ]);
  });

  it('revoking ANOTHER device of the same user does not block this device', async () => {
    world.tables.user_devices = [device({ device_id: OTHER_DEVICE_ID, is_device_revoked: true })];
    expect((await postSession()).status).toBe(200);
  });

  it('store failure -> 500 INTERNAL_ERROR', async () => {
    // The real store already turns DB errors into a generic AppError 500 (see
    // osp60-session-store.test.ts). An unexpected throw is masked by errorHandler in production.
    world.store.bindSession.mockRejectedValueOnce(new Error('db down'));
    expectError(await postSession(), 500, 'INTERNAL_ERROR');
  });

  it('malformed JSON is still rejected with 400 by jsonBody (before the handler)', async () => {
    const res = await request(createTestApp(world))
      .post('/api/v1/auth/session')
      .set('Authorization', `Bearer ${TOKEN}`)
      .set('Content-Type', 'application/json')
      .send('{bad');
    expectError(res, 400, 'VALIDATION_ERROR');
  });
});

// ---------------------------------------------------------------------------------------
// OSP-60 + OSP-61 together: the row written here is what the guard reads.
describe('OSP-60 x OSP-61: binding makes the token usable on guarded routes', () => {
  it('before binding the token is SESSION_NOT_BOUND; after it the guard passes (handoff tests 1, 8)', async () => {
    const app = createTestApp(world);
    expectError(await whoami(TOKEN, app), 403, 'SESSION_NOT_BOUND');

    // /auth/session itself is reachable WITHOUT an existing binding (guard excluded).
    expect((await postSession(TOKEN, BODY, app)).status).toBe(200);

    const res = await whoami(TOKEN, app);
    expect(res.status).toBe(200);
    expect(res.body.auth).toEqual({
      user_id: USER_ID,
      role: 'rescuer',
      device_id: DEVICE_ID,
      session_id: SESSION_ID,
    });
  });

  it('re-login on the same device rebinds: old token SESSION_NOT_BOUND, new token passes (handoff test 2)', async () => {
    const app = createTestApp(world);
    await postSession(TOKEN, BODY, app);
    await postSession(NEW_TOKEN, { ...BODY, device_name: 'Renamed phone' }, app);

    expect(world.tables.user_devices).toHaveLength(1);
    expect(world.tables.user_devices[0]).toMatchObject({
      session_id: NEW_SESSION_ID,
      device_name: 'Renamed phone',
    });
    expectError(await whoami(TOKEN, app), 403, 'SESSION_NOT_BOUND');
    expect((await whoami(NEW_TOKEN, app)).status).toBe(200);
  });

  it('same token with two device_ids -> the session is bound to one row only (handoff test 4)', async () => {
    const app = createTestApp(world);
    await postSession(TOKEN, BODY, app);
    await postSession(TOKEN, { device_id: OTHER_DEVICE_ID, device_name: 'Tablet' }, app);

    const bound = world.tables.user_devices.filter((row) => row.session_id === SESSION_ID);
    expect(bound).toHaveLength(1);
    expect(bound[0]?.device_id).toBe(OTHER_DEVICE_ID);

    // The guard finds exactly one row (no 500 from maybeSingle).
    const res = await whoami(TOKEN, app);
    expect(res.status).toBe(200);
    expect(res.body.auth.device_id).toBe(OTHER_DEVICE_ID);
  });
});
