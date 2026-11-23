import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { supabaseAdmin } from '../src/config/supabase.js';
import { AppError } from '../src/types/errors.js';
import {
  ADMIN_ID,
  COORD_DEVICE_ID,
  COORD_ID,
  COORD_SECOND_DEVICE_ID,
  COORD_SECOND_SESSION_ID,
  COORD_SESSION_ID,
  MISSING_ID,
  RESCUER_ID,
  adminAuth,
  coordAuth,
  coordSecondAuth,
  createDirectory,
  fakeAdminStore,
  fakeAuthAdmin,
  guardDepsFor,
  rescuerAuth,
  type Directory,
  type FakeAuthAdmin,
} from './helpers/osp66-fakes.js';

// OSP-66: yönetici API'si, GERÇEK uygulama ve GERÇEK OSP-61 guard'ı üzerinde.
// Yalnızca veri erişimi (AdminStore) ve Supabase Auth (AuthAdminPort) bellekte.
// Gerçek Supabase'e hiçbir çağrı yapılmamalı.

const realFromSpy = vi.spyOn(supabaseAdmin, 'from').mockImplementation(() => {
  throw new Error('Real Supabase access is forbidden in tests');
});
const realRpcSpy = vi.spyOn(supabaseAdmin, 'rpc').mockImplementation(() => {
  throw new Error('Real Supabase RPC is forbidden in tests');
});

afterAll(() => {
  expect(realFromSpy).not.toHaveBeenCalled();
  expect(realRpcSpy).not.toHaveBeenCalled();
  realFromSpy.mockRestore();
  realRpcSpy.mockRestore();
});

let dir: Directory;
let adminStore: ReturnType<typeof fakeAdminStore>;
let authAdmin: FakeAuthAdmin;
let app: ReturnType<typeof createApp>;

beforeEach(() => {
  dir = createDirectory();
  adminStore = fakeAdminStore(dir);
  authAdmin = fakeAuthAdmin();
  app = createApp({ authGuardDeps: guardDepsFor(dir), adminStore, authAdmin });
});

const validCreateBody = {
  email: 'New.Coordinator@Connect.Internal',
  password: 'Sufficiently-Long-1',
  full_name: 'Yeni Koordinatör',
  role: 'coordinator',
};

describe('authorization (OSP-61 guard + OSP-62 requireRole)', () => {
  it('rejects a request without a token with 401', async () => {
    const res = await request(app).get('/api/v1/admin/users');
    expect(res.status).toBe(401);
    expect(res.body.error_code).toBe('UNAUTHENTICATED');
  });

  it.each([
    ['coordinator', coordAuth],
    ['rescuer', rescuerAuth],
  ])('rejects %s with 403 ROLE_FORBIDDEN before touching the store', async (_name, auth) => {
    const res = await request(app).get('/api/v1/admin/users').set(auth);
    expect(res.status).toBe(403);
    expect(res.body.error_code).toBe('ROLE_FORBIDDEN');
    expect(adminStore.calls.listUsers).toBeUndefined();
  });
});

describe('GET /api/v1/admin/users', () => {
  it('lists users with default paging and no-store caching', async () => {
    const res = await request(app).get('/api/v1/admin/users').set(adminAuth);
    expect(res.status).toBe(200);
    expect(res.body.limit).toBe(50);
    expect(res.body.offset).toBe(0);
    expect(res.body.users.length).toBe(dir.profiles.size);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(adminStore.calls.listUsers).toEqual([{ limit: 50, offset: 0 }]);
  });

  it.each(['limit=0', 'limit=101', 'limit=abc', 'offset=-1'])('rejects %s with 400', async (query) => {
    const res = await request(app).get(`/api/v1/admin/users?${query}`).set(adminAuth);
    expect(res.status).toBe(400);
    expect(res.body.error_code).toBe('VALIDATION_ERROR');
  });
});

describe('POST /api/v1/admin/users', () => {
  it('creates a coordinator with a normalised e-mail and writes the profile through the store', async () => {
    const res = await request(app).post('/api/v1/admin/users').set(adminAuth).send(validCreateBody);

    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({
      email: 'new.coordinator@connect.internal',
      role: 'coordinator',
      is_active: true,
    });
    expect(res.body.user).not.toHaveProperty('password');

    expect(authAdmin.createAuthUser).toHaveBeenCalledWith({
      email: 'new.coordinator@connect.internal',
      password: 'Sufficiently-Long-1',
      role: 'coordinator',
    });
    expect(adminStore.calls.createUserProfile?.[0]).toMatchObject({
      actor: { user_id: ADMIN_ID, role: 'administrator' },
      role: 'coordinator',
    });
  });

  it('refuses to create an administrator with 403 ROLE_FORBIDDEN and makes no Auth or DB call', async () => {
    const res = await request(app)
      .post('/api/v1/admin/users')
      .set(adminAuth)
      .send({ ...validCreateBody, role: 'administrator' });

    expect(res.status).toBe(403);
    expect(res.body.error_code).toBe('ROLE_FORBIDDEN');
    expect(authAdmin.createAuthUser).not.toHaveBeenCalled();
    expect(adminStore.calls.createUserProfile).toBeUndefined();
  });

  it.each([
    ['invalid e-mail', { email: 'not-an-email' }],
    ['short password', { password: 'short' }],
    ['password over bcrypt limit', { password: 'x'.repeat(73) }],
    ['unknown role', { role: 'superuser' }],
    ['missing full_name', { full_name: undefined }],
  ])('rejects %s with 400 and makes no Auth call', async (_name, override) => {
    const res = await request(app)
      .post('/api/v1/admin/users')
      .set(adminAuth)
      .send({ ...validCreateBody, ...override });
    expect(res.status).toBe(400);
    expect(res.body.error_code).toBe('VALIDATION_ERROR');
    expect(authAdmin.createAuthUser).not.toHaveBeenCalled();
  });

  it('answers 409 CONFLICT for a duplicate e-mail', async () => {
    authAdmin.failCreate = true;
    authAdmin.failCreateWith = 'already registered';
    const res = await request(app).post('/api/v1/admin/users').set(adminAuth).send(validCreateBody);
    expect(res.status).toBe(409);
    expect(res.body.error_code).toBe('CONFLICT');
  });

  it('compensates by deleting the Auth account when the profile step fails', async () => {
    vi.spyOn(adminStore, 'createUserProfile').mockRejectedValueOnce(
      new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.'),
    );

    const res = await request(app).post('/api/v1/admin/users').set(adminAuth).send(validCreateBody);

    expect(res.status).toBe(500);
    expect(res.body.error_code).toBe('INTERNAL_ERROR');
    expect(authAdmin.deleteAuthUser).toHaveBeenCalledTimes(1);
    const created = authAdmin.created[0];
    expect(created).toBeDefined();
    expect(authAdmin.deleteAuthUser).toHaveBeenCalledWith(created?.id);
  });
});

describe('devices', () => {
  it('lists a user\'s devices without exposing session ids', async () => {
    const res = await request(app).get(`/api/v1/admin/users/${COORD_ID}/devices`).set(adminAuth);
    expect(res.status).toBe(200);
    expect(res.body.devices).toHaveLength(2);
    expect(res.body.devices.every((d: { has_session: boolean }) => d.has_session === true)).toBe(true);
    expect(JSON.stringify(res.body)).not.toContain(COORD_SESSION_ID);
    expect(JSON.stringify(res.body)).not.toContain('session_id');
  });

  it('answers 404 for an unknown user', async () => {
    const res = await request(app).get(`/api/v1/admin/users/${MISSING_ID}/devices`).set(adminAuth);
    expect(res.status).toBe(404);
    expect(res.body.error_code).toBe('NOT_FOUND');
  });

  it('answers 400 for a malformed user id', async () => {
    const res = await request(app).get('/api/v1/admin/users/not-a-uuid/devices').set(adminAuth);
    expect(res.status).toBe(400);
  });
});

describe('POST .../devices/:deviceId/revoke (single-device revoke)', () => {
  it('revokes one device, deletes only its session, and leaves the other device alone', async () => {
    const res = await request(app)
      .post(`/api/v1/admin/users/${COORD_ID}/devices/${COORD_SECOND_DEVICE_ID}/revoke`)
      .set(adminAuth);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ device_id: COORD_SECOND_DEVICE_ID, is_device_revoked: true, status: 'REVOKED' });

    const revoked = dir.devices.find((d) => d.device_id === COORD_SECOND_DEVICE_ID);
    expect(revoked?.is_device_revoked).toBe(true);
    expect(revoked?.device_revoked_at).not.toBeNull();
    // The bound session id stays on the row so the guard answers DEVICE_REVOKED, not SESSION_NOT_BOUND.
    expect(revoked?.session_id).toBe(COORD_SECOND_SESSION_ID);
    expect(dir.sessions.has(COORD_SECOND_SESSION_ID)).toBe(false);

    const other = dir.devices.find((d) => d.device_id === COORD_DEVICE_ID);
    expect(other?.is_device_revoked).toBe(false);
    expect(dir.sessions.has(COORD_SESSION_ID)).toBe(true);
    expect(dir.audit.map((row) => row.action_type)).toContain('DEVICE_REVOKED');
  });

  it('is idempotent: a second revoke answers ALREADY_REVOKED and writes no new audit row', async () => {
    const path = `/api/v1/admin/users/${COORD_ID}/devices/${COORD_SECOND_DEVICE_ID}/revoke`;
    await request(app).post(path).set(adminAuth);
    const auditBefore = dir.audit.length;

    const res = await request(app).post(path).set(adminAuth);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ALREADY_REVOKED');
    expect(dir.audit.length).toBe(auditBefore);
  });

  it('answers 404 when the device does not belong to the user', async () => {
    const res = await request(app)
      .post(`/api/v1/admin/users/${RESCUER_ID}/devices/${COORD_DEVICE_ID}/revoke`)
      .set(adminAuth);
    expect(res.status).toBe(404);
    expect(res.body.error_code).toBe('NOT_FOUND');
  });
});

describe('POST .../revoke-all (global revoke)', () => {
  it('disables the account in the database BEFORE banning it in Auth', async () => {
    const disableSpy = vi.spyOn(adminStore, 'disableUser');

    const res = await request(app).post(`/api/v1/admin/users/${COORD_ID}/revoke-all`).set(adminAuth);

    expect(res.status).toBe(200);
    expect(res.body.user).toEqual({ id: COORD_ID, is_active: false });
    expect(dir.profiles.get(COORD_ID)?.is_active).toBe(false);
    expect(dir.profiles.get(COORD_ID)?.all_sessions_revoked_at).not.toBeNull();
    expect(dir.sessions.has(COORD_SESSION_ID)).toBe(false);
    expect(dir.sessions.has(COORD_SECOND_SESSION_ID)).toBe(false);
    expect(dir.audit.map((row) => row.action_type)).toContain('ACCOUNT_DISABLED');

    expect(authAdmin.banUser).toHaveBeenCalledWith(COORD_ID);
    const disabledAt = disableSpy.mock.invocationCallOrder[0] ?? Number.NaN;
    const bannedAt = vi.mocked(authAdmin.banUser).mock.invocationCallOrder[0] ?? Number.NaN;
    expect(disabledAt).toBeLessThan(bannedAt);
  });

  it('refuses to disable the caller\'s own account with 409 and changes nothing', async () => {
    const res = await request(app).post(`/api/v1/admin/users/${ADMIN_ID}/revoke-all`).set(adminAuth);
    expect(res.status).toBe(409);
    expect(res.body.error_code).toBe('CONFLICT');
    expect(dir.profiles.get(ADMIN_ID)?.is_active).toBe(true);
    expect(authAdmin.banUser).not.toHaveBeenCalled();
  });

  it('answers 404 for an unknown user and does not ban anyone', async () => {
    const res = await request(app).post(`/api/v1/admin/users/${MISSING_ID}/revoke-all`).set(adminAuth);
    expect(res.status).toBe(404);
    expect(authAdmin.banUser).not.toHaveBeenCalled();
  });

  it('keeps the account disabled in the database and answers 500 when the Auth ban fails', async () => {
    authAdmin.failBan = true;
    const res = await request(app).post(`/api/v1/admin/users/${COORD_ID}/revoke-all`).set(adminAuth);
    expect(res.status).toBe(500);
    expect(res.body.error_code).toBe('INTERNAL_ERROR');
    expect(dir.profiles.get(COORD_ID)?.is_active).toBe(false);
  });
});

describe('POST .../reactivate', () => {
  it('re-enables the account, lifts the Auth ban, and audits it', async () => {
    await request(app).post(`/api/v1/admin/users/${COORD_ID}/revoke-all`).set(adminAuth);

    const res = await request(app).post(`/api/v1/admin/users/${COORD_ID}/reactivate`).set(adminAuth);

    expect(res.status).toBe(200);
    expect(res.body.user).toEqual({ id: COORD_ID, is_active: true });
    expect(dir.profiles.get(COORD_ID)?.is_active).toBe(true);
    expect(authAdmin.unbanUser).toHaveBeenCalledWith(COORD_ID);
    expect(dir.audit.map((row) => row.action_type)).toContain('USER_REACTIVATED');
  });

  it('answers 404 for an unknown user', async () => {
    const res = await request(app).post(`/api/v1/admin/users/${MISSING_ID}/reactivate`).set(adminAuth);
    expect(res.status).toBe(404);
    expect(authAdmin.unbanUser).not.toHaveBeenCalled();
  });
});

describe('GET /api/v1/admin/audit-logs', () => {
  it('filters by action type and pages the result', async () => {
    await request(app).post(`/api/v1/admin/users/${COORD_ID}/devices/${COORD_DEVICE_ID}/revoke`).set(adminAuth);

    const res = await request(app)
      .get('/api/v1/admin/audit-logs?action_type=DEVICE_REVOKED&limit=10&offset=0')
      .set(adminAuth);

    expect(res.status).toBe(200);
    expect(res.body.logs.length).toBeGreaterThan(0);
    expect(res.body.logs.every((row: { action_type: string }) => row.action_type === 'DEVICE_REVOKED')).toBe(true);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it.each([
    ['unknown action type', 'action_type=NOT_A_REAL_ACTION'],
    ['limit above 100', 'limit=101'],
    ['malformed from date', 'from=yesterday'],
    ['malformed actor id', 'actor_user_id=123'],
  ])('rejects %s with 400', async (_name, query) => {
    const res = await request(app).get(`/api/v1/admin/audit-logs?${query}`).set(adminAuth);
    expect(res.status).toBe(400);
    expect(res.body.error_code).toBe('VALIDATION_ERROR');
  });
});

describe('acceptance criteria through the REAL guard (shared directory)', () => {
  // Koordinatörün isteği: guard'ın kararı yanıtı belirler.
  //   guard reddederse -> 403 DEVICE_REVOKED / ACCOUNT_DISABLED / SESSION_NOT_BOUND
  //   guard geçerse   -> 403 ROLE_FORBIDDEN (koordinatör /admin'e giremez)
  // Böylece "guard hâlâ kabul ediyor mu" tek bir istekle gözlemlenir.
  const probe = (auth: { Authorization: string }) =>
    request(app).get('/api/v1/admin/users').set(auth);

  it('AC1: single-device revoke fails the next call from that device with DEVICE_REVOKED, the other device keeps working', async () => {
    expect((await probe(coordAuth)).body.error_code).toBe('ROLE_FORBIDDEN');
    expect((await probe(coordSecondAuth)).body.error_code).toBe('ROLE_FORBIDDEN');

    await request(app)
      .post(`/api/v1/admin/users/${COORD_ID}/devices/${COORD_SECOND_DEVICE_ID}/revoke`)
      .set(adminAuth);

    const revokedDevice = await probe(coordSecondAuth);
    expect(revokedDevice.status).toBe(403);
    expect(revokedDevice.body.error_code).toBe('DEVICE_REVOKED');

    const otherDevice = await probe(coordAuth);
    expect(otherDevice.status).toBe(403);
    expect(otherDevice.body.error_code).toBe('ROLE_FORBIDDEN');
  });

  it('AC2: global revoke rejects every session of the user with ACCOUNT_DISABLED', async () => {
    await request(app).post(`/api/v1/admin/users/${COORD_ID}/revoke-all`).set(adminAuth);

    for (const auth of [coordAuth, coordSecondAuth]) {
      const res = await probe(auth);
      expect(res.status).toBe(403);
      expect(res.body.error_code).toBe('ACCOUNT_DISABLED');
    }
  });

  it('AC2b: the account cannot sign in again until reactivated, and tokens issued before the disable stay revoked after reactivation', async () => {
    await request(app).post(`/api/v1/admin/users/${COORD_ID}/revoke-all`).set(adminAuth);
    await request(app).post(`/api/v1/admin/users/${COORD_ID}/reactivate`).set(adminAuth);

    // The OLD token (issued before the disable) must still be rejected...
    const oldToken = await probe(coordAuth);
    expect(oldToken.body.error_code).toBe('ACCOUNT_DISABLED');
    // The account itself is active again (the guard checks this for fresh tokens).
    expect(dir.profiles.get(COORD_ID)?.is_active).toBe(true);
  });

  it('AC3: an administrator cannot be created through the API (ROLE_FORBIDDEN)', async () => {
    const res = await request(app)
      .post('/api/v1/admin/users')
      .set(adminAuth)
      .send({ email: 'x@connect.internal', password: 'Sufficiently-Long-1', full_name: 'X', role: 'administrator' });
    expect(res.status).toBe(403);
    expect(res.body.error_code).toBe('ROLE_FORBIDDEN');
  });

  it('a rescuer is denied by role and the rescuer account is left untouched', async () => {
    const res = await request(app).get('/api/v1/admin/users').set(rescuerAuth);
    expect(res.body.error_code).toBe('ROLE_FORBIDDEN');
    expect(dir.profiles.get(RESCUER_ID)?.is_active).toBe(true);
  });
});
