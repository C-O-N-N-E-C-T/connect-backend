/**
 * OSP-66 test sahteleri. Tek bir bellek içi "dizin" (profiller, cihazlar, oturumlar, audit)
 * hem gerçek OSP-61 guard'ına (dbClient + getClaims) hem de yönetici store'una bağlanır.
 * Böylece "cihazı iptal et -> bir sonraki istek DEVICE_REVOKED" gibi kabul kriterleri gerçek
 * guard üzerinden doğrulanır. Ağ yok, Supabase yok.
 */
import { randomUUID } from 'node:crypto';
import { vi } from 'vitest';
import type { AuthGuardDeps } from '../../src/middleware/auth.js';
import type { AdminDeviceRow, AdminStore, AdminUserRow, AuthAdminPort } from '../../src/services/admin-store.js';
import type { AuditLogsQuery } from '../../src/schemas/admin.js';
import type { AppRole, AuditLog } from '../../src/types/database.js';
import type { AuthContext } from '../../src/types/express.js';

export const ADMIN_ID = '11111111-1111-4111-8111-111111111111';
export const ADMIN_DEVICE_ID = '12121212-1212-4121-8121-121212121212';
export const ADMIN_SESSION_ID = '13131313-1313-4131-8131-131313131313';
export const COORD_ID = '22222222-2222-4222-8222-222222222222';
export const COORD_DEVICE_ID = '23232323-2323-4232-8232-232323232323';
export const COORD_SESSION_ID = '24242424-2424-4242-8242-242424242424';
export const COORD_SECOND_DEVICE_ID = '25252525-2525-4252-8252-252525252525';
export const COORD_SECOND_SESSION_ID = '26262626-2626-4262-8262-262626262626';
export const RESCUER_ID = '33333333-3333-4333-8333-333333333333';
export const RESCUER_DEVICE_ID = '34343434-3434-4343-8343-343434343434';
export const RESCUER_SESSION_ID = '35353535-3535-4353-8353-353535353535';
export const MISSING_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

export const ADMIN_TOKEN = 'admin.test.token';
export const COORD_TOKEN = 'coord.test.token';
export const COORD_SECOND_TOKEN = 'coord2.test.token';
export const RESCUER_TOKEN = 'rescuer.test.token';

export const adminAuth = { Authorization: `Bearer ${ADMIN_TOKEN}` };
export const coordAuth = { Authorization: `Bearer ${COORD_TOKEN}` };
export const coordSecondAuth = { Authorization: `Bearer ${COORD_SECOND_TOKEN}` };
export const rescuerAuth = { Authorization: `Bearer ${RESCUER_TOKEN}` };

interface ProfileState {
  id: string;
  email: string;
  full_name: string | null;
  role: AppRole;
  is_active: boolean;
  created_at: string;
  all_sessions_revoked_at: string | null;
}

interface DeviceState {
  user_id: string;
  device_id: string;
  device_name: string | null;
  session_id: string | null;
  last_login_at: string | null;
  is_device_revoked: boolean;
  device_revoked_at: string | null;
}

export interface Directory {
  profiles: Map<string, ProfileState>;
  devices: DeviceState[];
  /** auth.sessions: session id -> user id. */
  sessions: Map<string, string>;
  audit: AuditLog[];
}

const NOW_ISO = () => new Date().toISOString();

/** Standart dizin: bir yönetici, bir koordinatör (iki cihazlı), bir kurtarıcı. */
export function createDirectory(): Directory {
  const created = '2026-11-20T10:00:00.000Z';
  const dir: Directory = {
    profiles: new Map(),
    devices: [],
    sessions: new Map(),
    audit: [],
  };
  const addUser = (id: string, email: string, role: AppRole) =>
    dir.profiles.set(id, {
      id,
      email,
      full_name: `${role} user`,
      role,
      is_active: true,
      created_at: created,
      all_sessions_revoked_at: null,
    });
  addUser(ADMIN_ID, 'admin@connect.internal', 'administrator');
  addUser(COORD_ID, 'coordinator@connect.internal', 'coordinator');
  addUser(RESCUER_ID, 'rescuer@connect.internal', 'rescuer');

  const addDevice = (userId: string, deviceId: string, sessionId: string, name: string) => {
    dir.devices.push({
      user_id: userId,
      device_id: deviceId,
      device_name: name,
      session_id: sessionId,
      last_login_at: created,
      is_device_revoked: false,
      device_revoked_at: null,
    });
    dir.sessions.set(sessionId, userId);
  };
  addDevice(ADMIN_ID, ADMIN_DEVICE_ID, ADMIN_SESSION_ID, 'admin phone');
  addDevice(COORD_ID, COORD_DEVICE_ID, COORD_SESSION_ID, 'coordinator laptop');
  addDevice(COORD_ID, COORD_SECOND_DEVICE_ID, COORD_SECOND_SESSION_ID, 'coordinator tablet');
  addDevice(RESCUER_ID, RESCUER_DEVICE_ID, RESCUER_SESSION_ID, 'rescuer phone');
  return dir;
}

/**
 * Gerçek guard'ın ihtiyacı olan iki Supabase bağımlılığı: getClaims (token -> claims) ve
 * dbClient.from (profil ve cihaz sorguları). Sorgu zinciri OSP-61 fake'iyle aynı biçimde.
 */
export function guardDepsFor(dir: Directory): AuthGuardDeps {
  const from = (table: string) => {
    const filters: Array<[string, unknown]> = [];
    const rows = (): Array<Record<string, unknown>> => {
      if (table === 'user_profiles') return [...dir.profiles.values()] as unknown as Array<Record<string, unknown>>;
      if (table === 'user_devices') return dir.devices as unknown as Array<Record<string, unknown>>;
      return [];
    };
    const builder = {
      select: (_columns: string) => builder,
      eq: (column: string, value: unknown) => {
        filters.push([column, value]);
        return builder;
      },
      maybeSingle: async () => ({
        data: rows().find((row) => filters.every(([c, v]) => row[c] === v)) ?? null,
        error: null,
      }),
    };
    return builder;
  };

  const tokenClaims: Record<string, { sub: string; session_id: string }> = {
    [ADMIN_TOKEN]: { sub: ADMIN_ID, session_id: ADMIN_SESSION_ID },
    [COORD_TOKEN]: { sub: COORD_ID, session_id: COORD_SESSION_ID },
    [COORD_SECOND_TOKEN]: { sub: COORD_ID, session_id: COORD_SECOND_SESSION_ID },
    [RESCUER_TOKEN]: { sub: RESCUER_ID, session_id: RESCUER_SESSION_ID },
  };

  const getClaims = async (token: string) => {
    const base = tokenClaims[token];
    if (!base) return { data: null, error: { name: 'AuthInvalidJwtError', message: 'Invalid JWT' } };
    // iat 60 s önce: global iptal (all_sessions_revoked_at) sonrası bu token geçersiz sayılır.
    const iat = Math.floor(Date.now() / 1000) - 60;
    return {
      data: {
        claims: { ...base, iat, exp: iat + 3600, aud: 'authenticated' },
        header: { alg: 'ES256' },
        signature: new Uint8Array(),
      },
      error: null,
    };
  };

  return { authClient: { auth: { getClaims } }, dbClient: { from } } as unknown as AuthGuardDeps;
}

/** Bellekteki dizine bağlı yönetici store'u. Her durum değişikliği dizinde gerçekten uygulanır. */
export function fakeAdminStore(dir: Directory): AdminStore & { calls: Record<string, unknown[]> } {
  const calls: Record<string, unknown[]> = {};
  const record = (name: string, arg: unknown) => {
    (calls[name] ??= []).push(arg);
  };
  const actorOf = (auth: AuthContext) => ({
    actor_user_id: auth.user_id,
    actor_role: auth.role,
    device_id: auth.device_id,
  });
  const audit = (action_type: AuditLog['action_type'], actor: AuthContext, target: string | null, metadata = {}) =>
    dir.audit.push({
      id: randomUUID(),
      ...actorOf(actor),
      action_type,
      target_record_id: target,
      metadata,
      created_at: NOW_ISO(),
    });

  return {
    calls,
    async findUserProfile(userId) {
      record('findUserProfile', userId);
      return dir.profiles.has(userId) ? { id: userId } : null;
    },
    async listUsers(limit, offset) {
      record('listUsers', { limit, offset });
      return [...dir.profiles.values()]
        .sort((a, b) => b.created_at.localeCompare(a.created_at))
        .slice(offset, offset + limit)
        .map((p): AdminUserRow => ({
          id: p.id,
          email: p.email,
          full_name: p.full_name,
          role: p.role,
          is_active: p.is_active,
          created_at: p.created_at,
          all_sessions_revoked_at: p.all_sessions_revoked_at,
        }));
    },
    async createUserProfile({ actor, user_id, role, full_name }) {
      record('createUserProfile', { actor, user_id, role, full_name });
      dir.profiles.set(user_id, {
        id: user_id,
        email: `${user_id}@new.test`,
        full_name,
        role,
        is_active: true,
        created_at: NOW_ISO(),
        all_sessions_revoked_at: null,
      });
      audit('USER_CREATED', actor, user_id, { role });
    },
    async listDevices(userId) {
      record('listDevices', userId);
      return dir.devices
        .filter((d) => d.user_id === userId)
        .map((d): AdminDeviceRow => ({
          device_id: d.device_id,
          device_name: d.device_name,
          last_login_at: d.last_login_at,
          is_device_revoked: d.is_device_revoked,
          device_revoked_at: d.device_revoked_at,
          has_session: d.session_id !== null,
        }));
    },
    async revokeDevice({ actor, user_id, device_id }) {
      record('revokeDevice', { actor, user_id, device_id });
      const device = dir.devices.find((d) => d.user_id === user_id && d.device_id === device_id);
      if (!device) return 'NOT_FOUND';
      if (device.is_device_revoked) return 'ALREADY_REVOKED';
      device.is_device_revoked = true;
      device.device_revoked_at = NOW_ISO();
      // Oturum satırı silinir, ama device.session_id KORUNUR: guard DEVICE_REVOKED demek için buna bakar.
      if (device.session_id) dir.sessions.delete(device.session_id);
      audit('DEVICE_REVOKED', actor, user_id, { revoked_device_id: device_id });
      return 'REVOKED';
    },
    async disableUser({ actor, user_id }) {
      record('disableUser', { actor, user_id });
      const profile = dir.profiles.get(user_id);
      if (!profile) return 'NOT_FOUND';
      profile.is_active = false;
      profile.all_sessions_revoked_at = NOW_ISO();
      for (const [sessionId, owner] of [...dir.sessions]) {
        if (owner === user_id) dir.sessions.delete(sessionId);
      }
      audit('ACCOUNT_DISABLED', actor, user_id, { reason: 'ADMIN_GLOBAL_REVOKE' });
      return 'DISABLED';
    },
    async activateUser({ actor, user_id }) {
      record('activateUser', { actor, user_id });
      const profile = dir.profiles.get(user_id);
      if (!profile) return 'NOT_FOUND';
      profile.is_active = true; // all_sessions_revoked_at bilerek korunur
      audit('USER_REACTIVATED', actor, user_id, {});
      return 'ACTIVATED';
    },
    async listAuditLogs(query: AuditLogsQuery) {
      record('listAuditLogs', query);
      return dir.audit
        .filter((row) => !query.action_type || row.action_type === query.action_type)
        .filter((row) => !query.actor_user_id || row.actor_user_id === query.actor_user_id)
        .filter((row) => !query.target_record_id || row.target_record_id === query.target_record_id)
        .slice(query.offset, query.offset + query.limit);
    },
  };
}

export interface FakeAuthAdmin extends AuthAdminPort {
  created: Array<{ id: string; email: string; role: AppRole }>;
  failCreate: boolean;
  failCreateWith: string | null;
  failBan: boolean;
}

/** Supabase Auth admin sahtesi. Başarısızlık anahtarları testlerde hata yollarını açar. */
export function fakeAuthAdmin(): FakeAuthAdmin {
  const port = {
    created: [] as Array<{ id: string; email: string; role: AppRole }>,
    failCreate: false,
    failCreateWith: null as string | null,
    failBan: false,
  } as FakeAuthAdmin;

  port.createAuthUser = vi.fn(async ({ email, role }: { email: string; password: string; role: AppRole }) => {
    if (port.failCreate) {
      const { AppError } = await import('../../src/types/errors.js');
      if (port.failCreateWith) {
        throw new AppError(409, 'CONFLICT', 'An account with this e-mail address already exists.');
      }
      throw new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');
    }
    const id = randomUUID();
    port.created.push({ id, email, role });
    return { id };
  }) as FakeAuthAdmin['createAuthUser'];

  port.deleteAuthUser = vi.fn(async () => undefined) as FakeAuthAdmin['deleteAuthUser'];

  port.banUser = vi.fn(async () => {
    if (port.failBan) {
      const { AppError } = await import('../../src/types/errors.js');
      throw new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');
    }
  }) as FakeAuthAdmin['banUser'];

  port.unbanUser = vi.fn(async () => undefined) as FakeAuthAdmin['unbanUser'];

  return port;
}
