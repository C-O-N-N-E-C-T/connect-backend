/**
 * OSP-65 test sahteleri: bir koordinatör ve bir kurtarıcı içeren guard bağımlılıkları
 * (tests/osp61-auth-guard.test.ts ile aynı yapı), bellekte duran AuditLogStore ve bellekte
 * duran VictimStore (OSP-62). Ağ yok, Supabase yok.
 */
import { vi } from 'vitest';
import type { AuthGuardDeps } from '../../src/middleware/auth.js';
import type { AuditEntry, AuditLogStore } from '../../src/services/audit-log.js';
import type { VictimStore } from '../../src/services/victim-store.js';
import type { RescuerObservation, VictimRecord } from '../../src/types/database.js';
import { AppError } from '../../src/types/errors.js';

export const USER_ID = '11111111-1111-4111-8111-111111111111';
export const SESSION_ID = '33333333-3333-4333-8333-333333333333';
export const DEVICE_ID = '44444444-4444-4444-8444-444444444444';
export const RESCUER_ID = '22222222-2222-4222-8222-222222222222';
export const RESCUER_SESSION_ID = '66666666-6666-4666-8666-666666666666';
export const RESCUER_DEVICE_ID = '55555555-5555-4555-8555-555555555555';
export const RECORD_ID = '88888888-8888-4888-8888-888888888888';
export const OBSERVATION_ID = '99999999-9999-4999-8999-999999999999';
export const MISSING_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
export const TOKEN = 'valid.test.token';
export const RESCUER_TOKEN = 'valid.rescuer.token';

/** TOKEN için guard'ın eklediği koordinatör kimliği. */
export const ACTOR = {
  user_id: USER_ID,
  role: 'coordinator',
  device_id: DEVICE_ID,
  session_id: SESSION_ID,
} as const;

/** RESCUER_TOKEN için guard'ın eklediği kurtarıcı kimliği. */
export const RESCUER_ACTOR = {
  user_id: RESCUER_ID,
  role: 'rescuer',
  device_id: RESCUER_DEVICE_ID,
  session_id: RESCUER_SESSION_ID,
} as const;

export const AUTH_HEADER = { Authorization: `Bearer ${TOKEN}` };
export const RESCUER_AUTH_HEADER = { Authorization: `Bearer ${RESCUER_TOKEN}` };

export function fakeGuardDeps(): AuthGuardDeps {
  const tables: Record<string, Array<Record<string, unknown>>> = {
    user_profiles: [
      { id: USER_ID, role: 'coordinator', is_active: true, all_sessions_revoked_at: null },
      { id: RESCUER_ID, role: 'rescuer', is_active: true, all_sessions_revoked_at: null },
    ],
    user_devices: [
      { user_id: USER_ID, device_id: DEVICE_ID, session_id: SESSION_ID, is_device_revoked: false },
      {
        user_id: RESCUER_ID,
        device_id: RESCUER_DEVICE_ID,
        session_id: RESCUER_SESSION_ID,
        is_device_revoked: false,
      },
    ],
  };
  const from = (table: string) => {
    const filters: Array<[string, unknown]> = [];
    const builder = {
      select: (_columns: string) => builder,
      eq: (column: string, value: unknown) => {
        filters.push([column, value]);
        return builder;
      },
      maybeSingle: async () => ({
        data: (tables[table] ?? []).find((row) => filters.every(([c, v]) => row[c] === v)) ?? null,
        error: null,
      }),
    };
    return builder;
  };
  const now = Math.floor(Date.now() / 1000);
  const claimsFor: Record<string, { sub: string; session_id: string }> = {
    [TOKEN]: { sub: USER_ID, session_id: SESSION_ID },
    [RESCUER_TOKEN]: { sub: RESCUER_ID, session_id: RESCUER_SESSION_ID },
  };
  const getClaims = async (token: string) => {
    const base = claimsFor[token];
    return base
      ? {
          data: {
            claims: { ...base, iat: now - 60, exp: now + 3600, aud: 'authenticated' },
            header: { alg: 'ES256' },
            signature: new Uint8Array(),
          },
          error: null,
        }
      : { data: null, error: { name: 'AuthInvalidJwtError', message: 'Invalid JWT' } };
  };
  return { authClient: { auth: { getClaims } }, dbClient: { from } } as unknown as AuthGuardDeps;
}

export interface FakeAuditStore extends AuditLogStore {
  rows: AuditEntry[];
  fail: boolean;
  write: ReturnType<typeof vi.fn> & AuditLogStore['write'];
}

export function fakeAuditStore(): FakeAuditStore {
  const store = {
    rows: [] as AuditEntry[],
    fail: false,
  } as FakeAuditStore;
  store.write = vi.fn(async (entry: AuditEntry) => {
    if (store.fail) throw new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');
    store.rows.push(entry);
  }) as FakeAuditStore['write'];
  return store;
}

export function victim(overrides: Partial<VictimRecord> = {}): VictimRecord {
  return {
    id: RECORD_ID,
    created_at: '2026-11-22T10:00:00+00:00',
    created_by: USER_ID,
    payload: { note: 'trapped under debris' },
    ...overrides,
  };
}

/**
 * src/services/victim-store.ts ile aynı sözleşmeye sahip, bellekte duran VictimStore.
 *
 * Yazma metotları gerçek SQL fonksiyonları gibi davranır: yeni durum hesaplanır, audit
 * satırı `audit` store'una yazılır ve değişiklik ANCAK audit başarılı olursa uygulanır
 * (audit hata verirse transaction geri alınmış gibi hiçbir şey değişmez).
 */
export interface FakeVictimStore extends VictimStore {
  records: VictimRecord[];
  observations: RescuerObservation[];
}

export function fakeVictimStore(
  initial: VictimRecord[] = [victim()],
  audit: AuditLogStore = fakeAuditStore(),
): FakeVictimStore {
  const records = initial.map((r) => ({ ...r, payload: { ...r.payload } }));
  const observations: RescuerObservation[] = [];
  return {
    records,
    observations,
    async listVictims() {
      return records.map((r) => ({ ...r }));
    },
    async getVictim(id) {
      const record = records.find((r) => r.id === id);
      return record ? { ...record } : null;
    },
    async overrideVictim(id, payload, actor, options = {}) {
      const record = records.find((r) => r.id === id);
      if (!record) return null;
      const merged = {
        ...record.payload,
        ...payload,
        _override: { by: actor.user_id, ...(options.reason !== undefined ? { reason: options.reason } : {}) },
      };
      await audit.write({
        actor,
        action_type: 'VICTIM_UPDATE',
        target_record_id: id,
        metadata: { override: true, has_reason: options.reason !== undefined },
      });
      record.payload = merged;
      return { ...record };
    },
    async insertObservation(payload, actor): Promise<RescuerObservation> {
      const observation = {
        id: OBSERVATION_ID,
        created_at: '2026-11-22T10:00:00+00:00',
        created_by: actor.user_id,
        payload,
      };
      await audit.write({ actor, action_type: 'OBSERVATION_SYNC', target_record_id: observation.id });
      observations.push(observation);
      return observation;
    },
  };
}
