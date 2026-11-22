import type { Request, Response, Router } from 'express';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { supabaseAdmin } from '../src/config/supabase.js';
import type { AuthGuardDeps } from '../src/middleware/auth.js';
import { requireRole } from '../src/middleware/require-role.js';
import {
  createSupabaseVictimStore,
  defaultVictimStore,
  type OverrideOptions,
  type VictimStore,
} from '../src/services/victim-store.js';
import type { AppRole, VictimRecord } from '../src/types/database.js';

// ---------------------------------------------------------------------------
// KESİN KURAL: bu dosyadaki hiçbir test gerçek (paylaşılan) Supabase projesine gitmez.
// - Guard: sahte getClaims + bellekte user_profiles/user_devices (OSP-61 deseni).
// - İş verisi: bellekte duran sahte VictimStore.
// - Güvenlik ağı: service-role client'ın `from`'u, global `fetch` ve defaultVictimStore
//   metotları casusla sarılır; herhangi biri çağrılırsa test başarısız olur.
// ---------------------------------------------------------------------------

const ROLES: readonly AppRole[] = ['rescuer', 'coordinator', 'administrator'];

const USERS: Record<AppRole, { id: string; session: string; device: string; token: string }> = {
  rescuer: {
    id: '11111111-1111-4111-8111-111111111111',
    session: '11111111-aaaa-4aaa-8aaa-111111111111',
    device: '11111111-dddd-4ddd-8ddd-111111111111',
    token: 'token.rescuer',
  },
  coordinator: {
    id: '22222222-2222-4222-8222-222222222222',
    session: '22222222-aaaa-4aaa-8aaa-222222222222',
    device: '22222222-dddd-4ddd-8ddd-222222222222',
    token: 'token.coordinator',
  },
  administrator: {
    id: '33333333-3333-4333-8333-333333333333',
    session: '33333333-aaaa-4aaa-8aaa-333333333333',
    device: '33333333-dddd-4ddd-8ddd-333333333333',
    token: 'token.administrator',
  },
};

const VICTIM_ID = '99999999-9999-4999-8999-999999999999';
const MISSING_VICTIM_ID = '88888888-8888-4888-8888-888888888888';

/** Token -> rol eşlemesi yapan sahte OSP-61 bağımlılıkları (ağ yok). */
function fakeGuardDeps(): AuthGuardDeps {
  const roleByToken = new Map(ROLES.map((role) => [USERS[role].token, role]));
  const getClaims = vi.fn(async (token: string) => {
    const role = roleByToken.get(token);
    if (!role) return { data: null, error: { name: 'AuthInvalidJwtError', message: 'bad' } };
    const user = USERS[role];
    return {
      data: {
        // JWT'deki user_role kasıtlı olarak yanlış: rol DB'den (user_profiles) gelmelidir.
        claims: {
          sub: user.id,
          session_id: user.session,
          iat: 1_790_000_000,
          aud: 'authenticated',
          user_role: 'administrator',
        },
        header: { alg: 'ES256' },
        signature: new Uint8Array(),
      },
      error: null,
    };
  });

  const from = (table: string) => {
    const filters = new Map<string, unknown>();
    const builder = {
      select: () => builder,
      eq: (column: string, value: unknown) => {
        filters.set(column, value);
        return builder;
      },
      maybeSingle: async () => {
        const role = ROLES.find(
          (r) => USERS[r].id === (filters.get('id') ?? filters.get('user_id')),
        );
        if (!role) return { data: null, error: null };
        const user = USERS[role];
        if (table === 'user_profiles') {
          return { data: { role, is_active: true, all_sessions_revoked_at: null }, error: null };
        }
        if (table === 'user_devices' && filters.get('session_id') === user.session) {
          return {
            data: { user_id: user.id, device_id: user.device, is_device_revoked: false },
            error: null,
          };
        }
        return { data: null, error: null };
      },
    };
    return builder;
  };

  return {
    authClient: { auth: { getClaims } },
    dbClient: { from },
  } as unknown as AuthGuardDeps;
}

/** Bellekte duran sahte store; her metot çağrı sayımı için vi.fn ile sarılıdır. */
function createFakeStore() {
  const victims: VictimRecord[] = [
    {
      id: VICTIM_ID,
      created_at: '2026-11-20T10:00:00+00:00',
      created_by: USERS.rescuer.id,
      payload: { status: 'trapped' },
    },
  ];
  const store = {
    listVictims: vi.fn(async () => victims.map((v) => ({ ...v }))),
    getVictim: vi.fn(async (id: string) => victims.find((v) => v.id === id) ?? null),
    overrideVictim: vi.fn(
      async (
        id: string,
        payload: Record<string, unknown>,
        actorUserId: string,
        options: OverrideOptions = {},
      ) => {
        const victim = victims.find((v) => v.id === id);
        if (!victim) return null;
        victim.payload = {
          ...victim.payload,
          ...payload,
          _override: { by: actorUserId, ...(options.reason ? { reason: options.reason } : {}) },
        };
        return { ...victim };
      },
    ),
    insertObservation: vi.fn(async (payload: Record<string, unknown>, actorUserId: string) => ({
      id: '77777777-7777-4777-8777-777777777777',
      created_at: '2026-11-22T10:00:00+00:00',
      created_by: actorUserId,
      payload,
    })),
  } satisfies VictimStore;
  return store;
}

type FakeStore = ReturnType<typeof createFakeStore>;
type StoreMethod = keyof VictimStore;

// Test-only admin ucu (karar 1: üretim koduna admin ucu eklenmez, OSP-66'nın işi).
const registerTestAdminRoute = (router: Router) => {
  router.get('/test-admin/ping', requireRole('administrator'), (_req: Request, res: Response) => {
    res.status(200).json({ ok: true });
  });
};

let store: FakeStore;
let app: ReturnType<typeof createApp>;

// Güvenlik ağı casusları
const realDbSpy = vi.spyOn(supabaseAdmin, 'from').mockImplementation(() => {
  throw new Error('Real Supabase access is forbidden in tests');
});
const fetchSpy = vi.fn(async () => {
  throw new Error('Network access is forbidden in tests');
});
const defaultStoreSpies = (Object.keys(defaultVictimStore) as StoreMethod[]).map((method) =>
  vi.spyOn(defaultVictimStore, method),
);

beforeAll(() => {
  vi.stubGlobal('fetch', fetchSpy);
});

afterAll(() => {
  // Hiçbir test gerçek DB'ye / ağa / varsayılan store'a ulaşmamış olmalı.
  expect(realDbSpy).not.toHaveBeenCalled();
  expect(fetchSpy).not.toHaveBeenCalled();
  for (const spy of defaultStoreSpies) expect(spy).not.toHaveBeenCalled();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

beforeEach(() => {
  store = createFakeStore();
  app = createApp({
    authGuardDeps: fakeGuardDeps(),
    victimStore: store,
    registerProtectedRoutes: registerTestAdminRoute,
  });
});

interface Endpoint {
  name: string;
  method: 'get' | 'post' | 'patch';
  path: string;
  body?: object;
  allowed: readonly AppRole[];
  successStatus: number;
  storeMethod: StoreMethod | null;
}

const ENDPOINTS: readonly Endpoint[] = [
  {
    name: 'POST /sync',
    method: 'post',
    path: '/api/v1/sync',
    body: { payload: { note: 'voice heard' } },
    allowed: ['rescuer'],
    successStatus: 201,
    storeMethod: 'insertObservation',
  },
  {
    name: 'GET /victims',
    method: 'get',
    path: '/api/v1/victims',
    allowed: ['coordinator', 'administrator'],
    successStatus: 200,
    storeMethod: 'listVictims',
  },
  {
    name: 'GET /victims/:id',
    method: 'get',
    path: `/api/v1/victims/${VICTIM_ID}`,
    allowed: ['coordinator', 'administrator'],
    successStatus: 200,
    storeMethod: 'getVictim',
  },
  {
    name: 'PATCH /victims/:id/override',
    method: 'patch',
    path: `/api/v1/victims/${VICTIM_ID}/override`,
    body: { payload: { status: 'rescued' }, reason: 'field confirmation' },
    allowed: ['coordinator'],
    successStatus: 200,
    storeMethod: 'overrideVictim',
  },
  {
    name: 'POST /assignments',
    method: 'post',
    path: '/api/v1/assignments',
    body: { victim_id: VICTIM_ID, rescuer_id: USERS.rescuer.id },
    allowed: ['coordinator'],
    successStatus: 201,
    // Kalıcı kayıt yok: hiçbir store metodu çağrılmamalı.
    storeMethod: null,
  },
];

const STORE_METHODS: readonly StoreMethod[] = [
  'listVictims',
  'getVictim',
  'overrideVictim',
  'insertObservation',
];

function send(
  endpoint: Pick<Endpoint, 'method' | 'path' | 'body'>,
  role: AppRole | null,
) {
  let req = request(app)[endpoint.method](endpoint.path);
  if (role) req = req.set('Authorization', `Bearer ${USERS[role].token}`);
  return endpoint.body ? req.send(endpoint.body) : req;
}

function expectError(res: request.Response, status: number, errorCode: string) {
  expect(res.status).toBe(status);
  expect(res.body).toEqual({ error_code: errorCode, message: expect.any(String) });
}

function expectNoStoreCalls() {
  for (const method of STORE_METHODS) expect(store[method]).not.toHaveBeenCalled();
}

// 3 rol x 5 uç = 15 hücre
const MATRIX = ENDPOINTS.flatMap((endpoint) =>
  ROLES.map((role) => ({ endpoint, role, allowed: endpoint.allowed.includes(role) })),
);

describe('OSP-62: RBAC matrisi (3 rol x 5 uç)', () => {
  it('matris 15 hücredir', () => {
    expect(MATRIX).toHaveLength(15);
  });

  it.each(MATRIX.map((cell) => [cell.role, cell.endpoint.name, cell.allowed ? 'izinli' : '403', cell] as const))(
    '%s -> %s: %s',
    async (_role, _name, _label, { endpoint, role, allowed }) => {
      const res = await send(endpoint, role);
      if (allowed) {
        expect(res.status).toBe(endpoint.successStatus);
        if (endpoint.storeMethod) {
          expect(store[endpoint.storeMethod]).toHaveBeenCalledTimes(1);
        } else {
          expectNoStoreCalls();
        }
      } else {
        expectError(res, 403, 'ROLE_FORBIDDEN');
        expectNoStoreCalls();
      }
    },
  );

  it('izinsiz istek şemaya uymayan (geçerli JSON) gövdeyle 400 değil 403 alır (rol kontrolü önce)', async () => {
    const res = await send({ method: 'post', path: '/api/v1/sync', body: { bogus: 1 } }, 'coordinator');
    expectError(res, 403, 'ROLE_FORBIDDEN');
    expectNoStoreCalls();
  });
});

describe('OSP-62: JSON sözdizimi hatası rol kontrolünden önce', () => {
  // Bilinçli davranış: app.ts'te jsonBody korumalı router'dan önce (guard'dan sonra) çalışır,
  // bu yüzden yetkisiz rol bile bozuk JSON'da 403 yerine 400 alır. Mount sırası değişirse bu
  // test bunu yakalar.
  it.each<AppRole>(['coordinator', 'administrator'])(
    'yetkisiz rol (%s) + bozuk JSON -> 400 VALIDATION_ERROR, store çağrılmaz',
    async (role) => {
      const res = await request(app)
        .post('/api/v1/sync')
        .set('Authorization', `Bearer ${USERS[role].token}`)
        .set('Content-Type', 'application/json')
        .send('{"payload":');
      expectError(res, 400, 'VALIDATION_ERROR');
      expectNoStoreCalls();
    },
  );
});

describe('OSP-62: test-only admin ucu (requireRole("administrator"))', () => {
  const adminEndpoint = { method: 'get', path: '/api/v1/test-admin/ping' } as const;

  it('administrator -> 200', async () => {
    const res = await send(adminEndpoint, 'administrator');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it.each<AppRole>(['rescuer', 'coordinator'])('%s -> 403 ROLE_FORBIDDEN', async (role) => {
    expectError(await send(adminEndpoint, role), 403, 'ROLE_FORBIDDEN');
  });
});

describe('OSP-62: token yoksa 401 (rol kontrolüne hiç gelinmez)', () => {
  it.each(ENDPOINTS.map((e) => [e.name, e] as const))('%s -> 401 UNAUTHENTICATED', async (_n, e) => {
    const res = await send(e, null);
    expectError(res, 401, 'UNAUTHENTICATED');
    expectNoStoreCalls();
  });

  it('geçersiz token -> 401', async () => {
    const res = await request(app).get('/api/v1/victims').set('Authorization', 'Bearer nope');
    expectError(res, 401, 'UNAUTHENTICATED');
  });
});

describe('OSP-62: kabul kriterleri', () => {
  it('rescuer -> GET /victims 403', async () => {
    expectError(await send(ENDPOINTS[1]!, 'rescuer'), 403, 'ROLE_FORBIDDEN');
  });

  it('coordinator -> POST /sync 403', async () => {
    expectError(await send(ENDPOINTS[0]!, 'coordinator'), 403, 'ROLE_FORBIDDEN');
  });

  it('administrator -> PATCH override 403, POST assignments 403, GET /victims 200', async () => {
    expectError(await send(ENDPOINTS[3]!, 'administrator'), 403, 'ROLE_FORBIDDEN');
    expectError(await send(ENDPOINTS[4]!, 'administrator'), 403, 'ROLE_FORBIDDEN');
    const res = await send(ENDPOINTS[1]!, 'administrator');
    expect(res.status).toBe(200);
    expect(res.body.victims).toHaveLength(1);
  });
});

describe('OSP-62: yanıt içerikleri ve kimlik bağlama', () => {
  it('POST /sync created_by = req.auth.user_id (gövdeden değil)', async () => {
    const res = await send(ENDPOINTS[0]!, 'rescuer');
    expect(res.status).toBe(201);
    expect(store.insertObservation).toHaveBeenCalledWith({ note: 'voice heard' }, USERS.rescuer.id);
    expect(res.body.observation.created_by).toBe(USERS.rescuer.id);
  });

  it('PATCH override actor = koordinatörün user_id\'si, yanıt güncel kayıt', async () => {
    const res = await send(ENDPOINTS[3]!, 'coordinator');
    expect(res.status).toBe(200);
    expect(store.overrideVictim).toHaveBeenCalledWith(
      VICTIM_ID,
      { status: 'rescued' },
      USERS.coordinator.id,
      { reason: 'field confirmation' },
    );
    expect(res.body.victim.payload.status).toBe('rescued');
    expect(res.body.victim.payload._override.reason).toBe('field confirmation');
  });

  it.each([
    ['GET /victims', '/api/v1/victims'],
    ['GET /victims/:id', `/api/v1/victims/${VICTIM_ID}`],
  ])('%s kişisel veri döndüğü için Cache-Control: no-store taşır', async (_label, path) => {
    const res = await send({ method: 'get', path }, 'coordinator');
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('POST /assignments stub olduğunu belirtir ve kalıcı kayıt yapmaz', async () => {
    const res = await send(ENDPOINTS[4]!, 'coordinator');
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      stub: true,
      persisted: false,
      assignment: { victim_id: VICTIM_ID, assigned_by: USERS.coordinator.id },
    });
  });
});

describe('OSP-62: doğrulama hataları', () => {
  it('GET /victims/:id geçersiz UUID -> 400 VALIDATION_ERROR, store çağrılmaz', async () => {
    const res = await send({ method: 'get', path: '/api/v1/victims/not-a-uuid' }, 'coordinator');
    expectError(res, 400, 'VALIDATION_ERROR');
    expectNoStoreCalls();
  });

  it('GET /victims/:id kayıt yok -> 404 NOT_FOUND', async () => {
    const res = await send({ method: 'get', path: `/api/v1/victims/${MISSING_VICTIM_ID}` }, 'administrator');
    expectError(res, 404, 'NOT_FOUND');
  });

  it('PATCH override kayıt yok -> 404 NOT_FOUND', async () => {
    const res = await send(
      { method: 'patch', path: `/api/v1/victims/${MISSING_VICTIM_ID}/override`, body: { payload: { a: 1 } } },
      'coordinator',
    );
    expectError(res, 404, 'NOT_FOUND');
  });

  it('PATCH override geçersiz UUID -> 400', async () => {
    const res = await send(
      { method: 'patch', path: '/api/v1/victims/123/override', body: { payload: { a: 1 } } },
      'coordinator',
    );
    expectError(res, 400, 'VALIDATION_ERROR');
    expectNoStoreCalls();
  });

  it.each([
    ['boş gövde', undefined],
    ['boş payload', { payload: {} }],
    ['payload dizi', { payload: [1, 2] }],
    ['bilinmeyen alan', { payload: { a: 1 }, extra: true }],
  ])('PATCH override %s -> 400', async (_label, body) => {
    const res = await send(
      { method: 'patch', path: `/api/v1/victims/${VICTIM_ID}/override`, ...(body ? { body } : {}) },
      'coordinator',
    );
    expectError(res, 400, 'VALIDATION_ERROR');
    expectNoStoreCalls();
  });

  it.each([
    ['payload yok', {}],
    ['payload string', { payload: 'x' }],
  ])('POST /sync %s -> 400', async (_label, body) => {
    expectError(await send({ method: 'post', path: '/api/v1/sync', body }, 'rescuer'), 400, 'VALIDATION_ERROR');
    expectNoStoreCalls();
  });

  it('POST /sync bozuk JSON -> 400', async () => {
    const res = await request(app)
      .post('/api/v1/sync')
      .set('Authorization', `Bearer ${USERS.rescuer.token}`)
      .set('Content-Type', 'application/json')
      .send('{"payload":');
    expectError(res, 400, 'VALIDATION_ERROR');
    expectNoStoreCalls();
  });

  it('POST /assignments geçersiz victim_id -> 400', async () => {
    const res = await send(
      { method: 'post', path: '/api/v1/assignments', body: { victim_id: 'x', rescuer_id: USERS.rescuer.id } },
      'coordinator',
    );
    expectError(res, 400, 'VALIDATION_ERROR');
  });
});

describe('OSP-62: createSupabaseVictimStore (sahte client, ağ yok)', () => {
  /** Zincirlenebilir sahte PostgREST builder; her çağrıyı kaydeder. */
  function fakeClient(result: { data: unknown; error: unknown }) {
    const calls: Array<[string, ...unknown[]]> = [];
    const builder: Record<string, unknown> = {};
    for (const name of ['select', 'eq', 'order', 'limit', 'update', 'insert']) {
      builder[name] = (...args: unknown[]) => {
        calls.push([name, ...args]);
        return builder;
      };
    }
    const finish = (name: string) => async () => {
      calls.push([name]);
      return result;
    };
    builder.maybeSingle = finish('maybeSingle');
    builder.single = finish('single');
    builder.returns = finish('returns');
    const from = vi.fn((table: string) => {
      calls.push(['from', table]);
      return builder;
    });
    return { client: { from } as unknown as Parameters<typeof createSupabaseVictimStore>[0], calls };
  }

  it('insertObservation created_by = actor ile rescuer_observations\'a yazar', async () => {
    const row = { id: 'x', created_at: 't', created_by: USERS.rescuer.id, payload: { a: 1 } };
    const { client, calls } = fakeClient({ data: row, error: null });
    await expect(
      createSupabaseVictimStore(client).insertObservation({ a: 1 }, USERS.rescuer.id),
    ).resolves.toEqual(row);
    expect(calls).toContainEqual(['from', 'rescuer_observations']);
    expect(calls).toContainEqual(['insert', { payload: { a: 1 }, created_by: USERS.rescuer.id }]);
  });

  it('overrideVictim reason verilirse _override.reason olarak yazar, verilmezse alanı eklemez', async () => {
    const existing = { id: VICTIM_ID, created_at: 't', created_by: null, payload: { a: 1 } };
    const withReason = fakeClient({ data: existing, error: null });
    await createSupabaseVictimStore(withReason.client).overrideVictim(
      VICTIM_ID,
      { b: 2 },
      USERS.coordinator.id,
      { reason: 'confirmed' },
    );
    const update = withReason.calls.find((c) => c[0] === 'update')?.[1] as {
      payload: { a: number; b: number; _override: Record<string, unknown> };
    };
    expect(update.payload).toMatchObject({
      a: 1,
      b: 2,
      _override: { by: USERS.coordinator.id, reason: 'confirmed', at: expect.any(String) },
    });

    const noReason = fakeClient({ data: existing, error: null });
    await createSupabaseVictimStore(noReason.client).overrideVictim(VICTIM_ID, { b: 2 }, USERS.coordinator.id);
    const update2 = noReason.calls.find((c) => c[0] === 'update')?.[1] as {
      payload: { _override: Record<string, unknown> };
    };
    expect(update2.payload._override).not.toHaveProperty('reason');
  });

  it('getVictim id ile filtreler; yoksa null', async () => {
    const { client, calls } = fakeClient({ data: null, error: null });
    await expect(createSupabaseVictimStore(client).getVictim(VICTIM_ID)).resolves.toBeNull();
    expect(calls).toContainEqual(['from', 'victim_records']);
    expect(calls).toContainEqual(['eq', 'id', VICTIM_ID]);
  });

  it('Supabase hatası ayrıntı sızdırmadan 500 INTERNAL_ERROR olur', async () => {
    const { client } = fakeClient({ data: null, error: { message: 'relation secret detail' } });
    await expect(createSupabaseVictimStore(client).listVictims()).rejects.toMatchObject({
      statusCode: 500,
      errorCode: 'INTERNAL_ERROR',
      message: expect.not.stringContaining('secret'),
    });
  });
});
