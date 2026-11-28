import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { AppRole } from '../../src/types/database.js';
import {
  addSession,
  authed,
  bindSession,
  createSessionUser,
  decodePayload,
  newCleanup,
  nextIp,
  nowSeconds,
  runCleanup,
  serviceClient,
  signHs256,
  uniqueEmail,
  type SessionUser,
} from './helpers.js';

// =============================================================================================
// OSP-68 / AC-19: kimlik doğrulama, rol matrisi ve iptal — GERÇEK uçtan uca ortam.
//
// - Gerçek Express uygulaması (createApp(), sahte bağımlılık YOK) process içinde, supertest ile.
// - Gerçek yerel Supabase: GoTrue (ES256 + JWKS), PostgREST, Postgres (migration'lar uygulanmış).
// - Fake tabanlı birim testleri (tests/osp61-*, osp62-*, osp66-*, osp70-*) davranışı izole
//   doğrular; bu dosya aynı kuralların gerçek token, gerçek DB ve gerçek RPC ile tuttuğunu gösterir.
// =============================================================================================

// Uygulama, helpers.ts'teki yerel-config kontrolünden SONRA dinamik olarak yüklenir:
// statik import'lar bildirim sırasıyla değerlendirildiğinden, src/app.js (ve .env okuyan
// src/config/env.ts) statik olsaydı import sıralaması değiştiğinde kontrolden önce çalışabilirdi.
// Dosya entegrasyon config'i dışında çalıştırılırsa helpers.ts açık bir hatayla durur ve bu
// satıra hiç gelinmez.
const { createApp } = await import('../../src/app.js');
const app = createApp();
const cleanup = newCleanup();
const admin = serviceClient();

let rescuer: SessionUser;
let coordinator: SessionUser;
let administrator: SessionUser;
let victimId: string;

beforeAll(async () => {
  rescuer = await createSessionUser(app, cleanup, 'rescuer', 'ac19-rescuer');
  coordinator = await createSessionUser(app, cleanup, 'coordinator', 'ac19-coord');
  administrator = await createSessionUser(app, cleanup, 'administrator', 'ac19-admin');

  // GET /victims/:id ve override için gerçek bir kazazede kaydı (service_role ile).
  const { data, error } = await admin
    .from('victim_records')
    .insert({ payload: { osp68: 'ac19', status: 'initial' } })
    .select('id')
    .single();
  if (error || !data) throw new Error(`victim insert failed: ${error?.message}`);
  victimId = data.id as string;
  cleanup.victimIds.add(victimId);
});

afterAll(async () => {
  await runCleanup(cleanup);
});

// ---------------------------------------------------------------------------------------------
// 1. Eksik / bozuk / süresi dolmuş JWT -> %100 401 UNAUTHENTICATED
// ---------------------------------------------------------------------------------------------

type Method = 'get' | 'post' | 'patch';
interface Endpoint {
  method: Method;
  path: string;
  body?: Record<string, unknown>;
}

// Var olmayan rastgele kimlikler: istek 401'de durmalı, hiçbir kayda ulaşmamalı.
const GHOST_ID = randomUUID();
const GHOST_DEVICE = randomUUID();

/** /api/v1 altındaki TÜM korumalı uçlar + public /auth/session + bilinmeyen bir yol. */
const ENDPOINTS: readonly Endpoint[] = [
  { method: 'post', path: '/api/v1/auth/session', body: { device_id: GHOST_DEVICE, device_name: 'x' } },
  { method: 'get', path: '/api/v1/auth/me' },
  { method: 'post', path: '/api/v1/auth/logout' },
  { method: 'post', path: '/api/v1/sync', body: { payload: { a: 1 } } },
  { method: 'get', path: '/api/v1/victims' },
  { method: 'get', path: `/api/v1/victims/${GHOST_ID}` },
  { method: 'patch', path: `/api/v1/victims/${GHOST_ID}/override`, body: { payload: { a: 1 } } },
  { method: 'post', path: '/api/v1/assignments', body: { victim_id: GHOST_ID, rescuer_id: GHOST_ID } },
  { method: 'get', path: '/api/v1/admin/users' },
  {
    method: 'post',
    path: '/api/v1/admin/users',
    body: { email: uniqueEmail('ac19-never'), password: 'Aa1!xxxxxxxx', full_name: 'x', role: 'rescuer' },
  },
  { method: 'get', path: `/api/v1/admin/users/${GHOST_ID}/devices` },
  { method: 'post', path: `/api/v1/admin/users/${GHOST_ID}/devices/${GHOST_DEVICE}/revoke` },
  { method: 'post', path: `/api/v1/admin/users/${GHOST_ID}/revoke-all` },
  { method: 'post', path: `/api/v1/admin/users/${GHOST_ID}/reactivate` },
  { method: 'get', path: '/api/v1/admin/audit-logs' },
  { method: 'get', path: '/api/v1/does-not-exist' },
];

/** Bir uca, verilen Authorization değeriyle (ya da hiç başlıksız) istek atar. Her istek ayrı IP. */
function send(ep: Endpoint, authorization: string | null): request.Test {
  let req = request(app)[ep.method](ep.path).set('X-Forwarded-For', nextIp());
  if (authorization !== null) req = req.set('Authorization', authorization);
  return ep.body ? req.send(ep.body) : req;
}

/**
 * POST /admin/users beklenmedik biçimde 201 dönerse (regresyon) oluşan kullanıcı, assertion'dan
 * ÖNCE temizlik listesine eklenir: test kırılsa bile yerel DB'de artık kalmaz.
 */
function trackCreatedUser(path: string, res: request.Response): void {
  const id = (res.body as { user?: { id?: unknown } } | undefined)?.user?.id;
  if (res.status === 201 && typeof id === 'string' && path === '/api/v1/admin/users') {
    cleanup.userIds.add(id);
  }
}

/** Token'ın imza kısmını başka bir geçerli token'ın imzasıyla değiştirir (imza artık uymaz). */
function swapSignature(token: string, donor: string): string {
  const [h, p] = token.split('.');
  return `${h}.${p}.${donor.split('.')[2]}`;
}

/** Payload'ı değiştirip ORİJİNAL imzayı korur (ör. rolü yükseltme denemesi). */
function tamperPayload(token: string, patch: Record<string, unknown>): string {
  const [h, , s] = token.split('.');
  const payload = { ...decodePayload(token), ...patch };
  return `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
}

/** Bağlı (bound) bir oturumun GERÇEK claim'leri; yalnızca iat/exp değiştirilerek yeniden imzalanır. */
function resignedClaims(user: SessionUser, iat: number, exp: number): Record<string, unknown> {
  return { ...decodePayload(user.accessToken), iat, exp };
}

/**
 * Her senaryo, testin çalıştığı anda Authorization başlığını üretir (null = başlık yok).
 * Gerçek token'lar beforeAll'da oluştuğu için fabrika fonksiyonu kullanılır.
 */
const BAD_CREDENTIALS: ReadonlyArray<[string, () => string | null]> = [
  ['missing Authorization header', () => null],
  ['empty Bearer value', () => 'Bearer '],
  ['wrong scheme with a real, valid token', () => `Token ${rescuer.accessToken}`],
  ['garbage token', () => 'Bearer not-a-jwt'],
  ['three garbage segments', () => 'Bearer aaaa.bbbb.cccc'],
  [
    'real token with a forged payload (role escalation, original signature)',
    () => `Bearer ${tamperPayload(rescuer.accessToken, { user_role: 'administrator', sub: administrator.id })}`,
  ],
  ['real token with another token\'s signature', () => `Bearer ${swapSignature(rescuer.accessToken, coordinator.accessToken)}`],
  [
    'alg "none" (unsigned) token with real claims',
    () => {
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const body = Buffer.from(JSON.stringify(decodePayload(rescuer.accessToken))).toString('base64url');
      return `Bearer ${header}.${body}.`;
    },
  ],
  [
    'HS256 token signed with a WRONG secret (real claims, not expired)',
    () => `Bearer ${signHs256(resignedClaims(rescuer, nowSeconds(), nowSeconds() + 600), 'x'.repeat(48))}`,
  ],
  [
    'EXPIRED token with a VALID signature (local JWT secret, real bound session claims)',
    () => `Bearer ${signHs256(resignedClaims(rescuer, nowSeconds() - 7200, nowSeconds() - 3600))}`,
  ],
];

describe('AC-19 / OSP-61: missing, malformed or expired JWT -> 100% HTTP 401 UNAUTHENTICATED', () => {
  it.each(BAD_CREDENTIALS)('AC-19: %s -> 401 on every /api/v1 endpoint', async (_name, makeHeader) => {
    const header = makeHeader();
    for (const ep of ENDPOINTS) {
      const res = await send(ep, header);
      trackCreatedUser(ep.path, res);
      const where = `${ep.method.toUpperCase()} ${ep.path}`;
      expect(res.status, where).toBe(401);
      expect(res.body, where).toEqual({ error_code: 'UNAUTHENTICATED', message: expect.any(String) });
      expect(res.headers['www-authenticate'], where).toBe('Bearer');
    }
  });

  it('AC-19: Supabase anon key and service_role key are not user tokens -> 401 everywhere', async () => {
    const { anonKey, serviceRoleKey } = inject('localSupabase');
    for (const key of [anonKey, serviceRoleKey]) {
      for (const ep of ENDPOINTS) {
        const res = await send(ep, `Bearer ${key}`);
        expect(res.status, `${ep.method.toUpperCase()} ${ep.path}`).toBe(401);
        expect(res.body.error_code).toBe('UNAUTHENTICATED');
      }
    }
  });

  it('AC-19 control: the SAME signing method with a future exp is accepted (so the expired token above was validly signed and failed only on exp)', async () => {
    const fresh = signHs256(resignedClaims(rescuer, nowSeconds(), nowSeconds() + 600));
    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${fresh}`)
      .set('X-Forwarded-For', rescuer.ip);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ user_id: rescuer.id, role: 'rescuer', device_id: rescuer.deviceId });
  });

  it('AC-19 control: every real user token is accepted on GET /auth/me (role from the database)', async () => {
    for (const user of [rescuer, coordinator, administrator]) {
      const res = await authed(request(app).get('/api/v1/auth/me'), user);
      expect(res.status, user.role).toBe(200);
      expect(res.body).toEqual({ user_id: user.id, role: user.role, device_id: user.deviceId });
    }
  });
});

// ---------------------------------------------------------------------------------------------
// 2. Tam rol matrisi (rescuer / coordinator / administrator)
// ---------------------------------------------------------------------------------------------

type Expectation = Record<AppRole, number>;
interface MatrixRow {
  name: string;
  method: Method;
  path: () => string;
  body?: () => Record<string, unknown>;
  expected: Expectation;
}

const MATRIX: readonly MatrixRow[] = [
  {
    name: 'POST /sync (rescuer observation)',
    method: 'post',
    path: () => '/api/v1/sync',
    body: () => ({ payload: { osp68: 'ac19-matrix' } }),
    expected: { rescuer: 201, coordinator: 403, administrator: 403 },
  },
  {
    name: 'GET /victims',
    method: 'get',
    path: () => '/api/v1/victims',
    expected: { rescuer: 403, coordinator: 200, administrator: 200 },
  },
  {
    name: 'GET /victims/:id',
    method: 'get',
    path: () => `/api/v1/victims/${victimId}`,
    expected: { rescuer: 403, coordinator: 200, administrator: 200 },
  },
  {
    name: 'FR-D-06 PATCH /victims/:id/override (administrator is read-only)',
    method: 'patch',
    path: () => `/api/v1/victims/${victimId}/override`,
    body: () => ({ payload: { status: 'overridden-by-matrix' } }),
    expected: { rescuer: 403, coordinator: 200, administrator: 403 },
  },
  {
    name: 'FR-D-07 POST /assignments (administrator may not assign)',
    method: 'post',
    path: () => '/api/v1/assignments',
    body: () => ({ victim_id: victimId, rescuer_id: rescuer.id }),
    expected: { rescuer: 403, coordinator: 201, administrator: 403 },
  },
  {
    name: 'GET /admin/users',
    method: 'get',
    path: () => '/api/v1/admin/users?limit=1',
    expected: { rescuer: 403, coordinator: 403, administrator: 200 },
  },
  {
    name: 'GET /admin/users/:id/devices',
    method: 'get',
    path: () => `/api/v1/admin/users/${rescuer.id}/devices`,
    expected: { rescuer: 403, coordinator: 403, administrator: 200 },
  },
  {
    name: 'GET /admin/audit-logs',
    method: 'get',
    path: () => `/api/v1/admin/audit-logs?limit=1&actor_user_id=${rescuer.id}`,
    expected: { rescuer: 403, coordinator: 403, administrator: 200 },
  },
  {
    // Hesap açma yalnızca yöneticinin işidir. Her çağrıda benzersiz e-posta; oluşan kullanıcı
    // trackCreatedUser ile temizlik listesine girer.
    name: 'POST /admin/users (create a rescuer account)',
    method: 'post',
    path: () => '/api/v1/admin/users',
    body: () => ({
      email: uniqueEmail('ac19-created'),
      password: `Aa1!${randomUUID()}`,
      full_name: 'OSP-68 created by admin',
      role: 'rescuer',
    }),
    expected: { rescuer: 403, coordinator: 403, administrator: 201 },
  },
  {
    // Yönetici bile administrator hesabı açamaz (yetki yükseltme). Hiçbir rol için kayıt oluşmaz.
    name: 'POST /admin/users with role=administrator (privilege escalation)',
    method: 'post',
    path: () => '/api/v1/admin/users',
    body: () => ({
      email: uniqueEmail('ac19-escalation'),
      password: 'Aa1!escalation-pw',
      full_name: 'OSP-68 escalation',
      role: 'administrator',
    }),
    expected: { rescuer: 403, coordinator: 403, administrator: 403 },
  },
  {
    // Var olmayan hedef: yönetici rol kontrolünü geçer ve 404 alır; diğer roller 403'te durur.
    name: 'POST /admin/users/:id/devices/:deviceId/revoke (unknown target)',
    method: 'post',
    path: () => `/api/v1/admin/users/${GHOST_ID}/devices/${GHOST_DEVICE}/revoke`,
    expected: { rescuer: 403, coordinator: 403, administrator: 404 },
  },
  {
    name: 'POST /admin/users/:id/revoke-all (unknown target)',
    method: 'post',
    path: () => `/api/v1/admin/users/${GHOST_ID}/revoke-all`,
    expected: { rescuer: 403, coordinator: 403, administrator: 404 },
  },
  {
    name: 'POST /admin/users/:id/reactivate (unknown target)',
    method: 'post',
    path: () => `/api/v1/admin/users/${GHOST_ID}/reactivate`,
    expected: { rescuer: 403, coordinator: 403, administrator: 404 },
  },
  {
    name: 'GET /auth/me',
    method: 'get',
    path: () => '/api/v1/auth/me',
    expected: { rescuer: 200, coordinator: 200, administrator: 200 },
  },
];

describe('AC-19 / OSP-62: full role matrix with real users (403 ROLE_FORBIDDEN outside the role)', () => {
  const users = (): Record<AppRole, SessionUser> => ({ rescuer, coordinator, administrator });

  for (const row of MATRIX) {
    it.each(['rescuer', 'coordinator', 'administrator'] as const)(
      `AC-19: ${row.name} as %s`,
      async (role) => {
        const user = users()[role];
        let req = authed(request(app)[row.method](row.path()), user);
        if (row.body) req = req.send(row.body());
        const res = await req;

        // Oluşan kayıtlar assertion'dan ÖNCE temizlik listesine eklenir (test kırılsa da artık kalmaz).
        trackCreatedUser(row.path(), res);
        if (row.method === 'post' && row.path() === '/api/v1/sync' && res.status === 201) {
          cleanup.observationIds.add(res.body.observation.id as string);
        }

        expect(res.status).toBe(row.expected[role]);
        if (res.status === 403) {
          expect(res.body).toEqual({ error_code: 'ROLE_FORBIDDEN', message: expect.any(String) });
        }
        if (res.status === 201 && row.path() === '/api/v1/admin/users') {
          expect(res.body.user).toMatchObject({ role: 'rescuer', is_active: true });
          // Hesap gerçekten oluştu: profil ve USER_CREATED audit satırı aynı transaction'da yazıldı.
          const { data: profile } = await admin.from('user_profiles').select('role').eq('id', res.body.user.id).single();
          expect(profile?.role).toBe('rescuer');
          const { data: audit } = await admin
            .from('audit_logs')
            .select('actor_user_id')
            .eq('action_type', 'USER_CREATED')
            .eq('target_record_id', res.body.user.id);
          expect(audit).toEqual([{ actor_user_id: administrator.id }]);
        }
      },
    );
  }

  it('AC-19 / FR-D-06: the administrator\'s rejected override changed nothing and wrote no VICTIM_UPDATE row', async () => {
    const res = await authed(request(app).patch(`/api/v1/victims/${victimId}/override`), administrator).send({
      payload: { status: 'admin-must-not-write' },
    });
    expect(res.status).toBe(403);
    expect(res.body.error_code).toBe('ROLE_FORBIDDEN');

    const { data: victim } = await admin.from('victim_records').select('payload').eq('id', victimId).single();
    expect(JSON.stringify(victim?.payload)).not.toContain('admin-must-not-write');

    const { data: rows, error } = await admin
      .from('audit_logs')
      .select('id')
      .eq('actor_user_id', administrator.id)
      .eq('action_type', 'VICTIM_UPDATE');
    expect(error).toBeNull();
    expect(rows).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------
// 3. OSP-66 iptali sonrası, süresi DOLMAMIŞ token'lar ilk istekte 403 alır
// ---------------------------------------------------------------------------------------------

/** Token'ın gerçekten süresi dolmamış olduğunu kanıtlar (403'ün nedeni exp olamaz). */
function expectUnexpired(user: SessionUser): void {
  const exp = Number(decodePayload(user.accessToken).exp);
  expect(exp).toBeGreaterThan(nowSeconds() + 60);
}

const me = (user: SessionUser) => authed(request(app).get('/api/v1/auth/me'), user);

describe('AC-19 / OSP-66: revocation takes effect on the very next request with an unexpired token', () => {
  it('AC-19: single-device revoke -> 403 DEVICE_REVOKED for that device only', async () => {
    const target = await createSessionUser(app, cleanup, 'rescuer', 'ac19-devrevoke');
    const secondDevice = await addSession(app, target);
    expect((await me(target)).status).toBe(200);
    expect((await me(secondDevice)).status).toBe(200);

    const revoke = await authed(
      request(app).post(`/api/v1/admin/users/${target.id}/devices/${target.deviceId}/revoke`),
      administrator,
    );
    expect(revoke.status).toBe(200);
    expect(revoke.body).toMatchObject({ device_id: target.deviceId, is_device_revoked: true, status: 'REVOKED' });

    // AYNI, süresi dolmamış token: ilk istek 403 DEVICE_REVOKED.
    expectUnexpired(target);
    const first = await me(target);
    expect(first.status).toBe(403);
    expect(first.body).toEqual({ error_code: 'DEVICE_REVOKED', message: expect.any(String) });
    // İş uçlarında da aynı sonuç (rol kontrolüne hiç ulaşılmaz).
    const sync = await authed(request(app).post('/api/v1/sync'), target).send({ payload: { a: 1 } });
    expect(sync.status).toBe(403);
    expect(sync.body.error_code).toBe('DEVICE_REVOKED');

    // Tek cihaz iptali: aynı kullanıcının diğer cihazı çalışmaya devam eder.
    expect((await me(secondDevice)).status).toBe(200);

    // İptal edilmiş cihaz başka bir oturumla yeniden bağlanamaz (OSP-60), diğer cihaz etkilenmez.
    const rebind = await bindSession(app, secondDevice.accessToken, target.deviceId, nextIp());
    expect(rebind.status).toBe(403);
    expect(rebind.body.error_code).toBe('DEVICE_REVOKED');
    expect((await me(secondDevice)).status).toBe(200);

    // Değişiklik ve audit satırı aynı transaction'da yazıldı (OSP-66).
    const { data: audit } = await admin
      .from('audit_logs')
      .select('actor_user_id, action_type, target_record_id, metadata')
      .eq('action_type', 'DEVICE_REVOKED')
      .eq('target_record_id', target.id);
    expect(audit).toEqual([
      {
        actor_user_id: administrator.id,
        action_type: 'DEVICE_REVOKED',
        target_record_id: target.id,
        metadata: { revoked_device_id: target.deviceId },
      },
    ]);
  });

  it('AC-19: global revoke (POST /admin/users/:id/revoke-all) -> 403 ACCOUNT_DISABLED on every device', async () => {
    const target = await createSessionUser(app, cleanup, 'coordinator', 'ac19-revokeall');
    expect((await me(target)).status).toBe(200);

    const revoke = await authed(request(app).post(`/api/v1/admin/users/${target.id}/revoke-all`), administrator);
    expect(revoke.status).toBe(200);
    expect(revoke.body).toEqual({ user: { id: target.id, is_active: false } });

    expectUnexpired(target);
    const first = await me(target);
    expect(first.status).toBe(403);
    expect(first.body).toEqual({ error_code: 'ACCOUNT_DISABLED', message: expect.any(String) });
    const victims = await authed(request(app).get('/api/v1/victims'), target);
    expect(victims.status).toBe(403);
    expect(victims.body.error_code).toBe('ACCOUNT_DISABLED');
    // Aynı token ile yeniden bağlanma da reddedilir.
    const rebind = await bindSession(app, target.accessToken, randomUUID(), nextIp());
    expect(rebind.status).toBe(403);
    expect(rebind.body.error_code).toBe('ACCOUNT_DISABLED');

    const { data: profile } = await admin
      .from('user_profiles')
      .select('is_active, all_sessions_revoked_at')
      .eq('id', target.id)
      .single();
    expect(profile?.is_active).toBe(false);
    expect(profile?.all_sessions_revoked_at).not.toBeNull();
  });

  it('AC-19: account closed (is_active=false) and global sign-out only (all_sessions_revoked_at) -> 403 ACCOUNT_DISABLED', async () => {
    const target = await createSessionUser(app, cleanup, 'rescuer', 'ac19-disable');
    expect((await me(target)).status).toBe(200);
    expectUnexpired(target);

    // (a) Hesap kapatma: is_active = false.
    await admin.from('user_profiles').update({ is_active: false }).eq('id', target.id).throwOnError();
    const closed = await me(target);
    expect(closed.status).toBe(403);
    expect(closed.body.error_code).toBe('ACCOUNT_DISABLED');

    // Kontrol: bayrak geri açılınca aynı token yeniden çalışır (403'ün nedeni yalnızca is_active).
    await admin.from('user_profiles').update({ is_active: true }).eq('id', target.id).throwOnError();
    expect((await me(target)).status).toBe(200);

    // (b) Global iptal: hesap aktif kalsa da bu andan önce verilmiş token'lar geçersiz.
    await admin
      .from('user_profiles')
      .update({ all_sessions_revoked_at: new Date().toISOString() })
      .eq('id', target.id)
      .throwOnError();
    const revoked = await me(target);
    expect(revoked.status).toBe(403);
    expect(revoked.body.error_code).toBe('ACCOUNT_DISABLED');
  });
});

// ---------------------------------------------------------------------------------------------
// Bonus: OSP-64 hız sınırı gerçek uygulamada (10 istek/dk/IP, GET /auth/me muaf)
// ---------------------------------------------------------------------------------------------
describe('AC-19 / OSP-64: auth rate limit on the real app', () => {
  it('AC-19: the 11th /api/v1/auth/* request from one IP in a minute -> 429 RATE_LIMITED; other IPs and GET /auth/me unaffected', async () => {
    const ip = nextIp();
    for (let i = 0; i < 10; i += 1) {
      const res = await request(app).post('/api/v1/auth/session').set('X-Forwarded-For', ip).send({});
      expect(res.status).toBe(401);
    }
    const limited = await request(app).post('/api/v1/auth/session').set('X-Forwarded-For', ip).send({});
    expect(limited.status).toBe(429);
    expect(limited.body.error_code).toBe('RATE_LIMITED');

    const otherIp = await request(app).post('/api/v1/auth/session').set('X-Forwarded-For', nextIp()).send({});
    expect(otherIp.status).toBe(401);

    // GET /auth/me sayılmaz (OSP-70): sınıra takılmış IP'den bile geçerli token ile 200.
    const meRes = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${rescuer.accessToken}`)
      .set('X-Forwarded-For', ip);
    expect(meRes.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------------------------
// Rol matrisi: POST /auth/logout (OSP-60) — her rol kendi oturumunu kapatabilir
//
// Logout oturumun cihaz bağını çözer; aynı token sonraki istekte SESSION_NOT_BOUND alır.
// GoTrue verify hız sınırını harcamamak için yeni oturum açılmaz: bu describe BİLEREK dosyanın
// EN SONUNDADIR ve temel oturumları (rescuer/coordinator/administrator) yalnızca burada bozar.
// Vitest bir dosyadaki testleri tanım sırasıyla, sırayla çalıştırır (shuffle kapalı); bu bloktan
// sonra temel oturumları kullanan test yoktur. afterAll temizliği token kullanmaz.
// ---------------------------------------------------------------------------------------------
describe('AC-19 / OSP-60: POST /auth/logout for every role (runs last; ends the base sessions)', () => {
  it.each(['rescuer', 'coordinator', 'administrator'] as const)(
    'AC-19: POST /auth/logout as %s -> 204, then the same token -> 403 SESSION_NOT_BOUND',
    async (role) => {
      const user = { rescuer, coordinator, administrator }[role];
      // Ön koşul: oturum hâlâ bağlı (önceki testler bozmadı).
      expect((await me(user)).status).toBe(200);

      const res = await authed(request(app).post('/api/v1/auth/logout'), user);
      expect(res.status).toBe(204);
      expect(res.text).toBe('');

      const after = await me(user);
      expect(after.status).toBe(403);
      expect(after.body).toEqual({ error_code: 'SESSION_NOT_BOUND', message: expect.any(String) });

      // LOGOUT audit satırı yazıldı; cihaz satırı silinmedi, yalnızca oturum bağı çözüldü.
      const { data: audit } = await admin
        .from('audit_logs')
        .select('actor_role, device_id')
        .eq('actor_user_id', user.id)
        .eq('action_type', 'LOGOUT');
      expect(audit).toEqual([{ actor_role: role, device_id: user.deviceId }]);
      const { data: device } = await admin
        .from('user_devices')
        .select('session_id, is_device_revoked')
        .eq('user_id', user.id)
        .eq('device_id', user.deviceId)
        .single();
      expect(device).toEqual({ session_id: null, is_device_revoked: false });
    },
  );
});
