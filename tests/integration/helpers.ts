import { createHmac, randomUUID } from 'node:crypto';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { Express } from 'express';
import request from 'supertest';
import { inject } from 'vitest';
import type { AppRole } from '../../src/types/database.js';
import { assertLocalUrl, requireProvidedConfig } from './local-guard.js';

/**
 * OSP-68 entegrasyon testleri için ortak yardımcılar.
 *
 * Tüm istemciler `globalSetup`'ın yerel Supabase CLI'dan okuyup `provide` ettiği değerlerle
 * kurulur; `.env` ya da `process.env.SUPABASE_*` burada okunmaz. Her istemci oluşturulmadan
 * önce adres yeniden korumadan geçirilir.
 */

// Entegrasyon config'i dışında çalıştırılırsa (globalSetup yok) burada açık bir hatayla durulur.
// Test dosyaları bu modülü uygulamadan (src/app.js -> .env okuyan env.ts) ÖNCE yükler.
const local = requireProvidedConfig(inject('localSupabase'));

/** Sunucu tarafı istemci ayarları: oturum saklama/yenileme yok. */
const NO_SESSION = {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
} as const;

function guardedUrl(): string {
  assertLocalUrl(local.apiUrl, 'Supabase API URL');
  return local.apiUrl;
}

/** service_role istemcisi: test verisi hazırlama/temizleme ve audit/RLS dışı kontroller için. */
export function serviceClient(): SupabaseClient {
  return createClient(guardedUrl(), local.serviceRoleKey, NO_SESSION);
}

/** anon istemcisi: oturumsuz, yalnızca anon key ile (mobil/web build'indeki anahtar). */
export function anonClient(): SupabaseClient {
  return createClient(guardedUrl(), local.anonKey, NO_SESSION);
}

/** Kullanıcı JWT'si ile doğrudan PostgREST'e giden istemci (backend'i atlayan saldırgan modeli). */
export function userClient(accessToken: string): SupabaseClient {
  return createClient(guardedUrl(), local.anonKey, {
    ...NO_SESSION,
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
  });
}

/** Tanınabilir, benzersiz test e-postası: artık kontrolü `osp68-%` ile yapılabilsin. */
export function uniqueEmail(tag: string): string {
  return `osp68-${tag}-${randomUUID().slice(0, 8)}@example.test`;
}

// ---------------------------------------------------------------------------------------------
// OSP-64 hız sınırı: /api/v1/auth/* 10 istek/dk/IP. Testlerde TRUST_PROXY=1 olduğu için
// uygulama istemci IP'sini X-Forwarded-For'dan alır; her isteğe ayrı bir IP verilerek testler
// birbirinin kotasını tüketmez. Uygulama koduna dokunulmaz.
// ---------------------------------------------------------------------------------------------
let ipCounter = 0;
// Dosya başına rastgele ikinci oktet: aynı süreçte birden fazla app olsa da çakışma olmaz.
const ipBase = 1 + Math.floor(Math.random() * 200);

/** Özel ağ bloğundan (RFC 1918, 10.0.0.0/8) her çağrıda farklı bir test IP'si döndürür. */
export function nextIp(): string {
  ipCounter += 1;
  return `10.${ipBase}.${Math.floor(ipCounter / 250)}.${(ipCounter % 250) + 1}`;
}

// ---------------------------------------------------------------------------------------------
// Test verisi kaydı: oluşturulan her şey burada tutulur ve afterAll'da silinir.
// ---------------------------------------------------------------------------------------------
export interface Cleanup {
  userIds: Set<string>;
  victimIds: Set<string>;
  observationIds: Set<string>;
}

export function newCleanup(): Cleanup {
  return { userIds: new Set(), victimIds: new Set(), observationIds: new Set() };
}

/**
 * Oluşturulan victim/observation kayıtlarını ve kullanıcıları siler.
 * - Kullanıcı silinince user_profiles ve user_devices ON DELETE CASCADE ile gider.
 * - audit_logs'ta kullanıcıya FK yok (OSP-65 kaldırdı), bu yüzden append-only audit satırları
 *   silmeyi engellemez; satırlar yerel DB'de kalır (docs/osp-68-verification.md).
 * Bir silme başarısız olursa diğerleri yine denenir, sonunda tek bir hata fırlatılır.
 */
export async function runCleanup(cleanup: Cleanup): Promise<void> {
  const admin = serviceClient();
  const errors: string[] = [];

  if (cleanup.observationIds.size > 0) {
    const { error } = await admin
      .from('rescuer_observations')
      .delete()
      .in('id', [...cleanup.observationIds]);
    if (error) errors.push(`rescuer_observations: ${error.message}`);
  }
  if (cleanup.victimIds.size > 0) {
    const { error } = await admin.from('victim_records').delete().in('id', [...cleanup.victimIds]);
    if (error) errors.push(`victim_records: ${error.message}`);
  }
  for (const id of cleanup.userIds) {
    const { error } = await admin.auth.admin.deleteUser(id);
    if (error) errors.push(`auth user ${id}: ${error.message}`);
  }
  if (errors.length > 0) throw new Error(`[OSP-68] cleanup failed:\n${errors.join('\n')}`);
}

// ---------------------------------------------------------------------------------------------
// Kullanıcı + oturum
// ---------------------------------------------------------------------------------------------
export interface TestUser {
  id: string;
  email: string;
  role: AppRole;
}

/** Auth kullanıcısı + aktif user_profiles satırı oluşturur (service_role, HTTP API'si kullanmaz). */
export async function createTestUser(cleanup: Cleanup, role: AppRole, tag: string): Promise<TestUser> {
  const admin = serviceClient();
  const email = uniqueEmail(tag);
  const { data, error } = await admin.auth.admin.createUser({
    email,
    // Yerel parola kuralına uyan, her seferinde farklı rastgele parola (hiç kullanılmaz).
    password: `Aa1!${randomUUID()}`,
    email_confirm: true,
    app_metadata: { role },
  });
  if (error || !data.user) throw new Error(`[OSP-68] createUser failed: ${error?.message}`);
  cleanup.userIds.add(data.user.id);

  const { error: profileError } = await admin
    .from('user_profiles')
    .insert({ id: data.user.id, role, full_name: `OSP-68 ${tag}`, is_active: true });
  if (profileError) throw new Error(`[OSP-68] profile insert failed: ${profileError.message}`);

  return { id: data.user.id, email, role };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Gerçek bir Supabase oturumu açar ve access token döndürür.
 *
 * Yerel config.toml'da `[auth.email] enable_signup = false` olduğu için yerel GoTrue
 * e-posta/parola girişini `email_provider_disabled` ile reddeder (config.toml değiştirilmez).
 * Bunun yerine service_role ile bir magic link üretilir (`generateLink`, e-posta gönderilmez)
 * ve `verifyOtp` ile doğrulanır. Sonuç, istemcilerin aldığıyla aynı gerçek oturumdur: ES256
 * imzalı, `session_id` claim'i auth.sessions'taki satıra karşılık gelir, token hook çalışmıştır.
 *
 * GoTrue'nun verify hız sınırı (30 istek, ~6/dk dolum) art arda çalıştırmalarda 429 verebilir;
 * bu durumda beklenip yeniden denenir. Bekleme SÜREÇ (test dosyası) başına toplam
 * `SIGN_IN_WAIT_BUDGET_MS` ile sınırlıdır; bütçe biterse açık bir hatayla durulur. Böylece
 * beforeAll/test, vitest'in zaman aşımına (hookTimeout/testTimeout) anlamsızca takılmaz.
 */
export const SIGN_IN_RETRY_DELAY_MS = 10_000;
export const SIGN_IN_WAIT_BUDGET_MS = 60_000;
// Bu süreçte 429 yüzünden şimdiye kadar beklenen toplam süre (forks havuzunda dosya başına sıfırlanır).
let signInWaitedMs = 0;

export async function signIn(email: string): Promise<{ accessToken: string; sessionId: string }> {
  const admin = serviceClient();
  for (;;) {
    const { data: link, error: linkError } = await admin.auth.admin.generateLink({
      type: 'magiclink',
      email,
    });
    if (linkError) throw new Error(`[OSP-68] generateLink failed: ${linkError.message}`);

    const { data, error } = await anonClient().auth.verifyOtp({
      token_hash: link.properties.hashed_token,
      type: 'magiclink',
    });
    if (!error && data.session) {
      const claims = decodePayload(data.session.access_token);
      return { accessToken: data.session.access_token, sessionId: String(claims.session_id) };
    }
    if (error?.status !== 429) {
      throw new Error(`[OSP-68] verifyOtp failed: ${error?.status} ${error?.message}`);
    }
    // 429: bütçe yetiyorsa bekle ve tekrar dene, yetmiyorsa hemen dur.
    if (signInWaitedMs + SIGN_IN_RETRY_DELAY_MS > SIGN_IN_WAIT_BUDGET_MS) {
      throw new Error(
        `[OSP-68] GoTrue verify rate limit (429) still active after waiting ${signInWaitedMs / 1000}s ` +
          `(budget ${SIGN_IN_WAIT_BUDGET_MS / 1000}s). Wait about a minute and run again.`,
      );
    }
    signInWaitedMs += SIGN_IN_RETRY_DELAY_MS;
    await sleep(SIGN_IN_RETRY_DELAY_MS);
  }
}

export interface SessionUser extends TestUser {
  accessToken: string;
  sessionId: string;
  deviceId: string;
  /** Bu kullanıcının isteklerinde kullanılan X-Forwarded-For IP'si. */
  ip: string;
}

/** POST /api/v1/auth/session (OSP-60): token'ın session_id'sini bir cihaza bağlar. */
export async function bindSession(
  app: Express,
  accessToken: string,
  deviceId: string,
  ip = nextIp(),
): Promise<request.Response> {
  return request(app)
    .post('/api/v1/auth/session')
    .set('Authorization', `Bearer ${accessToken}`)
    .set('X-Forwarded-For', ip)
    .send({ device_id: deviceId, device_name: 'OSP-68 integration device' });
}

/** Kullanıcı oluşturur, gerçek oturum açar ve oturumu yeni bir cihaza bağlar (200 beklenir). */
export async function createSessionUser(
  app: Express,
  cleanup: Cleanup,
  role: AppRole,
  tag: string,
): Promise<SessionUser> {
  const user = await createTestUser(cleanup, role, tag);
  return addSession(app, user);
}

/** Var olan kullanıcı için yeni bir oturum açıp yeni bir cihaza bağlar (ikinci cihaz senaryosu). */
export async function addSession(app: Express, user: TestUser): Promise<SessionUser> {
  const { accessToken, sessionId } = await signIn(user.email);
  const deviceId = randomUUID();
  const ip = nextIp();
  const res = await bindSession(app, accessToken, deviceId, ip);
  if (res.status !== 200) {
    throw new Error(`[OSP-68] /auth/session for ${user.role} answered ${res.status} ${res.text}`);
  }
  return { ...user, accessToken, sessionId, deviceId, ip };
}

/** supertest isteğine kullanıcının token'ını ve IP'sini ekler. */
export function authed(req: request.Test, user: Pick<SessionUser, 'accessToken' | 'ip'>): request.Test {
  return req.set('Authorization', `Bearer ${user.accessToken}`).set('X-Forwarded-For', user.ip);
}

// ---------------------------------------------------------------------------------------------
// JWT yardımcıları (yalnızca Node crypto; yeni bağımlılık yok)
// ---------------------------------------------------------------------------------------------
/** JWT payload'ını DOĞRULAMADAN çözer; yalnızca test verisi üretmek için. */
export function decodePayload(token: string): Record<string, unknown> {
  const part = token.split('.')[1];
  if (!part) throw new Error('[OSP-68] not a JWT');
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;
}

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

/**
 * HS256 ile JWT imzalar. Yerel GoTrue, ES256 imzalama anahtarının yanında JWT_SECRET'ı (HS256)
 * da doğrulama anahtarı olarak kabul eder. Böylece `exp` değeri geçmişte olan ama İMZASI
 * GEÇERLİ bir token üretilebilir (testlerde geçerlilik bir kontrol testiyle kanıtlanır).
 * `secret` verilmezse yerel JWT secret kullanılır.
 */
export function signHs256(payload: Record<string, unknown>, secret: string = local.jwtSecret): string {
  const header = b64url({ alg: 'HS256', typ: 'JWT' });
  const body = b64url(payload);
  const signature = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

/** Şimdiki zaman, saniye cinsinden (JWT iat/exp birimi). */
export const nowSeconds = () => Math.floor(Date.now() / 1000);
