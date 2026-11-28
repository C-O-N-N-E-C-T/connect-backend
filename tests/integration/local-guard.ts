import { execFileSync } from 'node:child_process';

/**
 * OSP-68: entegrasyon testleri için "YALNIZCA YEREL SUPABASE" koruması.
 *
 * Bu dosya hem vitest `globalSetup` (ana süreç) hem de her test dosyasından önce çalışan
 * `setup-env.ts` (işçi süreç) tarafından kullanılır. Kural basittir: Supabase API adresi ya da
 * veritabanı adresi 127.0.0.1 / localhost dışında bir host'a işaret ediyorsa test paketi HİÇ
 * başlamaz, tek bir ağ isteği bile atılmadan hata fırlatılır.
 *
 * Neden: entegrasyon testleri kullanıcı oluşturur, cihaz iptal eder ve 30 günlük silme
 * fonksiyonunu çağırır. Bunların canlı (paylaşılan) projede çalışması veri kaybı demektir.
 *
 * Bu modül `src/` içinden hiçbir şey import etmez: `src/config/env.ts` import edildiği anda
 * `.env` dosyasını okur, koruma ise ondan ÖNCE ve ondan bağımsız çalışmalıdır.
 */

/** İzin verilen host'lar. `localhost.evil.com` gibi benzerleri tam eşleşme sayesinde reddedilir. */
export const ALLOWED_LOCAL_HOSTS: readonly string[] = ['127.0.0.1', 'localhost'];

/** Koruma ihlali; mesajda adresin TAMAMI değil yalnızca host yazılır (anahtar sızmasın diye). */
export class NonLocalSupabaseError extends Error {
  constructor(what: string, host: string) {
    super(
      `[OSP-68] REFUSING TO RUN: ${what} host "${host}" is not local ` +
        `(allowed: ${ALLOWED_LOCAL_HOSTS.join(', ')}). Integration tests run ONLY against ` +
        'the local Docker Supabase started with `npx supabase start`.',
    );
    this.name = 'NonLocalSupabaseError';
  }
}

/**
 * Verilen adresin host'u yerel değilse `NonLocalSupabaseError` fırlatır.
 * Boş, ayrıştırılamayan ya da http/https/postgres(ql) dışı bir şema da reddedilir
 * (belirsiz durumda kapalı kal).
 */
export function assertLocalUrl(rawUrl: string | undefined, what = 'Supabase URL'): URL {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    throw new NonLocalSupabaseError(what, '<empty>');
  }
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new NonLocalSupabaseError(what, '<unparseable>');
  }
  if (!['http:', 'https:', 'postgres:', 'postgresql:'].includes(url.protocol)) {
    throw new NonLocalSupabaseError(what, `${url.protocol}//${url.hostname}`);
  }
  if (!ALLOWED_LOCAL_HOSTS.includes(url.hostname.toLowerCase())) {
    throw new NonLocalSupabaseError(what, url.hostname);
  }
  return url;
}

/** Entegrasyon testlerinin ihtiyaç duyduğu yerel değerler (globalSetup -> işçilere `provide`). */
export interface LocalSupabaseConfig {
  apiUrl: string;
  anonKey: string;
  serviceRoleKey: string;
  dbUrl: string;
  /** HS256 yerel JWT secret'ı; süresi dolmuş ama geçerli imzalı token üretmek için. */
  jwtSecret: string;
}

/** `supabase status -o json` çıktısından gerekli alanları seçer; eksik alan varsa hata verir. */
export function parseStatusJson(raw: string): LocalSupabaseConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('[OSP-68] `supabase status -o json` did not return JSON. Is it running?');
  }
  const obj = (parsed ?? {}) as Record<string, unknown>;
  const pick = (...keys: string[]): string => {
    for (const key of keys) {
      const value = obj[key];
      if (typeof value === 'string' && value.length > 0) return value;
    }
    // Değer değil yalnızca anahtar adı yazılır.
    throw new Error(`[OSP-68] \`supabase status\` output has no ${keys.join(' / ')} field.`);
  };
  return {
    apiUrl: pick('API_URL'),
    anonKey: pick('ANON_KEY', 'PUBLISHABLE_KEY'),
    serviceRoleKey: pick('SERVICE_ROLE_KEY', 'SECRET_KEY'),
    dbUrl: pick('DB_URL'),
    jwtSecret: pick('JWT_SECRET'),
  };
}

/**
 * Yerel Supabase değerlerini çözer ve korumadan geçirir.
 *
 * 1. `INTEGRATION_SUPABASE_URL` verilmişse (ör. farklı bir yerel port), Supabase CLI'ya bile
 *    gidilmeden ÖNCE korumadan geçirilir. Uzak bir değer burada durur.
 * 2. Anahtarlar her zaman yerel CLI'dan (`npx supabase status -o json`) okunur; `.env` ya da
 *    kabuktaki `SUPABASE_*` değişkenleri hiçbir koşulda kullanılmaz.
 * 3. CLI'nın döndürdüğü API ve DB adresleri de korumadan geçer.
 *
 * `runStatus` testte sahte CLI çıktısı vermek için enjekte edilebilir.
 */
export function resolveLocalSupabase(
  options: {
    env?: NodeJS.ProcessEnv;
    runStatus?: () => string;
  } = {},
): LocalSupabaseConfig {
  const env = options.env ?? process.env;
  const override = env.INTEGRATION_SUPABASE_URL;
  if (override !== undefined) assertLocalUrl(override, 'INTEGRATION_SUPABASE_URL');

  const runStatus =
    options.runStatus ??
    (() =>
      execFileSync('npx', ['supabase', 'status', '-o', 'json'], {
        encoding: 'utf8',
        // stderr'deki uyarılar (ör. durmuş servisler) teste karışmasın.
        stdio: ['ignore', 'pipe', 'ignore'],
      }));

  const config = parseStatusJson(runStatus());
  if (override !== undefined) config.apiUrl = override;

  assertLocalUrl(config.apiUrl, 'Supabase API URL');
  assertLocalUrl(config.dbUrl, 'Supabase DB URL');
  return config;
}

/**
 * `inject('localSupabase')` sonucunu doğrular. Değer yoksa dosya entegrasyon config'i
 * (globalSetup) dışında çalıştırılmıştır: ileride anlamsız bir TypeError almak yerine
 * burada açık bir hatayla durulur. Test dosyaları bunu uygulamayı (ve dolayısıyla `.env`'i
 * okuyan `src/config/env.ts`'i) yüklemeden ÖNCE çağırır.
 */
export function requireProvidedConfig(value: LocalSupabaseConfig | null | undefined): LocalSupabaseConfig {
  if (value === undefined || value === null || typeof value.apiUrl !== 'string') {
    throw new Error(
      '[OSP-68] Local Supabase config is missing: run via `npm run test:integration` ' +
        '(vitest.integration.config.ts), not with plain vitest.',
    );
  }
  return value;
}
