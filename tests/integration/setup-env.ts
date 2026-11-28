import { inject } from 'vitest';
import { assertLocalUrl, requireProvidedConfig } from './local-guard.js';

/**
 * OSP-68: her entegrasyon test dosyasından ÖNCE (işçi süreçte) çalışır.
 *
 * Sorun: `src/config/env.ts` import edildiği anda `dotenv.config()` ile `.env`'i okur. O dosyada
 * canlı projenin adresi ve anahtarları olabilir.
 * Çözüm: dotenv varsayılan olarak ZATEN TANIMLI değişkenlerin üzerine yazmaz (override: false).
 * Bu yüzden uygulama import edilmeden önce env şemasındaki TÜM anahtarlar burada yerel
 * değerlerle doldurulur; `.env`'den gelen bir değer şemadaki hiçbir alana ulaşamaz.
 * Ardından uygulamanın gerçekten kullandığı `env` nesnesi yerel değerlerle karşılaştırılır;
 * tek bir fark bile varsa test dosyası hiç başlamadan durur.
 */
const local = requireProvidedConfig(inject('localSupabase'));

// Savunma katmanı 2: globalSetup'ı atlatan bir senaryoya karşı burada da kontrol edilir.
assertLocalUrl(local.apiUrl, 'Supabase API URL');
assertLocalUrl(local.dbUrl, 'Supabase DB URL');

const forcedEnv: Record<string, string> = {
  NODE_ENV: 'test',
  PORT: '3000',
  CORS_ORIGIN: 'http://localhost:5173',
  // Bir proxy hop'una güvenilir: testler her isteğe ayrı bir X-Forwarded-For IP'si verir ve
  // OSP-64 hız sınırını (10 istek/dk/IP) uygulama koduna dokunmadan, IP başına izole eder.
  TRUST_PROXY: '1',
  SUPABASE_URL: local.apiUrl,
  SUPABASE_ANON_KEY: local.anonKey,
  SUPABASE_SERVICE_ROLE_KEY: local.serviceRoleKey,
  DATABASE_URL: local.dbUrl,
  // Seed değişkenleri uygulama tarafından kullanılmaz; yine de .env'den sızmasınlar diye boş.
  SEED_ADMIN_EMAIL: '',
  SEED_ADMIN_PASSWORD: '',
  SEED_ADMIN_FULL_NAME: '',
  SEED_COORDINATOR_EMAIL: '',
  SEED_COORDINATOR_PASSWORD: '',
  SEED_COORDINATOR_FULL_NAME: '',
  SEED_RESCUER_EMAIL: '',
  SEED_RESCUER_PASSWORD: '',
  SEED_RESCUER_FULL_NAME: '',
};
Object.assign(process.env, forcedEnv);

// Uygulamanın env yükleyicisi ŞİMDİ import edilir (dotenv burada çalışır, üzerine yazamaz).
const { env, envSchema } = await import('../../src/config/env.js');

// Şemadaki her alan için uygulamanın gördüğü değer, zorladığımız değerle aynı olmalı.
for (const key of Object.keys(envSchema.shape)) {
  const expected = forcedEnv[key];
  const actual = (env as Record<string, unknown>)[key];
  if (expected === undefined || String(actual) !== expected) {
    // Değer yazılmaz, yalnızca anahtar adı (gizli anahtar sızmasın).
    throw new Error(`[OSP-68] App env "${key}" does not match the local Supabase value; refusing to run.`);
  }
}
assertLocalUrl(env.SUPABASE_URL, 'App SUPABASE_URL');
