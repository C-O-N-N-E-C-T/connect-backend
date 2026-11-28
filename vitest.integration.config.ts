import { defineConfig } from 'vitest/config';

/**
 * OSP-68: AC-19 / AC-28 entegrasyon testleri (`npm run test:integration`).
 *
 * - Gerçek Express uygulaması (process içinde, supertest) + YEREL Docker Supabase.
 * - `globalSetup`: yerel değerleri `npx supabase status -o json` ile okur ve "yalnızca yerel"
 *   korumasını çalıştırır; host 127.0.0.1/localhost değilse hiçbir test dosyası yüklenmez.
 * - `setupFiles`: her test dosyasından ÖNCE, uygulama import edilmeden process.env'i yerel
 *   değerlerle doldurur; böylece `.env`'deki (uzak) değerler hiçbir koşulda kullanılmaz.
 */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/integration/**/*.test.ts'],
    globalSetup: ['tests/integration/global-setup.ts'],
    setupFiles: ['tests/integration/setup-env.ts'],
    globals: false,
    // Dosyalar sırayla çalışır: aynı yerel veritabanını ve GoTrue hız sınırını paylaşırlar,
    // 30 günlük silme (purge) de tüm tabloyu etkiler; paralellik belirsizlik getirirdi.
    fileParallelism: false,
    // forks: her dosya ayrı bir alt süreçte, temiz modül durumu ve process.env ile çalışır.
    pool: 'forks',
    // Zaman aşımları, signIn'in 429 bekleme bütçesine (helpers.ts SIGN_IN_WAIT_BUDGET_MS =
    // 60 sn, dosya başına toplam) göre ayarlıdır: bütçe bir test ya da hook içinde tamamen
    // harcansa bile önce signIn'in açık hatası görünür, vitest'in genel zaman aşımı değil.
    // testTimeout: bazı testler (iptal senaryoları) kendi kullanıcısını açar -> 60 sn + pay.
    testTimeout: 90_000,
    // beforeAll: 3 kullanıcı açar; normalde ~1 sn, en kötü durumda 60 sn bekleme + pay.
    hookTimeout: 120_000,
  },
});
