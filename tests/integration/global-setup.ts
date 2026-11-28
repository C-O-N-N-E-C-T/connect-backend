import type { TestProject } from 'vitest/node';
import { resolveLocalSupabase, type LocalSupabaseConfig } from './local-guard.js';

/**
 * OSP-68 vitest globalSetup (ana süreçte, HİÇBİR test dosyası yüklenmeden önce bir kez çalışır).
 *
 * 1. "Yalnızca yerel" koruması: `INTEGRATION_SUPABASE_URL` (verildiyse) ve Supabase CLI'nın
 *    bildirdiği API/DB adresleri 127.0.0.1 ya da localhost değilse burada hata fırlatılır.
 *    Vitest globalSetup hatasında paketi durdurur: tek bir test ya da ağ isteği çalışmaz.
 * 2. Yerel anahtarlar `npx supabase status -o json` çıktısından okunur (`.env` OKUNMAZ) ve
 *    işçi süreçlere `provide` ile aktarılır. Değerler hiçbir yerde loglanmaz.
 */
export default function setup(project: TestProject): void {
  const config = resolveLocalSupabase();
  project.provide('localSupabase', config);
}

declare module 'vitest' {
  export interface ProvidedContext {
    localSupabase: LocalSupabaseConfig;
  }
}
