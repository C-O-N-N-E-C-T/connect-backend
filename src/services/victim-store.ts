import type { SupabaseClient } from '@supabase/supabase-js';
import { supabaseAdmin } from '../config/supabase.js';
import type { RescuerObservation, VictimRecord } from '../types/database.js';
import { AppError } from '../types/errors.js';
import type { AuthContext } from '../types/express.js';

/**
 * OSP-62: Stub iş uçlarının veri erişim katmanı.
 * Route'lar veritabanına doğrudan değil bu arayüz üzerinden erişir; böylece testler bellekte
 * duran sahte bir store enjekte eder (`createApp({ victimStore })`) ve hiçbir test gerçek
 * (paylaşılan) Supabase projesine dokunmaz.
 *
 * OSP-65 (AC-28): YAZMA metotları (`overrideVictim`, `insertObservation`) audit satırını da
 * aynı DB transaction'ında yazar (SQL fonksiyonları, migration
 * `20261123120000_osp65_atomic_victim_writes.sql`). Audit yazılamazsa değişiklik de geri alınır
 * ve metot 500 fırlatır. Okuma metotları audit yazmaz; onu route `victimAudit` ile yapar.
 */
/** Override'a eşlik eden ek bilgiler. */
export interface OverrideOptions {
  /**
   * Koordinatörün override gerekçesi; verilirse `_override.reason` olarak kayıtta saklanır.
   * Audit satırına metin değil, yalnızca `has_reason` yazılır.
   */
  reason?: string | undefined;
}

export interface VictimStore {
  listVictims(): Promise<VictimRecord[]>;
  /** Kayıt yoksa `null`. */
  getVictim(id: string): Promise<VictimRecord | null>;
  /** Kayıt yoksa `null` (hiçbir şey yazılmaz); varsa güncel kayıt + VICTIM_UPDATE audit satırı. */
  overrideVictim(
    id: string,
    payload: Record<string, unknown>,
    actor: AuthContext,
    options?: OverrideOptions,
  ): Promise<VictimRecord | null>;
  /** Gözlem + OBSERVATION_SYNC audit satırı, tek transaction'da. */
  insertObservation(
    payload: Record<string, unknown>,
    actor: AuthContext,
  ): Promise<RescuerObservation>;
}

const RECORD_COLUMNS = 'id, created_at, created_by, payload';
// Stub listeleme için üst sınır; sayfalama E9'da eklenecek.
const LIST_LIMIT = 100;

// Supabase hatasının ayrıntısı (tablo/sütun adları vb.) istemciye asla gönderilmez.
const storeError = () =>
  new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');

/**
 * Supabase (service-role) üzerinde çalışan gerçek uygulama. RLS, anon/authenticated
 * rollerine bu tabloları kapattığı için service-role client gerekir; yetki kontrolü
 * (rol) bu katmana gelmeden `requireRole` ile yapılmış olur.
 */
export function createSupabaseVictimStore(
  client: Pick<SupabaseClient, 'from' | 'rpc'>,
): VictimStore {
  return {
    async listVictims() {
      const { data, error } = await client
        .from('victim_records')
        .select(RECORD_COLUMNS)
        .order('created_at', { ascending: false })
        .limit(LIST_LIMIT)
        .returns<VictimRecord[]>();
      if (error) throw storeError();
      return data ?? [];
    },

    async getVictim(id) {
      const { data, error } = await client
        .from('victim_records')
        .select(RECORD_COLUMNS)
        .eq('id', id)
        .maybeSingle<VictimRecord>();
      if (error) throw storeError();
      return data ?? null;
    },

    async overrideVictim(id, payload, actor, options = {}) {
      // Oku + birleştir + yaz + audit tek SQL fonksiyonunda (satır FOR UPDATE ile kilitli).
      const { data, error } = await client.rpc('override_victim_audited', {
        p_victim_id: id,
        p_actor_user_id: actor.user_id,
        p_actor_role: actor.role,
        p_device_id: actor.device_id,
        p_payload: payload,
        p_reason: options.reason ?? null,
      });
      if (error) throw storeError();
      return (data as VictimRecord | null) ?? null;
    },

    async insertObservation(payload, actor) {
      // created_by her zaman doğrulanmış kimlikten (req.auth.user_id) gelir, gövdeden değil.
      const { data, error } = await client.rpc('sync_observation_audited', {
        p_actor_user_id: actor.user_id,
        p_actor_role: actor.role,
        p_device_id: actor.device_id,
        p_payload: payload,
      });
      if (error || !data) throw storeError();
      return data as RescuerObservation;
    },
  };
}

// Gerçek store ilk kullanımda oluşturulur (tembel); modül import edildiğinde hiçbir sorgu
// yapılmaz. Testler sahte store verdiği için bu fonksiyon testlerde hiç çağrılmaz.
let lazyStore: VictimStore | undefined;
function getDefaultStore(): VictimStore {
  lazyStore ??= createSupabaseVictimStore(supabaseAdmin);
  return lazyStore;
}

/** Üretim store'u: `createApp()` seçeneksiz çağrıldığında kullanılır. */
export const defaultVictimStore: VictimStore = {
  listVictims: () => getDefaultStore().listVictims(),
  getVictim: (id) => getDefaultStore().getVictim(id),
  overrideVictim: (id, payload, actor, options) =>
    getDefaultStore().overrideVictim(id, payload, actor, options),
  insertObservation: (payload, actor) => getDefaultStore().insertObservation(payload, actor),
};
