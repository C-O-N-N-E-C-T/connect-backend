import type { SupabaseClient } from '@supabase/supabase-js';
import { supabaseAdmin } from '../config/supabase.js';
import type { RescuerObservation, VictimRecord } from '../types/database.js';
import { AppError } from '../types/errors.js';

/**
 * OSP-62: Stub iş uçlarının veri erişim katmanı.
 * Route'lar veritabanına doğrudan değil bu arayüz üzerinden erişir; böylece testler bellekte
 * duran sahte bir store enjekte eder (`createApp({ victimStore })`) ve hiçbir test gerçek
 * (paylaşılan) Supabase projesine dokunmaz.
 */
/** Override'a eşlik eden ek bilgiler. */
export interface OverrideOptions {
  /** Koordinatörün override gerekçesi; verilirse `_override.reason` olarak saklanır. */
  reason?: string | undefined;
}

export interface VictimStore {
  listVictims(): Promise<VictimRecord[]>;
  /** Kayıt yoksa `null`. */
  getVictim(id: string): Promise<VictimRecord | null>;
  /** Kayıt yoksa `null`; varsa güncel kayıt. */
  overrideVictim(
    id: string,
    payload: Record<string, unknown>,
    actorUserId: string,
    options?: OverrideOptions,
  ): Promise<VictimRecord | null>;
  insertObservation(
    payload: Record<string, unknown>,
    actorUserId: string,
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
export function createSupabaseVictimStore(client: Pick<SupabaseClient, 'from'>): VictimStore {
  async function getVictim(id: string): Promise<VictimRecord | null> {
    const { data, error } = await client
      .from('victim_records')
      .select(RECORD_COLUMNS)
      .eq('id', id)
      .maybeSingle<VictimRecord>();
    if (error) throw storeError();
    return data ?? null;
  }

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

    getVictim,

    async overrideVictim(id, payload, actorUserId, options = {}) {
      // STUB: önce oku, sonra birleştirip yaz. İki adım atomik değildir; eşzamanlı override'lar
      // birbirini ezebilir. Gerçek override modeli (sürümleme/denetim kaydı) E9'da gelecek.
      const existing = await getVictim(id);
      if (!existing) return null;
      const merged = {
        ...existing.payload,
        ...payload,
        // Son override'ı kimin/ne zaman yaptığı kayıt içinde izlenebilsin.
        _override: {
          by: actorUserId,
          at: new Date().toISOString(),
          // Gerekçe yalnızca verildiyse yazılır (boş alan bırakılmaz).
          ...(options.reason !== undefined ? { reason: options.reason } : {}),
        },
      };
      const { data, error } = await client
        .from('victim_records')
        .update({ payload: merged })
        .eq('id', id)
        .select(RECORD_COLUMNS)
        .maybeSingle<VictimRecord>();
      if (error) throw storeError();
      return data ?? null;
    },

    async insertObservation(payload, actorUserId) {
      // created_by her zaman doğrulanmış kimlikten (req.auth.user_id) gelir, gövdeden değil.
      const { data, error } = await client
        .from('rescuer_observations')
        .insert({ payload, created_by: actorUserId })
        .select(RECORD_COLUMNS)
        .single<RescuerObservation>();
      if (error || !data) throw storeError();
      return data;
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
  overrideVictim: (id, payload, actorUserId, options) =>
    getDefaultStore().overrideVictim(id, payload, actorUserId, options),
  insertObservation: (payload, actorUserId) =>
    getDefaultStore().insertObservation(payload, actorUserId),
};
