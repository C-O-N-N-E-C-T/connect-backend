import type { SupabaseClient } from '@supabase/supabase-js';
import { supabaseAdmin } from '../config/supabase.js';
import type { AuditActionType } from '../types/database.js';
import { AppError } from '../types/errors.js';
import type { AuthContext } from '../types/express.js';

/**
 * OSP-65: backend kodunun public.audit_logs tablosuna satır yazmasının tek yolu.
 *
 * - Actor her zaman `req.auth`'tan gelir (OSP-61 guard), asla istek gövdesinden veya header'dan.
 * - Fail-closed: satır yazılamazsa genel bir 500 fırlatılır; bu yüzden çağıran taraf,
 *   istemciye veri göndermeden ÖNCE `await` etmelidir ("audit satırı olmadan veri yok").
 * - Tablonun kendisi yalnızca eklenebilir (OSP-65 migration'ı); bu servis sadece INSERT yapar.
 *
 * LOGIN / LOGOUT / LOGIN_REJECTED OSP-60 SQL fonksiyonlarında, RETENTION_PURGE ise OSP-67
 * fonksiyonunda yazılır; bu servis üzerinden değil.
 */
export interface AuditEntry {
  actor: AuthContext;
  action_type: AuditActionType;
  target_record_id?: string | null;
  metadata?: Record<string, unknown>;
}

export interface AuditLogStore {
  write(entry: AuditEntry): Promise<void>;
}

const internalError = () =>
  new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');

type InsertClient = Pick<SupabaseClient, 'from'>;

export function createSupabaseAuditLogStore(client: InsertClient): AuditLogStore {
  return {
    async write(entry) {
      let failed = false;
      try {
        const { error } = await client.from('audit_logs').insert({
          actor_user_id: entry.actor.user_id,
          actor_role: entry.actor.role,
          device_id: entry.actor.device_id,
          action_type: entry.action_type,
          target_record_id: entry.target_record_id ?? null,
          metadata: entry.metadata ?? {},
        });
        failed = Boolean(error);
      } catch {
        failed = true;
      }
      if (failed) {
        // Sadece sabit mesaj: Supabase hatası satır verisi veya iç ayrıntı içerebilir.
        console.error(`[connect-backend] OSP-65: failed to write ${entry.action_type} audit row`);
        throw internalError();
      }
    },
  };
}

/** Üretim store'u: service-role client kullanır. */
export const defaultAuditLogStore: AuditLogStore = createSupabaseAuditLogStore(supabaseAdmin);
