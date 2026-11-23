import type { Request } from 'express';
import { AppError } from '../types/errors.js';
import type { AuthContext } from '../types/express.js';
import { defaultAuditLogStore, type AuditEntry, type AuditLogStore } from './audit-log.js';

/**
 * OSP-65: OSP-62'nin kazazede verisi uçları (src/routes/business.ts) için audit yardımcısı.
 *
 * OKUMA uçlarında işlem başarılı olduktan SONRA ve cevap gönderilmeden ÖNCE çağrılır:
 *
 *   const victim = await store.getVictim(id);       // bulunamazsa -> 404, audit satırı yok
 *   if (!victim) throw victimNotFoundError();
 *   await audit.view(req, victim.id);               // satır yazılamazsa 500 fırlatır
 *   res.status(200).json({ victim });
 *
 * YAZMA uçlarında audit satırını store, değişiklikle aynı DB transaction'ında yazar
 * (src/services/victim-store.ts). Audit yazılamazsa değişiklik de geri alınır. Route yalnızca
 * store başarıyla döndükten sonra `audit.recordedByStore(req)` ile isteği işaretler.
 *
 * | Uç                            | Audit'i yazan                    | Satır                          |
 * |-------------------------------|----------------------------------|--------------------------------|
 * | GET   /victims                | list(req, { result_count })      | TEK VICTIM_LIST_VIEW (özet)    |
 * | GET   /victims/:id            | view(req, id)                    | VICTIM_VIEW + hedef id         |
 * | PATCH /victims/:id/override   | store.overrideVictim (tek tx)    | VICTIM_UPDATE + `has_reason`   |
 * | POST  /sync                   | store.insertObservation (tek tx) | OBSERVATION_SYNC + hedef id    |
 *
 * Başarılı her istek "audit edildi" olarak işaretlenir; `requireVictimAudit`
 * (src/middleware/victim-audit-enforcer.ts) bu path'lerde işaretsiz her 2xx cevabı engeller.
 */
export interface VictimListSummary {
  /** Sadece doğrulanmış filtre değerleri (asla ham query string değil). */
  filters?: Record<string, unknown>;
  result_count: number;
}

export interface VictimAudit {
  list(req: Request, summary: VictimListSummary): Promise<void>;
  view(req: Request, victimId: string): Promise<void>;
  /**
   * Store audit satırını yazımla aynı transaction'da yazdı (overrideVictim / insertObservation);
   * isteği "audit edildi" olarak işaretler. Yalnızca store başarıyla döndükten sonra çağrılır.
   */
  recordedByStore(req: Request): void;
}

/** Audit satırı yazılmış istekler. WeakSet: kayıtlar istekle birlikte bellekten silinir. */
const auditedRequests = new WeakSet<Request>();

/** `requireVictimAudit` kullanır: bu istek için audit satırı yazıldıysa true döner. */
export function wasVictimAudited(req: Request): boolean {
  return auditedRequests.has(req);
}

function actorOf(req: Request): AuthContext {
  if (!req.auth) {
    // Programlama hatası: route requireAuth arkasında değil. Fail-closed.
    console.error('[connect-backend] OSP-65: victim audit called on a route without req.auth');
    throw new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');
  }
  return req.auth;
}

export function createVictimAudit(store: AuditLogStore): VictimAudit {
  async function record(req: Request, entry: Omit<AuditEntry, 'actor'>) {
    await store.write({ actor: actorOf(req), ...entry });
    auditedRequests.add(req);
  }

  return {
    list: (req, summary) =>
      record(req, {
        action_type: 'VICTIM_LIST_VIEW',
        target_record_id: null,
        metadata: { filters: summary.filters ?? {}, result_count: summary.result_count },
      }),
    view: (req, victimId) =>
      record(req, { action_type: 'VICTIM_VIEW', target_record_id: victimId }),
    recordedByStore: (req) => {
      actorOf(req);
      auditedRequests.add(req);
    },
  };
}

/** src/routes/business.ts tarafından kullanılan üretim örneği. */
export const victimAudit: VictimAudit = createVictimAudit(defaultAuditLogStore);
