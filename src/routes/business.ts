import type { NextFunction, Request, RequestHandler, Response, Router } from 'express';
import type { ZodType } from 'zod';
import { unauthenticatedError } from '../middleware/auth.js';
import { requireRole } from '../middleware/require-role.js';
import { requireVictimAudit } from '../middleware/victim-audit-enforcer.js';
import {
  assignmentBodySchema,
  syncBodySchema,
  victimIdParamSchema,
  victimOverrideBodySchema,
} from '../schemas/business.js';
import { victimAudit, type VictimAudit } from '../services/victim-audit.js';
import type { VictimStore } from '../services/victim-store.js';
import { AppError } from '../types/errors.js';
import type { AuthContext } from '../types/express.js';

/**
 * OSP-62: RBAC matrisini taşıyan STUB iş uçları (yollar /api/v1'e görelidir).
 *
 * | Uç                             | rescuer | coordinator | administrator |
 * |--------------------------------|---------|-------------|---------------|
 * | POST  /sync                    | evet    | 403         | 403           |
 * | GET   /victims                 | 403     | evet        | evet          |
 * | GET   /victims/:id             | 403     | evet        | evet          |
 * | PATCH /victims/:id/override    | 403     | evet        | 403           |
 * | POST  /assignments             | 403     | evet        | 403           |
 *
 * Sıra her uçta aynıdır: `requireRole` -> doğrulama -> store. Şemaya uymayan (ama geçerli
 * JSON olan) gövde rol kontrolünde 403 alır ve store'a hiç ulaşmaz. JSON sözdizimi hatası ise
 * rol kontrolünden ÖNCE 400 döner: app.ts'te `jsonBody` bu router'dan önce (kimlik
 * doğrulandıktan sonra) çalışır; mount sırası bilinçli olarak böyledir.
 */

const invalidIdError = () =>
  new AppError(400, 'VALIDATION_ERROR', 'The record id must be a valid UUID.');
// Zod ayrıntıları gönderilmez: istemciye sabit, kısa bir mesaj yeterli (stub).
const invalidPayloadError = () =>
  new AppError(400, 'VALIDATION_ERROR', 'The request body failed validation.');
const victimNotFoundError = () =>
  new AppError(404, 'NOT_FOUND', 'The requested victim record does not exist.');

/**
 * Kazazede verisi kişisel veridir: tarayıcı/proxy önbelleğinde saklanmasın diye okuma
 * uçlarının yanıtlarına `Cache-Control: no-store` eklenir.
 */
const noStore: RequestHandler = (_req: Request, res: Response, next: NextFunction) => {
  res.set('Cache-Control', 'no-store');
  next();
};

/** Gövdeyi şemaya göre doğrular; geçersizse 400 VALIDATION_ERROR fırlatır. */
function parseBody<T>(schema: ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) throw invalidPayloadError();
  return parsed.data;
}

/** `:id` parametresini UUID olarak doğrular (geçersiz değer DB'ye hiç gönderilmez). */
function parseVictimId(req: Request): string {
  const parsed = victimIdParamSchema.safeParse(req.params.id);
  if (!parsed.success) throw invalidIdError();
  return parsed.data;
}

/** `requireRole` sonrasında `req.auth` her zaman vardır; tip daraltma + savunma amaçlı kontrol. */
function authOf(req: Request): AuthContext {
  if (!req.auth) throw unauthenticatedError();
  return req.auth;
}

export function registerBusinessRoutes(
  router: Router,
  store: VictimStore,
  audit: VictimAudit = victimAudit,
): void {
  // OSP-65 (AC-28): başarılı her kazazede verisi cevabından önce audit satırı yazılmış olmalı;
  // yazılmamışsa requireVictimAudit 2xx cevabı 500'e çevirir. /assignments hiçbir şey
  // kaydetmediği (stub) için şimdilik audit edilmez.
  router.use(['/sync', '/victims'], requireVictimAudit);

  // Express 5: async handler'ın fırlattığı hata otomatik olarak errorHandler'a gider.
  router.post('/sync', requireRole('rescuer'), async (req: Request, res: Response) => {
    const auth = authOf(req);
    const body = parseBody(syncBodySchema, req.body);
    const observation = await store.insertObservation(body.payload, auth.user_id);
    await audit.sync(req, observation.id);
    res.status(201).json({ observation });
  });

  router.get(
    '/victims',
    requireRole('coordinator', 'administrator'),
    noStore,
    async (req: Request, res: Response) => {
      const victims = await store.listVictims();
      // Liste için TEK bir özet satırı (kayıt başına bir satır değil).
      await audit.list(req, { result_count: victims.length });
      res.status(200).json({ victims });
    },
  );

  router.get(
    '/victims/:id',
    requireRole('coordinator', 'administrator'),
    noStore,
    async (req: Request, res: Response) => {
      const id = parseVictimId(req);
      const victim = await store.getVictim(id);
      if (!victim) throw victimNotFoundError();
      await audit.view(req, victim.id);
      res.status(200).json({ victim });
    },
  );

  // Administrator salt-okur: override yalnızca sahadaki koordinatörün yetkisidir.
  router.patch(
    '/victims/:id/override',
    requireRole('coordinator'),
    async (req: Request, res: Response) => {
      const auth = authOf(req);
      const id = parseVictimId(req);
      const body = parseBody(victimOverrideBodySchema, req.body);
      // Doğrulanan gerekçe (varsa) atılmaz; store `_override.reason` olarak kaydeder.
      const victim = await store.overrideVictim(id, body.payload, auth.user_id, {
        reason: body.reason,
      });
      if (!victim) throw victimNotFoundError();
      await audit.override(req, victim.id, { reason: body.reason });
      res.status(200).json({ victim });
    },
  );

  // STUB: atama tablosu henüz yok; gövde doğrulanır ama hiçbir şey kalıcı kaydedilmez.
  router.post('/assignments', requireRole('coordinator'), (req: Request, res: Response) => {
    const auth = authOf(req);
    const body = parseBody(assignmentBodySchema, req.body);
    res.status(201).json({
      stub: true,
      persisted: false,
      assignment: { ...body, assigned_by: auth.user_id },
    });
  });
}