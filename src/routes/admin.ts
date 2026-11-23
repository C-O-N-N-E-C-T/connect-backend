import type { NextFunction, Request, RequestHandler, Response, Router } from 'express';
import { z, type ZodType } from 'zod';
import { unauthenticatedError } from '../middleware/auth.js';
import { requireRole, roleForbiddenError } from '../middleware/require-role.js';
import {
  auditLogsQuerySchema,
  createUserBodySchema,
  deviceIdParamSchema,
  listUsersQuerySchema,
  userIdParamSchema,
} from '../schemas/admin.js';
import type { AdminStore, AuthAdminPort } from '../services/admin-store.js';
import type { AuthContext } from '../types/express.js';
import { AppError } from '../types/errors.js';

/**
 * OSP-66: administrator API (yollar /api/v1'e görelidir).
 *
 * | Uç                                          | Açıklama                               |
 * |---------------------------------------------|----------------------------------------|
 * | GET    /admin/users                         | kullanıcı listesi (sayfalı)            |
 * | POST   /admin/users                         | rescuer / coordinator hesabı açar     |
 * | GET    /admin/users/:id/devices             | kullanıcının cihazları                 |
 * | POST   /admin/users/:id/devices/:d/revoke   | tek cihaz iptali                       |
 * | POST   /admin/users/:id/revoke-all          | global iptal (pasifleştirme + ban)     |
 * | POST   /admin/users/:id/reactivate          | hesabı yeniden etkinleştirir           |
 * | GET    /admin/audit-logs                    | filtreli, sayfalı audit kayıtları      |
 *
 * Sıra: guard (OSP-61) -> requireRole('administrator') -> doğrulama -> store -> cevap.
 * Yetkisiz roller doğrulamaya ve veritabanına hiç ulaşmaz.
 */

const invalidIdError = () => new AppError(400, 'VALIDATION_ERROR', 'The id must be a valid UUID.');
const invalidBodyError = () =>
  new AppError(400, 'VALIDATION_ERROR', 'The request failed validation.');
const invalidQueryError = () =>
  new AppError(400, 'VALIDATION_ERROR', 'The query parameters failed validation.');
const userNotFoundError = () => new AppError(404, 'NOT_FOUND', 'The requested user does not exist.');
const deviceNotFoundError = () =>
  new AppError(404, 'NOT_FOUND', 'The requested device does not exist for this user.');
const selfTargetError = () =>
  new AppError(409, 'CONFLICT', 'You cannot disable your own account.');

/** Yönetici uçları kişisel veri döndürür: önbelleğe alınmasın. */
const noStore: RequestHandler = (_req: Request, res: Response, next: NextFunction) => {
  res.set('Cache-Control', 'no-store');
  next();
};

/** Şemayı doğrular ve ÇIKTI tipini döndürür (varsayılan değerli alanlar dolu gelir). */
function parseWith<S extends ZodType>(schema: S, value: unknown, onError: () => AppError): z.output<S> {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw onError();
  return parsed.data as z.output<S>;
}

function authOf(req: Request): AuthContext {
  if (!req.auth) throw unauthenticatedError();
  return req.auth;
}

export interface AdminRouteDeps {
  store: AdminStore;
  authAdmin: AuthAdminPort;
}

export function registerAdminRoutes(router: Router, deps: AdminRouteDeps): void {
  const { store, authAdmin } = deps;

  // Tüm /admin uçları yalnızca administrator. Rol dışı istekler burada 403 alır.
  router.use('/admin', requireRole('administrator'));

  router.get('/admin/users', noStore, async (req: Request, res: Response) => {
    const query = parseWith(listUsersQuerySchema, req.query, invalidQueryError);
    const users = await store.listUsers(query.limit, query.offset);
    res.status(200).json({ users, limit: query.limit, offset: query.offset });
  });

  router.post('/admin/users', noStore, async (req: Request, res: Response) => {
    const actor = authOf(req);
    const body = parseWith(createUserBodySchema, req.body, invalidBodyError);

    // AC: yetki yükseltmeyi önler. Auth'a ya da veritabanına dokunmadan reddedilir.
    if (body.role === 'administrator') throw roleForbiddenError();

    const created = await authAdmin.createAuthUser({
      email: body.email,
      password: body.password,
      role: body.role,
    });

    try {
      await store.createUserProfile({
        actor,
        user_id: created.id,
        role: body.role,
        full_name: body.full_name,
      });
    } catch (error) {
      // Telafi: profil ya da audit yazılamadıysa Auth hesabını geri al. Bu başarısız olursa
      // hesap yetim kalır; bunu loglamak yeterli, istemciye yine 500 dönülür.
      await authAdmin.deleteAuthUser(created.id).catch(() => {
        console.error(`[connect-backend] OSP-66: compensation failed for auth user ${created.id}`);
      });
      throw error;
    }

    res.status(201).json({
      user: {
        id: created.id,
        email: body.email,
        full_name: body.full_name,
        role: body.role,
        is_active: true,
      },
    });
  });

  router.get('/admin/users/:id/devices', noStore, async (req: Request, res: Response) => {
    const userId = parseWith(userIdParamSchema, req.params.id, invalidIdError);
    if (!(await store.findUserProfile(userId))) throw userNotFoundError();
    const devices = await store.listDevices(userId);
    res.status(200).json({ devices });
  });

  router.post(
    '/admin/users/:id/devices/:deviceId/revoke',
    noStore,
    async (req: Request, res: Response) => {
      const actor = authOf(req);
      const userId = parseWith(userIdParamSchema, req.params.id, invalidIdError);
      const deviceId = parseWith(deviceIdParamSchema, req.params.deviceId, invalidIdError);

      const status = await store.revokeDevice({ actor, user_id: userId, device_id: deviceId });
      if (status === 'NOT_FOUND') throw deviceNotFoundError();

      res.status(200).json({ device_id: deviceId, is_device_revoked: true, status });
    },
  );

  router.post('/admin/users/:id/revoke-all', noStore, async (req: Request, res: Response) => {
    const actor = authOf(req);
    const userId = parseWith(userIdParamSchema, req.params.id, invalidIdError);

    // Kendi hesabını kilitlemek, tek yöneticiyi sistemden atar. Bu kural spec'te yok, eklendi.
    if (userId === actor.user_id) throw selfTargetError();

    // Önce veritabanı: guard bir sonraki istekte ACCOUNT_DISABLED döndürür. Ban çağrısı
    // başarısız olursa hesap yine de devre dışıdır ve admin isteği tekrar edebilir.
    const status = await store.disableUser({ actor, user_id: userId });
    if (status === 'NOT_FOUND') throw userNotFoundError();

    await authAdmin.banUser(userId);

    res.status(200).json({ user: { id: userId, is_active: false } });
  });

  router.post('/admin/users/:id/reactivate', noStore, async (req: Request, res: Response) => {
    const actor = authOf(req);
    const userId = parseWith(userIdParamSchema, req.params.id, invalidIdError);

    const status = await store.activateUser({ actor, user_id: userId });
    if (status === 'NOT_FOUND') throw userNotFoundError();

    await authAdmin.unbanUser(userId);

    res.status(200).json({ user: { id: userId, is_active: true } });
  });

  router.get('/admin/audit-logs', noStore, async (req: Request, res: Response) => {
    const query = parseWith(auditLogsQuerySchema, req.query, invalidQueryError);
    const logs = await store.listAuditLogs(query);
    res.status(200).json({ logs, limit: query.limit, offset: query.offset });
  });
}
