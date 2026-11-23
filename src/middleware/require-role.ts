import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { APP_ROLES, type AppRole } from '../types/database.js';
import { AppError } from '../types/errors.js';
import type { AuthContext } from '../types/express.js';
import { unauthenticatedError } from './auth.js';

/**
 * OSP-62: Rol tabanlı erişim kontrolü (RBAC).
 *
 * Rol YALNIZCA OSP-61 guard'ının (`requireAuth`) doldurduğu `req.auth.role` alanından okunur.
 * Bu alan veritabanındaki `user_profiles.role` değeridir; header, gövde veya JWT'nin kendisi
 * burada asla okunmaz/decode edilmez. Bu yüzden middleware her zaman `requireAuth`'tan SONRA
 * çalışmalıdır (korumalı /api/v1 router'ı zaten guard'ın arkasına bağlıdır).
 */

// Tüm rol ihlallerinde aynı mesaj: hangi rollerin izinli olduğu istemciye sızdırılmaz.
const ROLE_FORBIDDEN_MESSAGE = 'Your role is not permitted to perform this action.';

export const roleForbiddenError = () => new AppError(403, 'ROLE_FORBIDDEN', ROLE_FORBIDDEN_MESSAGE);

/**
 * İleride ABAC (SCRT-4-2) kuralları için genişleme noktası.
 * Bir politika, rol kontrolü GEÇTİKTEN sonra doğrulanmış kimlik (`auth`) ve istekle çağrılır;
 * `false` dönerse istek 403 ROLE_FORBIDDEN ile reddedilir. Daha özel bir hata gerekiyorsa
 * politika kendisi bir `AppError` fırlatabilir. Örnek (ileride): "koordinatör yalnızca kendi
 * bölgesindeki kayıtları görebilir".
 */
export type AccessPolicy = (auth: AuthContext, req: Request) => boolean | Promise<boolean>;

export interface AccessRule {
  /** İzinli roller; en az bir rol zorunludur. */
  roles: readonly AppRole[];
  /** Sırayla çalışan ek politikalar (ABAC); hepsi `true` dönmelidir. Varsayılan: yok. */
  policies?: readonly AccessPolicy[];
}

/**
 * Rol listesini route tanımlanırken (uygulama açılışında) doğrular.
 * Karar: boş liste bir TASARIM HATASIDIR ve hemen `Error` fırlatılır. Sessizce "herkesi
 * reddet" ya da daha kötüsü "herkese izin ver" davranışı yanlış yazılmış bir route'u gizlerdi;
 * açılışta patlamak hatayı test/geliştirme aşamasında görünür kılar. Tip sistemi dışından gelen
 * (ör. `as` ile zorlanmış) bilinmeyen rol adları da aynı sebeple reddedilir.
 */
function assertValidRoles(roles: readonly AppRole[]): void {
  if (roles.length === 0) {
    throw new Error('requireRole: at least one allowed role must be given.');
  }
  for (const role of roles) {
    if (!(APP_ROLES as readonly string[]).includes(role)) {
      throw new Error(`requireRole: unknown role "${String(role)}".`);
    }
  }
}

/**
 * Genel erişim guard'ı: önce rol, ardından (varsa) ABAC politikaları.
 * - `req.auth` yoksa 401 UNAUTHENTICATED (savunma amaçlı: normalde guard bunu zaten engeller,
 *   ama middleware yanlışlıkla guard'sız bir route'a takılırsa erişim AÇIK kalmaz).
 * - rol izinli değilse veya bir politika `false` dönerse 403 ROLE_FORBIDDEN.
 */
export function createAccessGuard(rule: AccessRule): RequestHandler {
  assertValidRoles(rule.roles);
  // Route tanımından sonra dışarıdan değiştirilemesin diye kopyalanır.
  const allowed: ReadonlySet<AppRole> = new Set(rule.roles);
  const policies = [...(rule.policies ?? [])];

  return async (req: Request, res: Response, next: NextFunction) => {
    const auth = req.auth;
    if (!auth) {
      // OSP-61 ile aynı 401 davranışı (RFC 6750 §3 başlığı dahil).
      res.set('WWW-Authenticate', 'Bearer');
      next(unauthenticatedError());
      return;
    }
    if (!allowed.has(auth.role)) {
      next(roleForbiddenError());
      return;
    }
    for (const policy of policies) {
      // Politika hatası (AppError veya beklenmeyen hata) global hata yakalayıcıya gider.
      if (!(await policy(auth, req))) {
        next(roleForbiddenError());
        return;
      }
    }
    next();
  };
}

/**
 * Yalnızca rol kontrolü: `router.get('/victims', requireRole('coordinator', 'administrator'), ...)`.
 * ABAC gerektiğinde aynı yerde `createAccessGuard({ roles, policies })` kullanılır.
 */
export function requireRole(...allowedRoles: AppRole[]): RequestHandler {
  return createAccessGuard({ roles: allowedRoles });
}
