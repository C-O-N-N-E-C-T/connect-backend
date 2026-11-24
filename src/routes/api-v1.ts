import express, {
  Router,
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
} from 'express';
import type { AuthGuard } from '../middleware/auth.js';
import type { AuditLogStore } from '../services/audit-log.js';
import { defaultAdminStore, defaultAuthAdmin, type AdminStore, type AuthAdminPort } from '../services/admin-store.js';
import { defaultSessionStore, type SessionStore } from '../services/session-store.js';
import { createVictimAudit, victimAudit } from '../services/victim-audit.js';
import { defaultVictimStore, type VictimStore } from '../services/victim-store.js';
import { AppError } from '../types/errors.js';
import { createLogoutHandler, createMeHandler, createSessionHandler } from './auth.js';
import { registerAdminRoutes } from './admin.js';
import { registerBusinessRoutes } from './business.js';

const parseJson = express.json({ limit: '1mb' });

/**
 * Generic 400 for every client-side body error; the parser's own message is never sent (it can
 * contain body content or zlib internals).
 */
export const invalidBodyError = () =>
  new AppError(
    400,
    'VALIDATION_ERROR',
    'The request body is malformed, too large or uses an unsupported encoding.',
  );

/**
 * JSON body parser. Protected routes get it AFTER the auth guard (see app.ts), so requests
 * without a valid token are rejected with 401 before any body is read. A public route that
 * needs a body adds it to its own route chain.
 *
 * Classification by origin, not by error shape: an error that body-parser itself passes to
 * `next` with a 4xx `status`/`statusCode` is a client body error and becomes
 * 400 VALIDATION_ERROR. That covers invalid JSON, a too-large body, an unsupported charset or
 * content encoding, an aborted request, and a corrupt gzip/deflate/br body (a zlib error that
 * body-parser wraps as 400 without a `type`). Errors with any other status (raw-body's 500s
 * for stream misuse) pass through unchanged. Errors thrown by route handlers never pass
 * through here, so they cannot be misreported as body errors.
 */
export const jsonBody: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  parseJson(req, res, (err?: unknown) => {
    if (err === undefined || err === null) {
      next();
      return;
    }
    const { status, statusCode } = err as { status?: unknown; statusCode?: unknown };
    const code = typeof status === 'number' ? status : statusCode;
    next(typeof code === 'number' && code >= 400 && code < 500 ? invalidBodyError() : err);
  });
};

/**
 * PUBLIC /api/v1 routes: reachable WITHOUT an access token. Only the health check and the
 * initial session binding belong here; every other /api/v1 endpoint goes into
 * `createProtectedApiRouter`.
 *
 * Mounted at the app root with full paths. The router is case-sensitive and strict, so only the
 * exact path matches: `/api/v1/auth/session/`, `/API/V1/AUTH/SESSION`, `/api/v1/health/` or
 * `/api/v1/auth/session-evil` do not match here and fall through to the guard (401).
 * The query string is ignored by routing.
 */
export function createPublicApiRouter(auth: AuthGuard, sessionStore: SessionStore): Router {
  const router = Router({ caseSensitive: true, strict: true });

  // GET (and HEAD) only; other methods fall through to the guard.
  router.get('/api/v1/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      service: 'connect-backend',
      version: 'v1',
    });
  });

  // OSP-60: session binding. The guard does not run here, so the handler verifies the caller
  // itself through the `auth` passed in (same guard instance and deps as the protected mount;
  // fakes in tests via createApp({ authGuardDeps, sessionStore })). `jsonBody` stays: the
  // public router gets no body parser otherwise. See src/routes/auth.ts.
  router.post('/api/v1/auth/session', jsonBody, createSessionHandler(auth, sessionStore));

  return router;
}

/**
 * PROTECTED /api/v1 routes: ALL /api/v1 endpoints except the public ones above go here.
 * Paths are relative to /api/v1. app.ts mounts this router behind `requireAuth` and
 * `jsonBody`, so every handler can rely on `req.auth` and a parsed JSON body.
 * Never mount routes for /api/v1 anywhere else.
 */
export function createProtectedApiRouter(options: ProtectedApiRouterOptions = {}): Router {
  const router = Router();

  // OSP-60: clears this session's device binding and writes LOGOUT. 204, no body.
  router.post('/auth/logout', createLogoutHandler(options.sessionStore ?? defaultSessionStore));

  // OSP-70 (user decision 'option 2', 2026-11-25): lightweight session check for the web
  // dashboard so a revoked device/account is detected on the next call (AC-19). Chosen instead
  // of pinging GET /victims, which writes a victim-access audit row on every call (OSP-65/AC-28),
  // or /admin/users, which returns user data. Behind the OSP-61 guard; no audit row, no body.
  router.get('/auth/me', createMeHandler());

  // OSP-62: rol korumalı stub iş uçları; store verilmezse gerçek (Supabase) store kullanılır.
  // OSP-65: audit satırları verilen store'a (testler) veya gerçek audit_logs tablosuna gider.
  registerBusinessRoutes(
    router,
    options.victimStore ?? defaultVictimStore,
    options.auditLogStore ? createVictimAudit(options.auditLogStore) : victimAudit,
  );

  // OSP-66: yönetici uçları; testler sahte store / Auth port verir, üretim Supabase kullanır.
  registerAdminRoutes(router, {
    store: options.adminStore ?? defaultAdminStore,
    authAdmin: options.authAdmin ?? defaultAuthAdmin,
  });
  return router;
}

/** OSP-62: korumalı router bağımlılıkları (test enjeksiyonu için opsiyonel obje). */
export interface ProtectedApiRouterOptions {
  /** OSP-60: /auth/logout store; verilmezse gerçek (Supabase) store kullanılır. */
  sessionStore?: SessionStore;
  victimStore?: VictimStore;
  /** OSP-65: kazazede verisi uçlarının audit store'u; verilmezse gerçek audit_logs tablosu. */
  auditLogStore?: AuditLogStore;
  /** OSP-66: yönetici uçlarının veri erişimi; verilmezse gerçek (Supabase) store. */
  adminStore?: AdminStore;
  /** OSP-66: yönetici uçlarının Supabase Auth erişimi; verilmezse gerçek auth.admin. */
  authAdmin?: AuthAdminPort;
}
