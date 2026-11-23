import express, {
  Router,
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
} from 'express';
import type { AuthGuard } from '../middleware/auth.js';
import { defaultSessionStore, type SessionStore } from '../services/session-store.js';
import { defaultVictimStore, type VictimStore } from '../services/victim-store.js';
import { AppError } from '../types/errors.js';
import { createLogoutHandler, createSessionHandler } from './auth.js';
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

  // OSP-62: rol korumalı stub iş uçları; store verilmezse gerçek (Supabase) store kullanılır.
  registerBusinessRoutes(router, options.victimStore ?? defaultVictimStore);
  return router;
}

/** OSP-62: korumalı router bağımlılıkları (test enjeksiyonu için opsiyonel obje). */
export interface ProtectedApiRouterOptions {
  /** OSP-60: /auth/logout store; verilmezse gerçek (Supabase) store kullanılır. */
  sessionStore?: SessionStore;
  victimStore?: VictimStore;
}
