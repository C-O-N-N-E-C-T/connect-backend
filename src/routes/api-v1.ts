import express, { Router, type Request, type Response } from 'express';
import type { ErrorResponsePayload } from '../types/errors.js';

/**
 * JSON body parser. Protected routes get it AFTER the auth guard (see app.ts), so requests
 * without a valid token are rejected with 401 before any body is read. A public route that
 * needs a body adds it to its own route chain.
 */
export const jsonBody = express.json({ limit: '1mb' });

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
export function createPublicApiRouter(): Router {
  const router = Router({ caseSensitive: true, strict: true });

  // GET (and HEAD) only; other methods fall through to the guard.
  router.get('/api/v1/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      service: 'connect-backend',
      version: 'v1',
    });
  });

  // OSP-60: replace this placeholder with the session binding handler (keep `jsonBody`).
  // The guard does not run here, so the handler must verify the caller itself with
  // `verifyAuthorizationHeader` + `loadActiveProfile` from middleware/auth.ts. Pass the
  // `VerifiedClaims` returned by `verifyAuthorizationHeader` as is: never a body `user_id` or a
  // self-decoded JWT (the branded type rejects those at compile time).
  router.post(
    '/api/v1/auth/session',
    jsonBody,
    (_req: Request, res: Response<ErrorResponsePayload>) => {
      res.status(404).json({
        error_code: 'NOT_FOUND',
        message: 'The requested endpoint does not exist.',
      });
    },
  );

  return router;
}

/**
 * PROTECTED /api/v1 routes: ALL /api/v1 endpoints except the public ones above go here
 * (e.g. OSP-60 `router.post('/auth/logout', ...)`). Paths are relative to /api/v1.
 * app.ts mounts this router behind `requireAuth` and `jsonBody`, so every handler can rely on
 * `req.auth` and a parsed JSON body. Never mount routes for /api/v1 anywhere else.
 */
export function createProtectedApiRouter(): Router {
  const router = Router();
  return router;
}
