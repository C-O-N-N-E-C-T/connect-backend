import cors from 'cors';
import express, { type NextFunction, type Request, type Response, type Router } from 'express';
import helmet from 'helmet';
import { env } from './config/env.js';
import { createRequireAuth, requireAuth, type AuthGuardDeps } from './middleware/auth.js';
import { requireHttps } from './middleware/https.js';
import { createAuthRateLimiter } from './middleware/rate-limit.js';
import {
  createProtectedApiRouter,
  createPublicApiRouter,
  jsonBody,
} from './routes/api-v1.js';
import { AppError, type ErrorResponsePayload } from './types/errors.js';

/** Test seams only; production calls `createApp()` without options. */
export interface AppOptions {
  /** Replaces the default Supabase-backed guard dependencies. */
  authGuardDeps?: AuthGuardDeps;
  /** Registers extra routes on the protected /api/v1 router (the production extension point). */
  registerProtectedRoutes?: (router: Router) => void;
}

export function createApp(options: AppOptions = {}) {
  const app = express();

  // Trust the reverse proxy / edge (Render) so req.secure and req.ip are correct
  app.set('trust proxy', env.TRUST_PROXY);

  // Security headers, HSTS enforced for 1 year across subdomains
  app.use(
    helmet({
      hsts: { maxAge: 31536000, includeSubDomains: true },
    }),
  );

  // Reject plain HTTP in production (NFR-SEC-02, AC-19)
  app.use(requireHttps);

  // Strict CORS configured from environment variable. Preflight (OPTIONS) requests end here
  // with 204, before the auth guard.
  app.use(
    cors({
      // Array form: unlisted origins get no Access-Control-Allow-Origin header at all
      origin: [env.CORS_ORIGIN],
      credentials: true,
    }),
  );

  app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      service: 'connect-backend',
    });
  });

  // ---------------------------------------------------------------------------------------
  // /api/v1 — order matters:
  //   1. auth rate limiter (OSP-64) on /api/v1/auth/*, before the guard, so unauthenticated
  //      brute force is still limited;
  //   2. PUBLIC router (health, POST /api/v1/auth/session) — exact paths, no token;
  //   3. auth guard (OSP-61), then JSON body parsing, then the PROTECTED router.
  // Every /api/v1 request that is not an exact public route hits the guard, so unknown
  // /api/v1 paths answer 401 to unauthenticated callers. New endpoints go into
  // routes/api-v1.ts (createProtectedApiRouter), never directly on `app`.
  // ---------------------------------------------------------------------------------------
  app.use('/api/v1/auth', createAuthRateLimiter());
  app.use(createPublicApiRouter());

  const guard = options.authGuardDeps ? createRequireAuth(options.authGuardDeps) : requireAuth;
  const protectedApiRouter = createProtectedApiRouter();
  options.registerProtectedRoutes?.(protectedApiRouter);
  app.use('/api/v1', guard, jsonBody, protectedApiRouter);

  // 404 handler following the Unified HTTP Error Contract
  app.use((_req: Request, res: Response<ErrorResponsePayload>) => {
    res.status(404).json({
      error_code: 'NOT_FOUND',
      message: 'The requested endpoint does not exist.',
    });
  });

  app.use(errorHandler);

  return app;
}

/**
 * body-parser errors (invalid JSON, body too large, unsupported charset/encoding, aborted
 * request, ...) are http-errors with a string `type` and a 4xx `status`.
 */
function isBodyParserError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const { type, status } = err as Error & { type?: unknown; status?: unknown };
  return typeof type === 'string' && typeof status === 'number' && status >= 400 && status < 500;
}

/** Global error handler following the Unified HTTP Error Contract. */
export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response<ErrorResponsePayload>,
  _next: NextFunction,
) {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      error_code: err.errorCode,
      message: err.message,
    });
    return;
  }

  // Client body errors: generic message, never the parser's own (it can echo body content).
  if (isBodyParserError(err)) {
    res.status(400).json({
      error_code: 'VALIDATION_ERROR',
      message: 'The request body is malformed, too large or uses an unsupported encoding.',
    });
    return;
  }

  const message =
    err instanceof Error && env.NODE_ENV !== 'production'
      ? err.message
      : 'An unexpected internal server error occurred.';

  res.status(500).json({
    error_code: 'INTERNAL_ERROR',
    message,
  });
}

export const app = createApp();
