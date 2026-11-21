import cors from 'cors';
import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import { env } from './config/env.js';
import { requireAuth } from './middleware/auth.js';
import { requireHttps } from './middleware/https.js';
import { authRateLimiter } from './middleware/rate-limit.js';
import { AppError, type ErrorResponsePayload } from './types/errors.js';

export function createApp() {
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

  // Strict CORS configured from environment variable
  app.use(
    cors({
      // Array form: unlisted origins get no Access-Control-Allow-Origin header at all
      origin: [env.CORS_ORIGIN],
      credentials: true,
    }),
  );

  // JSON request body parser
  app.use(express.json({ limit: '1mb' }));

  // Health check endpoints
  app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      service: 'connect-backend',
    });
  });

  app.get('/api/v1/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      service: 'connect-backend',
      version: 'v1',
    });
  });

  // Rate limit all auth endpoints (OSP-64). Runs before the auth guard so that
  // unauthenticated brute force against /api/v1/auth/* is still limited.
  app.use('/api/v1/auth', authRateLimiter);

  // Stateful auth guard on everything under /api/v1 except the public routes (OSP-61).
  // Unknown /api/v1 paths therefore answer 401 to unauthenticated callers instead of 404.
  app.use('/api/v1', (req: Request, res: Response, next: NextFunction) => {
    if (isPublicApiRoute(req)) {
      next();
      return;
    }
    requireAuth(req, res, next);
  });

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
 * Routes under /api/v1 reachable without a token (OSP-61): the health check and the initial
 * session binding (POST /api/v1/auth/session, implemented by OSP-60).
 * Exact, case-sensitive match on method and full path (query string ignored). Express 5 routing
 * itself is case-insensitive and ignores one trailing slash, so variants like
 * `/api/v1/auth/session/` or `/API/V1/AUTH/SESSION` are NOT excluded and get the guard (fails
 * closed); prefix look-alikes such as `/api/v1/auth/session-evil` are guarded too.
 */
const PUBLIC_API_ROUTES: ReadonlyArray<{ methods: readonly string[]; path: string }> = [
  { methods: ['GET', 'HEAD'], path: '/api/v1/health' },
  { methods: ['POST'], path: '/api/v1/auth/session' },
];

export function isPublicApiRoute(req: Request): boolean {
  const fullPath = `${req.baseUrl}${req.path}`;
  return PUBLIC_API_ROUTES.some(
    (route) => route.path === fullPath && route.methods.includes(req.method),
  );
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
