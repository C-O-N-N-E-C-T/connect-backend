import cors from 'cors';
import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import { env } from './config/env.js';
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

  // Rate limit all auth endpoints (OSP-64)
  app.use('/api/v1/auth', authRateLimiter);

  // 404 handler following the Unified HTTP Error Contract
  app.use((_req: Request, res: Response<ErrorResponsePayload>) => {
    res.status(404).json({
      error_code: 'NOT_FOUND',
      message: 'The requested endpoint does not exist.',
    });
  });

  // Global error handler following the Unified HTTP Error Contract
  app.use(
    (
      err: unknown,
      _req: Request,
      res: Response<ErrorResponsePayload>,
      _next: NextFunction,
    ) => {
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
    },
  );

  return app;
}

export const app = createApp();
