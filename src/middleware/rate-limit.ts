import rateLimit from 'express-rate-limit';
import type { Request, Response } from 'express';
import type { ErrorResponsePayload } from '../types/errors.js';

/**
 * OSP-64: max 10 requests per minute per client IP on /api/v1/auth/*.
 * Note: the default store is in-memory, so the limit applies per running instance.
 */
export const authRateLimiter = rateLimit({
  windowMs: 60_000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req: Request, res: Response<ErrorResponsePayload>) => {
    res.status(429).json({
      error_code: 'RATE_LIMITED',
      message: 'Too many authentication requests. Please try again later.',
    });
  },
});
