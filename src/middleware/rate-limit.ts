import rateLimit from 'express-rate-limit';
import type { Request, Response } from 'express';
import type { ErrorResponsePayload } from '../types/errors.js';

/**
 * OSP-64: max 10 requests per minute per client IP on /api/v1/auth/*, except GET /auth/me (OSP-70).
 * Note: the default store is in-memory, so the limit applies per running instance.
 * A factory so each `createApp()` gets its own store (one app per process in production).
 */
export const createAuthRateLimiter = () =>
  rateLimit({
    windowMs: 60_000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    // OSP-70 (user decision "A", 2026-11-25): GET /api/v1/auth/me is NOT counted.
    // The web dashboard calls it on startup and when the tab becomes visible again (at most once
    // per 10 s per user). Behind a shared crisis-centre NAT, counting it would let those checks use
    // up the 10/min budget that logins (POST /auth/session) need. /auth/me sits behind the OSP-61
    // guard (valid token, account and device required) and is not a login/brute-force target, like
    // the other protected endpoints, which have no rate limit either.
    // Exact match only (req.path is relative to the /api/v1/auth mount): any other path or method,
    // including HEAD and lookalikes such as /me/ or /ME, is still counted (the safe direction).
    skip: (req: Request) => req.method === 'GET' && req.path === '/me',
    handler: (_req: Request, res: Response<ErrorResponsePayload>) => {
      res.status(429).json({
        error_code: 'RATE_LIMITED',
        message: 'Too many authentication requests. Please try again later.',
      });
    },
  });
