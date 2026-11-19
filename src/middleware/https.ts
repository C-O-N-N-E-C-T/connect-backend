import type { NextFunction, Request, Response } from 'express';
import { env } from '../config/env.js';
import type { ErrorResponsePayload } from '../types/errors.js';

/**
 * NFR-SEC-02 / AC-19: In production, plain HTTP requests are rejected.
 * Responds 426 Upgrade Required so the client knows it must retry over TLS.
 * Relies on `trust proxy` (TRUST_PROXY) so `req.secure` reflects the edge's X-Forwarded-Proto.
 */
export function requireHttps(req: Request, res: Response<ErrorResponsePayload>, next: NextFunction) {
  if (env.NODE_ENV !== 'production' || req.secure) {
    next();
    return;
  }

  res
    .status(426)
    .set('Upgrade', 'TLS/1.2, HTTP/1.1')
    .json({
      error_code: 'HTTPS_REQUIRED',
      message: 'HTTPS is required. Retry this request over https://.',
    });
}
