import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { wasVictimAudited } from '../services/victim-audit.js';

/**
 * OSP-65 (AC-28): audit satırı olmadan başarılı kazazede verisi cevabı yok.
 *
 * src/routes/business.ts içinde /victims ve /sync path'lerine takılır. Bir handler,
 * `victimAudit` ile audit edilmemiş bir istek için 2xx cevap gönderirse
 * (res.json, res.send, res.end, res.write, 204, ...) gövde atılır ve istemciye onun yerine
 * 500 INTERNAL_ERROR gider. 3xx/4xx/5xx cevaplar değişmeden geçer
 * (başarısız istekler audit edilmez).
 *
 * Bu bir güvenlik ağıdır: audit çağrısını unutan bir uç veri sızdıramaz ve testleri
 * hemen kırılır.
 */
const BLOCKED_BODY = JSON.stringify({
  error_code: 'INTERNAL_ERROR',
  message: 'An unexpected internal server error occurred.',
});

type AnyFn = (...args: unknown[]) => unknown;

export const requireVictimAudit: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  const originalWrite = res.write.bind(res) as AnyFn;
  const originalEnd = res.end.bind(res) as AnyFn;
  let blocked = false;

  const mustBlock = () => res.statusCode >= 200 && res.statusCode < 300 && !wasVictimAudited(req);

  const block = () => {
    blocked = true;
    console.error(
      `[connect-backend] OSP-65: blocked unaudited ${req.method} ${req.baseUrl}${req.path} response`,
    );
    if (!res.headersSent) {
      res.statusCode = 500;
      res.removeHeader('ETag');
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Length', Buffer.byteLength(BLOCKED_BODY));
    }
    originalEnd(BLOCKED_BODY);
  };

  res.write = ((...args: unknown[]) => {
    if (blocked) return false;
    if (mustBlock()) {
      block();
      return false;
    }
    return originalWrite(...args);
  }) as Response['write'];

  res.end = ((...args: unknown[]) => {
    if (blocked) return res;
    if (mustBlock()) {
      block();
      return res;
    }
    originalEnd(...args);
    return res;
  }) as Response['end'];

  next();
};