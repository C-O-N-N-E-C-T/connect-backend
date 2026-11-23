import express, { type Request, type Response } from 'express';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { errorHandler } from '../src/app.js';
import { createRequireAuth } from '../src/middleware/auth.js';
import { requireVictimAudit } from '../src/middleware/victim-audit-enforcer.js';
import { createVictimAudit } from '../src/services/victim-audit.js';
import { AUTH_HEADER, RECORD_ID, fakeAuditStore, fakeGuardDeps, type FakeAuditStore } from './helpers/osp65-fakes.js';

// Enforcer tek başına: audit çağrısını unutan (veya yapan) route'lar, Express'in cevap
// gönderebildiği her yolla.

let store: FakeAuditStore;
let log: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  store = fakeAuditStore();
  log = vi.spyOn(console, 'error').mockImplementation(() => undefined);
});
afterEach(() => {
  log.mockRestore();
});

const SECRET = { id: RECORD_ID, payload: { note: 'secret victim data' } };

function buildApp() {
  const audit = createVictimAudit(store);
  const app = express();
  const router = express.Router();
  router.use('/victims', requireVictimAudit);

  // Audit çağrısı unutulmuş:
  router.get('/victims/json', (_req: Request, res: Response) => {
    res.status(200).json(SECRET);
  });
  router.get('/victims/send', (_req: Request, res: Response) => {
    res.send('secret victim data');
  });
  router.get('/victims/write', (_req: Request, res: Response) => {
    res.status(200);
    res.write('secret ');
    res.end('victim data');
  });
  router.delete('/victims/no-content', (_req: Request, res: Response) => {
    res.status(204).end();
  });
  // Doğru şekilde audit edilmiş:
  router.get('/victims/audited', async (req: Request, res: Response) => {
    await audit.view(req, RECORD_ID);
    res.status(200).json(SECRET);
  });
  // Başarısız istek (bilerek audit edilmez):
  router.get('/victims/missing', (_req: Request, res: Response) => {
    res.status(404).json({ error_code: 'NOT_FOUND', message: 'Victim record not found.' });
  });
  // /victims dışında: enforcer uygulanmamalı.
  router.get('/other', (_req: Request, res: Response) => {
    res.status(200).json({ ok: true });
  });

  app.use('/api/v1', createRequireAuth(fakeGuardDeps()), express.json(), router);
  app.use(errorHandler);
  return app;
}

function expectBlocked(res: request.Response) {
  expect(res.status).toBe(500);
  expect(res.body).toEqual({ error_code: 'INTERNAL_ERROR', message: expect.any(String) });
  expect(res.text).not.toContain('secret');
  expect(log).toHaveBeenCalledWith(expect.stringContaining('blocked unaudited'));
}

describe('OSP-65 requireVictimAudit', () => {
  it.each(['/victims/json', '/victims/send', '/victims/write'])(
    'unaudited 2xx via %s -> 500 and no victim data',
    async (path) => {
      expectBlocked(await request(buildApp()).get(`/api/v1${path}`).set(AUTH_HEADER));
    },
  );

  it('unaudited 204 -> 500', async () => {
    expectBlocked(await request(buildApp()).delete('/api/v1/victims/no-content').set(AUTH_HEADER));
  });

  it('audited 2xx passes through unchanged', async () => {
    const res = await request(buildApp()).get('/api/v1/victims/audited').set(AUTH_HEADER);
    expect(res.status).toBe(200);
    expect(res.body).toEqual(SECRET);
    expect(store.rows).toHaveLength(1);
    expect(log).not.toHaveBeenCalled();
  });

  it('4xx responses pass through unchanged and need no audit row', async () => {
    const res = await request(buildApp()).get('/api/v1/victims/missing').set(AUTH_HEADER);
    expect(res.status).toBe(404);
    expect(res.body.error_code).toBe('NOT_FOUND');
    expect(log).not.toHaveBeenCalled();
  });

  it('a failed audit write -> 500 from the error handler, no data', async () => {
    store.fail = true;
    const res = await request(buildApp()).get('/api/v1/victims/audited').set(AUTH_HEADER);
    expect(res.status).toBe(500);
    expect(res.text).not.toContain('secret');
  });

  it('routes outside /victims are not affected', async () => {
    const res = await request(buildApp()).get('/api/v1/other').set(AUTH_HEADER);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });
});
