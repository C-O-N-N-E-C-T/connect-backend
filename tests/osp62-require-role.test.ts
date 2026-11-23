import express, { type Request, type RequestHandler, type Response } from 'express';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { errorHandler } from '../src/app.js';
import {
  createAccessGuard,
  requireRole,
  type AccessPolicy,
} from '../src/middleware/require-role.js';
import type { AppRole } from '../src/types/database.js';
import { AppError } from '../src/types/errors.js';
import type { AuthContext } from '../src/types/express.js';

// Birim testler: requireRole, OSP-61 guard'ı olmadan; `req.auth` test içinde elle konur.
// Ağ veya veritabanı erişimi yoktur.

const AUTH_BASE: Omit<AuthContext, 'role'> = {
  user_id: '11111111-1111-4111-8111-111111111111',
  device_id: '44444444-4444-4444-8444-444444444444',
  session_id: '33333333-3333-4333-8333-333333333333',
};

/** `role` verilirse req.auth'u doldurur, verilmezse req.auth hiç konmaz (guard'sız senaryo). */
function buildApp(guard: RequestHandler, role?: AppRole) {
  const app = express();
  app.use((req, _res, next) => {
    if (role) req.auth = { ...AUTH_BASE, role };
    next();
  });
  app.get('/target', guard, (_req: Request, res: Response) => {
    res.status(200).json({ ok: true });
  });
  app.use(errorHandler);
  return app;
}

function expectError(res: request.Response, status: number, errorCode: string) {
  expect(res.status).toBe(status);
  expect(res.body).toEqual({ error_code: errorCode, message: expect.any(String) });
}

describe('OSP-62: requireRole', () => {
  it.each<AppRole>(['rescuer', 'coordinator', 'administrator'])(
    'izinli rol (%s) geçer',
    async (role) => {
      const res = await request(buildApp(requireRole(role), role)).get('/target');
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ ok: true });
    },
  );

  it('birden çok izinli rolden herhangi biri yeterlidir', async () => {
    const guard = requireRole('coordinator', 'administrator');
    expect((await request(buildApp(guard, 'coordinator')).get('/target')).status).toBe(200);
    expect((await request(buildApp(guard, 'administrator')).get('/target')).status).toBe(200);
  });

  it('izinsiz rol 403 ROLE_FORBIDDEN alır ve handler çalışmaz', async () => {
    const handler = vi.fn();
    const app = express();
    app.use((req, _res, next) => {
      req.auth = { ...AUTH_BASE, role: 'administrator' };
      next();
    });
    app.get('/target', requireRole('coordinator'), handler);
    app.use(errorHandler);
    expectError(await request(app).get('/target'), 403, 'ROLE_FORBIDDEN');
    expect(handler).not.toHaveBeenCalled();
  });

  it('403 mesajı izinli rolleri sızdırmaz', async () => {
    const res = await request(buildApp(requireRole('coordinator'), 'rescuer')).get('/target');
    expect(res.body.message).not.toMatch(/coordinator|administrator/i);
  });

  it('req.auth yoksa (guard atlanmışsa) 401 UNAUTHENTICATED + WWW-Authenticate', async () => {
    const res = await request(buildApp(requireRole('rescuer'))).get('/target');
    expectError(res, 401, 'UNAUTHENTICATED');
    expect(res.headers['www-authenticate']).toBe('Bearer');
  });

  it('rol yalnızca req.auth.role\'den okunur: header/gövde/sahte JWT rolü etkisizdir', async () => {
    const res = await request(buildApp(requireRole('administrator'), 'rescuer'))
      .get('/target')
      .set('X-User-Role', 'administrator')
      .set('Authorization', 'Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyX3JvbGUiOiJhZG1pbmlzdHJhdG9yIn0.')
      .query({ role: 'administrator' });
    expectError(res, 403, 'ROLE_FORBIDDEN');
  });

  it('boş rol listesi tasarım hatasıdır: route tanımlanırken hemen fırlatır', () => {
    expect(() => requireRole()).toThrow(/at least one allowed role/);
    expect(() => createAccessGuard({ roles: [] })).toThrow(/at least one allowed role/);
  });

  it('bilinmeyen rol adı (tip dışı zorlama) tanım anında reddedilir', () => {
    expect(() => requireRole('superuser' as AppRole)).toThrow(/unknown role/);
  });
});

describe('OSP-62: ABAC genişleme noktası (createAccessGuard policies)', () => {
  it('rol geçince politikalar çalışır; hepsi true ise istek geçer', async () => {
    const policy = vi.fn<AccessPolicy>(() => true);
    const guard = createAccessGuard({ roles: ['coordinator'], policies: [policy] });
    expect((await request(buildApp(guard, 'coordinator')).get('/target')).status).toBe(200);
    expect(policy).toHaveBeenCalledTimes(1);
    expect(policy.mock.calls[0]?.[0]).toMatchObject({ role: 'coordinator' });
  });

  it('politika false dönerse 403 ROLE_FORBIDDEN', async () => {
    const guard = createAccessGuard({ roles: ['coordinator'], policies: [async () => false] });
    expectError(await request(buildApp(guard, 'coordinator')).get('/target'), 403, 'ROLE_FORBIDDEN');
  });

  it('rol izinsizse politika hiç çalışmaz', async () => {
    const policy = vi.fn<AccessPolicy>(() => true);
    const guard = createAccessGuard({ roles: ['coordinator'], policies: [policy] });
    expectError(await request(buildApp(guard, 'rescuer')).get('/target'), 403, 'ROLE_FORBIDDEN');
    expect(policy).not.toHaveBeenCalled();
  });

  it('politika kendi AppError\'ını fırlatabilir', async () => {
    const guard = createAccessGuard({
      roles: ['coordinator'],
      policies: [
        () => {
          throw new AppError(404, 'NOT_FOUND', 'hidden');
        },
      ],
    });
    expectError(await request(buildApp(guard, 'coordinator')).get('/target'), 404, 'NOT_FOUND');
  });
});
