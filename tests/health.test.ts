import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { app } from '../src/app.js';
import { loadEnvOrExit, parseEnv } from '../src/config/env.js';

describe('OSP-57: Backend Skeleton & Environment Loader', () => {
  it('GET /api/v1/health returns 200 OK with service metadata', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      status: 'ok',
      service: 'connect-backend',
      version: 'v1',
    });
  });

  // Paths outside /api/v1; unknown /api/v1 paths are behind the OSP-61 auth guard (401).
  it('Unknown routes return 404 following Unified HTTP Error Contract', async () => {
    const res = await request(app).get('/non-existent-route');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({
      error_code: 'NOT_FOUND',
      message: 'The requested endpoint does not exist.',
    });
  });

  it('parseEnv validates required SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, and DATABASE_URL', () => {
    const valid = parseEnv({
      NODE_ENV: 'development',
      PORT: '4000',
      CORS_ORIGIN: 'http://localhost:5173',
      SUPABASE_URL: 'https://test-project.supabase.co',
      SUPABASE_ANON_KEY: 'anon-key-value',
      SUPABASE_SERVICE_ROLE_KEY: 'service-role-key-value',
      DATABASE_URL: 'postgresql://postgres:postgres@127.0.0.1:54322/postgres',
    });

    expect(valid.PORT).toBe(4000);
    expect(valid.SUPABASE_URL).toBe('https://test-project.supabase.co');
    expect(valid.DATABASE_URL).toBe(
      'postgresql://postgres:postgres@127.0.0.1:54322/postgres',
    );
  });

  it('loadEnvOrExit exits immediately with code 1 and clear error when a required variable is missing', () => {
    const exitSpy = vi
      .spyOn(process, 'exit')
      .mockImplementation(((code?: number) => {
        throw new Error(`process.exit(${code})`);
      }) as never);
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() =>
      loadEnvOrExit({
        NODE_ENV: 'development',
      }),
    ).toThrow('process.exit(1)');

    expect(errorSpy).toHaveBeenCalled();
    exitSpy.mockRestore();
    errorSpy.mockRestore();
  });
});
