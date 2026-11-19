import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, app } from '../src/app.js';
import { env } from '../src/config/env.js';

const originalNodeEnv = env.NODE_ENV;
const originalTrustProxy = env.TRUST_PROXY;

afterEach(() => {
  env.NODE_ENV = originalNodeEnv;
  env.TRUST_PROXY = originalTrustProxy;
});

describe('OSP-64: HTTPS/TLS, CORS and auth rate limiting', () => {
  it('rejects plain HTTP with 426 HTTPS_REQUIRED in production', async () => {
    env.NODE_ENV = 'production';
    const res = await request(createApp()).get('/api/v1/health');

    expect(res.status).toBe(426);
    expect(res.headers['upgrade']).toBe('TLS/1.2, HTTP/1.1');
    expect(res.body).toEqual({
      error_code: 'HTTPS_REQUIRED',
      message: 'HTTPS is required. Retry this request over https://.',
    });
  });

  it('accepts HTTPS requests in production when the proxy sends X-Forwarded-Proto: https', async () => {
    env.NODE_ENV = 'production';
    env.TRUST_PROXY = 1;
    const res = await request(createApp())
      .get('/api/v1/health')
      .set('X-Forwarded-Proto', 'https');

    expect(res.status).toBe(200);
  });

  it('ignores a spoofed X-Forwarded-Proto header when no proxy is trusted', async () => {
    env.NODE_ENV = 'production';
    env.TRUST_PROXY = 0;
    const res = await request(createApp())
      .get('/api/v1/health')
      .set('X-Forwarded-Proto', 'https');

    expect(res.status).toBe(426);
  });

  it('allows plain HTTP outside production', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
  });

  it('sends HSTS with a one-year max-age and includeSubDomains', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.headers['strict-transport-security']).toContain('max-age=31536000');
    expect(res.headers['strict-transport-security']).toContain('includeSubDomains');
  });

  it('CORS allows only the configured dashboard origin', async () => {
    const allowed = await request(app)
      .get('/api/v1/health')
      .set('Origin', env.CORS_ORIGIN);
    expect(allowed.headers['access-control-allow-origin']).toBe(env.CORS_ORIGIN);

    const blocked = await request(app)
      .get('/api/v1/health')
      .set('Origin', 'https://evil.example.com');
    expect(blocked.headers['access-control-allow-origin']).toBeUndefined();
  });

  // Keep this test the only one in this file that hits /api/v1/auth,
  // because the limiter store is shared across requests in the same module.
  it('returns 429 RATE_LIMITED after 10 auth requests per minute', async () => {
    for (let i = 0; i < 10; i++) {
      const res = await request(app).post('/api/v1/auth/session');
      expect(res.status).toBe(404);
    }

    const limited = await request(app).post('/api/v1/auth/session');
    expect(limited.status).toBe(429);
    expect(limited.body).toEqual({
      error_code: 'RATE_LIMITED',
      message: 'Too many authentication requests. Please try again later.',
    });
  });
});
