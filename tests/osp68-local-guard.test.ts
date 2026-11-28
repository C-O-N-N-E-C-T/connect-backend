import { describe, expect, it, vi } from 'vitest';
import {
  assertLocalUrl,
  NonLocalSupabaseError,
  parseStatusJson,
  requireProvidedConfig,
  resolveLocalSupabase,
} from './integration/local-guard.js';

// OSP-68: entegrasyon paketinin "yalnızca yerel Supabase" korumasının BİRİM testleri.
// Bu dosya `npm test` ile çalışır; ağa, Docker'a ya da Supabase CLI'ya gitmez
// (CLI çıktısı `runStatus` ile sahte verilir).

/** Sahte `supabase status -o json` çıktısı; anahtarlar bilerek anlamsız değerlerdir. */
function fakeStatus(overrides: Record<string, string> = {}): string {
  return JSON.stringify({
    API_URL: 'http://127.0.0.1:54321',
    ANON_KEY: 'fake-anon',
    SERVICE_ROLE_KEY: 'fake-service',
    DB_URL: 'postgresql://postgres:postgres@127.0.0.1:54322/postgres',
    JWT_SECRET: 'fake-secret',
    ...overrides,
  });
}

describe('OSP-68 local-only guard: assertLocalUrl', () => {
  it.each([
    'http://127.0.0.1:54321',
    'http://localhost:54321',
    'http://LOCALHOST:54321',
    'postgresql://postgres:postgres@127.0.0.1:54322/postgres',
  ])('accepts a local address: %s', (url) => {
    expect(() => assertLocalUrl(url)).not.toThrow();
  });

  it.each([
    'https://example.supabase.co',
    'https://abcdefghijklmnop.supabase.co',
    'http://localhost.example.com:54321',
    'http://127.0.0.1.example.com',
    'http://10.0.0.5:54321',
    'http://0.0.0.0:54321',
    'postgresql://postgres:pw@db.example.supabase.co:5432/postgres',
    'ftp://127.0.0.1',
    'not a url',
    '',
    undefined,
    // Atlatma denemeleri (regresyon koruması): userinfo ile host gizleme, DNS joker alan adı,
    // IPv6 loopback (izin listesinde yok), sondaki nokta ve büyük harfli benzer alan adı.
    'http://localhost@evil.com',
    'http://user:pw@127.0.0.1.nip.io',
    'http://[::1]:54321',
    'http://localhost.:54321',
    'postgresql://u@LOCALHOST.evil.com/db',
  ])('rejects a non-local or invalid address: %s', (url) => {
    expect(() => assertLocalUrl(url)).toThrow(NonLocalSupabaseError);
  });

  it('never echoes the full URL (only the host) in the error message', () => {
    try {
      assertLocalUrl('https://user:secret-token@example.supabase.co/path?key=abc');
      expect.unreachable();
    } catch (err) {
      expect((err as Error).message).toContain('example.supabase.co');
      expect((err as Error).message).not.toContain('secret-token');
      expect((err as Error).message).not.toContain('key=abc');
    }
  });
});

describe('OSP-68 local-only guard: resolveLocalSupabase', () => {
  it('reads every value from the Supabase CLI status output, not from SUPABASE_* env vars', () => {
    const config = resolveLocalSupabase({
      env: { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_ANON_KEY: 'remote' },
      runStatus: () => fakeStatus(),
    });
    expect(config.apiUrl).toBe('http://127.0.0.1:54321');
    expect(config.anonKey).toBe('fake-anon');
    expect(config.serviceRoleKey).toBe('fake-service');
    expect(config.jwtSecret).toBe('fake-secret');
  });

  it('stops on a remote INTEGRATION_SUPABASE_URL before the CLI is even called', () => {
    const runStatus = vi.fn(() => fakeStatus());
    expect(() =>
      resolveLocalSupabase({
        env: { INTEGRATION_SUPABASE_URL: 'https://example.supabase.co' },
        runStatus,
      }),
    ).toThrow(NonLocalSupabaseError);
    expect(runStatus).not.toHaveBeenCalled();
  });

  it('accepts a local INTEGRATION_SUPABASE_URL override', () => {
    const config = resolveLocalSupabase({
      env: { INTEGRATION_SUPABASE_URL: 'http://localhost:54321' },
      runStatus: () => fakeStatus(),
    });
    expect(config.apiUrl).toBe('http://localhost:54321');
  });

  it('stops when the CLI itself reports a non-local API or DB address', () => {
    expect(() =>
      resolveLocalSupabase({ env: {}, runStatus: () => fakeStatus({ API_URL: 'https://example.supabase.co' }) }),
    ).toThrow(NonLocalSupabaseError);
    expect(() =>
      resolveLocalSupabase({
        env: {},
        runStatus: () =>
          fakeStatus({ DB_URL: 'postgresql://postgres:pw@db.example.supabase.co:5432/postgres' }),
      }),
    ).toThrow(NonLocalSupabaseError);
  });

  it('fails closed on non-JSON or incomplete CLI output', () => {
    expect(() => parseStatusJson('Stopped services: ...')).toThrow(/did not return JSON/);
    expect(() => parseStatusJson(JSON.stringify({ API_URL: 'http://127.0.0.1:54321' }))).toThrow(
      /no ANON_KEY/,
    );
  });
});

describe('OSP-68 local-only guard: requireProvidedConfig (run outside the integration config)', () => {
  it('throws a clear error instead of a TypeError when globalSetup did not provide the config', () => {
    expect(() => requireProvidedConfig(undefined)).toThrow(/\[OSP-68\].*npm run test:integration/);
    expect(() => requireProvidedConfig(null)).toThrow(/npm run test:integration/);
  });

  it('returns the provided config unchanged', () => {
    const config = parseStatusJson(fakeStatus());
    expect(requireProvidedConfig(config)).toBe(config);
  });
});
