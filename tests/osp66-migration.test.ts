import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// OSP-66 migration'ının STATİK kontrolleri. Veritabanına bağlanmaz; davranışın gerçek
// doğrulaması yerel Supabase'de yapılır (docs/osp-66-admin-api.md, bölüm 6).

const MIGRATION = path.resolve(
  import.meta.dirname,
  '..',
  'supabase',
  'migrations',
  '20261123130000_osp66_admin_api.sql',
);
const sql = fs.readFileSync(MIGRATION, 'utf8');

/** Bir fonksiyonun CREATE ... ile SONRAKİ CREATE/REVOKE arasındaki gövdesini döndürür. */
function bodyOf(name: string): string {
  const start = sql.indexOf(`CREATE OR REPLACE FUNCTION public.${name}(`);
  expect(start, `function ${name} must be defined`).toBeGreaterThan(-1);
  const next = sql.indexOf('CREATE OR REPLACE FUNCTION', start + 10);
  const revoke = sql.indexOf('-- 7. Privileges', start);
  const ends = [next, revoke].filter((i) => i > -1);
  return sql.slice(start, ends.length ? Math.min(...ends) : sql.length);
}

const FUNCTIONS = [
  'admin_revoke_session',
  'admin_create_user_profile',
  'admin_revoke_device',
  'admin_disable_user',
  'admin_activate_user',
  'admin_list_users',
];

describe('OSP-66 migration: functions', () => {
  it.each(FUNCTIONS)('%s is SECURITY DEFINER with a pinned search_path', (name) => {
    const body = bodyOf(name);
    expect(body).toMatch(/SECURITY DEFINER/);
    expect(body).toMatch(/SET search_path = ''/);
  });

  it.each(FUNCTIONS)('%s is executable by service_role only', (name) => {
    expect(sql).toMatch(
      new RegExp(`REVOKE ALL ON FUNCTION public\\.${name}\\([^)]*\\)\\s+FROM PUBLIC, anon, authenticated;`),
    );
    expect(sql).toMatch(
      new RegExp(`GRANT EXECUTE ON FUNCTION public\\.${name}\\([^)]*\\)\\s+TO service_role;`),
    );
  });
});

describe('OSP-66 migration: atomic state change + audit', () => {
  it.each([
    ['admin_create_user_profile', 'USER_CREATED'],
    ['admin_revoke_device', 'DEVICE_REVOKED'],
    ['admin_disable_user', 'ACCOUNT_DISABLED'],
    ['admin_activate_user', 'USER_REACTIVATED'],
  ])('%s writes its audit row (%s) inside the same function', (name, action) => {
    const body = bodyOf(name);
    expect(body).toMatch(/INSERT INTO public\.audit_logs/);
    expect(body).toContain(`'${action}'`);
  });

  it('admin_revoke_device keeps session_id (the guard looks devices up by it)', () => {
    const body = bodyOf('admin_revoke_device');
    expect(body).not.toMatch(/session_id\s*=\s*NULL/i);
    expect(body).toMatch(/PERFORM public\.admin_revoke_session\(v_session_id\)/);
  });

  it('admin_revoke_device locks the row and is idempotent (no audit on repeat)', () => {
    const body = bodyOf('admin_revoke_device');
    expect(body).toMatch(/FOR UPDATE/);
    expect(body).toMatch(/ALREADY_REVOKED/);
  });

  it('admin_disable_user sets is_active=false, the revocation timestamp, and deletes sessions', () => {
    const body = bodyOf('admin_disable_user');
    expect(body).toMatch(/is_active = false/);
    expect(body).toMatch(/all_sessions_revoked_at = now\(\)/);
    expect(body).toMatch(/DELETE FROM auth\.sessions WHERE user_id = p_user_id/);
  });

  it('admin_activate_user does NOT clear all_sessions_revoked_at', () => {
    const body = bodyOf('admin_activate_user');
    expect(body).toMatch(/is_active = true/);
    expect(body).not.toMatch(/all_sessions_revoked_at\s*=/);
  });
});

describe('OSP-66 migration: safety rules', () => {
  it('session deletion is isolated in a helper that only service_role may execute', () => {
    const body = bodyOf('admin_revoke_session');
    expect(body).toMatch(/DELETE FROM auth\.sessions WHERE id = p_session_id/);
    expect(sql).toMatch(
      /REVOKE ALL ON FUNCTION public\.admin_revoke_session\(UUID\)\s+FROM PUBLIC, anon, authenticated;/,
    );
  });

  it('no function grants anything to anon or authenticated', () => {
    expect(sql).not.toMatch(/GRANT EXECUTE[^;]*TO (anon|authenticated)/);
  });

  it('the migration does not touch the OSP-65 append-only triggers or table ownership', () => {
    expect(sql).not.toMatch(/DISABLE TRIGGER/i);
    expect(sql).not.toMatch(/ALTER TABLE public\.audit_logs/i);
    expect(sql).not.toMatch(/DROP TABLE/i);
    expect(sql).not.toMatch(/TRUNCATE/i);
  });
});
