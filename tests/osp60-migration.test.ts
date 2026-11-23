import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// Static checks of the OSP-60 SQL (same approach as tests/osp58-schema.test.ts).
// They do not run the SQL; they pin the security-relevant parts so a later edit cannot
// silently drop them. Run `supabase db reset` locally to execute the migration for real.

const MIGRATIONS = path.resolve(import.meta.dirname, '..', 'supabase', 'migrations');
const sql = fs.readFileSync(path.join(MIGRATIONS, '20261122100000_osp60_session_binding.sql'), 'utf8');
const uniqueSql = fs.readFileSync(path.join(MIGRATIONS, '20261122100100_osp60_session_id_unique.sql'), 'utf8');

const FUNCTIONS = [
  ['bind_device_session', 'UUID, public.app_role, UUID, TEXT, UUID'],
  ['unbind_device_session', 'UUID, public.app_role, UUID, UUID'],
  ['record_login_rejected', 'UUID, public.app_role, UUID, TEXT'],
] as const;

function functionBody(name: string): string {
  const match = sql.match(
    new RegExp(`CREATE\\s+OR\\s+REPLACE\\s+FUNCTION\\s+public\\.${name}\\([\\s\\S]*?\\$\\$([\\s\\S]*?)\\$\\$`, 'i'),
  );
  expect(match, `function ${name} not found`).not.toBeNull();
  return match?.[1] ?? '';
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

describe('OSP-60 migration: session binding RPCs', () => {
  // bind/unbind only touch public tables -> INVOKER. record_login_rejected reads auth.users,
  // which service_role cannot SELECT on Supabase -> DEFINER (found when testing on local Supabase).
  const SECURITY: Record<(typeof FUNCTIONS)[number][0], 'INVOKER' | 'DEFINER'> = {
    bind_device_session: 'INVOKER',
    unbind_device_session: 'INVOKER',
    record_login_rejected: 'DEFINER',
  };

  it.each(FUNCTIONS)('%s has the expected SECURITY mode and a fixed search_path', (name) => {
    const header = sql.match(
      new RegExp(`FUNCTION\\s+public\\.${name}\\([\\s\\S]*?AS\\s+\\$\\$`, 'i'),
    )?.[0];
    expect(header).toMatch(new RegExp(`SECURITY\\s+${SECURITY[name]}`, 'i'));
    expect(header).toMatch(/SET\s+search_path\s*=\s*public/i);
  });

  it.each(FUNCTIONS)('%s is executable only by service_role', (name, args) => {
    const sig = `public\\.${name}\\(${escape(args).replace(/,\s*/g, ',\\s*')}\\)`;
    expect(sql).toMatch(new RegExp(`REVOKE\\s+ALL\\s+ON\\s+FUNCTION\\s+${sig}\\s+FROM\\s+PUBLIC`, 'i'));
    expect(sql).toMatch(
      new RegExp(`REVOKE\\s+EXECUTE\\s+ON\\s+FUNCTION\\s+${sig}\\s+FROM\\s+anon,\\s*authenticated`, 'i'),
    );
    expect(sql).toMatch(new RegExp(`GRANT\\s+EXECUTE\\s+ON\\s+FUNCTION\\s+${sig}\\s+TO\\s+service_role`, 'i'));
    expect(sql).not.toMatch(new RegExp(`GRANT[^;]*${sig}[^;]*TO[^;]*\\b(anon|authenticated)\\b`, 'i'));
  });

  it('bind_device_session locks the device row before checking revocation', () => {
    expect(functionBody('bind_device_session')).toMatch(/FROM\s+public\.user_devices[\s\S]*?FOR\s+UPDATE/i);
  });

  it('bind_device_session upserts on (user_id, device_id) and never writes revocation columns', () => {
    const body = functionBody('bind_device_session');
    expect(body).toMatch(/ON\s+CONFLICT\s*\(\s*user_id\s*,\s*device_id\s*\)\s+DO\s+UPDATE/i);
    const upsert = body.match(/INSERT\s+INTO\s+public\.user_devices[\s\S]*?;/i)?.[0] ?? '';
    // Only the column list and the SET clause may write; the trailing WHERE only reads.
    const writes = upsert.split(/\bWHERE\b/i)[0] ?? '';
    expect(writes).not.toMatch(/is_device_revoked|device_revoked_at/i);
    // The conflict update is skipped for revoked rows.
    expect(upsert).toMatch(/WHERE\s+public\.user_devices\.is_device_revoked\s*=\s*false/i);
  });

  it('bind_device_session clears the session_id from other rows before binding', () => {
    const body = functionBody('bind_device_session');
    const clear = body.search(/UPDATE\s+public\.user_devices\s+SET\s+session_id\s*=\s*NULL/i);
    const upsert = body.search(/INSERT\s+INTO\s+public\.user_devices/i);
    expect(clear).toBeGreaterThan(-1);
    expect(clear).toBeLessThan(upsert);
  });

  it('writes LOGIN / LOGIN_REJECTED / LOGOUT audit rows in the functions', () => {
    expect(functionBody('bind_device_session')).toMatch(/'LOGIN'/);
    expect(functionBody('bind_device_session')).toMatch(/'LOGIN_REJECTED'/);
    expect(functionBody('unbind_device_session')).toMatch(/'LOGOUT'/);
    expect(functionBody('record_login_rejected')).toMatch(/'LOGIN_REJECTED'/);
  });

  it('unbind_device_session matches on user_id AND session_id', () => {
    const body = functionBody('unbind_device_session');
    expect(body).toMatch(/WHERE\s+user_id\s*=\s*p_user_id\s+AND\s+session_id\s*=\s*p_session_id/i);
  });

  it('optional migration adds a partial unique index on user_devices.session_id', () => {
    expect(uniqueSql).toMatch(
      /CREATE\s+UNIQUE\s+INDEX[\s\S]*ON\s+public\.user_devices\s*\(\s*session_id\s*\)\s*WHERE\s+session_id\s+IS\s+NOT\s+NULL/i,
    );
  });
});
