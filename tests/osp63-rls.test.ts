import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// OSP-63 migration'ının STATİK kontrolleri. Veritabanına bağlanmaz; kabul kriterlerinin gerçek
// doğrulaması yerel Supabase'de scripts/osp63-verify-rls.sql ile yapılır (docs/osp-63-rls.md).

const MIGRATIONS = path.resolve(import.meta.dirname, '..', 'supabase', 'migrations');
const FILE = '20261126120000_osp63_rls_policies.sql';

const stripComments = (sql: string) => sql.replace(/--.*$/gm, '');
const sql = stripComments(fs.readFileSync(path.join(MIGRATIONS, FILE), 'utf8'));
const migrationFiles = fs
  .readdirSync(MIGRATIONS)
  .filter((f) => f.endsWith('.sql'))
  .sort();
const allSql = migrationFiles
  .map((f) => stripComments(fs.readFileSync(path.join(MIGRATIONS, f), 'utf8')))
  .join('\n');

const DENY_TABLES = ['victim_records', 'rescuer_observations', 'audit_logs'];
const SELF_READ = [
  ['user_profiles', 'id'],
  ['user_devices', 'user_id'],
] as const;

/** Bir CREATE POLICY ifadesini sonraki `;` karakterine kadar döndürür. */
function policyOn(table: string): string {
  const m = sql.match(new RegExp(`CREATE\\s+POLICY\\s+\\w+\\s+ON\\s+public\\.${table}\\b[^;]*;`, 'i'));
  expect(m, `policy on ${table} must exist`).not.toBeNull();
  return m![0];
}

describe('OSP-63 migration: is_active_user() helper', () => {
  const fn = sql.match(/CREATE\s+OR\s+REPLACE\s+FUNCTION\s+public\.is_active_user\(\)([\s\S]*?)\$\$([\s\S]*?)\$\$/i);

  it('is SECURITY DEFINER, STABLE, with a pinned empty search_path', () => {
    expect(fn).not.toBeNull();
    expect(fn![1]).toMatch(/SECURITY\s+DEFINER/i);
    expect(fn![1]).toMatch(/\bSTABLE\b/i);
    expect(fn![1]).toMatch(/SET\s+search_path\s*=\s*''/i);
  });

  it("checks the caller's own profile and is_active = true", () => {
    expect(fn![2]).toMatch(/FROM\s+public\.user_profiles/i);
    expect(fn![2]).toMatch(/auth\.uid\(\)/i);
    expect(fn![2]).toMatch(/is_active\s*=\s*true/i);
  });

  it('is executable by authenticated (policies run as the caller) but not by anon/PUBLIC', () => {
    expect(sql).toMatch(/REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.is_active_user\(\)\s+FROM\s+PUBLIC,\s*anon;/i);
    expect(sql).toMatch(/GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.is_active_user\(\)\s+TO\s+authenticated;/i);
    expect(sql).not.toMatch(/REVOKE[^;]*ON\s+FUNCTION\s+public\.is_active_user\(\)[^;]*authenticated/i);
  });
});

describe('OSP-63 migration: self-read policies', () => {
  it.each(SELF_READ)('%s: SELECT only, authenticated only, own row (%s = auth.uid()) and active', (table, col) => {
    const policy = policyOn(table);
    expect(policy).toMatch(/FOR\s+SELECT/i);
    expect(policy).toMatch(/TO\s+authenticated\b/i);
    expect(policy).not.toMatch(/\banon\b/i);
    expect(policy).toMatch(new RegExp(`\\b${col}\\s*=\\s*\\(SELECT\\s+auth\\.uid\\(\\)\\)`, 'i'));
    expect(policy).toMatch(/public\.is_active_user\(\)/i);
    expect(policy).not.toMatch(/WITH\s+CHECK/i);
  });

  it.each(SELF_READ)('%s: authenticated keeps SELECT only, anon gets nothing', (table) => {
    const revoke = sql.search(
      new RegExp(`REVOKE\\s+ALL\\s+ON\\s+public\\.${table}\\s+FROM\\s+PUBLIC,\\s*anon,\\s*authenticated;`, 'i'),
    );
    const grant = sql.search(new RegExp(`GRANT\\s+SELECT\\s+ON\\s+public\\.${table}\\s+TO\\s+authenticated;`, 'i'));
    expect(revoke).toBeGreaterThan(-1);
    expect(grant).toBeGreaterThan(revoke); // REVOKE ALL first, then SELECT back
    expect(sql).not.toMatch(new RegExp(`GRANT\\s+(?!SELECT\\s+ON)[^;]*ON\\s+public\\.${table}\\b`, 'i'));
  });
});

describe('OSP-63: deny-by-default tables (all migrations)', () => {
  it.each(DENY_TABLES)('%s has no policy in any migration', (table) => {
    expect(allSql).not.toMatch(new RegExp(`CREATE\\s+POLICY[^;]*ON\\s+public\\.${table}\\b`, 'i'));
  });

  it.each(['victim_records', 'rescuer_observations'])('%s: ALL privileges revoked from anon/authenticated', (table) => {
    expect(sql).toMatch(
      new RegExp(`REVOKE\\s+ALL\\s+ON\\s+public\\.${table}\\s+FROM\\s+PUBLIC,\\s*anon,\\s*authenticated;`, 'i'),
    );
  });

  it('does not change the OSP-65 audit_logs privileges', () => {
    expect(sql).not.toMatch(/(GRANT|REVOKE)[^;]*ON\s+(TABLE\s+)?public\.audit_logs/i);
  });

  it('every policy in any migration names its role explicitly (authenticated or service_role only)', () => {
    // A CREATE POLICY without a TO clause applies to PUBLIC, which includes anon.
    const policies = allSql.match(/CREATE\s+POLICY[^;]*;/gi) ?? [];
    expect(policies.length).toBeGreaterThanOrEqual(2);
    for (const p of policies) {
      const to = p.match(/\bTO\s+([\w\s,]+?)\s+(USING|WITH)\b/i);
      expect(to, `policy without explicit TO: ${p.slice(0, 80)}`).not.toBeNull();
      for (const role of to![1]!.split(',').map((r) => r.trim().toLowerCase())) {
        expect(['authenticated', 'service_role']).toContain(role);
      }
    }
  });
});

describe('OSP-63: RLS on 100% of public tables', () => {
  it('every public table created by a migration has RLS enabled', () => {
    const created = [...allSql.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?public\.(\w+)/gi)].map((m) => m[1]!);
    expect(created.length).toBeGreaterThanOrEqual(5);
    for (const table of created) {
      expect(allSql, `${table} must enable RLS`).toMatch(
        new RegExp(`ALTER\\s+TABLE\\s+public\\.${table}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, 'i'),
      );
    }
  });

  it('guards the live database: fails the migration if any public table has RLS off', () => {
    expect(sql).toMatch(/relrowsecurity/i);
    expect(sql).toMatch(/nspname\s*=\s*'public'/i);
    expect(sql).toMatch(/RAISE\s+EXCEPTION/i);
  });

  it('guards against leftover client privileges and RLS-bypassing views', () => {
    expect(sql).toMatch(/has_table_privilege\(/i);
    expect(sql).toMatch(/relkind\s+IN\s+\('v',\s*'m'\)/i);
    expect(sql).toMatch(/security_invoker=true/i);
  });

  it('does not FORCE RLS (owner-run SECURITY DEFINER functions rely on the owner bypass)', () => {
    expect(allSql).not.toMatch(/FORCE\s+ROW\s+LEVEL\s+SECURITY/i);
  });

  it('runs after the last migration it depends on (OSP-66)', () => {
    expect(migrationFiles.indexOf(FILE)).toBeGreaterThan(
      migrationFiles.indexOf('20261123130000_osp66_admin_api.sql'),
    );
  });
});
