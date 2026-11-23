import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// OSP-65 SQL'inin statik kontrolleri (osp58 / osp60 migration testleriyle aynı yaklaşım).
// Güvenlik açısından kritik kısımları sabitler; gerçekten çalıştırmak için yerelde
// `supabase db reset` kullanın.

const MIGRATIONS = path.resolve(import.meta.dirname, '..', 'supabase', 'migrations');
const FILE = '20261122120000_osp65_audit_log_immutability.sql';
const sql = fs.readFileSync(path.join(MIGRATIONS, FILE), 'utf8');
// Yorumlar çıkarılır; kontroller sadece çalıştırılabilir SQL'e bakar.
const code = sql.replace(/--.*$/gm, '');

describe('OSP-65 migration: append-only audit_logs', () => {
  it('runs after the OSP-58, OSP-60 and OSP-67 migrations', () => {
    const files = fs.readdirSync(MIGRATIONS).filter((f) => f.endsWith('.sql')).sort();
    expect(files.at(-1)).toBe(FILE);
  });

  it('drops the actor_user_id foreign key (ON DELETE SET NULL would UPDATE audit rows)', () => {
    expect(code).toMatch(/c\.contype\s*=\s*'f'/i);
    expect(code).toMatch(/a\.attname\s*=\s*'actor_user_id'/i);
    expect(code).toMatch(/ALTER\s+TABLE\s+public\.audit_logs\s+DROP\s+CONSTRAINT/i);
  });

  it('revokes INSERT/UPDATE/DELETE/TRUNCATE from PUBLIC, anon and authenticated', () => {
    expect(code).toMatch(
      /REVOKE\s+INSERT,\s*UPDATE,\s*DELETE,\s*TRUNCATE\s+ON\s+public\.audit_logs\s+FROM\s+PUBLIC,\s*anon,\s*authenticated\s*;/i,
    );
  });

  it('leaves service_role with SELECT and INSERT only', () => {
    expect(code).toMatch(
      /REVOKE\s+UPDATE,\s*DELETE,\s*TRUNCATE\s+ON\s+public\.audit_logs\s+FROM\s+service_role\s*;/i,
    );
    expect(code).toMatch(/GRANT\s+SELECT,\s*INSERT\s+ON\s+public\.audit_logs\s+TO\s+service_role\s*;/i);
    expect(code).not.toMatch(/GRANT\s+[^;]*\b(UPDATE|DELETE|TRUNCATE|ALL)\b[^;]*ON\s+public\.audit_logs/i);
  });

  it('defines the reject function with a fixed search_path and RAISE EXCEPTION', () => {
    const fn = code.match(
      /CREATE\s+OR\s+REPLACE\s+FUNCTION\s+public\.audit_logs_reject_mutation\(\)([\s\S]*?)\$\$([\s\S]*?)\$\$/i,
    );
    expect(fn, 'audit_logs_reject_mutation not found').not.toBeNull();
    expect(fn?.[1]).toMatch(/RETURNS\s+trigger/i);
    expect(fn?.[1]).toMatch(/SET\s+search_path\s*=\s*''/i);
    expect(fn?.[2]).toMatch(/RAISE\s+EXCEPTION/i);
  });

  it('blocks UPDATE and DELETE with a BEFORE ... FOR EACH ROW trigger', () => {
    expect(code).toMatch(
      /CREATE\s+TRIGGER\s+audit_logs_no_update_delete\s+BEFORE\s+UPDATE\s+OR\s+DELETE\s+ON\s+public\.audit_logs\s+FOR\s+EACH\s+ROW\s+EXECUTE\s+FUNCTION\s+public\.audit_logs_reject_mutation\(\)/i,
    );
  });

  it('blocks TRUNCATE with a BEFORE ... FOR EACH STATEMENT trigger', () => {
    expect(code).toMatch(
      /CREATE\s+TRIGGER\s+audit_logs_no_truncate\s+BEFORE\s+TRUNCATE\s+ON\s+public\.audit_logs\s+FOR\s+EACH\s+STATEMENT\s+EXECUTE\s+FUNCTION\s+public\.audit_logs_reject_mutation\(\)/i,
    );
  });

  it('never modifies or deletes audit rows itself', () => {
    expect(code).not.toMatch(/UPDATE\s+public\.audit_logs\s+SET/i);
    expect(code).not.toMatch(/DELETE\s+FROM\s+public\.audit_logs/i);
    expect(code).not.toMatch(/TRUNCATE\s+(TABLE\s+)?public\.audit_logs/i);
  });

  it('existing SQL functions only INSERT into audit_logs (compatible with the triggers)', () => {
    const others = fs
      .readdirSync(MIGRATIONS)
      .filter((f) => f.endsWith('.sql') && f !== FILE)
      .map((f) => fs.readFileSync(path.join(MIGRATIONS, f), 'utf8').replace(/--.*$/gm, ''))
      .join('\n');
    expect(others).not.toMatch(/UPDATE\s+public\.audit_logs/i);
    expect(others).not.toMatch(/DELETE\s+FROM\s+public\.audit_logs/i);
    expect(others).not.toMatch(/TRUNCATE\s+(TABLE\s+)?public\.audit_logs/i);
  });
});