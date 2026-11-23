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
    // "En son dosya" değil: sonradan eklenen migration'lar (OSP-63, OSP-66, ...) testi kırmaz.
    const files = fs.readdirSync(MIGRATIONS).filter((f) => f.endsWith('.sql')).sort();
    const at = files.indexOf(FILE);
    expect(at).toBeGreaterThanOrEqual(0);
    for (const prefix of ['_osp58_', '_osp60_', '_osp67_']) {
      const deps = files.filter((f) => f.includes(prefix));
      expect(deps.length, `${prefix} migration not found`).toBeGreaterThan(0);
      for (const dep of deps) expect(files.indexOf(dep)).toBeLessThan(at);
    }
  });

  it('drops the actor_user_id foreign key (ON DELETE SET NULL would UPDATE audit rows)', () => {
    expect(code).toMatch(/c\.contype\s*=\s*'f'/i);
    expect(code).toMatch(/a\.attname\s*=\s*'actor_user_id'/i);
    expect(code).toMatch(/ALTER\s+TABLE\s+public\.audit_logs\s+DROP\s+CONSTRAINT/i);
  });

  it('revokes ALL privileges first (no leftover TRIGGER / REFERENCES), from every role', () => {
    expect(code).toMatch(
      /REVOKE\s+ALL\s+ON\s+public\.audit_logs\s+FROM\s+PUBLIC,\s*anon,\s*authenticated,\s*service_role\s*;/i,
    );
  });

  it('then grants only SELECT to authenticated (RLS) and SELECT, INSERT to service_role', () => {
    const grants = [...code.matchAll(/GRANT\s+([^;]*?)\s+ON\s+public\.audit_logs\s+TO\s+([^;]*?)\s*;/gi)].map(
      (m) => [m[1]!.replace(/\s+/g, ' ').toUpperCase(), m[2]!.trim()],
    );
    expect(grants).toEqual([
      ['SELECT', 'authenticated'],
      ['SELECT, INSERT', 'service_role'],
    ]);
    const revokeAt = code.search(/REVOKE\s+ALL\s+ON\s+public\.audit_logs/i);
    const firstGrantAt = code.search(/GRANT\s+[^;]*ON\s+public\.audit_logs/i);
    expect(revokeAt).toBeGreaterThanOrEqual(0);
    expect(revokeAt).toBeLessThan(firstGrantAt);
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

describe('OSP-65 migration: victim writes and their audit rows are atomic', () => {
  const ATOMIC = '20261123120000_osp65_atomic_victim_writes.sql';
  const atomic = fs.readFileSync(path.join(MIGRATIONS, ATOMIC), 'utf8').replace(/--.*$/gm, '');
  const body = (name: string) => {
    const m = atomic.match(
      new RegExp(`CREATE\\s+OR\\s+REPLACE\\s+FUNCTION\\s+public\\.${name}\\(([\\s\\S]*?)\\$\\$([\\s\\S]*?)\\$\\$`, 'i'),
    );
    expect(m, `${name} not found`).not.toBeNull();
    return { header: m![1]!, code: m![2]! };
  };

  it('runs after the append-only migration', () => {
    const files = fs.readdirSync(MIGRATIONS).filter((f) => f.endsWith('.sql')).sort();
    expect(files.indexOf(ATOMIC)).toBeGreaterThan(files.indexOf(FILE));
  });

  it('sync_observation_audited inserts the observation AND its OBSERVATION_SYNC row in one function', () => {
    const fn = body('sync_observation_audited');
    expect(fn.header).toMatch(/SET\s+search_path\s*=\s*''/i);
    expect(fn.code).toMatch(/INSERT\s+INTO\s+public\.rescuer_observations/i);
    expect(fn.code).toMatch(/INSERT\s+INTO\s+public\.audit_logs[\s\S]*'OBSERVATION_SYNC'/i);
    // Hata yutulmaz: EXCEPTION bloğu olsaydı audit hatası yazımı geri almadan kaybolabilirdi.
    expect(fn.code).not.toMatch(/\bEXCEPTION\b/i);
  });

  it('override_victim_audited locks the row, updates it AND writes VICTIM_UPDATE in one function', () => {
    const fn = body('override_victim_audited');
    expect(fn.header).toMatch(/SET\s+search_path\s*=\s*''/i);
    expect(fn.code).toMatch(/FROM\s+public\.victim_records[\s\S]*FOR\s+UPDATE/i);
    expect(fn.code).toMatch(/UPDATE\s+public\.victim_records/i);
    expect(fn.code).toMatch(/INSERT\s+INTO\s+public\.audit_logs[\s\S]*'VICTIM_UPDATE'/i);
    expect(fn.code).not.toMatch(/\bEXCEPTION\b/i);
  });

  it('never copies the free-text override reason into audit_logs (only has_reason)', () => {
    const fn = body('override_victim_audited');
    const auditInsert = fn.code.slice(fn.code.search(/INSERT\s+INTO\s+public\.audit_logs/i));
    expect(auditInsert).toMatch(/'has_reason',\s*p_reason\s+IS\s+NOT\s+NULL/i);
    expect(auditInsert).not.toMatch(/'reason',\s*p_reason/i);
  });

  it.each(['sync_observation_audited', 'override_victim_audited'])(
    '%s is executable by service_role only',
    (name) => {
      expect(atomic).toMatch(new RegExp(`REVOKE\\s+ALL\\s+ON\\s+FUNCTION\\s+public\\.${name}\\([^)]*\\)\\s+FROM\\s+PUBLIC\\s*;`, 'i'));
      expect(atomic).toMatch(
        new RegExp(`REVOKE\\s+EXECUTE\\s+ON\\s+FUNCTION\\s+public\\.${name}\\([^)]*\\)\\s+FROM\\s+anon,\\s*authenticated\\s*;`, 'i'),
      );
      expect(atomic).toMatch(new RegExp(`GRANT\\s+EXECUTE\\s+ON\\s+FUNCTION\\s+public\\.${name}\\([^)]*\\)\\s+TO\\s+service_role\\s*;`, 'i'));
    },
  );

  it('never modifies or deletes audit rows', () => {
    expect(atomic).not.toMatch(/UPDATE\s+public\.audit_logs/i);
    expect(atomic).not.toMatch(/DELETE\s+FROM\s+public\.audit_logs/i);
  });
});
