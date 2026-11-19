import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT_DIR = path.resolve(import.meta.dirname, '..');
const MIGRATION_PATH = path.join(
  ROOT_DIR,
  'supabase',
  'migrations',
  '20261119200000_osp67_retention_purge_pg_cron.sql',
);

describe('OSP-67: 30-Day Retention Purge & pg_cron Migration', () => {
  const migrationSql = fs.readFileSync(MIGRATION_PATH, 'utf8');

  it('adds backwards-compatible metadata column to public.audit_logs', () => {
    expect(migrationSql).toMatch(
      /ALTER\s+TABLE\s+public\.audit_logs\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+metadata\s+JSONB\s+NOT\s+NULL\s+DEFAULT\s+'\{\}'::jsonb/i,
    );
  });

  it('defines public.purge_expired_records() with SECURITY DEFINER and fixed search_path', () => {
    expect(migrationSql).toMatch(/CREATE\s+OR\s+REPLACE\s+FUNCTION\s+public\.purge_expired_records\(\)/i);
    expect(migrationSql).toMatch(/SECURITY\s+DEFINER/i);
    expect(migrationSql).toMatch(/SET\s+search_path\s*=\s*public/i);
    expect(migrationSql).toMatch(/interval\s+'30 days'/i);
  });

  it('deletes rescuer_observations BEFORE victim_records for future E8 FK compatibility', () => {
    const obsDeleteIdx = migrationSql.search(/DELETE\s+FROM\s+public\.rescuer_observations/i);
    const victimDeleteIdx = migrationSql.search(/DELETE\s+FROM\s+public\.victim_records/i);

    expect(obsDeleteIdx).toBeGreaterThan(-1);
    expect(victimDeleteIdx).toBeGreaterThan(-1);
    expect(obsDeleteIdx).toBeLessThan(victimDeleteIdx);

    expect(migrationSql).toMatch(/WHERE\s+created_at\s*<\s*v_cutoff/i);
    expect(migrationSql).toMatch(/GET\s+DIAGNOSTICS\s+v_observations_deleted\s*=\s*ROW_COUNT/i);
    expect(migrationSql).toMatch(/GET\s+DIAGNOSTICS\s+v_victims_deleted\s*=\s*ROW_COUNT/i);
  });

  it('writes a RETENTION_PURGE summary entry into public.audit_logs', () => {
    expect(migrationSql).toMatch(/INSERT\s+INTO\s+public\.audit_logs/i);
    expect(migrationSql).toMatch(/'RETENTION_PURGE'/);
    expect(migrationSql).toMatch(/'rescuer_observations_deleted'/);
    expect(migrationSql).toMatch(/'victim_records_deleted'/);
    expect(migrationSql).toMatch(/'total_deleted'/);
  });

  it('revokes purge execution from PUBLIC, anon, authenticated and grants to service_role', () => {
    expect(migrationSql).toMatch(
      /REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.purge_expired_records\(\)\s+FROM\s+PUBLIC/i,
    );
    expect(migrationSql).toMatch(
      /REVOKE\s+EXECUTE\s+ON\s+FUNCTION\s+public\.purge_expired_records\(\)\s+FROM\s+anon\s*,\s*authenticated/i,
    );
    expect(migrationSql).toMatch(
      /GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.purge_expired_records\(\)\s+TO\s+service_role/i,
    );
  });

  it('enables pg_cron and schedules purge-expired-records-daily idempotently', () => {
    expect(migrationSql).toMatch(/CREATE\s+EXTENSION\s+IF\s+NOT\s+EXISTS\s+pg_cron/i);
    expect(migrationSql).toMatch(/cron\.unschedule\('purge-expired-records-daily'\)/i);
    expect(migrationSql).toMatch(
      /cron\.schedule\(\s*'purge-expired-records-daily'\s*,\s*'0 3 \* \* \*'\s*,\s*'SELECT public\.purge_expired_records\(\);'\s*\)/i,
    );
  });

  it('stays strictly within OSP-67 scope (no OSP-63 policies or OSP-65 triggers)', () => {
    expect(migrationSql).not.toMatch(/CREATE\s+POLICY/i);
    expect(migrationSql).not.toMatch(/CREATE\s+TRIGGER/i);
  });
});
