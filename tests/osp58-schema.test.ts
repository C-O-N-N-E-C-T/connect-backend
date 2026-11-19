import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { APP_ROLES } from '../src/types/database.js';

const ROOT_DIR = path.resolve(import.meta.dirname, '..');
const MIGRATION_PATH = path.join(
  ROOT_DIR,
  'supabase',
  'migrations',
  '20261119180000_osp58_auth_schema_and_token_hook.sql',
);
const CONFIG_TOML_PATH = path.join(ROOT_DIR, 'supabase', 'config.toml');

describe('OSP-58: Auth Schema Migration & Custom Access Token Hook', () => {
  const migrationSql = fs.readFileSync(MIGRATION_PATH, 'utf8');
  const configToml = fs.readFileSync(CONFIG_TOML_PATH, 'utf8');

  it('APP_ROLES matches the locked app_role enum strictly', () => {
    expect(APP_ROLES).toEqual(['rescuer', 'coordinator', 'administrator']);
  });

  it('defines public.app_role enum with only rescuer, coordinator, and administrator', () => {
    expect(migrationSql).toMatch(/CREATE\s+TYPE\s+public\.app_role\s+AS\s+ENUM/i);
    expect(migrationSql).toMatch(/'rescuer'/);
    expect(migrationSql).toMatch(/'coordinator'/);
    expect(migrationSql).toMatch(/'administrator'/);
  });

  it('creates all five required tables and UNIQUE(user_id, device_id)', () => {
    expect(migrationSql).toMatch(/CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+public\.user_profiles/i);
    expect(migrationSql).toMatch(/CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+public\.user_devices/i);
    expect(migrationSql).toMatch(/CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+public\.audit_logs/i);
    expect(migrationSql).toMatch(/CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+public\.victim_records/i);
    expect(migrationSql).toMatch(
      /CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+public\.rescuer_observations/i,
    );
    expect(migrationSql).toMatch(/UNIQUE\s*\(\s*user_id\s*,\s*device_id\s*\)/i);
  });

  it('keeps actor_user_id, actor_role, device_id, and target_record_id nullable in audit_logs', () => {
    const auditMatch = migrationSql.match(
      /CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+public\.audit_logs\s*\(([\s\S]*?)\);/i,
    );
    expect(auditMatch).not.toBeNull();
    const auditBody = auditMatch?.[1] ?? '';

    expect(auditBody).toMatch(/actor_user_id\s+UUID\s+REFERENCES/i);
    expect(auditBody).not.toMatch(/actor_user_id[^\n,]*NOT\s+NULL/i);
    expect(auditBody).toMatch(/actor_role\s+public\.app_role(?!\s+NOT\s+NULL)/i);
    expect(auditBody).toMatch(/device_id\s+UUID(?!\s+NOT\s+NULL)/i);
    expect(auditBody).toMatch(/target_record_id\s+UUID(?!\s+NOT\s+NULL)/i);
  });

  it('defines created_at TIMESTAMPTZ NOT NULL DEFAULT now() on stub tables', () => {
    for (const tableName of ['victim_records', 'rescuer_observations']) {
      const tableMatch = migrationSql.match(
        new RegExp(
          `CREATE\\s+TABLE\\s+IF\\s+NOT\\s+EXISTS\\s+public\\.${tableName}\\s*\\(([\\s\\S]*?)\\);`,
          'i',
        ),
      );
      expect(tableMatch).not.toBeNull();
      expect(tableMatch?.[1]).toMatch(/created_at\s+TIMESTAMPTZ\s+NOT\s+NULL\s+DEFAULT\s+now\(\)/i);
    }
  });

  it('enables RLS on all 5 tables while staying strictly within OSP-58 scope', () => {
    for (const tableName of [
      'user_profiles',
      'user_devices',
      'audit_logs',
      'victim_records',
      'rescuer_observations',
    ]) {
      expect(migrationSql).toMatch(
        new RegExp(`ALTER\\s+TABLE\\s+public\\.${tableName}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, 'i'),
      );
    }

    // Out-of-scope guards: OSP-63 policies, OSP-65 triggers, OSP-67 pg_cron
    expect(migrationSql).not.toMatch(/CREATE\s+POLICY/i);
    expect(migrationSql).not.toMatch(/CREATE\s+TRIGGER/i);
    expect(migrationSql).not.toMatch(/pg_cron/i);
  });

  it('hardens custom_access_token_hook and reads role only from active user_profiles', () => {
    expect(migrationSql).toMatch(/CREATE\s+OR\s+REPLACE\s+FUNCTION\s+public\.custom_access_token_hook/i);
    expect(migrationSql).toMatch(/SECURITY\s+DEFINER/i);
    expect(migrationSql).toMatch(/SET\s+search_path\s*=\s*public/i);
    expect(migrationSql).toMatch(/FROM\s+public\.user_profiles/i);
    expect(migrationSql).toMatch(/is_active\s*=\s*true/i);
    expect(migrationSql).not.toMatch(/user_metadata|raw_user_meta_data/i);
    expect(migrationSql).toMatch(
      /REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.custom_access_token_hook\(jsonb\)\s+FROM\s+PUBLIC/i,
    );
    expect(migrationSql).toMatch(
      /REVOKE\s+EXECUTE\s+ON\s+FUNCTION\s+public\.custom_access_token_hook\(jsonb\)\s+FROM\s+anon\s*,\s*authenticated/i,
    );
    expect(migrationSql).toMatch(
      /GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.custom_access_token_hook\(jsonb\)\s+TO\s+supabase_auth_admin/i,
    );
  });

  it('enables custom_access_token hook in supabase/config.toml', () => {
    expect(configToml).toMatch(
      /\[auth\.hook\.custom_access_token\]\s*\r?\nenabled\s*=\s*true\s*\r?\nuri\s*=\s*"pg-functions:\/\/postgres\/public\/custom_access_token_hook"/,
    );
  });
});
