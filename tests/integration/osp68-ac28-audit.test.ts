import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  anonClient,
  authed,
  createSessionUser,
  newCleanup,
  runCleanup,
  serviceClient,
  userClient,
  type SessionUser,
} from './helpers.js';

// =============================================================================================
// OSP-68 / AC-28: audit log (FR-B-06, NFR-SEC-06) ve 30 günlük silme — GERÇEK uçtan uca ortam.
//
// Gerçek uygulama + gerçek yerel Supabase. Audit satırları service_role ile doğrudan
// audit_logs tablosundan okunur; her çalıştırmada yeni kullanıcılar oluştuğu için
// `actor_user_id` filtresi önceki çalıştırmaların satırlarıyla karışmaz.
// =============================================================================================

// Uygulama, helpers.ts'teki yerel-config kontrolünden SONRA dinamik olarak yüklenir:
// statik import'lar bildirim sırasıyla değerlendirildiğinden, src/app.js (ve .env okuyan
// src/config/env.ts) statik olsaydı import sıralaması değiştiğinde kontrolden önce çalışabilirdi.
// Dosya entegrasyon config'i dışında çalıştırılırsa helpers.ts açık bir hatayla durur ve bu
// satıra hiç gelinmez.
const { createApp } = await import('../../src/app.js');
const app = createApp();
const cleanup = newCleanup();
const admin = serviceClient();

let rescuer: SessionUser;
let coordinator: SessionUser;
let administrator: SessionUser;
let victimId: string;

interface AuditRow {
  id: string;
  actor_user_id: string | null;
  actor_role: string | null;
  device_id: string | null;
  action_type: string;
  target_record_id: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

/** Bir aktörün belirli tipteki audit satırları (en eski önce). */
async function auditRows(actorId: string, actionType: string): Promise<AuditRow[]> {
  const { data, error } = await admin
    .from('audit_logs')
    .select('*')
    .eq('actor_user_id', actorId)
    .eq('action_type', actionType)
    .order('created_at', { ascending: true });
  if (error) throw new Error(`audit read failed: ${error.message}`);
  return data as AuditRow[];
}

/** service_role ile kazazede kaydı ekler; `createdAt` verilirse geçmiş tarihli olur. */
async function insertVictim(payload: Record<string, unknown>, createdAt?: string): Promise<string> {
  const { data, error } = await admin
    .from('victim_records')
    .insert({ payload, ...(createdAt ? { created_at: createdAt } : {}) })
    .select('id')
    .single();
  if (error || !data) throw new Error(`victim insert failed: ${error?.message}`);
  cleanup.victimIds.add(data.id as string);
  return data.id as string;
}

async function insertObservation(payload: Record<string, unknown>, createdAt: string): Promise<string> {
  const { data, error } = await admin
    .from('rescuer_observations')
    .insert({ payload, created_at: createdAt })
    .select('id')
    .single();
  if (error || !data) throw new Error(`observation insert failed: ${error?.message}`);
  cleanup.observationIds.add(data.id as string);
  return data.id as string;
}

const daysAgo = (days: number) => new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

beforeAll(async () => {
  rescuer = await createSessionUser(app, cleanup, 'rescuer', 'ac28-rescuer');
  coordinator = await createSessionUser(app, cleanup, 'coordinator', 'ac28-coord');
  administrator = await createSessionUser(app, cleanup, 'administrator', 'ac28-admin');
  victimId = await insertVictim({ osp68: 'ac28', status: 'initial' });
});

afterAll(async () => {
  await runCleanup(cleanup);
});

// ---------------------------------------------------------------------------------------------
// 4a. Kazazede GET / POST / PATCH çağrıları audit satırı üretir
// ---------------------------------------------------------------------------------------------
describe('AC-28 / FR-B-06: victim data calls write an audit row', () => {
  it('AC-28: GET /victims -> exactly ONE VICTIM_LIST_VIEW row (actor, role, device, result_count)', async () => {
    const before = await auditRows(coordinator.id, 'VICTIM_LIST_VIEW');
    const res = await authed(request(app).get('/api/v1/victims'), coordinator);
    expect(res.status).toBe(200);

    const after = await auditRows(coordinator.id, 'VICTIM_LIST_VIEW');
    expect(after).toHaveLength(before.length + 1);
    const row = after[after.length - 1]!;
    expect(row).toMatchObject({
      actor_user_id: coordinator.id,
      actor_role: 'coordinator',
      device_id: coordinator.deviceId,
      target_record_id: null,
    });
    expect(row.metadata.result_count).toBe(res.body.victims.length);
  });

  it('AC-28: GET /victims/:id -> VICTIM_VIEW row with the record id (coordinator and administrator)', async () => {
    for (const user of [coordinator, administrator]) {
      const res = await authed(request(app).get(`/api/v1/victims/${victimId}`), user);
      expect(res.status, user.role).toBe(200);
      const rows = await auditRows(user.id, 'VICTIM_VIEW');
      expect(rows.filter((r) => r.target_record_id === victimId), user.role).toHaveLength(1);
      expect(rows[0]).toMatchObject({ actor_role: user.role, device_id: user.deviceId });
    }
  });

  it('AC-28 / FR-D-06: PATCH /victims/:id/override -> VICTIM_UPDATE row in the same transaction; reason text NOT copied to audit', async () => {
    const reason = `OSP-68 secret reason ${randomUUID()}`;
    const res = await authed(request(app).patch(`/api/v1/victims/${victimId}/override`), coordinator).send({
      payload: { status: 'overridden' },
      reason,
    });
    expect(res.status).toBe(200);

    const rows = await auditRows(coordinator.id, 'VICTIM_UPDATE');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      actor_role: 'coordinator',
      device_id: coordinator.deviceId,
      target_record_id: victimId,
      metadata: { override: true, has_reason: true },
    });
    expect(JSON.stringify(rows[0])).not.toContain(reason);

    const { data: victim } = await admin.from('victim_records').select('payload').eq('id', victimId).single();
    expect(victim?.payload).toMatchObject({ status: 'overridden' });
  });

  it('AC-28: POST /sync -> OBSERVATION_SYNC row whose target is the stored observation', async () => {
    const res = await authed(request(app).post('/api/v1/sync'), rescuer).send({ payload: { osp68: 'ac28-sync' } });
    expect(res.status).toBe(201);
    const observationId = res.body.observation.id as string;
    cleanup.observationIds.add(observationId);

    const rows = await auditRows(rescuer.id, 'OBSERVATION_SYNC');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      actor_role: 'rescuer',
      device_id: rescuer.deviceId,
      target_record_id: observationId,
    });
    const { data: stored } = await admin.from('rescuer_observations').select('id').eq('id', observationId);
    expect(stored).toHaveLength(1);
  });

  it('AC-28: failed requests (403 role, 404 unknown record) write NO victim audit row', async () => {
    const denied = await authed(request(app).get('/api/v1/victims'), rescuer);
    expect(denied.status).toBe(403);
    expect(await auditRows(rescuer.id, 'VICTIM_LIST_VIEW')).toEqual([]);

    const missingId = randomUUID();
    const missing = await authed(request(app).get(`/api/v1/victims/${missingId}`), coordinator);
    expect(missing.status).toBe(404);
    const { data } = await admin.from('audit_logs').select('id').eq('target_record_id', missingId);
    expect(data).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------
// 4b. audit_logs değiştirilemez: service_role bile UPDATE / DELETE yapamaz
// ---------------------------------------------------------------------------------------------
describe('AC-28 / NFR-SEC-06: audit_logs is append-only, even for service_role', () => {
  let target: AuditRow;

  beforeAll(async () => {
    // Bu dosyanın ürettiği gerçek bir satır (LOGIN, POST /auth/session sırasında yazıldı).
    const rows = await auditRows(coordinator.id, 'LOGIN');
    expect(rows.length).toBeGreaterThan(0);
    target = rows[0]!;
  });

  it('AC-28: service_role UPDATE -> permission denied (42501), row unchanged', async () => {
    const { error } = await admin.from('audit_logs').update({ action_type: 'TAMPERED' }).eq('id', target.id);
    expect(error?.code).toBe('42501');
    const { data } = await admin.from('audit_logs').select('*').eq('id', target.id).single();
    expect(data).toEqual(target);
  });

  it('AC-28: service_role DELETE -> permission denied (42501), row still there', async () => {
    const { error } = await admin.from('audit_logs').delete().eq('id', target.id);
    expect(error?.code).toBe('42501');
    const { data } = await admin.from('audit_logs').select('id').eq('id', target.id);
    expect(data).toEqual([{ id: target.id }]);
  });

  it('AC-28: service_role UPSERT over an existing row (INSERT ... ON CONFLICT DO UPDATE) -> denied', async () => {
    const { error } = await admin
      .from('audit_logs')
      .upsert({ ...target, action_type: 'TAMPERED' }, { onConflict: 'id' });
    expect(error?.code).toBe('42501');
    const { data } = await admin.from('audit_logs').select('*').eq('id', target.id).single();
    expect(data).toEqual(target);
  });

  it('AC-28: anon and authenticated clients cannot INSERT audit rows', async () => {
    const forged = { action_type: 'LOGIN', actor_user_id: coordinator.id };
    const anon = await anonClient().from('audit_logs').insert(forged);
    expect(anon.error?.code).toBe('42501');
    const user = await userClient(coordinator.accessToken).from('audit_logs').insert(forged);
    expect(user.error?.code).toBe('42501');
  });

  /**
   * TRUNCATE PostgREST/supabase-js ile ifade edilemez. Yerel Docker DB konteynerinde psql ile,
   * geri alınan (ROLLBACK) bir transaction içinde denenir. Konteyner adı config.toml'daki
   * project_id'den gelir; yalnızca yerel Docker'a gider.
   */
  it('AC-28: TRUNCATE is refused for service_role (privilege) and for the table owner (trigger)', () => {
    const psql = (sql: string): string => {
      try {
        execFileSync(
          'docker',
          ['exec', 'supabase_db_connect-backend', 'psql', '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', sql],
          { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
        );
        return 'OK';
      } catch (err) {
        return String((err as { stderr?: string }).stderr ?? err);
      }
    };
    expect(psql('BEGIN; SET LOCAL ROLE service_role; TRUNCATE public.audit_logs; ROLLBACK;')).toMatch(
      /permission denied for table audit_logs/,
    );
    expect(psql('BEGIN; TRUNCATE public.audit_logs; ROLLBACK;')).toMatch(/append-only: TRUNCATE is not allowed/);
  });
});

// ---------------------------------------------------------------------------------------------
// 4c. 30 günlük silme (OSP-67 purge_expired_records)
// ---------------------------------------------------------------------------------------------
describe('AC-28 / FR-B-06: 30-day retention purge (purge_expired_records)', () => {
  it('AC-28: deletes victim/observation rows older than 30 days, keeps newer ones, writes a RETENTION_PURGE audit row', async () => {
    const tag = { osp68: 'ac28-purge', run: randomUUID() };
    const oldVictim = await insertVictim(tag, daysAgo(31));
    const freshVictim = await insertVictim(tag, daysAgo(29));
    const nowVictim = await insertVictim(tag);
    const oldObservation = await insertObservation(tag, daysAgo(31));
    const freshObservation = await insertObservation(tag, daysAgo(29));

    const { data: summary, error } = await admin.rpc('purge_expired_records');
    expect(error).toBeNull();
    expect(summary).toMatchObject({ retention_days: 30, audit_log_id: expect.any(String) });
    expect(summary.victim_records_deleted).toBeGreaterThanOrEqual(1);
    expect(summary.rescuer_observations_deleted).toBeGreaterThanOrEqual(1);

    const victims = await admin.from('victim_records').select('id').in('id', [oldVictim, freshVictim, nowVictim]);
    expect(victims.data?.map((r) => r.id).sort()).toEqual([freshVictim, nowVictim].sort());
    const observations = await admin
      .from('rescuer_observations')
      .select('id')
      .in('id', [oldObservation, freshObservation]);
    expect(observations.data?.map((r) => r.id)).toEqual([freshObservation]);

    // Fonksiyonun yazdığı özet satırı: aktörsüz sistem olayı, sayımlar metadata'da.
    const { data: purgeRow } = await admin.from('audit_logs').select('*').eq('id', summary.audit_log_id).single();
    expect(purgeRow).toMatchObject({
      action_type: 'RETENTION_PURGE',
      actor_user_id: null,
      actor_role: null,
      target_record_id: null,
      metadata: {
        retention_days: 30,
        victim_records_deleted: summary.victim_records_deleted,
        rescuer_observations_deleted: summary.rescuer_observations_deleted,
        total_deleted: summary.total_deleted,
      },
    });
  });

  it('AC-28: anon and authenticated clients cannot call purge_expired_records', async () => {
    const anon = await anonClient().rpc('purge_expired_records');
    expect(anon.error?.code).toBe('42501');
    const user = await userClient(administrator.accessToken).rpc('purge_expired_records');
    expect(user.error?.code).toBe('42501');
  });
});
