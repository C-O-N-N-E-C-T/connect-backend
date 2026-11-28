import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  anonClient,
  createSessionUser,
  newCleanup,
  runCleanup,
  serviceClient,
  userClient,
  type SessionUser,
} from './helpers.js';

// =============================================================================================
// OSP-68 / AC-28 + OSP-63: deny-by-default RLS — istemcinin backend'i ATLAYIP doğrudan
// PostgREST'e gittiği senaryo. Anon key her web/mobil build'inde bulunur; bir saldırgan
// kendi JWT'si ile `supabase.from(...)` çağırabilir. Bu testler veritabanının kendisinin
// reddettiğini gerçek yerel PostgREST üzerinden gösterir
// (statik kontroller: tests/osp63-rls.test.ts, SQL doğrulaması: scripts/osp63-verify-rls.sql).
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

const DENIED_FOR_ANON = [
  'victim_records',
  'rescuer_observations',
  'audit_logs',
  'user_profiles',
  'user_devices',
] as const;

let userA: SessionUser; // coordinator
let userB: SessionUser; // rescuer

beforeAll(async () => {
  userA = await createSessionUser(app, cleanup, 'coordinator', 'rls-a');
  userB = await createSessionUser(app, cleanup, 'rescuer', 'rls-b');

  // Tablolar boş olduğu için "0 satır" görülmesin: her korunan tabloda en az bir satır olsun.
  const victim = await admin.from('victim_records').insert({ payload: { osp68: 'rls' } }).select('id').single();
  if (victim.error || !victim.data) throw new Error(`victim insert failed: ${victim.error?.message}`);
  cleanup.victimIds.add(victim.data.id as string);
  const observation = await admin
    .from('rescuer_observations')
    .insert({ payload: { osp68: 'rls' } })
    .select('id')
    .single();
  if (observation.error || !observation.data) throw new Error(`observation insert failed: ${observation.error?.message}`);
  cleanup.observationIds.add(observation.data.id as string);
});

afterAll(async () => {
  await runCleanup(cleanup);
});

describe('AC-28 / OSP-63: anon client (anon key only) can read nothing', () => {
  it.each(DENIED_FOR_ANON)('AC-28: anon SELECT %s -> permission denied (42501)', async (table) => {
    const { data, error } = await anonClient().from(table).select('*').limit(1);
    expect(error?.code).toBe('42501');
    expect(data).toBeNull();
  });
});

describe('AC-28 / OSP-63: authenticated client (real user JWT) bypassing the backend', () => {
  it.each(['victim_records', 'rescuer_observations'] as const)(
    'AC-28: authenticated SELECT %s -> permission denied (42501)',
    async (table) => {
      const { data, error } = await userClient(userA.accessToken).from(table).select('*').limit(1);
      expect(error?.code).toBe('42501');
      expect(data).toBeNull();
    },
  );

  it('AC-28: authenticated SELECT audit_logs -> 0 rows, although the user\'s own LOGIN row exists', async () => {
    const own = await admin.from('audit_logs').select('id').eq('actor_user_id', userA.id);
    expect(own.data?.length).toBeGreaterThan(0);

    const { data, error } = await userClient(userA.accessToken).from('audit_logs').select('*');
    expect(error).toBeNull();
    expect(data).toEqual([]);
  });

  it('AC-28: a user reads ONLY their own profile (no filter -> exactly one row; other user -> 0 rows)', async () => {
    const client = userClient(userA.accessToken);
    const all = await client.from('user_profiles').select('id, role');
    expect(all.error).toBeNull();
    expect(all.data).toEqual([{ id: userA.id, role: 'coordinator' }]);

    const other = await client.from('user_profiles').select('id').eq('id', userB.id);
    expect(other.error).toBeNull();
    expect(other.data).toEqual([]);
  });

  it('AC-28: a user reads ONLY their own devices', async () => {
    const client = userClient(userA.accessToken);
    const all = await client.from('user_devices').select('user_id, device_id');
    expect(all.error).toBeNull();
    expect(all.data).toEqual([{ user_id: userA.id, device_id: userA.deviceId }]);

    const other = await client.from('user_devices').select('device_id').eq('user_id', userB.id);
    expect(other.error).toBeNull();
    expect(other.data).toEqual([]);
  });

  it('AC-28: no client write: role escalation, device un-revoke, victim insert -> permission denied; role unchanged', async () => {
    const client = userClient(userA.accessToken);
    const escalate = await client.from('user_profiles').update({ role: 'administrator' }).eq('id', userA.id);
    expect(escalate.error?.code).toBe('42501');
    const device = await client.from('user_devices').update({ is_device_revoked: false }).eq('user_id', userA.id);
    expect(device.error?.code).toBe('42501');
    const victim = await client.from('victim_records').insert({ payload: { forged: true } });
    expect(victim.error?.code).toBe('42501');

    const { data } = await admin.from('user_profiles').select('role').eq('id', userA.id).single();
    expect(data?.role).toBe('coordinator');
  });

  it('AC-28: after is_active=false the user cannot read even their own profile/device rows; other users unaffected', async () => {
    await admin.from('user_profiles').update({ is_active: false }).eq('id', userA.id).throwOnError();

    const client = userClient(userA.accessToken);
    const profile = await client.from('user_profiles').select('id');
    expect(profile.error).toBeNull();
    expect(profile.data).toEqual([]);
    const devices = await client.from('user_devices').select('device_id');
    expect(devices.error).toBeNull();
    expect(devices.data).toEqual([]);

    const otherProfile = await userClient(userB.accessToken).from('user_profiles').select('id');
    expect(otherProfile.data).toEqual([{ id: userB.id }]);
    const otherDevices = await userClient(userB.accessToken).from('user_devices').select('device_id');
    expect(otherDevices.data).toEqual([{ device_id: userB.deviceId }]);
  });
});
