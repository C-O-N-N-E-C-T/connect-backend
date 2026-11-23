import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { supabaseAdmin } from '../src/config/supabase.js';
import type { VictimStore } from '../src/services/victim-store.js';
import {
  ACTOR,
  AUTH_HEADER,
  MISSING_ID,
  OBSERVATION_ID,
  RECORD_ID,
  RESCUER_ACTOR,
  RESCUER_AUTH_HEADER,
  fakeAuditStore,
  fakeGuardDeps,
  fakeVictimStore,
  victim,
  type FakeAuditStore,
} from './helpers/osp65-fakes.js';

// AC-28, GERÇEK OSP-62 uçları (src/routes/business.ts) üzerinde, gerçek uygulama ile:
// OSP-61 guard -> requireRole -> doğrulama -> store -> OSP-65 audit -> cevap.
// Sadece store'lar bellekte.

const realDbSpy = vi.spyOn(supabaseAdmin, 'from').mockImplementation(() => {
  throw new Error('Real Supabase access is forbidden in tests');
});

afterAll(() => {
  expect(realDbSpy).not.toHaveBeenCalled();
  realDbSpy.mockRestore();
});

let audit: FakeAuditStore;
let store: VictimStore;

beforeEach(() => {
  audit = fakeAuditStore();
  store = fakeVictimStore([
    victim(),
    victim({ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }),
    victim({ id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }),
  ]);
});

const app = () =>
  createApp({ authGuardDeps: fakeGuardDeps(), victimStore: store, auditLogStore: audit });

describe('OSP-65: one audit row per successful victim-data request (AC-28)', () => {
  it('GET /victims -> 200 and ONE VICTIM_LIST_VIEW summary row (not one per record)', async () => {
    const res = await request(app()).get('/api/v1/victims').set(AUTH_HEADER);
    expect(res.status).toBe(200);
    expect(res.body.victims).toHaveLength(3);
    expect(audit.rows).toEqual([
      {
        actor: ACTOR,
        action_type: 'VICTIM_LIST_VIEW',
        target_record_id: null,
        metadata: { filters: {}, result_count: 3 },
      },
    ]);
  });

  it('GET /victims/:id -> 200 and one VICTIM_VIEW row with target_record_id', async () => {
    const res = await request(app()).get(`/api/v1/victims/${RECORD_ID}`).set(AUTH_HEADER);
    expect(res.status).toBe(200);
    expect(res.body.victim.id).toBe(RECORD_ID);
    expect(audit.rows).toEqual([{ actor: ACTOR, action_type: 'VICTIM_VIEW', target_record_id: RECORD_ID }]);
  });

  it('PATCH /victims/:id/override -> 200 and one VICTIM_UPDATE row (override + reason)', async () => {
    const res = await request(app())
      .patch(`/api/v1/victims/${RECORD_ID}/override`)
      .set(AUTH_HEADER)
      .send({ payload: { triage: 'red' }, reason: 'visual check' });
    expect(res.status).toBe(200);
    expect(audit.rows).toEqual([
      {
        actor: ACTOR,
        action_type: 'VICTIM_UPDATE',
        target_record_id: RECORD_ID,
        metadata: { override: true, reason: 'visual check' },
      },
    ]);
  });

  it('PATCH /victims/:id/override without a reason -> metadata has no reason key', async () => {
    await request(app())
      .patch(`/api/v1/victims/${RECORD_ID}/override`)
      .set(AUTH_HEADER)
      .send({ payload: { triage: 'yellow' } })
      .expect(200);
    expect(audit.rows[0]?.metadata).toEqual({ override: true });
  });

  it('POST /sync (rescuer) -> 201 and one OBSERVATION_SYNC row with the observation id', async () => {
    const res = await request(app())
      .post('/api/v1/sync')
      .set(RESCUER_AUTH_HEADER)
      .send({ payload: { note: 'voice heard' } });
    expect(res.status).toBe(201);
    expect(audit.rows).toEqual([
      { actor: RESCUER_ACTOR, action_type: 'OBSERVATION_SYNC', target_record_id: OBSERVATION_ID },
    ]);
  });
});

describe('OSP-65: failed requests write no audit row', () => {
  it.each([
    ['rescuer on GET /victims (403)', () => request(app()).get('/api/v1/victims').set(RESCUER_AUTH_HEADER), 403],
    ['coordinator on POST /sync (403)', () => request(app()).post('/api/v1/sync').set(AUTH_HEADER).send({ payload: {} }), 403],
    ['unknown id (404)', () => request(app()).get(`/api/v1/victims/${MISSING_ID}`).set(AUTH_HEADER), 404],
    ['override of unknown id (404)', () =>
      request(app()).patch(`/api/v1/victims/${MISSING_ID}/override`).set(AUTH_HEADER).send({ payload: { a: 1 } }), 404],
    ['invalid uuid (400)', () => request(app()).get('/api/v1/victims/not-a-uuid').set(AUTH_HEADER), 400],
    ['invalid override body (400)', () =>
      request(app()).patch(`/api/v1/victims/${RECORD_ID}/override`).set(AUTH_HEADER).send({ payload: {} }), 400],
    ['no token (401)', () => request(app()).get('/api/v1/victims'), 401],
  ] as const)('%s', async (_name, call, status) => {
    const res = await call();
    expect(res.status).toBe(status);
    expect(audit.write).not.toHaveBeenCalled();
  });
});

describe('OSP-65: safety', () => {
  it.each([
    ['GET /victims', () => request(app()).get('/api/v1/victims').set(AUTH_HEADER)],
    ['GET /victims/:id', () => request(app()).get(`/api/v1/victims/${RECORD_ID}`).set(AUTH_HEADER)],
    ['POST /sync', () => request(app()).post('/api/v1/sync').set(RESCUER_AUTH_HEADER).send({ payload: { n: 1 } })],
  ] as const)('fail closed: audit write fails on %s -> 500 and no victim data', async (_name, call) => {
    audit.fail = true;
    const res = await call();
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error_code: 'INTERNAL_ERROR', message: expect.any(String) });
    expect(res.text).not.toContain('trapped');
    expect(res.text).not.toContain(OBSERVATION_ID);
  });

  it('the actor comes from the verified token, not from spoofed headers or body', async () => {
    await request(app())
      .patch(`/api/v1/victims/${RECORD_ID}/override`)
      .set(AUTH_HEADER)
      .set('X-User-Id', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee')
      .send({ payload: { actor_user_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', role: 'administrator' } })
      .expect(200);
    expect(audit.rows[0]?.actor).toEqual(ACTOR);
  });

  it('POST /assignments (stub, persists nothing) is not audited and still answers 201', async () => {
    const res = await request(app())
      .post('/api/v1/assignments')
      .set(AUTH_HEADER)
      .send({ victim_id: RECORD_ID, rescuer_id: RESCUER_ACTOR.user_id });
    expect(res.status).toBe(201);
    expect(audit.write).not.toHaveBeenCalled();
  });
});