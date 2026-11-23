import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSupabaseAuditLogStore } from '../src/services/audit-log.js';
import { AppError } from '../src/types/errors.js';
import type { AuthContext } from '../src/types/express.js';

const ACTOR: AuthContext = {
  user_id: '11111111-1111-4111-8111-111111111111',
  role: 'coordinator',
  device_id: '44444444-4444-4444-8444-444444444444',
  session_id: '33333333-3333-4333-8333-333333333333',
};
const RECORD_ID = '88888888-8888-4888-8888-888888888888';

function fakeClient(result: { error: unknown } | Error) {
  const insert = vi.fn(async (_row: Record<string, unknown>) => {
    if (result instanceof Error) throw result;
    return { data: null, ...result };
  });
  const from = vi.fn((_table: string) => ({ insert }));
  return { client: { from } as never, from, insert };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('OSP-65 AuditLogStore (Supabase)', () => {
  it('inserts one row into audit_logs with the actor taken from the auth context', async () => {
    const { client, from, insert } = fakeClient({ error: null });
    await createSupabaseAuditLogStore(client).write({
      actor: ACTOR,
      action_type: 'VICTIM_VIEW',
      target_record_id: RECORD_ID,
    });

    expect(from).toHaveBeenCalledWith('audit_logs');
    expect(insert).toHaveBeenCalledTimes(1);
    expect(insert.mock.calls[0]?.[0]).toEqual({
      actor_user_id: ACTOR.user_id,
      actor_role: ACTOR.role,
      device_id: ACTOR.device_id,
      action_type: 'VICTIM_VIEW',
      target_record_id: RECORD_ID,
      metadata: {},
    });
  });

  it('defaults target_record_id to null and keeps metadata', async () => {
    const { client, insert } = fakeClient({ error: null });
    await createSupabaseAuditLogStore(client).write({
      actor: ACTOR,
      action_type: 'VICTIM_LIST_VIEW',
      metadata: { filters: { status: 'open' }, result_count: 3 },
    });
    expect(insert.mock.calls[0]?.[0]).toMatchObject({
      target_record_id: null,
      metadata: { filters: { status: 'open' }, result_count: 3 },
    });
  });

  it.each([
    ['returns an error', { error: { message: 'relation "audit_logs" secret detail' } }],
    ['throws', new Error('fetch failed: secret detail')],
  ])('fails closed with a generic 500 when Supabase %s', async (_label, result) => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { client } = fakeClient(result);

    const err = await createSupabaseAuditLogStore(client)
      .write({ actor: ACTOR, action_type: 'VICTIM_UPDATE', target_record_id: RECORD_ID })
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(AppError);
    expect(err).toMatchObject({ statusCode: 500, errorCode: 'INTERNAL_ERROR' });
    expect((err as Error).message).not.toMatch(/secret/);
    expect(log).toHaveBeenCalledTimes(1);
    expect(String(log.mock.calls[0]?.[0])).not.toMatch(/secret/);
  });
});
