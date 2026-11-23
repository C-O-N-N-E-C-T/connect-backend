import { describe, expect, it, vi } from 'vitest';
import { createSupabaseSessionStore } from '../src/services/session-store.js';
import { AppError } from '../src/types/errors.js';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const DEVICE_ID = '44444444-4444-4444-8444-444444444444';
const SESSION_ID = '33333333-3333-4333-8333-333333333333';

function storeWith(result: { data: unknown; error: unknown }) {
  const rpc = vi.fn(async () => result);
  const store = createSupabaseSessionStore({ rpc } as unknown as Parameters<typeof createSupabaseSessionStore>[0]);
  return { store, rpc };
}

const bindInput = {
  user_id: USER_ID,
  role: 'rescuer' as const,
  device_id: DEVICE_ID,
  device_name: 'Pixel 8',
  session_id: SESSION_ID,
};

async function expectInternal(promise: Promise<unknown>) {
  const err = await promise.catch((e: unknown) => e);
  expect(err).toBeInstanceOf(AppError);
  expect(err).toMatchObject({ statusCode: 500, errorCode: 'INTERNAL_ERROR' });
  // The upstream message never leaks.
  expect((err as Error).message).not.toMatch(/secret/);
}

describe('OSP-60 Supabase session store (RPC wiring)', () => {
  it('bindSession calls bind_device_session with p_* arguments and returns BOUND', async () => {
    const { store, rpc } = storeWith({
      data: { status: 'BOUND', authenticated_at: '2026-11-22T10:00:00.123456+00:00' },
      error: null,
    });
    await expect(store.bindSession(bindInput)).resolves.toEqual({
      status: 'BOUND',
      authenticated_at: '2026-11-22T10:00:00.123456+00:00',
    });
    expect(rpc).toHaveBeenCalledWith('bind_device_session', {
      p_user_id: USER_ID,
      p_role: 'rescuer',
      p_device_id: DEVICE_ID,
      p_device_name: 'Pixel 8',
      p_session_id: SESSION_ID,
    });
  });

  it('bindSession passes DEVICE_REVOKED through', async () => {
    const { store } = storeWith({ data: { status: 'DEVICE_REVOKED' }, error: null });
    await expect(store.bindSession(bindInput)).resolves.toEqual({ status: 'DEVICE_REVOKED' });
  });

  it.each([
    ['RPC error', { data: null, error: { message: 'secret db detail' } }],
    ['null data', { data: null, error: null }],
    ['unknown status', { data: { status: 'MAYBE' }, error: null }],
    ['BOUND without timestamp', { data: { status: 'BOUND' }, error: null }],
    ['BOUND with garbage timestamp', { data: { status: 'BOUND', authenticated_at: 'yesterday' }, error: null }],
  ])('bindSession fails closed (500) on %s', async (_name, result) => {
    await expectInternal(storeWith(result).store.bindSession(bindInput));
  });

  it('unbindSession calls unbind_device_session; error -> 500', async () => {
    const ok = storeWith({ data: null, error: null });
    await ok.store.unbindSession({ user_id: USER_ID, role: 'rescuer', device_id: DEVICE_ID, session_id: SESSION_ID });
    expect(ok.rpc).toHaveBeenCalledWith('unbind_device_session', {
      p_user_id: USER_ID,
      p_role: 'rescuer',
      p_device_id: DEVICE_ID,
      p_session_id: SESSION_ID,
    });

    await expectInternal(
      storeWith({ data: null, error: { message: 'secret' } }).store.unbindSession({
        user_id: USER_ID,
        role: 'rescuer',
        device_id: DEVICE_ID,
        session_id: SESSION_ID,
      }),
    );
  });

  it('recordRejectedLogin calls record_login_rejected', async () => {
    const { store, rpc } = storeWith({ data: null, error: null });
    await store.recordRejectedLogin({ user_id: USER_ID, role: null, device_id: DEVICE_ID, reason: 'ACCOUNT_DISABLED' });
    expect(rpc).toHaveBeenCalledWith('record_login_rejected', {
      p_user_id: USER_ID,
      p_role: null,
      p_device_id: DEVICE_ID,
      p_reason: 'ACCOUNT_DISABLED',
    });
  });
});
