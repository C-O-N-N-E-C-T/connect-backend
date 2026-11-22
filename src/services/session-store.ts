import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import { supabaseAdmin } from '../config/supabase.js';
import type { AppRole } from '../types/database.js';
import { AppError } from '../types/errors.js';

/**
 * OSP-60: every database WRITE of the session endpoints goes through this interface
 * (binding, unbinding, audit rows). The OSP-61 guard only READS, through `AuthGuardDeps`.
 *
 * Kept separate from `AuthGuardDeps` on purpose: the guard's deps expose only `from`, and
 * widening them would change OSP-61 code. Tests inject an in-memory store through
 * `createApp({ sessionStore })`; production uses the Supabase RPC store below.
 */
export interface SessionStore {
  /** Revocation check + device upsert + LOGIN audit, atomically (see the OSP-60 migration). */
  bindSession(input: BindSessionInput): Promise<BindSessionResult>;
  /** Clears the current session's binding + LOGOUT audit, atomically. */
  unbindSession(input: UnbindSessionInput): Promise<void>;
  /** LOGIN_REJECTED audit row for a verified user whose account is disabled. */
  recordRejectedLogin(input: RejectedLoginInput): Promise<void>;
}

export interface BindSessionInput {
  /** JWT `sub` from VerifiedClaims, never from the body. */
  user_id: string;
  /** From public.user_profiles.role (loadActiveProfile), never from the JWT. */
  role: AppRole;
  device_id: string;
  device_name: string;
  /** JWT `session_id` from VerifiedClaims. */
  session_id: string;
}

export type BindSessionResult =
  | { status: 'BOUND'; authenticated_at: string }
  | { status: 'DEVICE_REVOKED' };

export interface UnbindSessionInput {
  user_id: string;
  role: AppRole;
  device_id: string;
  session_id: string;
}

export interface RejectedLoginInput {
  user_id: string;
  /** Unknown when the profile is missing or the guard rejected it without returning it. */
  role: AppRole | null;
  device_id: string | null;
  reason: 'ACCOUNT_DISABLED';
}

const internalError = () =>
  new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');

/** Shape returned by public.bind_device_session(); anything else fails closed (500). */
const bindResultSchema = z.discriminatedUnion('status', [
  z.object({
    status: z.literal('BOUND'),
    authenticated_at: z.string().refine((value) => !Number.isNaN(Date.parse(value))),
  }),
  z.object({ status: z.literal('DEVICE_REVOKED') }),
]);

type RpcClient = Pick<SupabaseClient, 'rpc'>;

/**
 * Production store: calls the OSP-60 Postgres functions with the service-role client.
 * Database errors become a generic 500 (fail closed); the upstream message never reaches
 * the client.
 */
export function createSupabaseSessionStore(client: RpcClient): SessionStore {
  return {
    async bindSession(input) {
      const { data, error } = await client.rpc('bind_device_session', {
        p_user_id: input.user_id,
        p_role: input.role,
        p_device_id: input.device_id,
        p_device_name: input.device_name,
        p_session_id: input.session_id,
      });
      if (error) throw internalError();
      const parsed = bindResultSchema.safeParse(data);
      if (!parsed.success) throw internalError();
      return parsed.data;
    },

    async unbindSession(input) {
      const { error } = await client.rpc('unbind_device_session', {
        p_user_id: input.user_id,
        p_role: input.role,
        p_device_id: input.device_id,
        p_session_id: input.session_id,
      });
      if (error) throw internalError();
    },

    async recordRejectedLogin(input) {
      const { error } = await client.rpc('record_login_rejected', {
        p_user_id: input.user_id,
        p_role: input.role,
        p_device_id: input.device_id,
        p_reason: input.reason,
      });
      if (error) throw internalError();
    },
  };
}

/** The single production store; `createApp()` without options uses exactly this one. */
export const defaultSessionStore: SessionStore = createSupabaseSessionStore(supabaseAdmin);
