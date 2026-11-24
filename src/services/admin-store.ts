import type { SupabaseClient } from '@supabase/supabase-js';
import { supabaseAdmin } from '../config/supabase.js';
import type { AppRole, AuditLog } from '../types/database.js';
import { AppError } from '../types/errors.js';
import type { AuthContext } from '../types/express.js';
import type { AuditLogsQuery } from '../schemas/admin.js';

/**
 * OSP-66: every database access of the administrator API goes through these two interfaces.
 *  - AdminStore: profiles, devices and audit reads; state changes are single RPC calls, so the
 *    change and its audit row commit together (or not at all).
 *  - AuthAdminPort: Supabase Auth admin calls (create, ban, unban, delete account).
 * Tests replace both with in-memory fakes; production uses the service-role client.
 */

export interface AdminUserRow {
  id: string;
  email: string | null;
  full_name: string | null;
  role: AppRole;
  is_active: boolean;
  created_at: string;
  all_sessions_revoked_at: string | null;
}

export interface AdminDeviceRow {
  device_id: string;
  device_name: string | null;
  last_login_at: string | null;
  is_device_revoked: boolean;
  device_revoked_at: string | null;
  /** Whether the device currently has a bound session. The session id itself is never returned. */
  has_session: boolean;
}

export type RevokeDeviceStatus = 'REVOKED' | 'ALREADY_REVOKED' | 'NOT_FOUND';
export type DisableUserStatus = 'DISABLED' | 'NOT_FOUND';
export type ActivateUserStatus = 'ACTIVATED' | 'NOT_FOUND';

export interface AdminActor {
  actor: AuthContext;
}

export interface AdminStore {
  /** Returns the profile id when the user exists, otherwise null. */
  findUserProfile(userId: string): Promise<{ id: string } | null>;
  listUsers(limit: number, offset: number): Promise<AdminUserRow[]>;
  createUserProfile(input: AdminActor & { user_id: string; role: AppRole; full_name: string }): Promise<void>;
  listDevices(userId: string): Promise<AdminDeviceRow[]>;
  revokeDevice(input: AdminActor & { user_id: string; device_id: string }): Promise<RevokeDeviceStatus>;
  disableUser(input: AdminActor & { user_id: string }): Promise<DisableUserStatus>;
  activateUser(input: AdminActor & { user_id: string }): Promise<ActivateUserStatus>;
  listAuditLogs(query: AuditLogsQuery): Promise<AuditLog[]>;
}

export interface AuthAdminPort {
  /** Creates a confirmed Auth account with the role in app_metadata; returns its id. */
  createAuthUser(input: { email: string; password: string; role: AppRole }): Promise<{ id: string }>;
  deleteAuthUser(userId: string): Promise<void>;
  /** Blocks new sign-ins (876000 h, as specified in OSP-66). */
  banUser(userId: string): Promise<void>;
  unbanUser(userId: string): Promise<void>;
}

/** Duplicate e-mail is reported by Supabase as an "already registered" message. */
const DUPLICATE_PATTERN = /already\s*(been\s*)?registered|already\s*exists|email_exists/i;

const internalError = () =>
  new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');

type AdminClient = Pick<SupabaseClient, 'from' | 'rpc'>;

export function createSupabaseAdminStore(client: AdminClient): AdminStore {
  async function rpcStatus(name: string, args: Record<string, unknown>): Promise<string> {
    const { data, error } = await client.rpc(name, args);
    if (error) throw internalError();
    const status = (data as { status?: unknown } | null)?.status;
    if (typeof status !== 'string') throw internalError();
    return status;
  }

  return {
    async findUserProfile(userId) {
      const { data, error } = await client
        .from('user_profiles')
        .select('id')
        .eq('id', userId)
        .maybeSingle<{ id: string }>();
      if (error) throw internalError();
      return data ?? null;
    },

    async listUsers(limit, offset) {
      const { data, error } = await client.rpc('admin_list_users', { p_limit: limit, p_offset: offset });
      if (error) throw internalError();
      return (data ?? []) as AdminUserRow[];
    },

    async createUserProfile({ actor, user_id, role, full_name }) {
      const status = await rpcStatus('admin_create_user_profile', {
        p_actor_user_id: actor.user_id,
        p_actor_role: actor.role,
        p_actor_device_id: actor.device_id,
        p_user_id: user_id,
        p_role: role,
        p_full_name: full_name,
      });
      if (status !== 'CREATED') throw internalError();
    },

    async listDevices(userId) {
      const { data, error } = await client
        .from('user_devices')
        .select('device_id, device_name, last_login_at, is_device_revoked, device_revoked_at, session_id')
        .eq('user_id', userId)
        .order('last_login_at', { ascending: false, nullsFirst: false });
      if (error) throw internalError();
      return (data ?? []).map((row) => {
        const { session_id, ...rest } = row as Record<string, unknown> & { session_id: string | null };
        return { ...rest, has_session: session_id !== null } as AdminDeviceRow;
      });
    },

    async revokeDevice({ actor, user_id, device_id }) {
      const status = await rpcStatus('admin_revoke_device', {
        p_actor_user_id: actor.user_id,
        p_actor_role: actor.role,
        p_actor_device_id: actor.device_id,
        p_user_id: user_id,
        p_device_id: device_id,
      });
      if (status !== 'REVOKED' && status !== 'ALREADY_REVOKED' && status !== 'NOT_FOUND') {
        throw internalError();
      }
      return status;
    },

    async disableUser({ actor, user_id }) {
      const status = await rpcStatus('admin_disable_user', {
        p_actor_user_id: actor.user_id,
        p_actor_role: actor.role,
        p_actor_device_id: actor.device_id,
        p_user_id: user_id,
      });
      if (status !== 'DISABLED' && status !== 'NOT_FOUND') throw internalError();
      return status;
    },

    async activateUser({ actor, user_id }) {
      const status = await rpcStatus('admin_activate_user', {
        p_actor_user_id: actor.user_id,
        p_actor_role: actor.role,
        p_actor_device_id: actor.device_id,
        p_user_id: user_id,
      });
      if (status !== 'ACTIVATED' && status !== 'NOT_FOUND') throw internalError();
      return status;
    },

    async listAuditLogs(query) {
      let request = client.from('audit_logs').select('*');
      if (query.action_type) request = request.eq('action_type', query.action_type);
      if (query.actor_user_id) request = request.eq('actor_user_id', query.actor_user_id);
      if (query.target_record_id) request = request.eq('target_record_id', query.target_record_id);
      if (query.from) request = request.gte('created_at', query.from);
      if (query.to) request = request.lte('created_at', query.to);
      const { data, error } = await request
        .order('created_at', { ascending: false })
        .order('id', { ascending: false })
        .range(query.offset, query.offset + query.limit - 1);
      if (error) throw internalError();
      return (data ?? []) as AuditLog[];
    },
  };
}

/** Production AdminStore: service-role client. */
export const defaultAdminStore: AdminStore = createSupabaseAdminStore(supabaseAdmin);

type AdminAuthApi = Pick<SupabaseClient['auth']['admin'], 'createUser' | 'deleteUser' | 'updateUserById'>;

/** Maps a Supabase Auth admin error: duplicate e-mail is a 409, everything else a generic 500. */
function authError(message: string | undefined): AppError {
  if (message && DUPLICATE_PATTERN.test(message)) {
    return new AppError(409, 'CONFLICT', 'An account with this e-mail address already exists.');
  }
  return internalError();
}

export function createSupabaseAuthAdmin(admin: AdminAuthApi): AuthAdminPort {
  return {
    async createAuthUser({ email, password, role }) {
      const { data, error } = await admin.createUser({
        email,
        password,
        email_confirm: true,
        app_metadata: { role },
      });
      if (error || !data.user) throw authError(error?.message);
      return { id: data.user.id };
    },

    async deleteAuthUser(userId) {
      const { error } = await admin.deleteUser(userId);
      if (error) throw internalError();
    },

    async banUser(userId) {
      const { error } = await admin.updateUserById(userId, { ban_duration: '876000h' });
      if (error) throw internalError();
    },

    async unbanUser(userId) {
      const { error } = await admin.updateUserById(userId, { ban_duration: 'none' });
      if (error) throw internalError();
    },
  };
}

/** Production AuthAdminPort: service-role client's auth.admin API. */
export const defaultAuthAdmin: AuthAdminPort = createSupabaseAuthAdmin(supabaseAdmin.auth.admin);
