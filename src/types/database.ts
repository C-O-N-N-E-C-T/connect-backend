export const APP_ROLES = ['rescuer', 'coordinator', 'administrator'] as const;

export type AppRole = (typeof APP_ROLES)[number];

export const AUDIT_ACTION_TYPES = [
  'LOGIN',
  'LOGOUT',
  'USER_CREATED',
  'DEVICE_REVOKED',
  'ACCOUNT_DISABLED',
  'USER_REACTIVATED',
  'VICTIM_LIST_VIEW',
  'VICTIM_VIEW',
  'VICTIM_UPDATE',
  'RETENTION_PURGE',
] as const;

export type AuditActionType = (typeof AUDIT_ACTION_TYPES)[number];

export interface UserProfile {
  id: string;
  full_name: string | null;
  role: AppRole;
  is_active: boolean;
  all_sessions_revoked_at: string | null;
  created_at: string;
}

export interface UserDevice {
  id: string;
  user_id: string;
  device_id: string;
  device_name: string | null;
  session_id: string | null;
  last_login_at: string | null;
  is_device_revoked: boolean;
  device_revoked_at: string | null;
}

export interface AuditLog {
  id: string;
  actor_user_id: string | null;
  actor_role: AppRole | null;
  device_id: string | null;
  action_type: AuditActionType | string;
  target_record_id: string | null;
  created_at: string;
}

export interface VictimRecord {
  id: string;
  created_at: string;
  created_by: string | null;
  payload: Record<string, unknown>;
}

export interface RescuerObservation {
  id: string;
  created_at: string;
  created_by: string | null;
  payload: Record<string, unknown>;
}
