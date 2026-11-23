import { z } from 'zod';
import { APP_ROLES, AUDIT_ACTION_TYPES } from '../types/database.js';

/**
 * OSP-66: administrator API input schemas. Invalid input answers 400 VALIDATION_ERROR; zod
 * details are never sent to the client (the router maps them to a fixed message).
 */

const uuid = z.string().uuid();

export const userIdParamSchema = uuid;
export const deviceIdParamSchema = uuid;

/** `role: 'administrator'` is valid JSON for this schema; the route rejects it with 403. */
export const createUserBodySchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  // Supabase enforces complexity (auth.password_requirements); 72 is bcrypt's input limit.
  password: z.string().min(10).max(72),
  full_name: z.string().trim().min(1).max(100),
  role: z.enum(APP_ROLES),
});

const paging = {
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).max(100_000).default(0),
};

export const listUsersQuerySchema = z.object(paging);

export const auditLogsQuerySchema = z.object({
  action_type: z.enum(AUDIT_ACTION_TYPES).optional(),
  actor_user_id: uuid.optional(),
  target_record_id: uuid.optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  ...paging,
});

export type CreateUserBody = z.infer<typeof createUserBodySchema>;
export type ListUsersQuery = z.infer<typeof listUsersQuerySchema>;
export type AuditLogsQuery = z.infer<typeof auditLogsQuerySchema>;
