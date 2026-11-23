import { z } from 'zod';

/** Android sends "<manufacturer> <model>" (≤ 100 chars); see connect-mobile OSP-60 assumptions A1. */
export const DEVICE_NAME_MAX_LENGTH = 100;

/**
 * OSP-60 (WAPP-3): body of POST /api/v1/auth/session.
 *
 * - `device_id`: random UUID created by the client on first launch (never IMEI / ANDROID_ID).
 * - `device_name`: human readable name shown to administrators.
 *
 * Unknown keys (e.g. a `user_id` sent by the client) are stripped, not rejected: identity
 * always comes from the verified token, so extra keys are harmless and older/newer clients
 * keep working.
 */
export const sessionRequestSchema = z.object({
  device_id: z.string().uuid(),
  device_name: z.string().trim().min(1).max(DEVICE_NAME_MAX_LENGTH),
});

export type SessionRequest = z.infer<typeof sessionRequestSchema>;
