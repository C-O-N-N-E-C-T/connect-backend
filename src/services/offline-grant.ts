/** OSP-60: an Offline Mission Grant is valid for 72 hours after authentication. */
export const OFFLINE_GRANT_TTL_MS = 72 * 60 * 60 * 1000;

/**
 * UNSIGNED Offline Mission Grant returned to rescuers by POST /api/v1/auth/session.
 * The Android app stores it and uses it to keep working without network for up to 72 h.
 * Field names and the `offline_mission_grant` key are fixed by connect-mobile (OSP-74, A2).
 */
export interface OfflineMissionGrant {
  user_id: string;
  device_id: string;
  /** ISO-8601 in UTC with a `Z` offset; the app rejects timestamps without an offset. */
  authenticated_at: string;
  /** Always exactly authenticated_at + 72 h. */
  expires_at: string;
}

/**
 * Builds the grant from the moment the session was bound (`last_login_at` in the database).
 * Pure function: no clock read, so tests can pin the time.
 */
export function buildOfflineMissionGrant(
  userId: string,
  deviceId: string,
  authenticatedAt: Date,
): OfflineMissionGrant {
  return {
    user_id: userId,
    device_id: deviceId,
    authenticated_at: authenticatedAt.toISOString(),
    expires_at: new Date(authenticatedAt.getTime() + OFFLINE_GRANT_TTL_MS).toISOString(),
  };
}
