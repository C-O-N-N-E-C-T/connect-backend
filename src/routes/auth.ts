import type { Request, RequestHandler, Response } from 'express';
import type { AuthGuard, VerifiedClaims } from '../middleware/auth.js';
import { sessionRequestSchema } from '../schemas/auth-session.js';
import { buildOfflineMissionGrant, type OfflineMissionGrant } from '../services/offline-grant.js';
import type { SessionStore } from '../services/session-store.js';
import type { AppRole } from '../types/database.js';
import { AppError } from '../types/errors.js';

/** 200 body of POST /api/v1/auth/session (contract: connect-mobile OSP-60 assumptions A2). */
export interface SessionResponse {
  user_id: string;
  role: AppRole;
  device_id: string;
  /** Present only for role === 'rescuer'. */
  offline_mission_grant?: OfflineMissionGrant;
}

const invalidSessionBody = () =>
  new AppError(
    400,
    'VALIDATION_ERROR',
    'The request body must contain a UUID device_id and a device_name of 1-100 characters.',
  );

const deviceRevokedError = () => new AppError(403, 'DEVICE_REVOKED', 'This device has been revoked.');

/**
 * POST /api/v1/auth/session (OSP-60). PUBLIC route: the OSP-61 guard does NOT run here,
 * because the session is not bound yet. This handler verifies the caller itself, using the
 * SAME guard instance (`auth`) the app uses, so the rules (aud, UUID claims, outage -> 500,
 * all_sessions_revoked_at) are identical.
 *
 * Order:
 *   1. token          auth.verifyAuthorizationHeader   -> 401 UNAUTHENTICATED / 500
 *   2. body           Zod (WAPP-3)                     -> 400 VALIDATION_ERROR
 *   3. account        auth.loadActiveProfile           -> 403 ACCOUNT_DISABLED (+ audit)
 *   4. bind + audit   store.bindSession (one DB tx)    -> 403 DEVICE_REVOKED   (+ audit)
 *   5. response       { user_id, role, device_id, offline_mission_grant? }
 *
 * The token is checked before the body, so an unauthenticated caller only ever sees 401.
 * The body is checked before the account, so a rejected-login audit row can carry the device.
 * (A malformed JSON body is still rejected with 400 earlier, by `jsonBody` in api-v1.ts.)
 */
export function createSessionHandler(auth: AuthGuard, store: SessionStore): RequestHandler {
  return async (req: Request, res: Response<SessionResponse>) => {
    // 1. Token. Do NOT call auth.resolveBoundDevice here: nothing is bound yet, it would
    //    always answer SESSION_NOT_BOUND.
    let claims: VerifiedClaims;
    try {
      claims = await auth.verifyAuthorizationHeader(req.headers.authorization);
    } catch (err) {
      // Same header the guard sends on 401 (RFC 6750 §3), for consistent client handling.
      if (err instanceof AppError && err.statusCode === 401) res.set('WWW-Authenticate', 'Bearer');
      throw err;
    }
    // SECURITY: `claims` is only READ below (sub, session_id). Never spread, copy, edit or
    // cast it; see the OSP-60 handoff note, section 3.

    // 2. Body.
    const parsed = sessionRequestSchema.safeParse(req.body);
    if (!parsed.success) throw invalidSessionBody();
    const { device_id, device_name } = parsed.data;

    // 3. Account: missing profile, is_active = false, or iat <= all_sessions_revoked_at.
    let role: AppRole;
    try {
      ({ role } = await auth.loadActiveProfile(claims));
    } catch (err) {
      if (err instanceof AppError && err.errorCode === 'ACCOUNT_DISABLED') {
        await recordRejectedLoginSafely(store, claims.sub, device_id);
      }
      throw err;
    }

    // 4. Bind the token's session_id to this device and write LOGIN, in one transaction.
    const result = await store.bindSession({
      user_id: claims.sub,
      role,
      device_id,
      device_name,
      session_id: claims.session_id,
    });
    if (result.status === 'DEVICE_REVOKED') throw deviceRevokedError();

    // 5. Response. Coordinators / administrators get 200 without a grant (accepted by both
    //    Android and Web); only rescuers receive the 72 h Offline Mission Grant.
    const body: SessionResponse = { user_id: claims.sub, role, device_id };
    if (role === 'rescuer') {
      body.offline_mission_grant = buildOfflineMissionGrant(
        claims.sub,
        device_id,
        new Date(result.authenticated_at),
      );
    }
    // The grant is session specific: never let a proxy or browser cache it.
    res.set('Cache-Control', 'no-store');
    res.status(200).json(body);
  };
}

/**
 * The account is disabled either way, so a failing audit write must not turn the 403 into a
 * 500 (clients would then show a generic error instead of "account disabled"). The failure is
 * logged for operators instead. LOGIN rows are different: they are written in the same
 * transaction as the binding, so they can never be missing for a successful login.
 */
async function recordRejectedLoginSafely(
  store: SessionStore,
  userId: string,
  deviceId: string,
): Promise<void> {
  try {
    // role is null: loadActiveProfile throws without returning the profile (OSP-61 code).
    await store.recordRejectedLogin({
      user_id: userId,
      role: null,
      device_id: deviceId,
      reason: 'ACCOUNT_DISABLED',
    });
  } catch {
    console.error('[connect-backend] OSP-60: failed to write LOGIN_REJECTED audit row');
  }
}

/**
 * POST /api/v1/auth/logout (OSP-60). PROTECTED route: the OSP-61 guard has already verified
 * the token, the account and the bound device, so `req.auth` is set. No body is read.
 *
 * Clears the binding of THIS session only (user_id + session_id from req.auth) and writes
 * LOGOUT in the same transaction. Answers 204; clients treat any 2xx as success.
 *
 * Known limit (agreed reading of the AC, see the PR): an expired or revoked token is rejected
 * by the guard (401 / 403) before this handler, so no LOGOUT row is written for it. The stale
 * binding is harmless: the access token expires, Supabase signOut() revokes the refresh token,
 * and the next login overwrites session_id.
 */
export function createLogoutHandler(store: SessionStore): RequestHandler {
  return async (req: Request, res: Response) => {
    const auth = req.auth;
    // Cannot happen behind requireAuth; fail closed if the route is ever mounted elsewhere.
    if (!auth) throw new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');

    await store.unbindSession({
      user_id: auth.user_id,
      role: auth.role,
      device_id: auth.device_id,
      session_id: auth.session_id,
    });
    res.status(204).end();
  };
}

/**
 * OSP-70 `GET /api/v1/auth/me`: answers `{ user_id, role, device_id }` from the guard's auth
 * context (role from the database, not the JWT). Never returns `session_id` or token material,
 * reads no body, writes no audit row. `Cache-Control: no-store` keeps it out of any cache.
 */
export function createMeHandler(): RequestHandler {
  return (req: Request, res: Response) => {
    const auth = req.auth;
    // Cannot happen behind requireAuth; fail closed if the route is ever mounted elsewhere.
    if (!auth) throw new AppError(500, 'INTERNAL_ERROR', 'An unexpected internal server error occurred.');

    res.set('Cache-Control', 'no-store');
    res.status(200).json({ user_id: auth.user_id, role: auth.role, device_id: auth.device_id });
  };
}
