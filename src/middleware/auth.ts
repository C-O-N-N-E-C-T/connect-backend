import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import { createSupabaseRequestClient, supabaseAdmin } from '../config/supabase.js';
import type { UserDevice, UserProfile } from '../types/database.js';
import { AppError } from '../types/errors.js';
import type { AuthContext } from '../types/express.js';

/**
 * Supabase dependencies of the guard, injectable so tests can replace them with fakes.
 * - `authClient`: only `auth.getClaims` is used.
 * - `dbClient`: service-role client used to read `user_profiles` and `user_devices`.
 */
export interface AuthGuardDeps {
  authClient: { auth: Pick<SupabaseClient['auth'], 'getClaims'> };
  dbClient: Pick<SupabaseClient, 'from'>;
}

// One uniform message for every 401 cause, so the response does not reveal why a token failed.
const UNAUTHENTICATED_MESSAGE = 'Authentication is required. Provide a valid Bearer access token.';
const INTERNAL_MESSAGE = 'An unexpected internal server error occurred.';

const unauthenticated = () => new AppError(401, 'UNAUTHENTICATED', UNAUTHENTICATED_MESSAGE);
// Generic message only: the PostgREST error must not reach the client (the global handler
// would echo err.message for non-AppError errors outside production).
const internalError = () => new AppError(500, 'INTERNAL_ERROR', INTERNAL_MESSAGE);

/**
 * Claims the guard relies on. `sub` and `session_id` are UUIDs in Supabase Auth tokens; anon /
 * service-role API keys have neither, so they are rejected here. Validating the UUID format also
 * keeps malformed values away from the uuid columns (which would otherwise surface as a 500).
 */
const requiredClaimsSchema = z.object({
  sub: z.string().uuid(),
  session_id: z.string().uuid(),
  iat: z.number().finite(),
});

/**
 * Returns the token of an `Authorization: Bearer <token>` header, or null.
 * Exactly two space-separated parts; the scheme is matched case-insensitively (RFC 7235),
 * the token must be non-empty and contain no further whitespace.
 */
export function extractBearerToken(header: string | undefined): string | null {
  if (typeof header !== 'string') return null;
  const parts = header.trim().split(' ');
  if (parts.length !== 2) return null;
  const [scheme, token] = parts as [string, string];
  if (scheme.toLowerCase() !== 'bearer' || token.length === 0 || /\s/.test(token)) return null;
  return token;
}

/**
 * Global revocation: a token is revoked when it was issued at or before `all_sessions_revoked_at`.
 * `iat` is whole epoch seconds (floored), so `iat * 1000 <= revokedAtMs` also rejects every token
 * issued earlier within the same second as the revocation (equal counts as revoked).
 * An unparseable timestamp fails closed (500) instead of letting the token through.
 */
function isRevokedByGlobalSignOut(iat: number, allSessionsRevokedAt: string | null): boolean {
  if (allSessionsRevokedAt === null) return false;
  const revokedAtMs = Date.parse(allSessionsRevokedAt);
  if (Number.isNaN(revokedAtMs)) throw internalError();
  return iat * 1000 <= revokedAtMs;
}

type ProfileRow = Pick<UserProfile, 'role' | 'is_active' | 'all_sessions_revoked_at'>;
type DeviceRow = Pick<UserDevice, 'user_id' | 'device_id' | 'is_device_revoked'>;

/**
 * OSP-61 stateful auth guard. Order of checks:
 *  1. Bearer header -> 401 UNAUTHENTICATED
 *  2. getClaims(token) + required claims -> 401 UNAUTHENTICATED
 *  3. user_profiles: missing / inactive / iat <= all_sessions_revoked_at -> 403 ACCOUNT_DISABLED
 *  4. user_devices by (session_id claim, user_id): missing -> 403 SESSION_NOT_BOUND,
 *     revoked -> 403 DEVICE_REVOKED
 *  5. req.auth = { user_id, role (from DB, not the JWT user_role claim), device_id, session_id }
 * Database errors fail closed with 500 INTERNAL_ERROR. Client-supplied device/session headers
 * are never read; the device lookup uses only the signed session_id claim. The token is never logged.
 */
export function createRequireAuth(deps: AuthGuardDeps): RequestHandler {
  async function authenticate(req: Request): Promise<AuthContext> {
    const token = extractBearerToken(req.headers.authorization);
    if (token === null) throw unauthenticated();

    // getClaims(jwt) (auth-js 2.119): rejects an expired/missing `exp` locally, then
    // - asymmetric alg with `kid` (+ WebCrypto): verifies the signature against the project
    //   JWKS (`/.well-known/jwks.json`, cached in-process for 10 minutes);
    // - symmetric (HS*) alg or no `kid`: falls back to `getUser(jwt)`, one Auth server round trip
    //   per request.
    // Only `exp` and the signature are checked (not iss/aud). It returns { error } for auth
    // errors but can also THROW for malformed input (e.g. JSON.parse of a garbage segment), so
    // every failure mode maps to 401. The token must be passed explicitly: without an argument
    // getClaims reads the (non-persisted) client session instead.
    let claims: unknown;
    try {
      const { data, error } = await deps.authClient.auth.getClaims(token);
      if (error || !data) throw unauthenticated();
      claims = data.claims;
    } catch {
      throw unauthenticated();
    }

    // Nothing from the token is trusted before getClaims succeeded.
    const parsedClaims = requiredClaimsSchema.safeParse(claims);
    if (!parsedClaims.success) throw unauthenticated();
    const { sub: userId, session_id: sessionId, iat } = parsedClaims.data;

    const profileResult = await deps.dbClient
      .from('user_profiles')
      .select('role, is_active, all_sessions_revoked_at')
      .eq('id', userId)
      .maybeSingle<ProfileRow>();
    if (profileResult.error) throw internalError();
    const profile = profileResult.data;
    if (
      !profile ||
      profile.is_active !== true ||
      isRevokedByGlobalSignOut(iat, profile.all_sessions_revoked_at)
    ) {
      throw new AppError(403, 'ACCOUNT_DISABLED', 'This account has been disabled or signed out.');
    }

    // Filtering on user_id as well prevents a session bound to another user from matching.
    // More than one row for the same (session_id, user_id) makes maybeSingle error -> 500
    // (fail closed); OSP-60 must bind each session_id to exactly one device row.
    const deviceResult = await deps.dbClient
      .from('user_devices')
      .select('user_id, device_id, is_device_revoked')
      .eq('session_id', sessionId)
      .eq('user_id', userId)
      .maybeSingle<DeviceRow>();
    if (deviceResult.error) throw internalError();
    const device = deviceResult.data;
    if (!device || device.user_id !== userId) {
      throw new AppError(403, 'SESSION_NOT_BOUND', 'This session is not bound to a registered device.');
    }
    if (device.is_device_revoked !== false) {
      throw new AppError(403, 'DEVICE_REVOKED', 'This device has been revoked.');
    }

    return { user_id: userId, role: profile.role, device_id: device.device_id, session_id: sessionId };
  }

  return function requireAuth(req: Request, _res: Response, next: NextFunction): void {
    authenticate(req).then(
      (auth) => {
        req.auth = auth;
        next();
      },
      (err: unknown) => {
        // Errors that are not AppError (e.g. a thrown network failure) fail closed with a generic 500.
        next(err instanceof AppError ? err : internalError());
      },
    );
  };
}

/**
 * Token verification uses a single module-level client created with the anon key: verifying a
 * token needs no privileges (JWKS is public, the getUser fallback is authorised by the user's own
 * JWT), and one shared instance avoids a client allocation per request. Table reads use the
 * service-role `supabaseAdmin`, because RLS denies them to anon/authenticated by default.
 */
const tokenVerifierClient = createSupabaseRequestClient();

export const requireAuth: RequestHandler = createRequireAuth({
  authClient: tokenVerifierClient,
  dbClient: supabaseAdmin,
});
