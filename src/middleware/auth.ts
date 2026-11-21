import type { NextFunction, Request, RequestHandler, Response } from 'express';
import {
  isAuthApiError,
  isAuthRetryableFetchError,
  type SupabaseClient,
} from '@supabase/supabase-js';
import { z } from 'zod';
import { createTokenVerifierClient, supabaseAdmin } from '../config/supabase.js';
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

export const unauthenticatedError = () =>
  new AppError(401, 'UNAUTHENTICATED', UNAUTHENTICATED_MESSAGE);
// Generic message only: the upstream error must not reach the client (the global handler
// would echo err.message for non-AppError errors outside production).
const internalError = () => new AppError(500, 'INTERNAL_ERROR', INTERNAL_MESSAGE);

/** Supabase emits `aud: "authenticated"`; an array form containing it is accepted too. */
const AUTHENTICATED_AUDIENCE = 'authenticated';

/**
 * Claims the guard relies on. `sub` and `session_id` are UUIDs in Supabase Auth access tokens;
 * anon / service-role API keys have neither and a different `aud`, so they are rejected here.
 * Validating the UUID format also keeps malformed values away from the uuid columns.
 */
const verifiedClaimsSchema = z.object({
  sub: z.string().uuid(),
  session_id: z.string().uuid(),
  iat: z.number().finite(),
  aud: z.union([
    z.literal(AUTHENTICATED_AUDIENCE),
    z.array(z.string()).refine((aud) => aud.includes(AUTHENTICATED_AUDIENCE)),
  ]),
});

/**
 * Type-only brand: this symbol never exists at runtime and is not exported, so outside this
 * module a `VerifiedClaims` value can only be obtained from `verifyAccessToken` /
 * `verifyAuthorizationHeader`, never built from a self-decoded JWT or a request body.
 */
declare const verifiedClaimsBrand: unique symbol;

/**
 * Claims of an access token that passed `getClaims` and the claim checks above.
 * Nominal (branded) and read-only, so the DB stages cannot be fed unverified or edited claims.
 */
export type VerifiedClaims = Readonly<z.infer<typeof verifiedClaimsSchema>> & {
  readonly [verifiedClaimsBrand]: true;
};

type ProfileRow = Pick<UserProfile, 'role' | 'is_active' | 'all_sessions_revoked_at'>;
type DeviceRow = Pick<UserDevice, 'user_id' | 'device_id' | 'is_device_revoked'>;

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
 * Classifies a getClaims failure (auth-js 2.119.0) as "Auth service unavailable" (-> 500, fail
 * closed, the client must not treat its session as dead) versus "token rejected" (-> 401):
 * - AuthRetryableFetchError: fetch rejected (network error, our timeout; status 0) or the Auth /
 *   JWKS endpoint answered 500-504 / 520-530                                        -> 500
 * - AuthApiError with status 429 or >= 500 (rate limited / other server error)       -> 500
 * - everything else -> 401: AuthInvalidJwtError (malformed, expired, bad signature),
 *   AuthApiError 4xx (token rejected by the Auth server), AuthSessionMissingError
 *   (session_not_found), AuthUnknownError (unparseable response, status unknown), and
 *   non-Auth throws (JSON.parse of a garbage token, WebCrypto errors).
 */
export function isAuthServiceUnavailable(error: unknown): boolean {
  if (isAuthRetryableFetchError(error)) return true;
  if (isAuthApiError(error)) return error.status === 429 || error.status >= 500;
  return false;
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

/**
 * OSP-61 auth stages. `requireAuth` composes all of them; `POST /api/v1/auth/session` (OSP-60,
 * not guarded) should reuse `verifyAuthorizationHeader` + `loadActiveProfile` instead of
 * re-implementing token verification. Every stage throws an AppError (401/403/500).
 */
export function createAuthGuard(deps: AuthGuardDeps) {
  /**
   * Verifies an access token with getClaims and returns its checked claims.
   * getClaims(jwt) (auth-js 2.119.0): rejects an expired/missing `exp` locally, then
   * - asymmetric alg (RS256/ES256) with `kid` (+ WebCrypto): verifies the signature against the
   *   project JWKS (`/.well-known/jwks.json`, cached in-process for 10 minutes);
   * - symmetric (HS*) alg, no `kid` or unknown `kid`: falls back to `getUser(jwt)`, one Auth
   *   server round trip per request.
   * It checks only `exp` and the signature; `aud` is checked here. It returns { error } for auth
   * errors but can also THROW for malformed input. The token must be passed explicitly: without
   * an argument getClaims reads the (non-persisted) client session instead.
   * Throws 401 UNAUTHENTICATED, or 500 INTERNAL_ERROR when the Auth service is unavailable.
   */
  async function verifyAccessToken(token: string): Promise<VerifiedClaims> {
    let claims: unknown;
    try {
      const { data, error } = await deps.authClient.auth.getClaims(token);
      if (error) {
        throw isAuthServiceUnavailable(error) ? internalError() : unauthenticatedError();
      }
      if (!data) throw unauthenticatedError();
      claims = data.claims;
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw isAuthServiceUnavailable(err) ? internalError() : unauthenticatedError();
    }

    // Nothing from the token is trusted before getClaims succeeded.
    const parsed = verifiedClaimsSchema.safeParse(claims);
    if (!parsed.success) throw unauthenticatedError();
    // The only place a VerifiedClaims value is created (type-level brand, no runtime change).
    return parsed.data as VerifiedClaims;
  }

  /** `Authorization` header -> verified claims. Missing/malformed header -> 401. */
  async function verifyAuthorizationHeader(header: string | undefined): Promise<VerifiedClaims> {
    const token = extractBearerToken(header);
    if (token === null) throw unauthenticatedError();
    return verifyAccessToken(token);
  }

  /**
   * Missing profile / is_active false / iat <= all_sessions_revoked_at -> 403 ACCOUNT_DISABLED.
   * `claims` MUST come from verifyAccessToken / verifyAuthorizationHeader (enforced by the brand).
   */
  async function loadActiveProfile(claims: VerifiedClaims): Promise<ProfileRow> {
    const { data: profile, error } = await deps.dbClient
      .from('user_profiles')
      .select('role, is_active, all_sessions_revoked_at')
      .eq('id', claims.sub)
      .maybeSingle<ProfileRow>();
    if (error) throw internalError();
    if (
      !profile ||
      profile.is_active !== true ||
      isRevokedByGlobalSignOut(claims.iat, profile.all_sessions_revoked_at)
    ) {
      throw new AppError(403, 'ACCOUNT_DISABLED', 'This account has been disabled or signed out.');
    }
    return profile;
  }

  /**
   * Device row bound to the token's signed session_id claim (never a client header).
   * `claims` MUST come from verifyAccessToken / verifyAuthorizationHeader (enforced by the brand).
   * Missing -> 403 SESSION_NOT_BOUND; revoked -> 403 DEVICE_REVOKED.
   * Filtering on user_id as well prevents a session bound to another user from matching.
   * More than one row for the same (session_id, user_id) makes maybeSingle error -> 500
   * (fail closed); OSP-60 must bind each session_id to exactly one device row.
   */
  async function resolveBoundDevice(claims: VerifiedClaims): Promise<DeviceRow> {
    const { data: device, error } = await deps.dbClient
      .from('user_devices')
      .select('user_id, device_id, is_device_revoked')
      .eq('session_id', claims.session_id)
      .eq('user_id', claims.sub)
      .maybeSingle<DeviceRow>();
    if (error) throw internalError();
    if (!device || device.user_id !== claims.sub) {
      throw new AppError(403, 'SESSION_NOT_BOUND', 'This session is not bound to a registered device.');
    }
    if (device.is_device_revoked !== false) {
      throw new AppError(403, 'DEVICE_REVOKED', 'This device has been revoked.');
    }
    return device;
  }

  /**
   * Order: Bearer header + getClaims (401) -> account (403 ACCOUNT_DISABLED) -> device
   * (403 SESSION_NOT_BOUND / DEVICE_REVOKED) -> req.auth with the role from the DB (the JWT
   * user_role claim is ignored). Database errors fail closed with 500. The token is never logged.
   */
  async function authenticate(req: Request): Promise<AuthContext> {
    const claims = await verifyAuthorizationHeader(req.headers.authorization);
    const profile = await loadActiveProfile(claims);
    const device = await resolveBoundDevice(claims);
    return {
      user_id: claims.sub,
      role: profile.role,
      device_id: device.device_id,
      session_id: claims.session_id,
    };
  }

  const requireAuth: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    let auth: AuthContext;
    try {
      auth = await authenticate(req);
    } catch (err) {
      const appError = err instanceof AppError ? err : internalError();
      // RFC 6750 §3; same value for every 401 cause.
      if (appError.statusCode === 401) res.set('WWW-Authenticate', 'Bearer');
      next(appError);
      return;
    }
    // Outside the try so an error thrown downstream is not reported as an auth failure;
    // Express 5 routes a rejected handler promise to the error handler.
    req.auth = auth;
    next();
  };

  return {
    verifyAccessToken,
    verifyAuthorizationHeader,
    loadActiveProfile,
    resolveBoundDevice,
    requireAuth,
  };
}

/** One guard instance: the stages plus `requireAuth`, all bound to the same deps. */
export type AuthGuard = ReturnType<typeof createAuthGuard>;

/** Shorthand used by tests and by callers that only need the middleware. */
export function createRequireAuth(deps: AuthGuardDeps): RequestHandler {
  return createAuthGuard(deps).requireAuth;
}

/**
 * Default wiring: token verification uses one module-level anon-key client (no privileges
 * needed, one shared instance, Auth calls time out); table reads use the service-role
 * `supabaseAdmin`, because RLS denies them to anon/authenticated.
 */
export const defaultAuthGuardDeps: AuthGuardDeps = {
  authClient: createTokenVerifierClient(),
  dbClient: supabaseAdmin,
};

/** The single production guard instance; `createApp()` without options uses exactly this one. */
export const defaultAuthGuard: AuthGuard = createAuthGuard(defaultAuthGuardDeps);

export const {
  verifyAccessToken,
  verifyAuthorizationHeader,
  loadActiveProfile,
  resolveBoundDevice,
  requireAuth,
} = defaultAuthGuard;
