import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { env } from './env.js';

/**
 * Privileged Supabase client initialized with `SUPABASE_SERVICE_ROLE_KEY`.
 * SECURITY RULE: Backend-only. Never persist sessions or auto-refresh tokens on the server.
 */
export const supabaseAdmin: SupabaseClient = createClient(
  env.SUPABASE_URL,
  env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  },
);

/**
 * Creates a request-scoped Supabase client using `SUPABASE_ANON_KEY`
 * and optional caller `Authorization: Bearer <jwt>` token for `getClaims()` verification.
 */
export function createSupabaseRequestClient(accessToken?: string): SupabaseClient {
  return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
    global: accessToken
      ? {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      : {},
  });
}

/** Upper bound for one Auth server call (JWKS fetch or getUser fallback) made by token verification. */
export const AUTH_VERIFY_TIMEOUT_MS = 5_000;

/**
 * Anon-key client used only for access-token verification (`auth.getClaims(token)`).
 * Verification needs no privileges: the JWKS endpoint is public and the getUser fallback is
 * authorised by the caller's own JWT. Every Auth request is cut off after `timeoutMs`, so a hung
 * Auth server surfaces as a retryable fetch error instead of hanging the API request.
 * `fetch` is injectable for tests.
 */
export function createTokenVerifierClient(
  options: { fetch?: typeof fetch; timeoutMs?: number } = {},
): SupabaseClient {
  const baseFetch = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? AUTH_VERIFY_TIMEOUT_MS;
  const fetchWithTimeout: typeof fetch = (input, init) => {
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    return baseFetch(input, { ...init, signal });
  };

  return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
    global: { fetch: fetchWithTimeout },
  });
}
