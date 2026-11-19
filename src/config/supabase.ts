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
