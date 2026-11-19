import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  CORS_ORIGIN: z.string().url('CORS_ORIGIN must be a valid URL').default('http://localhost:5173'),
  SUPABASE_URL: z.string().url('SUPABASE_URL must be a valid URL'),
  SUPABASE_ANON_KEY: z.string().min(1, 'SUPABASE_ANON_KEY is required'),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1, 'SUPABASE_SERVICE_ROLE_KEY is required'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  SEED_ADMIN_EMAIL: z.string().email().optional(),
  SEED_ADMIN_PASSWORD: z.string().min(10).optional(),
  SEED_ADMIN_FULL_NAME: z.string().min(1).optional(),
  SEED_COORDINATOR_EMAIL: z.string().email().optional(),
  SEED_COORDINATOR_PASSWORD: z.string().min(10).optional(),
  SEED_COORDINATOR_FULL_NAME: z.string().min(1).optional(),
  SEED_RESCUER_EMAIL: z.string().email().optional(),
  SEED_RESCUER_PASSWORD: z.string().min(10).optional(),
  SEED_RESCUER_FULL_NAME: z.string().min(1).optional(),
});

export type AppEnv = z.infer<typeof envSchema>;

/**
 * Validates raw environment variables against the locked CONNECT backend schema.
 * Throws a descriptive Error if any required variable is missing or invalid.
 */
export function parseEnv(rawEnv: NodeJS.ProcessEnv = process.env): AppEnv {
  const result = envSchema.safeParse(rawEnv);

  if (!result.success) {
    const formatted = result.error.issues
      .map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${formatted}`);
  }

  return result.data;
}

/**
 * Validates environment variables on startup and exits immediately (`process.exit(1)`)
 * with a clear error message if any required variable is missing.
 */
export function loadEnvOrExit(rawEnv: NodeJS.ProcessEnv = process.env): AppEnv {
  try {
    return parseEnv(rawEnv);
  } catch (error) {
    console.error(
      '[connect-backend] FATAL: Failed to start due to missing/invalid environment variables.',
    );
    if (error instanceof Error) {
      console.error(error.message);
    }
    process.exit(1);
  }
}

const isTestEnv = process.env.NODE_ENV === 'test' || process.env.VITEST === 'true';

export const env: AppEnv = isTestEnv
  ? parseEnv({
      NODE_ENV: 'test',
      PORT: process.env.PORT ?? '3000',
      CORS_ORIGIN: process.env.CORS_ORIGIN ?? 'http://localhost:5173',
      SUPABASE_URL: process.env.SUPABASE_URL ?? 'https://example-test-project.supabase.co',
      SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY ?? 'test-anon-key',
      SUPABASE_SERVICE_ROLE_KEY:
        process.env.SUPABASE_SERVICE_ROLE_KEY ?? 'test-service-role-key',
      DATABASE_URL:
        process.env.DATABASE_URL ??
        'postgresql://postgres:postgres@127.0.0.1:54322/postgres',
      ...process.env,
    })
  : loadEnvOrExit(process.env);
