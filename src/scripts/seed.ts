import path from 'node:path';
import { pathToFileURL } from 'node:url';
import dotenv from 'dotenv';
import { z } from 'zod';
import type { AppRole } from '../types/database.js';

export interface SeedAccountSpec {
  email: string;
  password: string;
  fullName: string;
  role: AppRole;
}

export interface SeedResultItem {
  email: string;
  role: AppRole;
  userId: string;
  action: 'created' | 'updated';
}

export interface SeedAuthUser {
  id: string;
  email?: string | null;
  app_metadata?: Record<string, unknown> | null;
  user_metadata?: Record<string, unknown> | null;
}

export interface SeedSupabaseClient {
  auth: {
    admin: {
      listUsers: (params?: { page?: number; perPage?: number }) => Promise<{
        data: { users: SeedAuthUser[] };
        error: { message: string } | null;
      }>;
      createUser: (attributes: {
        email: string;
        password: string;
        email_confirm: boolean;
        app_metadata: Record<string, unknown>;
        user_metadata: Record<string, unknown>;
      }) => Promise<{
        data: { user: SeedAuthUser | null };
        error: { message: string } | null;
      }>;
      updateUserById: (
        uid: string,
        attributes: {
          email_confirm?: boolean;
          app_metadata?: Record<string, unknown>;
          user_metadata?: Record<string, unknown>;
        },
      ) => Promise<{
        data: { user: SeedAuthUser | null };
        error: { message: string } | null;
      }>;
    };
  };
  from: (table: 'user_profiles') => {
    upsert: (
      values: {
        id: string;
        full_name: string;
        role: AppRole;
        is_active: boolean;
      },
      options?: { onConflict?: string },
    ) => PromiseLike<{ error: { message: string } | null }>;
  };
}

export const seedPasswordSchema = z
  .string()
  .min(10, 'Seed password must be at least 10 characters long')
  .regex(/[a-z]/, 'Seed password must include at least one lowercase letter')
  .regex(/[A-Z]/, 'Seed password must include at least one uppercase letter')
  .regex(/[0-9]/, 'Seed password must include at least one digit')
  .regex(/[^A-Za-z0-9]/, 'Seed password must include at least one symbol');

const seedEnvSchema = z.object({
  SEED_ADMIN_EMAIL: z.string().trim().email('SEED_ADMIN_EMAIL must be a valid email'),
  SEED_ADMIN_PASSWORD: seedPasswordSchema,
  SEED_ADMIN_FULL_NAME: z.string().trim().min(1).default('System Administrator'),
  SEED_COORDINATOR_EMAIL: z
    .string()
    .trim()
    .email('SEED_COORDINATOR_EMAIL must be a valid email'),
  SEED_COORDINATOR_PASSWORD: seedPasswordSchema,
  SEED_COORDINATOR_FULL_NAME: z.string().trim().min(1).default('Disaster Coordinator'),
  SEED_RESCUER_EMAIL: z.string().trim().email('SEED_RESCUER_EMAIL must be a valid email'),
  SEED_RESCUER_PASSWORD: seedPasswordSchema,
  SEED_RESCUER_FULL_NAME: z.string().trim().min(1).default('Field Rescuer'),
});

/**
 * Parses and validates seed account specifications strictly from environment variables.
 * Never logs or includes plaintext password values in error messages.
 */
export function parseSeedAccounts(rawEnv: NodeJS.ProcessEnv = process.env): SeedAccountSpec[] {
  const result = seedEnvSchema.safeParse(rawEnv);

  if (!result.success) {
    const formatted = result.error.issues
      .map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid seed environment configuration:\n${formatted}`);
  }

  const parsed = result.data;
  const accounts: SeedAccountSpec[] = [
    {
      email: parsed.SEED_ADMIN_EMAIL.toLowerCase(),
      password: parsed.SEED_ADMIN_PASSWORD,
      fullName: parsed.SEED_ADMIN_FULL_NAME,
      role: 'administrator',
    },
    {
      email: parsed.SEED_COORDINATOR_EMAIL.toLowerCase(),
      password: parsed.SEED_COORDINATOR_PASSWORD,
      fullName: parsed.SEED_COORDINATOR_FULL_NAME,
      role: 'coordinator',
    },
    {
      email: parsed.SEED_RESCUER_EMAIL.toLowerCase(),
      password: parsed.SEED_RESCUER_PASSWORD,
      fullName: parsed.SEED_RESCUER_FULL_NAME,
      role: 'rescuer',
    },
  ];

  const uniqueEmails = new Set(accounts.map((account) => account.email));
  if (uniqueEmails.size !== accounts.length) {
    throw new Error(
      'Invalid seed environment configuration: administrator, coordinator, and rescuer emails must be distinct.',
    );
  }

  return accounts;
}

async function listAllExistingUsersByEmail(
  adminClient: SeedSupabaseClient,
): Promise<Map<string, SeedAuthUser>> {
  const byEmail = new Map<string, SeedAuthUser>();
  const perPage = 200;
  let page = 1;

  while (true) {
    const { data, error } = await adminClient.auth.admin.listUsers({ page, perPage });
    if (error) {
      throw new Error(`Failed to list existing Supabase Auth users: ${error.message}`);
    }

    const users = data?.users ?? [];
    for (const user of users) {
      if (user.email) {
        byEmail.set(user.email.trim().toLowerCase(), user);
      }
    }

    if (users.length < perPage) {
      break;
    }
    page += 1;
  }

  return byEmail;
}

function isAlreadyRegisteredError(message?: string): boolean {
  if (!message) return false;
  return /already\s*(been\s*)?registered|already\s*exists|email_exists/i.test(message);
}

async function syncExistingAuthUser(
  adminClient: SeedSupabaseClient,
  existing: SeedAuthUser,
  account: SeedAccountSpec,
): Promise<string> {
  const existingUserMeta = { ...(existing.user_metadata ?? {}) };
  const needsUserMetadataClean =
    'role' in existingUserMeta || 'user_role' in existingUserMeta;

  if (needsUserMetadataClean) {
    delete existingUserMeta.role;
    delete existingUserMeta.user_role;
  }

  const { error } = await adminClient.auth.admin.updateUserById(existing.id, {
    email_confirm: true,
    app_metadata: {
      ...(existing.app_metadata ?? {}),
      role: account.role,
    },
    ...(needsUserMetadataClean ? { user_metadata: existingUserMeta } : {}),
  });

  if (error) {
    throw new Error(
      `Failed to update existing seed user ${account.email} (${account.role}): ${error.message}`,
    );
  }

  return existing.id;
}

/**
 * Idempotently provisions pre-provisioned Auth users (`email_confirm: true`, `app_metadata.role`)
 * and upserts their matching rows in `public.user_profiles` without storing roles in `user_metadata`.
 */
export async function seedAccounts(
  adminClient: SeedSupabaseClient,
  accounts: SeedAccountSpec[],
): Promise<SeedResultItem[]> {
  const existingByEmail = await listAllExistingUsersByEmail(adminClient);
  const results: SeedResultItem[] = [];

  for (const account of accounts) {
    const existing = existingByEmail.get(account.email);
    let userId: string;
    let action: 'created' | 'updated';

    if (!existing) {
      const { data, error } = await adminClient.auth.admin.createUser({
        email: account.email,
        password: account.password,
        email_confirm: true,
        app_metadata: { role: account.role },
        user_metadata: {},
      });

      if (error && isAlreadyRegisteredError(error.message)) {
        const refreshed = await listAllExistingUsersByEmail(adminClient);
        const racedUser = refreshed.get(account.email);
        if (!racedUser) {
          throw new Error(
            `Seed user ${account.email} (${account.role}) already exists but could not be resolved via listUsers.`,
          );
        }
        existingByEmail.set(account.email, racedUser);
        userId = await syncExistingAuthUser(adminClient, racedUser, account);
        action = 'updated';
      } else if (error || !data.user) {
        throw new Error(
          `Failed to create seed user ${account.email} (${account.role}): ${error?.message ?? 'missing user in response'}`,
        );
      } else {
        userId = data.user.id;
        action = 'created';
        existingByEmail.set(account.email, data.user);
      }
    } else {
      userId = await syncExistingAuthUser(adminClient, existing, account);
      action = 'updated';
    }

    const { error: profileError } = await adminClient.from('user_profiles').upsert(
      {
        id: userId,
        full_name: account.fullName,
        role: account.role,
        is_active: true,
      },
      { onConflict: 'id' },
    );

    if (profileError) {
      throw new Error(
        `Failed to upsert user_profiles for ${account.email} (${userId}): ${profileError.message}`,
      );
    }

    results.push({
      email: account.email,
      role: account.role,
      userId,
      action,
    });
  }

  return results;
}

export async function runSeed(): Promise<SeedResultItem[]> {
  dotenv.config();
  const accounts = parseSeedAccounts(process.env);
  const { supabaseAdmin } = await import('../config/supabase.js');
  const results = await seedAccounts(
    supabaseAdmin as unknown as SeedSupabaseClient,
    accounts,
  );

  for (const item of results) {
    console.log(`[seed] ${item.action} ${item.role} ${item.email} (${item.userId})`);
  }

  return results;
}

const isDirectExecution =
  Boolean(process.argv[1]) &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1] ?? '')).href;

if (isDirectExecution) {
  runSeed().catch((err) => {
    console.error('[seed] FATAL:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
