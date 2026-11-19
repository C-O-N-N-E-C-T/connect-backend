import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { parseEnv } from '../src/config/env.js';
import {
  parseSeedAccounts,
  seedAccounts,
  type SeedAuthUser,
  type SeedSupabaseClient,
} from '../src/scripts/seed.js';

const ROOT_DIR = path.resolve(import.meta.dirname, '..');
const SEED_SCRIPT_PATH = path.join(ROOT_DIR, 'src', 'scripts', 'seed.ts');
const ENV_EXAMPLE_PATH = path.join(ROOT_DIR, '.env.example');

function makeEphemeralStrongPassword(): string {
  return `Aa1!${crypto.randomBytes(8).toString('hex')}`;
}

function buildValidSeedEnv(): NodeJS.ProcessEnv {
  return {
    SEED_ADMIN_EMAIL: '  Admin@Connect.Internal ',
    SEED_ADMIN_PASSWORD: makeEphemeralStrongPassword(),
    SEED_ADMIN_FULL_NAME: 'System Administrator',
    SEED_COORDINATOR_EMAIL: 'Coordinator@Connect.Internal',
    SEED_COORDINATOR_PASSWORD: makeEphemeralStrongPassword(),
    SEED_COORDINATOR_FULL_NAME: 'Disaster Coordinator',
    SEED_RESCUER_EMAIL: 'Rescuer@Connect.Internal',
    SEED_RESCUER_PASSWORD: makeEphemeralStrongPassword(),
    SEED_RESCUER_FULL_NAME: 'Field Rescuer',
  };
}

function createInMemorySeedClient(initialUsers: SeedAuthUser[] = []) {
  const users = new Map<string, SeedAuthUser>();
  for (const user of initialUsers) {
    users.set(user.id, { ...user });
  }
  const upsertedProfiles: Array<Record<string, unknown>> = [];
  let seq = 1;

  const listUsers = vi.fn(async (params?: { page?: number; perPage?: number }) => {
    const page = params?.page ?? 1;
    const perPage = params?.perPage ?? 200;
    const all = Array.from(users.values());
    const start = (page - 1) * perPage;
    return {
      data: { users: all.slice(start, start + perPage) },
      error: null,
    };
  });

  const createUser = vi.fn(
    async (attrs: {
      email: string;
      password: string;
      email_confirm: boolean;
      app_metadata: Record<string, unknown>;
      user_metadata: Record<string, unknown>;
    }) => {
      const id = `00000000-0000-4000-8000-00000000000${seq++}`;
      const created: SeedAuthUser = {
        id,
        email: attrs.email,
        app_metadata: attrs.app_metadata,
        user_metadata: attrs.user_metadata,
      };
      users.set(id, created);
      return { data: { user: created }, error: null };
    },
  );

  const updateUserById = vi.fn(
    async (
      uid: string,
      attrs: {
        email_confirm?: boolean;
        app_metadata?: Record<string, unknown>;
        user_metadata?: Record<string, unknown>;
      },
    ) => {
      const existing = users.get(uid);
      if (!existing) {
        return { data: { user: null }, error: { message: 'User not found' } };
      }
      const updated: SeedAuthUser = {
        ...existing,
        app_metadata: attrs.app_metadata ?? existing.app_metadata ?? {},
        user_metadata: attrs.user_metadata ?? existing.user_metadata ?? {},
      };
      users.set(uid, updated);
      return { data: { user: updated }, error: null };
    },
  );

  const upsert = vi.fn(
    async (
      values: {
        id: string;
        full_name: string;
        role: string;
        is_active: boolean;
      },
      _options?: { onConflict?: string },
    ) => {
      upsertedProfiles.push(values);
      return { error: null };
    },
  );

  const client: SeedSupabaseClient = {
    auth: {
      admin: {
        listUsers,
        createUser,
        updateUserById,
      },
    },
    from: () => ({ upsert }),
  };

  return { client, listUsers, createUser, updateUserById, upsert, upsertedProfiles };
}

describe('OSP-59: Idempotent Account Seeder', () => {
  it('main Express server parseEnv succeeds when SEED_* variables are omitted or empty strings', () => {
    const baseEnv: NodeJS.ProcessEnv = {
      NODE_ENV: 'production',
      PORT: '3000',
      CORS_ORIGIN: 'https://dashboard.example.com',
      SUPABASE_URL: 'https://example.supabase.co',
      SUPABASE_ANON_KEY: 'anon-key',
      SUPABASE_SERVICE_ROLE_KEY: 'service-role-key',
      DATABASE_URL: 'postgresql://postgres:pass@127.0.0.1:54322/postgres',
    };

    expect(() => parseEnv(baseEnv)).not.toThrow();
    expect(() =>
      parseEnv({
        ...baseEnv,
        SEED_ADMIN_EMAIL: '',
        SEED_ADMIN_PASSWORD: '',
        SEED_COORDINATOR_EMAIL: '',
        SEED_COORDINATOR_PASSWORD: '',
        SEED_RESCUER_EMAIL: '',
        SEED_RESCUER_PASSWORD: '',
      }),
    ).not.toThrow();
  });

  it('parseSeedAccounts validates and normalizes administrator, coordinator, and rescuer specs', () => {
    const accounts = parseSeedAccounts(buildValidSeedEnv());
    expect(accounts).toHaveLength(3);
    expect(accounts.map((a) => ({ email: a.email, role: a.role }))).toEqual([
      { email: 'admin@connect.internal', role: 'administrator' },
      { email: 'coordinator@connect.internal', role: 'coordinator' },
      { email: 'rescuer@connect.internal', role: 'rescuer' },
    ]);
  });

  it('parseSeedAccounts rejects missing, weak, or duplicate seed configuration without leaking passwords', () => {
    expect(() => parseSeedAccounts({})).toThrow(/Invalid seed environment configuration/);

    const weakPwd = `weakpass${crypto.randomInt(1000, 9999)}`;
    const weakEnv = {
      ...buildValidSeedEnv(),
      SEED_RESCUER_PASSWORD: weakPwd,
    };
    let thrownMessage = '';
    try {
      parseSeedAccounts(weakEnv);
    } catch (err) {
      thrownMessage = err instanceof Error ? err.message : String(err);
    }
    expect(thrownMessage).toMatch(/must include at least one symbol/);
    expect(thrownMessage).not.toContain(weakPwd);

    const shortEnv = {
      ...buildValidSeedEnv(),
      SEED_ADMIN_PASSWORD: 'Ab!1',
    };
    expect(() => parseSeedAccounts(shortEnv)).toThrow(/at least 10 characters/);

    const dupEnv = {
      ...buildValidSeedEnv(),
      SEED_COORDINATOR_EMAIL: 'admin@connect.internal',
    };
    expect(() => parseSeedAccounts(dupEnv)).toThrow(/must be distinct/);
  });

  it('first run creates all 3 users with email_confirm=true, app_metadata.role, empty user_metadata, and upserts profiles', async () => {
    const accounts = parseSeedAccounts(buildValidSeedEnv());
    const mock = createInMemorySeedClient();

    const results = await seedAccounts(mock.client, accounts);

    expect(results.map((r) => ({ role: r.role, action: r.action }))).toEqual([
      { role: 'administrator', action: 'created' },
      { role: 'coordinator', action: 'created' },
      { role: 'rescuer', action: 'created' },
    ]);
    expect(mock.createUser).toHaveBeenCalledTimes(3);
    expect(mock.updateUserById).not.toHaveBeenCalled();

    for (const call of mock.createUser.mock.calls) {
      const arg = call[0];
      expect(arg.email_confirm).toBe(true);
      expect(arg.app_metadata).toHaveProperty('role');
      expect(arg.user_metadata).toEqual({});
      expect(arg.user_metadata).not.toHaveProperty('role');
      expect(arg.user_metadata).not.toHaveProperty('user_role');
    }

    expect(mock.upsert).toHaveBeenCalledTimes(3);
    expect(mock.upsertedProfiles.map((p) => p.role)).toEqual([
      'administrator',
      'coordinator',
      'rescuer',
    ]);
  });

  it('second run across paginated listUsers is idempotent, avoids createUser, cleans stray user_metadata role, and repairs user_profiles', async () => {
    const accounts = parseSeedAccounts(buildValidSeedEnv());
    const fillerUsers: SeedAuthUser[] = Array.from({ length: 200 }, (_, i) => ({
      id: `filler-${i}`,
      email: `filler${i}@example.com`,
      app_metadata: {},
      user_metadata: {},
    }));
    const existingSeedUsers: SeedAuthUser[] = [
      {
        id: 'existing-admin-id',
        email: 'admin@connect.internal',
        app_metadata: { provider: 'email' },
        user_metadata: { role: 'rescuer', display_name: 'Admin' },
      },
      {
        id: 'existing-coord-id',
        email: 'coordinator@connect.internal',
        app_metadata: { role: 'coordinator' },
        user_metadata: { user_role: 'administrator' },
      },
      {
        id: 'existing-rescuer-id',
        email: 'rescuer@connect.internal',
        app_metadata: { role: 'rescuer' },
        user_metadata: {},
      },
    ];

    const mock = createInMemorySeedClient([...fillerUsers, ...existingSeedUsers]);
    const results = await seedAccounts(mock.client, accounts);

    expect(mock.listUsers).toHaveBeenCalledTimes(2);
    expect(mock.createUser).not.toHaveBeenCalled();
    expect(mock.updateUserById).toHaveBeenCalledTimes(3);
    expect(results.map((r) => ({ userId: r.userId, action: r.action }))).toEqual([
      { userId: 'existing-admin-id', action: 'updated' },
      { userId: 'existing-coord-id', action: 'updated' },
      { userId: 'existing-rescuer-id', action: 'updated' },
    ]);

    const adminUpdateCall = mock.updateUserById.mock.calls[0]?.[1];
    expect(adminUpdateCall?.app_metadata).toEqual({ provider: 'email', role: 'administrator' });
    expect(adminUpdateCall?.user_metadata).toEqual({ display_name: 'Admin' });
    expect(adminUpdateCall?.user_metadata).not.toHaveProperty('role');

    const coordUpdateCall = mock.updateUserById.mock.calls[1]?.[1];
    expect(coordUpdateCall?.user_metadata).toEqual({});
    expect(coordUpdateCall?.user_metadata).not.toHaveProperty('user_role');

    expect(mock.upsert).toHaveBeenCalledTimes(3);
    expect(mock.upsertedProfiles.map((p) => p.id)).toEqual([
      'existing-admin-id',
      'existing-coord-id',
      'existing-rescuer-id',
    ]);
  });

  it('repairs partial records gracefully even if createUser reports an already-registered race condition', async () => {
    const accounts = parseSeedAccounts(buildValidSeedEnv()).slice(0, 1);
    const adminSpec = accounts[0]!;
    let listCallCount = 0;
    const upsertedProfiles: Array<Record<string, unknown>> = [];

    const raceClient: SeedSupabaseClient = {
      auth: {
        admin: {
          listUsers: vi.fn(async () => {
            listCallCount += 1;
            if (listCallCount === 1) {
              return { data: { users: [] }, error: null };
            }
            return {
              data: {
                users: [
                  {
                    id: 'raced-existing-uuid',
                    email: adminSpec.email,
                    app_metadata: {},
                    user_metadata: {},
                  },
                ],
              },
              error: null,
            };
          }),
          createUser: vi.fn(async () => ({
            data: { user: null },
            error: { message: 'A user with this email address has already been registered' },
          })),
          updateUserById: vi.fn(async (uid) => ({
            data: { user: { id: uid, email: adminSpec.email } },
            error: null,
          })),
        },
      },
      from: () => ({
        upsert: vi.fn(async (values) => {
          upsertedProfiles.push(values);
          return { error: null };
        }),
      }),
    };

    const results = await seedAccounts(raceClient, accounts);
    expect(results).toEqual([
      {
        email: adminSpec.email,
        role: 'administrator',
        userId: 'raced-existing-uuid',
        action: 'updated',
      },
    ]);
    expect(upsertedProfiles).toHaveLength(1);
    expect(upsertedProfiles[0]).toMatchObject({
      id: 'raced-existing-uuid',
      role: 'administrator',
      is_active: true,
    });
  });

  it('contains no hardcoded or fallback passwords in src/scripts/seed.ts or .env.example (SCRT-2)', () => {
    const seedSource = fs.readFileSync(SEED_SCRIPT_PATH, 'utf8');
    const envExample = fs.readFileSync(ENV_EXAMPLE_PATH, 'utf8');

    expect(seedSource).not.toMatch(
      /ChangeMe|password\s*[:=]\s*['"][^'"]+['"]|(?:password|SEED_\w*PASSWORD)[^\n;]*\?\?\s*['"][^'"]+['"]/i,
    );
    expect(seedSource).toMatch(/parseSeedAccounts\(process\.env\)/);
    expect(seedSource).not.toMatch(/console\.log\([^)]*password/i);

    expect(envExample).toMatch(/^SEED_ADMIN_PASSWORD=$/m);
    expect(envExample).toMatch(/^SEED_COORDINATOR_PASSWORD=$/m);
    expect(envExample).toMatch(/^SEED_RESCUER_PASSWORD=$/m);
    expect(envExample).not.toMatch(/ChangeMe/i);
  });
});
