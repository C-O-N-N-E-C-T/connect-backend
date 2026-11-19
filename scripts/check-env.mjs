import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const ENV_PATH = path.join(ROOT_DIR, '.env');
const SUPABASE_BIN_PATH = path.join(
  ROOT_DIR,
  'node_modules',
  '.bin',
  process.platform === 'win32' ? 'supabase.cmd' : 'supabase',
);

const REQUIRED_KEYS = [
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'DATABASE_URL',
];

const SEED_KEYS = [
  'SEED_ADMIN_EMAIL',
  'SEED_ADMIN_PASSWORD',
  'SEED_COORDINATOR_EMAIL',
  'SEED_COORDINATOR_PASSWORD',
  'SEED_RESCUER_EMAIL',
  'SEED_RESCUER_PASSWORD',
];

const PLACEHOLDER_PATTERNS = [
  /your-project-ref/i,
  /your-supabase-/i,
  /^<set-strong-/i,
];

let errors = 0;
let warnings = 0;

function ok(msg) {
  console.log(`[OK] ${msg}`);
}

function warn(msg) {
  console.log(`[!] ${msg}`);
  warnings += 1;
}

function fail(msg) {
  console.log(`[X] ${msg}`);
  errors += 1;
}

function parseEnvFile(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const map = new Map();

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx <= 0) {
      continue;
    }
    const key = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    map.set(key, value);
  }

  return map;
}

function isPlaceholder(value) {
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(value));
}

// 1. Node.js version check (matches .nvmrc and setup-windows.ps1)
const majorMatch = process.versions.node.match(/^(\d+)\./);
const nodeMajor = majorMatch ? Number(majorMatch[1]) : 0;

if (nodeMajor >= 26) {
  ok(`Node.js v${process.versions.node} (Active LTS)`);
} else if (nodeMajor >= 24) {
  warn(`Node.js v${process.versions.node} (fallback LTS; recommended: Node 26.x per .nvmrc)`);
} else {
  fail(`Node.js v${process.versions.node} is below >=24.0.0 (install Node 26.x LTS per .nvmrc)`);
}

// 2. Local Supabase CLI devDependency check
if (fs.existsSync(SUPABASE_BIN_PATH)) {
  ok('Local Supabase CLI installed in node_modules');
} else {
  fail('Local Supabase CLI not found in node_modules (run: npm ci)');
}

// 3. .env presence and required variables (NEVER prints values)
if (!fs.existsSync(ENV_PATH)) {
  fail('.env file not found (run: cp .env.example .env)');
} else {
  ok('.env file exists');
  const envMap = parseEnvFile(ENV_PATH);

  for (const key of REQUIRED_KEYS) {
    const value = envMap.get(key) ?? '';
    if (!value || isPlaceholder(value)) {
      fail(`Required variable ${key} is missing or still uses a template placeholder in .env`);
    } else {
      ok(`${key} is configured`);
    }
  }

  const missingSeed = SEED_KEYS.filter((key) => {
    const value = envMap.get(key) ?? '';
    return !value || isPlaceholder(value);
  });

  if (missingSeed.length === 0) {
    ok('All SEED_* credentials are configured in .env');
  } else {
    warn(`SEED_* variables incomplete (${missingSeed.length} missing; only required for npm run seed)`);
  }
}

console.log(`\nSummary: ${errors} error(s), ${warnings} warning(s).`);
if (errors > 0) {
  process.exit(1);
}
