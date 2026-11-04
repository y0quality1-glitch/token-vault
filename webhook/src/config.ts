import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DEFAULT_WEBHOOK_INSTANCE_ID } from '@token-vault/shared';

const envFile = resolve(import.meta.dirname, '../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

function required(name: string, minLength: number): string {
  const v = process.env[name];
  if (!v || v.length < minLength) {
    console.error(`[vault] ${name} is missing or too short. Run "npm run setup" at the repo root.`);
    process.exit(1);
  }
  return v;
}

const encryptionKey = Buffer.from(required('VAULT_ENCRYPTION_KEY', 40), 'base64');
if (encryptionKey.length !== 32) {
  console.error('[vault] VAULT_ENCRYPTION_KEY must be base64 of exactly 32 bytes (AES-256).');
  process.exit(1);
}

// A dedicated name (not DATABASE_URL) so the customer zone is never pointed at the
// control plane's database by accident.
const databaseUrl = process.env.WEBHOOK_DATABASE_URL ?? '';
if (!/^postgres(ql)?:\/\//.test(databaseUrl)) {
  console.error('[vault] WEBHOOK_DATABASE_URL is missing. Start Postgres (npm run db:up) and run "npm run setup", or export WEBHOOK_DATABASE_URL=postgres://…');
  process.exit(1);
}

const seedMode = process.env.SEED_MODE ?? 'if-missing';
if (seedMode !== 'if-missing' && seedMode !== 'reset') {
  console.error('[vault] SEED_MODE must be "if-missing" (default) or "reset".');
  process.exit(1);
}

function readAppKey(): string | undefined {
  const file = process.env.GITHUB_APP_PRIVATE_KEY_FILE;
  if (file) return readFileSync(file, 'utf8');
  const inline = process.env.GITHUB_APP_PRIVATE_KEY;
  return inline ? inline.replace(/\\n/g, '\n') : undefined;
}

export const config = {
  port: Number(process.env.PORT ?? 4100),
  signingSecret: required('WEBHOOK_SIGNING_SECRET', 32),
  encryptionKey,
  encryptionKeyRef: 'env:VAULT_ENCRYPTION_KEY#v1',
  instanceId: process.env.WEBHOOK_INSTANCE_ID ?? DEFAULT_WEBHOOK_INSTANCE_ID,
  githubMode: (process.env.GITHUB_MODE === 'live' ? 'live' : 'mock') as 'mock' | 'live',
  databaseUrl,
  /** Optional GitHub App private key held only by this webhook (PEM; literal "\n" sequences allowed). */
  githubAppPrivateKey: readAppKey(),
  dbPoolMax: Number(process.env.DB_POOL_MAX ?? 5),
  /** if-missing: (re)create demo mock credentials only where absent or unreadable. reset: wipe the store first (tests). */
  seedMode: seedMode as 'if-missing' | 'reset',
  /** Pre-PostgreSQL JSON store; imported once on startup if present, then renamed. */
  legacyDataFile: process.env.WEBHOOK_DATA_FILE ?? resolve(import.meta.dirname, '../data/vault-store.json'),
  version: '0.1.0-poc',
  maxClockSkewMs: 60_000,
  maxExecutionTtlMs: 60_000,
};
