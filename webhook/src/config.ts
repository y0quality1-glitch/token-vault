import { existsSync } from 'node:fs';
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

export const config = {
  port: Number(process.env.PORT ?? 4100),
  signingSecret: required('WEBHOOK_SIGNING_SECRET', 32),
  encryptionKey,
  encryptionKeyRef: 'env:VAULT_ENCRYPTION_KEY#v1',
  instanceId: process.env.WEBHOOK_INSTANCE_ID ?? DEFAULT_WEBHOOK_INSTANCE_ID,
  githubMode: (process.env.GITHUB_MODE === 'live' ? 'live' : 'mock') as 'mock' | 'live',
  /** Ciphertext-only store. Override (e.g. in tests) to avoid touching the local dev store. */
  dataFile: process.env.WEBHOOK_DATA_FILE ?? resolve(import.meta.dirname, '../data/vault-store.json'),
  version: '0.1.0-poc',
  maxClockSkewMs: 60_000,
  maxExecutionTtlMs: 60_000,
};
