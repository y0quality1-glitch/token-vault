import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const envFile = resolve(import.meta.dirname, '../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

const signingSecret = process.env.WEBHOOK_SIGNING_SECRET ?? '';
if (signingSecret.length < 32) {
  console.error('[api] WEBHOOK_SIGNING_SECRET is missing or too short. Run "npm run setup" at the repo root.');
  process.exit(1);
}

const databaseUrl = process.env.DATABASE_URL ?? '';
if (!/^postgres(ql)?:\/\//.test(databaseUrl)) {
  console.error('[api] DATABASE_URL is missing. Start Postgres (npm run db:up) and run "npm run setup", or export DATABASE_URL=postgres://…');
  process.exit(1);
}

const seedMode = process.env.SEED_MODE ?? 'if-empty';
if (seedMode !== 'if-empty' && seedMode !== 'reset') {
  console.error('[api] SEED_MODE must be "if-empty" (default) or "reset".');
  process.exit(1);
}

export const config = {
  port: Number(process.env.PORT ?? 4000),
  databaseUrl,
  dbPoolMax: Number(process.env.DB_POOL_MAX ?? 10),
  /** if-empty: seed demo data only into an empty database. reset: wipe and reseed on start (tests). */
  seedMode: seedMode as 'if-empty' | 'reset',
  /** Shared HMAC secret for control plane <-> webhook signing. Held in env, never in the database. */
  webhookSigningSecret: signingSecret,
  webhookSigningSecretRef: 'env:WEBHOOK_SIGNING_SECRET',
  defaultWebhookUrl: process.env.DEFAULT_WEBHOOK_URL ?? 'http://localhost:4100',
  heartbeatIntervalMs: Number(process.env.HEARTBEAT_INTERVAL_MS ?? 30_000),
  sessionTtlMs: 8 * 60 * 60 * 1000,
  sessionCookie: 'tv_session',
  cookieSecure: process.env.NODE_ENV === 'production',
  executionTtlMs: 30_000,
  webhookTimeoutMs: 5_000,
};
