import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const envFile = resolve(import.meta.dirname, '../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

const signingSecret = process.env.WEBHOOK_SIGNING_SECRET ?? '';
if (signingSecret.length < 32) {
  console.error('[api] WEBHOOK_SIGNING_SECRET is missing or too short. Run "npm run setup" at the repo root.');
  process.exit(1);
}

export const config = {
  port: Number(process.env.PORT ?? 4000),
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
