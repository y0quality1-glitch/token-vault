import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadWebhookTls, type WebhookTls } from './lib/webhook-tls';

const envFile = resolve(import.meta.dirname, '../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

const signingSecret = process.env.WEBHOOK_SIGNING_SECRET ?? '';
if (signingSecret.length < 32) {
  console.error('[api] WEBHOOK_SIGNING_SECRET is missing or too short. Run "npm run setup" at the repo root.');
  process.exit(1);
}
// Signing-secret rotation: previous secrets are still accepted on webhook responses until removed.
const previousSigningSecrets = (process.env.WEBHOOK_PREVIOUS_SIGNING_SECRETS ?? '').split(',').map((v) => v.trim()).filter((v) => v && v !== signingSecret);
if (previousSigningSecrets.some((v) => v.length < 32)) {
  console.error('[api] every WEBHOOK_PREVIOUS_SIGNING_SECRETS entry must be at least 32 characters.');
  process.exit(1);
}

// mTLS to customer webhooks (optional): client certificate, webhook CA, and https-only.
let webhookTls: WebhookTls;
try {
  webhookTls = loadWebhookTls(process.env);
} catch (e) {
  console.error(`[api] ${(e as Error).message}.`);
  process.exit(1);
}

// HMAC key for audit-chain signatures. Kept outside the database, so someone who can write
// to the database cannot forge signatures for altered or inserted audit records.
const auditSigningKey = process.env.AUDIT_SIGNING_KEY ?? '';
if (auditSigningKey.length < 32) {
  console.error('[api] AUDIT_SIGNING_KEY is missing or too short. Run "npm run setup" at the repo root, or export a random value of 32+ characters.');
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

// Provider definitions are pulled from the CMS catalog and verified against this pinned key.
function readCmsPublicKey(): string | undefined {
  const file = process.env.CMS_PUBLIC_KEY_FILE;
  if (file) return readFileSync(file, 'utf8');
  const inline = process.env.CMS_PUBLIC_KEY;
  return inline ? inline.replace(/\\n/g, '\n') : undefined;
}
const cmsCatalogUrl = process.env.CMS_CATALOG_URL || undefined;
const cmsPublicKey = readCmsPublicKey();
if (cmsCatalogUrl && !cmsPublicKey) {
  console.error('[api] CMS_CATALOG_URL is set but CMS_PUBLIC_KEY is missing: definitions cannot be verified. Run "npm run setup" or unset CMS_CATALOG_URL.');
  process.exit(1);
}

export const config = {
  port: Number(process.env.PORT ?? 4000),
  databaseUrl,
  auditSigningKey,
  dbPoolMax: Number(process.env.DB_POOL_MAX ?? 10),
  /** if-empty: seed demo data only into an empty database. reset: wipe and reseed on start (tests). */
  seedMode: seedMode as 'if-empty' | 'reset',
  /** Shared HMAC secret for control plane <-> webhook signing. Held in env, never in the database. */
  /** Signs every request to customer webhooks. */
  webhookSigningSecret: signingSecret,
  /** Accepted on webhook responses and health challenges: the current secret, then previous ones during a rotation. */
  webhookAcceptedSecrets: [signingSecret, ...previousSigningSecrets],
  webhookSigningSecretRef: 'env:WEBHOOK_SIGNING_SECRET',
  defaultWebhookUrl: process.env.DEFAULT_WEBHOOK_URL ?? 'http://localhost:4100',
  heartbeatIntervalMs: Number(process.env.HEARTBEAT_INTERVAL_MS ?? 30_000),
  /** How often every stored credential is re-tested with its provider (default 6 h; 0 = never). */
  credentialCheckIntervalMs: Number(process.env.CREDENTIAL_CHECK_INTERVAL_MS ?? 6 * 3600_000),
  sessionTtlMs: 8 * 60 * 60 * 1000,
  sessionCookie: 'tv_session',
  cookieSecure: process.env.NODE_ENV === 'production',
  executionTtlMs: 30_000,
  webhookTimeoutMs: 5_000,
  /** mTLS to customer webhooks: CA, client certificate, https-only. */
  webhookTls,
  /** Where the admin console is served; OAuth providers redirect back to <this>/oauth/callback. */
  consolePublicUrl: (process.env.CONSOLE_PUBLIC_URL ?? 'http://localhost:5173').replace(/\/$/, ''),
  /** Signed provider catalog (optional; without it only the bundled definitions are used). */
  cmsCatalogUrl,
  cmsPublicKey,
  cmsPollIntervalMs: Number(process.env.CMS_POLL_INTERVAL_MS ?? 30_000),
  /** Slack Web API base (tests and air-gapped setups point it elsewhere). */
  slackApiUrl: (process.env.SLACK_API_URL ?? 'https://slack.com/api').replace(/\/$/, ''),
  /** Where Slack sends button clicks: <this>/slack/interactions (shown in the console when configuring Slack). */
  apiPublicUrl: (process.env.API_PUBLIC_URL ?? 'http://localhost:4000').replace(/\/$/, ''),
  /**
   * Key for secrets Token Vault itself stores in its database (Slack bot token and signing
   * secret). Optional: derived from AUDIT_SIGNING_KEY when unset; set it to rotate independently.
   */
  settingsEncryptionKey: process.env.SETTINGS_ENCRYPTION_KEY ?? '',
  /**
   * Seed for the Ed25519 key that signs decision tokens (integrations not in brokered mode).
   * Optional: derived from AUDIT_SIGNING_KEY when unset. The public key is published at
   * /.well-known/jwks.json, so verifiers pick up a new key without configuration.
   */
  decisionSigningKey: process.env.DECISION_SIGNING_KEY ?? '',
  /** How long a decision token (and the decision it carries) is valid. */
  decisionTokenTtlS: Math.min(Math.max(Number(process.env.DECISION_TOKEN_TTL_S ?? 120) || 120, 10), 900),
};
