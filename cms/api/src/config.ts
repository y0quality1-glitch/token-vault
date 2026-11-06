import { createPrivateKey, createPublicKey } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { publicKeyId } from '@token-vault/shared/signing';

const envFile = resolve(import.meta.dirname, '../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

function fail(message: string): never {
  console.error(`[cms] ${message}`);
  process.exit(1);
}

const databaseUrl = process.env.CMS_DATABASE_URL ?? '';
if (!/^postgres(ql)?:\/\//.test(databaseUrl)) fail('CMS_DATABASE_URL is missing. Run "npm run setup" at the repo root, or export CMS_DATABASE_URL=postgres://…');

// Ed25519 key that signs published definitions. Only this service holds it;
// consumers pin the public key served at /catalog/v1/public-key.
let signingKey;
try {
  signingKey = createPrivateKey((process.env.CMS_SIGNING_PRIVATE_KEY ?? '').replace(/\\n/g, '\n'));
} catch {
  fail('CMS_SIGNING_PRIVATE_KEY is missing or not a PEM private key. Run "npm run setup" at the repo root.');
}
if (signingKey.asymmetricKeyType !== 'ed25519') fail('CMS_SIGNING_PRIVATE_KEY must be an Ed25519 key.');
const publicKey = createPublicKey(signingKey);

const seedMode = process.env.SEED_MODE ?? 'if-empty';
if (seedMode !== 'if-empty' && seedMode !== 'reset') fail('SEED_MODE must be "if-empty" (default) or "reset".');

// Administrators may publish a version directly (no second reviewer). Set to "false" to
// require two people for every publication (separation of duties), as in production.
const adminDirectPublish = (process.env.CMS_ADMIN_DIRECT_PUBLISH ?? 'true') !== 'false';

export const config = {
  adminDirectPublish,
  port: Number(process.env.PORT ?? 4200),
  databaseUrl,
  dbPoolMax: Number(process.env.DB_POOL_MAX ?? 5),
  signingKey,
  publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  keyId: publicKeyId(publicKey),
  seedMode: seedMode as 'if-empty' | 'reset',
  sessionCookie: 'tv_cms_session',
  sessionTtlMs: 8 * 3600_000,
  cookieSecure: process.env.NODE_ENV === 'production',
};
