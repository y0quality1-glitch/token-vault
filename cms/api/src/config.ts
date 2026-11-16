import { createHash, createPrivateKey, createPublicKey, hkdfSync, type KeyObject } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { publicKeyId } from '@token-vault/shared/signing';

/**
 * Configuration (template: src/config.ts). Loads `.env.<env>` for NODE_ENV (`.env.dev`,
 * `.env.uat`, `.env.beta`, `.env.prod`), else `.env` (written by `npm run setup`). Variables
 * already set in the environment win. Every value is validated here, so a missing or bad
 * setting stops the service at start-up instead of failing a request later.
 */
export enum ENV {
  DEVELOPMENT = 'development',
  PRODUCTION = 'production',
  UAT = 'uat',
  BETA = 'beta',
  TEST = 'test',
}

const nodeEnv = (process.env.NODE_ENV ?? ENV.DEVELOPMENT).trim().toLowerCase();
const envFileFor: Record<string, string> = { [ENV.DEVELOPMENT]: '.env.dev', [ENV.UAT]: '.env.uat', [ENV.BETA]: '.env.beta', [ENV.PRODUCTION]: '.env.prod' };
for (const name of [envFileFor[nodeEnv], '.env']) {
  const file = name && resolve(import.meta.dirname, '..', name);
  if (file && existsSync(file)) {
    process.loadEnvFile(file);
    break;
  }
}

function fail(message: string): never {
  console.error(`[cms] ${message}`);
  process.exit(1);
}

export const NodeEnvironment = nodeEnv;
export const IS_PRODUCTION = nodeEnv === ENV.PRODUCTION;

/** Every admin route is mounted under this prefix; the signed catalog stays at /catalog/v1. */
export const PATH = '/api/v1';
export const CATALOG_PATH = '/catalog/v1';
export const PORT = Number(process.env.PORT ?? 4200);

// ---------------------------------------------------------------- database
const databaseUrl = process.env.CMS_DATABASE_URL ?? '';
if (!/^postgres(ql)?:\/\//.test(databaseUrl)) fail('CMS_DATABASE_URL is missing. Run "npm run setup" at the repo root, or export CMS_DATABASE_URL=postgres://…');
const readUrl = process.env.CMS_DATABASE_READ_URL ?? '';
if (readUrl && !/^postgres(ql)?:\/\//.test(readUrl)) fail('CMS_DATABASE_READ_URL must be a postgres:// URL (a read replica), or unset.');
const sslMode = (process.env.CMS_DATABASE_SSL ?? 'off').toLowerCase();
if (!['off', 'require'].includes(sslMode)) fail('CMS_DATABASE_SSL must be "off" (default) or "require" (TLS with certificate validation).');

export const DB_URL = databaseUrl;
/** Optional read replica: reads go to it, writes and transactions to CMS_DATABASE_URL. */
export const DB_READ_URL = readUrl || null;
/** TLS with certificate validation; the CA comes from NODE_EXTRA_CA_CERTS when it isn't a public one. */
export const DB_SSL = sslMode === 'require';
export const DB_POOL_MAX = Number(process.env.DB_POOL_MAX ?? 5);

// ---------------------------------------------------------------- signing
// Ed25519 key that signs published definitions. Only this service holds it;
// consumers pin the public key served at /catalog/v1/public-key.
let signingKey: KeyObject;
try {
  signingKey = createPrivateKey((process.env.CMS_SIGNING_PRIVATE_KEY ?? '').replace(/\\n/g, '\n'));
} catch {
  fail('CMS_SIGNING_PRIVATE_KEY is missing or not a PEM private key. Run "npm run setup" at the repo root.');
}
if (signingKey.asymmetricKeyType !== 'ed25519') fail('CMS_SIGNING_PRIVATE_KEY must be an Ed25519 key.');
const publicKey = createPublicKey(signingKey);
/** The active signing key. An object (read at use time) so a key rotation can be exercised in tests. */
export const SIGNING: { key: KeyObject; publicKeyPem: string; keyId: string } = {
  key: signingKey,
  publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  keyId: publicKeyId(publicKey),
};

// ---------------------------------------------------------------- auth
/**
 * HS256 secret for session tokens (JWT). Required in production. Elsewhere it is derived from
 * the signing key with its own label when unset, so a fresh checkout works without one.
 */
const jwtSecretEnv = process.env.CMS_JWT_SECRET ?? '';
if (jwtSecretEnv && jwtSecretEnv.length < 32) fail('CMS_JWT_SECRET must be at least 32 characters.');
if (!jwtSecretEnv && IS_PRODUCTION) fail('CMS_JWT_SECRET is required in production (32+ random characters).');
export const JWT_SECRET_KEY =
  jwtSecretEnv ||
  Buffer.from(hkdfSync('sha256', signingKey.export({ type: 'pkcs8', format: 'der' }), 'token-vault-cms', 'cms/jwt-session/v1', 32)).toString('base64url');
export const JWT_ISSUER = 'token-vault-cms';
export const SESSION_TTL_S = 8 * 3600;
export const SESSION_COOKIE = 'tv_cms_session';
export const COOKIE_SECURE = IS_PRODUCTION;
/** Fingerprint for logs only (never the secret). */
export const JWT_KEY_FINGERPRINT = createHash('sha256').update(JWT_SECRET_KEY).digest('hex').slice(0, 8);

// ---------------------------------------------------------------- behaviour
const seedMode = process.env.SEED_MODE ?? 'if-empty';
if (seedMode !== 'if-empty' && seedMode !== 'reset') fail('SEED_MODE must be "if-empty" (default) or "reset".');
export const SEED_MODE = seedMode as 'if-empty' | 'reset';

// Administrators may publish a version directly (no second reviewer). Set to "false" to
// require two people for every publication (separation of duties), as in production.
export const SETTINGS = { adminDirectPublish: (process.env.CMS_ADMIN_DIRECT_PUBLISH ?? 'true') !== 'false' };

/** Browser origins allowed to call the API cross-origin (comma-separated). Default: none (same origin through the CMS UI's proxy). */
export const CORS_ORIGINS = (process.env.CMS_CORS_ORIGINS ?? '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

/** Paging limits for /getall routes (template fix B-09: never return a whole table). */
export const PAGE_SIZE_DEFAULT = 25;
export const PAGE_SIZE_MAX = 200;

// ---------------------------------------------------------------- response contract
export enum StatusCode {
  SUCCESS = '10000',
  FAILURE = '10001',
  RETRY = '10002',
  INVALID_ACCESS_TOKEN = '10003',
}

export enum ResponseStatus {
  SUCCESS = 200,
  CREATED = 201,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  METHOD_NOT_FOUND = 405,
  CONFLICT = 409,
  INTERNAL_ERROR = 500,
}
