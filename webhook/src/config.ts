import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DEFAULT_WEBHOOK_INSTANCE_ID } from '@token-vault/shared';
import { parseUpstreamModes, type UpstreamMode } from './upstream-modes';
import { buildKeyring, parseKey, type Keyring } from './security/keyring';
import type { KeyProvider } from './security/key-provider';
import { parseKeyProviderConfig, type KeyProviderConfig } from './security/provider-config';
import { awsKmsProvider } from './security/providers/aws-kms';
import { vaultTransitProvider } from './security/providers/vault-transit';
import { loadTlsConfig, type TlsConfig } from './security/tls';

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

// The current key encrypts everything new. Previous keys (comma-separated) only decrypt
// records written before a rotation; the store re-encrypts those under the current key at
// start-up, after which a previous key can be removed (see docs: encryption key rotation).
//
// With a KMS (VAULT_KEY_PROVIDER=aws-kms|vault-transit), records are sealed with per-record data
// keys wrapped by the KMS; VAULT_ENCRYPTION_KEY is then optional and only opens older records.
let keyring: Keyring | null = null;
let keyProviderConfig: KeyProviderConfig;
let dataKeyCacheSeconds: number;
try {
  ({ provider: keyProviderConfig, cacheSeconds: dataKeyCacheSeconds } = parseKeyProviderConfig(process.env));
  const envKey = process.env.VAULT_ENCRYPTION_KEY?.trim();
  if (keyProviderConfig.kind === 'env' && !envKey) required('VAULT_ENCRYPTION_KEY', 40);
  if (envKey) {
    keyring = buildKeyring(
      parseKey(envKey, 'VAULT_ENCRYPTION_KEY'),
      (process.env.VAULT_PREVIOUS_ENCRYPTION_KEYS ?? '').split(',').map((k) => k.trim()).filter(Boolean).map((k, i) => parseKey(k, `VAULT_PREVIOUS_ENCRYPTION_KEYS (entry ${i + 1})`)),
    );
  }
} catch (e) {
  console.error(`[vault] ${(e as Error).message}.`);
  process.exit(1);
}
// HTTPS and client-certificate (mTLS) settings for the control plane -> webhook link.
let tls: TlsConfig | null = null;
try {
  tls = loadTlsConfig(process.env);
} catch (e) {
  console.error(`[vault] ${(e as Error).message}.`);
  process.exit(1);
}

const keyProvider: KeyProvider | null =
  keyProviderConfig.kind === 'aws-kms' ? awsKmsProvider(keyProviderConfig) : keyProviderConfig.kind === 'vault-transit' ? vaultTransitProvider(keyProviderConfig) : null;

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

/**
 * Provider definitions are pulled from the CMS catalog and verified against this pinned
 * public key. The webhook trusts the CMS key directly, not the control plane: nothing the
 * control plane sends can change where this webhook sends customer credentials.
 */
function readCmsPublicKey(): string | undefined {
  const file = process.env.CMS_PUBLIC_KEY_FILE;
  if (file) return readFileSync(file, 'utf8');
  const inline = process.env.CMS_PUBLIC_KEY;
  return inline ? inline.replace(/\\n/g, '\n') : undefined;
}
const cmsCatalogUrl = process.env.CMS_CATALOG_URL || undefined;
const cmsPublicKey = readCmsPublicKey();
if (cmsCatalogUrl && !cmsPublicKey) {
  console.error('[vault] CMS_CATALOG_URL is set but CMS_PUBLIC_KEY is missing: definitions cannot be verified. Run "npm run setup" or unset CMS_CATALOG_URL.');
  process.exit(1);
}

let modes: ReturnType<typeof parseUpstreamModes>;
try {
  modes = parseUpstreamModes(process.env);
} catch (e) {
  console.error(`[vault] ${(e as Error).message}.`);
  process.exit(1);
}
const { defaultMode, providerModes } = modes;

// Signing-secret rotation: previous secrets are accepted (and answered with) until removed,
// so the webhook can switch first and the control plane after, without failed requests.
const signingSecret = required('WEBHOOK_SIGNING_SECRET', 32);
const previousSigningSecrets = (process.env.WEBHOOK_PREVIOUS_SIGNING_SECRETS ?? '').split(',').map((v) => v.trim()).filter((v) => v && v !== signingSecret);
if (previousSigningSecrets.some((v) => v.length < 32)) {
  console.error('[vault] every WEBHOOK_PREVIOUS_SIGNING_SECRETS entry must be at least 32 characters.');
  process.exit(1);
}

export const config = {
  /** Whether calls for this application go to the real API ("live") or the simulators ("mock"). */
  modeFor: (provider: string): UpstreamMode => providerModes[provider] ?? defaultMode,
  providerModes,
  port: Number(process.env.PORT ?? 4100),
  signingSecret,
  /** Accepted when verifying the control plane: the current secret, then previous ones during a rotation. */
  signingSecrets: [signingSecret, ...previousSigningSecrets],
  /** Current environment AES-256 key (env-mode sealing, env-mode fingerprints); null with a KMS and no legacy key. */
  get encryptionKey(): Buffer | null {
    return this.keyring?.current.key ?? null;
  },
  /** Environment keys (current and previous); records name the key that encrypted them. Null with a KMS and no legacy key. */
  keyring,
  /** HTTPS / mTLS settings, or null for plain HTTP. */
  tls,
  /** The KMS wrapping per-record data keys, or null in env mode. */
  keyProvider,
  keyProviderKind: keyProviderConfig.kind,
  dataKeyCacheSeconds,
  /** Ref of the key new records are written with (derived, so a rotated keyring is reflected). */
  get encryptionKeyRef(): string {
    return this.keyProvider?.ref ?? this.keyring!.current.ref;
  },
  instanceId: process.env.WEBHOOK_INSTANCE_ID ?? DEFAULT_WEBHOOK_INSTANCE_ID,
  /** The default upstream mode (applications without an override in PROVIDER_MODES). */
  githubMode: defaultMode,
  databaseUrl,
  /** Optional GitHub App private key held only by this webhook (PEM; literal "\n" sequences allowed). */
  githubAppPrivateKey: readAppKey(),
  dbPoolMax: Number(process.env.DB_POOL_MAX ?? 5),
  /** Signed provider catalog (optional; without it only the bundled definitions are used). */
  cmsCatalogUrl,
  cmsPublicKey,
  cmsPollIntervalMs: Number(process.env.CMS_POLL_INTERVAL_MS ?? 30_000),
  /**
   * WEBHOOK_ALLOW_DESTRUCTIVE=true lets this webhook run destructive operations (delete a
   * repository, overwrite a file), and then only for requests a human approved in Token Vault.
   * Off by default: the customer decides whether destructive actions can ever run.
   */
  allowDestructive: process.env.WEBHOOK_ALLOW_DESTRUCTIVE === 'true',
  /** Lifetime of access tokens issued by the simulated OAuth server (mock mode only). */
  mockOAuthTokenTtlS: Number(process.env.MOCK_OAUTH_TOKEN_TTL_S ?? 3600),
  /** if-missing: (re)create demo mock credentials only where absent or unreadable. reset: wipe the store first (tests). */
  seedMode: seedMode as 'if-missing' | 'reset',
  /** Pre-PostgreSQL JSON store; imported once on startup if present, then renamed. */
  legacyDataFile: process.env.WEBHOOK_DATA_FILE ?? resolve(import.meta.dirname, '../data/vault-store.json'),
  version: '0.1.0-poc',
  maxClockSkewMs: 60_000,
  maxExecutionTtlMs: 60_000,
};
