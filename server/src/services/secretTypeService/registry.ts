import { BUILTIN_SECRET_TYPES, CUSTOM_SECRET_TYPE_PREFIX, type SecretTypeDefinition } from '@token-vault/shared';
import { SecretTypeRegistry, SecretTypeSync } from '@token-vault/shared/secret-type-sync';
import { config } from '../../config';
import { db } from '../../databases/client';
import { CustomSecretTypeEntity } from '../../entities';
import { pgSecretTypeCache } from './catalogCache';

/**
 * Secret types the control plane trusts (spec 4.9.3). With a CMS, only types published in its
 * catalog and verified against the pinned key (secret-type signature context); without one,
 * the predefined types. Secrets are validated against these, so publishing a type needs no deploy.
 *
 * Organization-defined types (spec 4.9.3 K, keys starting "custom-") come from the
 * `custom_secret_types` table, cached per organization for a short time (several instances
 * converge within CUSTOM_TTL_MS; the instance that saves a type sees it at once).
 */
export const secretTypeSync =
  config.cmsCatalogUrl && config.cmsPublicKey
    ? new SecretTypeSync({ url: config.cmsCatalogUrl, publicKeyPem: config.cmsPublicKey, intervalMs: config.cmsPollIntervalMs, cache: pgSecretTypeCache, log: (m) => console.log(`[api] ${m}`) })
    : null;

export const secretTypes: SecretTypeRegistry = secretTypeSync?.registry ?? SecretTypeRegistry.bundled(BUILTIN_SECRET_TYPES);

const CUSTOM_TTL_MS = 30_000;
const customCache = new Map<string, { at: number; rows: Map<string, CustomSecretTypeEntity> }>();

export const isCustomTypeKey = (key: string) => key.startsWith(CUSTOM_SECRET_TYPE_PREFIX);

/** Loads (or refreshes) an organization's custom types into the cache; call before looking them up. */
export async function loadCustomTypes(orgId: string, force = false): Promise<CustomSecretTypeEntity[]> {
  const hit = customCache.get(orgId);
  if (hit && !force && Date.now() - hit.at < CUSTOM_TTL_MS) return [...hit.rows.values()];
  const rows = await db.findBy(CustomSecretTypeEntity, { organizationId: orgId });
  customCache.set(orgId, { at: Date.now(), rows: new Map(rows.map((r) => [r.key, r])) });
  return rows;
}

export function customTypeRow(orgId: string, key: string): CustomSecretTypeEntity | undefined {
  return customCache.get(orgId)?.rows.get(key);
}

/**
 * A type by key. Custom types need the organization (and loadCustomTypes first); an archived
 * custom type still resolves, so its existing secrets keep working.
 */
export const getSecretType = (key: string, orgId?: string): SecretTypeDefinition | undefined =>
  isCustomTypeKey(key) ? (orgId ? customTypeRow(orgId, key)?.definition : undefined) : secretTypes.get(key);
