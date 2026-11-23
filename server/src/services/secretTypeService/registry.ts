import { BUILTIN_SECRET_TYPES, type SecretTypeDefinition } from '@token-vault/shared';
import { SecretTypeRegistry, SecretTypeSync } from '@token-vault/shared/secret-type-sync';
import { config } from '../../config';
import { pgSecretTypeCache } from './catalogCache';

/**
 * Secret types the control plane trusts (spec 4.9.3). With a CMS, only types published in its
 * catalog and verified against the pinned key (secret-type signature context); without one,
 * the predefined types. Secrets are validated against these, so publishing a type needs no deploy.
 */
export const secretTypeSync =
  config.cmsCatalogUrl && config.cmsPublicKey
    ? new SecretTypeSync({ url: config.cmsCatalogUrl, publicKeyPem: config.cmsPublicKey, intervalMs: config.cmsPollIntervalMs, cache: pgSecretTypeCache, log: (m) => console.log(`[api] ${m}`) })
    : null;

export const secretTypes: SecretTypeRegistry = secretTypeSync?.registry ?? SecretTypeRegistry.bundled(BUILTIN_SECRET_TYPES);

export const getSecretType = (key: string): SecretTypeDefinition | undefined => secretTypes.get(key);
