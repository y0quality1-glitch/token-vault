import { BUNDLED_DEFINITIONS, ProviderRegistry } from '@token-vault/shared';
import { CatalogSync } from '@token-vault/shared/catalog-sync';
import { config } from '../config';

/** Definitions this webhook trusts: bundled ones, replaced and extended by the verified CMS catalog. */
export const registry = new ProviderRegistry(BUNDLED_DEFINITIONS);

export const catalogSync =
  config.cmsCatalogUrl && config.cmsPublicKey
    ? new CatalogSync({ url: config.cmsCatalogUrl, publicKeyPem: config.cmsPublicKey, registry, intervalMs: config.cmsPollIntervalMs, log: (m) => console.log(`[vault] ${m}`) })
    : null;
