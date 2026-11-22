import { eq } from 'drizzle-orm';
import { BUILTIN_SECRET_TYPES, type SignedDefinition } from '@token-vault/shared';
import type { CatalogCache, CatalogState } from '@token-vault/shared/catalog-sync';
import { SecretTypeRegistry, SecretTypeSync } from '@token-vault/shared/secret-type-sync';
import { config } from '../config';
import { db } from '../db/client';
import { providerCatalogState } from '../db/schema';

/** Row of provider_catalog_state holding the verified secret types (row 1 holds the provider catalog). */
const SECRET_TYPES_ROW = 2;

const cache: CatalogCache = {
  async load(): Promise<CatalogState | null> {
    const [row] = await db.select().from(providerCatalogState).where(eq(providerCatalogState.id, SECRET_TYPES_ROW));
    if (!row) return null;
    return { envelopes: (Array.isArray(row.envelopes) ? row.envelopes : []) as SignedDefinition[], highWater: row.highWater ?? {}, savedAt: row.savedAt };
  },
  async save(state: CatalogState): Promise<void> {
    await db
      .insert(providerCatalogState)
      .values({ id: SECRET_TYPES_ROW, envelopes: state.envelopes, highWater: state.highWater, savedAt: state.savedAt })
      .onConflictDoUpdate({ target: providerCatalogState.id, set: { envelopes: state.envelopes, highWater: state.highWater, savedAt: state.savedAt } });
  },
};

/**
 * Secret types this webhook trusts, verified by the webhook itself against the pinned CMS key.
 * A secret's value is validated against these before it is encrypted and stored, so the
 * control plane cannot make the webhook accept a structure the CMS never published.
 */
export const secretTypeSync =
  config.cmsCatalogUrl && config.cmsPublicKey
    ? new SecretTypeSync({ url: config.cmsCatalogUrl, publicKeyPem: config.cmsPublicKey, intervalMs: config.cmsPollIntervalMs, cache, log: (m) => console.log(`[vault] ${m}`) })
    : null;

export const secretTypes: SecretTypeRegistry = secretTypeSync?.registry ?? SecretTypeRegistry.bundled(BUILTIN_SECRET_TYPES);
