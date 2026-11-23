import type { SignedDefinition } from '@token-vault/shared';
import type { CatalogCache, CatalogState } from '@token-vault/shared/catalog-sync';
import { db } from '../../databases/client';
import { ProviderCatalogStateEntity } from '../../entities';

/** Row of provider_catalog_state holding the verified secret types (row 1 holds the provider catalog). */
const SECRET_TYPES_ROW = 2;

/** Persists the last verified secret types, so a restart without the CMS keeps them (re-verified on load). */
export const pgSecretTypeCache: CatalogCache = {
  async load(): Promise<CatalogState | null> {
    const row = await db.findOneBy(ProviderCatalogStateEntity, { id: SECRET_TYPES_ROW });
    if (!row) return null;
    return { envelopes: (Array.isArray(row.envelopes) ? row.envelopes : []) as SignedDefinition[], highWater: row.highWater ?? {}, savedAt: row.savedAt };
  },
  async save(state: CatalogState): Promise<void> {
    await db.upsert(ProviderCatalogStateEntity, { id: SECRET_TYPES_ROW, envelopes: state.envelopes, highWater: state.highWater, savedAt: state.savedAt } as never, ['id']);
  },
};
