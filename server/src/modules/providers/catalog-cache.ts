import { eq } from 'drizzle-orm';
import type { SignedDefinition } from '@token-vault/shared';
import type { CatalogCache, CatalogState } from '@token-vault/shared/catalog-sync';
import { db } from '../../db/client';
import { providerCatalogState } from '../../db/schema';

/** Persists this service's last verified catalog in its own database (a single row). */
export const pgCatalogCache: CatalogCache = {
  async load(): Promise<CatalogState | null> {
    const [row] = await db.select().from(providerCatalogState).where(eq(providerCatalogState.id, 1));
    if (!row) return null;
    return { envelopes: (Array.isArray(row.envelopes) ? row.envelopes : []) as SignedDefinition[], highWater: row.highWater ?? {}, savedAt: row.savedAt };
  },
  async save(state: CatalogState): Promise<void> {
    await db
      .insert(providerCatalogState)
      .values({ id: 1, envelopes: state.envelopes, highWater: state.highWater, savedAt: state.savedAt })
      .onConflictDoUpdate({ target: providerCatalogState.id, set: { envelopes: state.envelopes, highWater: state.highWater, savedAt: state.savedAt } });
  },
};
