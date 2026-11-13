import type { ProvidersResponse } from '@token-vault/shared';
import { notFound } from '../../lib/errors';
import { catalogSync, providerInfo, registry } from './registry';

/** Providers the control plane currently trusts (bundled or verified from the CMS catalog). */
export default class ProviderService {
  list(): ProvidersResponse {
    return {
      providers: registry.list().map(providerInfo),
      catalog: catalogSync ? { url: catalogSync.status.url, keyIds: catalogSync.status.keyIds, lastSuccessAt: catalogSync.status.lastSuccessAt, lastError: catalogSync.status.lastError, restoredFrom: catalogSync.status.restored?.savedAt ?? null } : null,
    };
  }

  get(key: string) {
    const entry = registry.entry(key);
    if (!entry) throw notFound('Provider');
    return providerInfo(entry);
  }
}
