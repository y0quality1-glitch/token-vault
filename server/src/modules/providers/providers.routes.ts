import { Router } from 'express';
import type { ProvidersResponse } from '@token-vault/shared';
import { notFound } from '../../lib/errors';
import { catalogSync, providerInfo, registry } from './registry';

export const providersRouter = Router();

/** Providers the control plane currently trusts (bundled or verified from the CMS catalog). */
providersRouter.get('/providers', (_req, res) => {
  const body: ProvidersResponse = {
    providers: registry.list().map(providerInfo),
    catalog: catalogSync ? { url: catalogSync.status.url, keyIds: catalogSync.status.keyIds, lastSuccessAt: catalogSync.status.lastSuccessAt, lastError: catalogSync.status.lastError, restoredFrom: catalogSync.status.restored?.savedAt ?? null } : null,
  };
  res.json(body);
});

providersRouter.get('/providers/:key', (req, res) => {
  const entry = registry.entry(String(req.params.key));
  if (!entry) throw notFound('Provider');
  res.json(providerInfo(entry));
});
