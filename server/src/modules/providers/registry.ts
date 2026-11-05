import { BUNDLED_DEFINITIONS, ProviderRegistry, catalogOf, operationsOf, type CatalogItem, type OperationDef, type ProviderInfo, type RegistryEntry } from '@token-vault/shared';
import { CatalogSync } from '@token-vault/shared/catalog-sync';
import { pgCatalogCache } from './catalog-cache';
import { config } from '../../config';

/**
 * Provider definitions the control plane trusts: bundled ones, replaced and extended by
 * the CMS catalog after signature verification. Operations, the integration catalog and
 * grantable scopes are all derived from here, so publishing in the CMS needs no deploy.
 */
export const registry = new ProviderRegistry(BUNDLED_DEFINITIONS);

export const catalogSync =
  config.cmsCatalogUrl && config.cmsPublicKey
    ? new CatalogSync({ url: config.cmsCatalogUrl, publicKeyPem: config.cmsPublicKey, registry, intervalMs: config.cmsPollIntervalMs, cache: pgCatalogCache, log: (m) => console.log(`[api] ${m}`) })
    : null;

let cache: { operations: OperationDef[]; catalog: CatalogItem[] } | null = null;
registry.onChange(() => {
  cache = null;
});
function derived() {
  cache ??= { operations: operationsOf(registry.definitions()), catalog: catalogOf(registry.definitions()) };
  return cache;
}

export const operations = (): OperationDef[] => derived().operations;
export const grantableOperationIds = (): string[] => operations().filter((o) => o.grantable).map((o) => o.id);
export const getOperation = (id: string): OperationDef | undefined => operations().find((o) => o.id === id);
export const providerCatalog = (): CatalogItem[] => derived().catalog;

export function providerInfo(e: RegistryEntry): ProviderInfo {
  const d = e.definition;
  const ops = operations().filter((o) => o.provider === d.key);
  return {
    key: d.key,
    name: d.name,
    description: d.description,
    version: d.version,
    source: e.source,
    digest: e.digest,
    catalog: { category: d.catalog.category, icon: d.catalog.icon, availability: d.catalog.availability, docsUrl: d.catalog.docsUrl ?? null, tags: d.catalog.tags },
    resource: { name: d.resource.name, label: d.resource.label, pattern: d.resource.pattern, example: d.resource.example },
    resourceFields: Object.fromEntries(Object.entries(d.resourceFields).map(([k, f]) => [k, { label: f.label, pattern: f.pattern, example: f.example }])),
    auth: d.auth.map((a) => ({ id: a.id, label: a.label, description: a.description, kind: a.kind, plugin: a.plugin, secretHint: a.secretHint, secretPattern: a.secretPattern, ...(a.oauth ? { oauth: { authorizeHost: new URL(a.oauth.authorizeUrl).host, scopes: a.oauth.scopes } } : {}) })),
    operations: ops.map((o) => ({ ...o, input: d.operations.find((x) => x.id === o.id)!.input })),
  };
}

/** Schema-level check for resource values; the provider's own pattern is applied where the provider is known. */
export const GENERIC_RESOURCE = /^[^\s,]{1,200}$/;

/** A field error if any value does not match the provider's primary-resource pattern. */
export function resourceProblem(provider: string, values: string[]): string | null {
  const def = registry.get(provider);
  if (!def) return `Unknown provider "${provider}"`;
  const re = new RegExp(def.resource.pattern);
  const bad = values.filter((v) => !re.test(v));
  return bad.length ? `Not a valid ${def.resource.label.toLowerCase()} for ${def.name}: ${bad.join(', ')}${def.resource.example ? ` (e.g. ${def.resource.example})` : ''}` : null;
}

/** Operations that do not belong to the provider. */
export function foreignOperations(provider: string, ids: string[]): string[] {
  return ids.filter((id) => getOperation(id)?.provider !== provider);
}
