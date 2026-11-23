import { SECRET_CATEGORIES, SECRET_CATEGORY_LABELS, type SecretTypeInfo, type SecretTypesResponse } from '@token-vault/shared';
import { notFound } from '../../lib/errors';
import { secretTypeSync, secretTypes } from './registry';

const info = (key: string): SecretTypeInfo | null => {
  const e = secretTypes.entry(key);
  return e ? { ...e.definition, categoryLabel: SECRET_CATEGORY_LABELS[e.definition.category], digest: e.digest, source: secretTypeSync ? 'catalog' : 'bundled' } : null;
};

/** The secret types the control plane trusts (spec 4.9.3): what a secret's structure is validated against. */
export default class SecretTypeService {
  /** `{ search?, filters: { category? } }`: search matches key, name, description and tags. */
  list(body: { search?: unknown; filters?: { category?: unknown } } = {}): SecretTypesResponse {
    const search = typeof body.search === 'string' ? body.search.trim().toLowerCase() : '';
    const category = typeof body.filters?.category === 'string' ? body.filters.category : '';
    const all = secretTypes.list().map((t) => info(t.key)!);
    const types = all.filter((t) => (!category || t.category === category) && (!search || [t.key, t.name, t.description, ...t.tags].some((x) => x.toLowerCase().includes(search))));
    const s = secretTypeSync?.status;
    return {
      types,
      categories: SECRET_CATEGORIES.map((key) => ({ key, label: SECRET_CATEGORY_LABELS[key], count: all.filter((t) => t.category === key).length })).filter((c) => c.count > 0),
      catalog: s ? { url: s.url, keyIds: s.keyIds, lastSuccessAt: s.lastSuccessAt, lastError: s.lastError, refused: s.refused } : null,
    };
  }

  get(key: string): SecretTypeInfo {
    const t = info(key);
    if (!t) throw notFound('Secret type');
    return t;
  }
}
