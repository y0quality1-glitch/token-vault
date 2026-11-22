import { SECRET_CATEGORY_LABELS, type CmsApplicationSummary, type SecretCategory } from '@token-vault/shared';

/** The kinds of CMS catalog entries. Both share the draft → review → sign → publish workflow. */
export type CatalogKind = CmsApplicationSummary['kind'];

export interface KindConfig {
  /** Console route prefix. */
  basePath: string;
  /** Admin API route prefix (getall, getbyid, save, newversion, archive). */
  apiBase: string;
  /** Plural, as a page title or breadcrumb. */
  plural: string;
  /** Singular, capitalized. */
  singular: string;
  /** Singular, in a sentence. */
  noun: string;
  /** Digest signing context shown on the Signature tab. */
  signatureContext: string;
}

export const KINDS: Record<CatalogKind, KindConfig> = {
  provider: {
    basePath: '/applications',
    apiBase: '/application',
    plural: 'Applications',
    singular: 'Application',
    noun: 'application',
    signatureContext: 'token-vault/provider-definition/v1',
  },
  secret_type: {
    basePath: '/secret-types',
    apiBase: '/secretType',
    plural: 'Secret types',
    singular: 'Secret type',
    noun: 'secret type',
    signatureContext: 'token-vault/secret-type/v1',
  },
};

export const secretCategoryLabel = (c: string) => SECRET_CATEGORY_LABELS[c as SecretCategory] ?? c;
