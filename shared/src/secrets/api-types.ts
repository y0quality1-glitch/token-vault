import type { SecretCategory, SecretTypeDefinition } from './schema';

/** A secret type as the control plane serves it (definition plus where it came from). */
export interface SecretTypeInfo extends SecretTypeDefinition {
  categoryLabel: string;
  /** sha256 of the canonical definition (as signed by the CMS). */
  digest: string;
  /** catalog: verified from the CMS; bundled: predefined (no CMS configured). */
  source: 'catalog' | 'bundled';
}

export interface SecretTypesResponse {
  types: SecretTypeInfo[];
  categories: { key: SecretCategory; label: string; count: number }[];
  /** Catalog sync state (null when the predefined types are used, without a CMS). */
  catalog: { url: string; keyIds: string[]; lastSuccessAt: string | null; lastError: string | null; refused: string[] } | null;
}
