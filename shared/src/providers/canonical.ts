/**
 * Canonical JSON: object keys sorted recursively, no whitespace. Two documents with the
 * same content always serialize identically, so a digest over it is stable across
 * services and storage round-trips (e.g. PostgreSQL jsonb reorders keys).
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) {
      const x = (v as Record<string, unknown>)[k];
      if (x !== undefined) out[k] = sortKeys(x);
    }
    return out;
  }
  return v;
}

/** What a CMS signature covers: a domain-separated digest, never raw JSON. */
export const SIGNATURE_CONTEXT = 'token-vault/provider-definition/v1';
export const signaturePayload = (digest: string) => `${SIGNATURE_CONTEXT}:${digest}`;

/** Kinds of signed catalog entries. Each has its own signature context. */
export type CatalogKind = 'provider' | 'secret_type';
export const CATALOG_KINDS: readonly CatalogKind[] = ['provider', 'secret_type'];
/**
 * Secret types are signed under a different context, so a signature over a provider
 * definition can never be presented as one over a secret type (or the other way round),
 * even though the CMS signs both with the same key.
 */
export const SECRET_TYPE_SIGNATURE_CONTEXT = 'token-vault/secret-type/v1';
export const signaturePayloadFor = (kind: CatalogKind, digest: string) => (kind === 'secret_type' ? `${SECRET_TYPE_SIGNATURE_CONTEXT}:${digest}` : signaturePayload(digest));

/** A published, signed provider definition as served by the CMS catalog. */
export interface SignedDefinition {
  definition: unknown;
  /** sha256 hex of canonicalJson(definition). */
  digest: string;
  /** base64 Ed25519 signature over signaturePayload(digest), by the CMS's active key. */
  signature: string;
  key_id: string;
  /**
   * Every signature of this version, one per CMS key that has signed it (the active key
   * first). During a key rotation, consumers pinning either key accept the definition.
   */
  signatures?: { key_id: string; signature: string }[];
  published_at: string;
  published_by: string;
  approved_by: string;
}
