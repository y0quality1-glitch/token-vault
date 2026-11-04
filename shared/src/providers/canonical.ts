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

/** A published, signed provider definition as served by the CMS catalog. */
export interface SignedDefinition {
  definition: unknown;
  /** sha256 hex of canonicalJson(definition). */
  digest: string;
  /** base64 Ed25519 signature over signaturePayload(digest). */
  signature: string;
  key_id: string;
  published_at: string;
  published_by: string;
  approved_by: string;
}
