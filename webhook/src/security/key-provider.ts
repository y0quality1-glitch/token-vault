import { randomBytes } from 'node:crypto';
import { open, seal, type Sealed } from './encryption';

/**
 * A key management service that protects the credential store's data keys (envelope
 * encryption). Each credential is sealed with its own random 256-bit data key; the KMS
 * encrypts ("wraps") that data key, and only the wrapped form is stored next to the
 * ciphertext. The master key never leaves the KMS, and every unwrap is logged there.
 */
export interface KeyProvider {
  kind: 'aws-kms' | 'vault-transit';
  /** Stored in each record: names the master key, never contains key material. */
  ref: string;
  /** Wraps a data key. `context` is authenticated (AWS: encryption context) and must be given again to unwrap. */
  wrap(dataKey: Buffer, context: Record<string, string>): Promise<string>;
  /** Unwraps a data key. `recordRef` is the key ref stored with the record (it may name an earlier master key). */
  unwrap(wrapped: string, context: Record<string, string>, recordRef: string): Promise<Buffer>;
  /** Whether this provider can unwrap a record whose key ref is `ref`. */
  handles(ref: string): boolean;
}

/** The KMS could not be reached or throttled us: retry later. Never means the credential is bad. */
export class KeyServiceUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyServiceUnavailableError';
  }
}

/** The KMS refused (no permission, wrong key, tampered or foreign ciphertext): the record cannot be opened. */
export class KeyAccessDeniedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyAccessDeniedError';
  }
}

/** Short-lived cache of unwrapped data keys, so a request does not always need a KMS call. */
export class DataKeyCache {
  #entries = new Map<string, { key: Buffer; expires: number }>();
  constructor(
    private ttlMs: number,
    private max = 1000,
  ) {}

  get(wrapped: string, now = Date.now()): Buffer | null {
    const hit = this.#entries.get(wrapped);
    if (!hit) return null;
    if (hit.expires <= now) {
      this.#drop(wrapped);
      return null;
    }
    return hit.key;
  }

  set(wrapped: string, key: Buffer, now = Date.now()) {
    if (this.ttlMs <= 0) return;
    if (this.#entries.size >= this.max) this.#drop(this.#entries.keys().next().value!);
    this.#entries.set(wrapped, { key: Buffer.from(key), expires: now + this.ttlMs });
  }

  clear() {
    for (const k of [...this.#entries.keys()]) this.#drop(k);
  }

  get size() {
    return this.#entries.size;
  }

  #drop(wrapped: string) {
    this.#entries.get(wrapped)?.key.fill(0); // do not leave key bytes around
    this.#entries.delete(wrapped);
  }
}

/** Authenticated context binding a wrapped data key to its credential (a moved key cannot be unwrapped for another record). */
export const recordContext = (credentialRef: string) => ({ token_vault_credential_ref: credentialRef });

/** Seals a secret with a fresh data key wrapped by the provider. */
export async function sealEnvelope(provider: KeyProvider, plaintext: string, credentialRef: string): Promise<{ sealed: Sealed; wrappedKey: string; ref: string }> {
  const dataKey = randomBytes(32);
  try {
    const sealed = seal(dataKey, plaintext, credentialRef);
    const wrappedKey = await provider.wrap(dataKey, recordContext(credentialRef));
    return { sealed, wrappedKey, ref: provider.ref };
  } finally {
    dataKey.fill(0);
  }
}

/** Opens an envelope-sealed record. Throws KeyServiceUnavailableError, KeyAccessDeniedError, or a decryption error. */
export async function openEnvelope(provider: KeyProvider, cache: DataKeyCache, sealed: Sealed, wrappedKey: string, credentialRef: string, recordRef: string): Promise<string> {
  let dataKey = cache.get(wrappedKey);
  if (!dataKey) {
    dataKey = await provider.unwrap(wrappedKey, recordContext(credentialRef), recordRef);
    if (dataKey.length !== 32) throw new KeyAccessDeniedError('the key service returned a data key of the wrong length');
    cache.set(wrappedKey, dataKey);
  }
  return open(dataKey, sealed, credentialRef);
}
