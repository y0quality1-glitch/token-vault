import { createHash } from 'node:crypto';
import { open, seal, type Sealed } from './encryption';

/**
 * Encryption keys of the credential store: the current key (encrypts everything new) and
 * any previous keys (still decrypt records written before a rotation, until those records
 * are re-encrypted). Each record stores the ref of the key that encrypted it; a key ref
 * names the key by a one-way id, never by its value.
 */
export interface VaultKey {
  id: string;
  ref: string;
  key: Buffer;
}

export interface Keyring {
  current: VaultKey;
  previous: VaultKey[];
}

/** Ref written by versions that had a single, unnamed key. Such records are tried against every key. */
export const LEGACY_KEY_REF = 'env:VAULT_ENCRYPTION_KEY#v1';

/** One-way id of a key: identifies it in records and logs without revealing it. */
export function keyIdOf(key: Buffer): string {
  return 'kid_' + createHash('sha256').update('token-vault/vault-key-id:').update(key).digest('hex').slice(0, 16);
}

function vaultKey(key: Buffer, role: string): VaultKey {
  const id = keyIdOf(key);
  return { id, ref: `env:${role}#${id}`, key };
}

/** Parses base64 AES-256 keys (32 bytes each). Throws with the variable name on anything else. */
export function parseKey(value: string, name: string): Buffer {
  const key = Buffer.from(value.trim(), 'base64');
  if (key.length !== 32) throw new Error(`${name} must be base64 of exactly 32 bytes (AES-256)`);
  return key;
}

export function buildKeyring(current: Buffer, previous: Buffer[] = []): Keyring {
  const cur = vaultKey(current, 'VAULT_ENCRYPTION_KEY');
  const seen = new Set([cur.id]);
  const prev: VaultKey[] = [];
  for (const k of previous) {
    const v = vaultKey(k, 'VAULT_PREVIOUS_ENCRYPTION_KEYS');
    if (seen.has(v.id)) continue; // the current key listed again, or a duplicate
    seen.add(v.id);
    prev.push(v);
  }
  return { current: cur, previous: prev };
}

/** The id a stored key ref names, or null for legacy and unknown refs. */
export function idInRef(ref: string): string | null {
  return /#(kid_[0-9a-f]{16})$/.exec(ref)?.[1] ?? null;
}

/**
 * Decrypts with the key the record names; legacy records (no key id) are tried against the
 * current key, then each previous key. Returns the plaintext and the key that opened it.
 */
export function openWith(ring: Keyring, sealed: Sealed, aad: string, ref: string): { plaintext: string; key: VaultKey } | null {
  const all = [ring.current, ...ring.previous];
  const named = idInRef(ref);
  const candidates = named ? all.filter((k) => k.id === named) : all;
  for (const k of candidates) {
    try {
      return { plaintext: open(k.key, sealed, aad), key: k };
    } catch {
      /* try the next key */
    }
  }
  return null;
}

/** Encrypts with the current key. */
export function sealWith(ring: Keyring, plaintext: string, aad: string): { sealed: Sealed; ref: string } {
  return { sealed: seal(ring.current.key, plaintext, aad), ref: ring.current.ref };
}
