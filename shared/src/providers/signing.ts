import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import { canonicalJson, signaturePayload, type SignedDefinition } from './canonical';
import { validateProviderDefinition, type ProviderDefinition } from './schema';

/**
 * Node-only helpers for verifying CMS-signed definitions (import "@token-vault/shared/signing").
 * Consumers pin one or more CMS public keys (several during a key rotation). A definition
 * is used only if its digest matches its content, at least one of its signatures verifies
 * with a pinned key, and it passes validation.
 */
export function definitionDigest(definition: unknown): string {
  return createHash('sha256').update(canonicalJson(definition)).digest('hex');
}

export function publicKeyId(key: KeyObject): string {
  return createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 16);
}

export class SignatureError extends Error {}

/** Pinned keys by key id. */
export type PinnedKeys = Map<string, KeyObject>;

/**
 * Parses one or more PEM public keys (concatenated, as in CMS_PUBLIC_KEY during a
 * rotation). Throws if there is none or one is malformed.
 */
export function parsePinnedKeys(pemBundle: string): PinnedKeys {
  const blocks = pemBundle.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g) ?? [];
  if (blocks.length === 0) throw new Error('no PEM public key found');
  const keys: PinnedKeys = new Map();
  for (const pem of blocks) {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('pinned CMS keys must be Ed25519');
    keys.set(publicKeyId(key), key);
  }
  return keys;
}

/** Every signature an envelope carries (older envelopes have only the primary one). */
export function signaturesOf(envelope: SignedDefinition): { key_id: string; signature: string }[] {
  return envelope.signatures?.length ? envelope.signatures : [{ key_id: envelope.key_id, signature: envelope.signature }];
}

export function verifySignedDefinition(envelope: SignedDefinition, pinned: string | PinnedKeys): ProviderDefinition {
  const keys = typeof pinned === 'string' ? parsePinnedKeys(pinned) : pinned;
  const candidates = signaturesOf(envelope).filter((s) => keys.has(s.key_id));
  if (candidates.length === 0) throw new SignatureError('signed with an unknown key');
  if (definitionDigest(envelope.definition) !== envelope.digest) throw new SignatureError('digest does not match the definition');
  const payload = Buffer.from(signaturePayload(envelope.digest));
  const ok = candidates.some((s) => {
    try {
      return verify(null, payload, keys.get(s.key_id)!, Buffer.from(s.signature, 'base64'));
    } catch {
      return false;
    }
  });
  if (!ok) throw new SignatureError('signature does not verify');
  return validateProviderDefinition(envelope.definition);
}
