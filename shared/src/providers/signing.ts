import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import { canonicalJson, signaturePayload, type SignedDefinition } from './canonical';
import { validateProviderDefinition, type ProviderDefinition } from './schema';

/**
 * Node-only helpers for verifying CMS-signed definitions (import "@token-vault/shared/signing").
 * Consumers pin the CMS public key; a definition is used only if its digest matches its
 * content, the signature verifies, and it passes validation.
 */
export function definitionDigest(definition: unknown): string {
  return createHash('sha256').update(canonicalJson(definition)).digest('hex');
}

export function publicKeyId(key: KeyObject): string {
  return createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 16);
}

export class SignatureError extends Error {}

export function verifySignedDefinition(envelope: SignedDefinition, publicKeyPem: string): ProviderDefinition {
  const key = createPublicKey(publicKeyPem);
  if (envelope.key_id !== publicKeyId(key)) throw new SignatureError('signed with an unknown key');
  if (definitionDigest(envelope.definition) !== envelope.digest) throw new SignatureError('digest does not match the definition');
  if (!verify(null, Buffer.from(signaturePayload(envelope.digest)), key, Buffer.from(envelope.signature, 'base64'))) throw new SignatureError('signature does not verify');
  return validateProviderDefinition(envelope.definition);
}
