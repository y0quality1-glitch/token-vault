import { createHash, randomBytes, scryptSync, sign, timingSafeEqual } from 'node:crypto';
import { signaturePayload } from '@token-vault/shared';
import { definitionDigest } from '@token-vault/shared/signing';
import { config } from '../config';

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

export function hashPassword(secret: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(secret, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function verifyPassword(secret: string, stored: string): boolean {
  const [alg, n, saltB64, hashB64] = stored.split('$');
  if (alg !== 'scrypt' || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = scryptSync(secret, Buffer.from(saltB64, 'base64'), expected.length, { N: Number(n), r: SCRYPT.r, p: SCRYPT.p });
  return timingSafeEqual(expected, actual);
}

export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');
export const sha256Hex = (data: string) => createHash('sha256').update(data).digest('hex');
export const newId = (prefix: string) => `${prefix}_${randomBytes(8).toString('hex')}`;

/** Signs a definition: Ed25519 over the domain-separated sha256 of its canonical JSON. */
export function signDefinition(definition: unknown): { digest: string; signature: string; keyId: string } {
  const digest = definitionDigest(definition);
  const signature = sign(null, Buffer.from(signaturePayload(digest)), config.signingKey).toString('base64');
  return { digest, signature, keyId: config.keyId };
}
