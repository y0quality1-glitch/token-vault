import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

/** Password-grade hash used for user passwords and agent API credentials. */
export function hashSecret(secret: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(secret, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function verifySecret(secret: string, stored: string): boolean {
  const [alg, n, saltB64, hashB64] = stored.split('$');
  if (alg !== 'scrypt' || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = scryptSync(secret, Buffer.from(saltB64, 'base64'), expected.length, { N: Number(n), r: SCRYPT.r, p: SCRYPT.p });
  return timingSafeEqual(expected, actual);
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export function hmacHex(secret: string, data: string): string {
  return createHmac('sha256', secret).update(data).digest('hex');
}

export function safeEqualHex(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return ab.length === bb.length && ab.length > 0 && timingSafeEqual(ab, bb);
}

// ------------------------------------------------------------------ agent API credentials
// Format: tvak_<keyId>_<secret>. keyId is public (lookup); the whole key is verified against a scrypt hash.
export const AGENT_KEY_PREFIX = 'tvak_';

export function generateAgentCredential() {
  const keyId = randomBytes(6).toString('hex');
  const secret = randomBytes(24).toString('base64url');
  const apiKey = `${AGENT_KEY_PREFIX}${keyId}_${secret}`;
  return { keyId, apiKey, hash: hashSecret(apiKey) };
}

export function parseAgentCredential(apiKey: string): { keyId: string } | null {
  const m = /^tvak_([0-9a-f]{12})_[A-Za-z0-9_-]{20,64}$/.exec(apiKey);
  return m ? { keyId: m[1]! } : null;
}

export function maskAgentKey(keyId: string) {
  return `${AGENT_KEY_PREFIX}${keyId}_••••••••••••`;
}
