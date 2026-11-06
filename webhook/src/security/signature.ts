import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Control plane -> webhook request signing (POC: shared-secret HMAC-SHA256).
 *
 * canonical = METHOD \n PATH(+query) \n TIMESTAMP \n NONCE \n SHA256(body)
 * headers   = x-tv-timestamp, x-tv-nonce, x-tv-signature
 *
 * Production design: mTLS or asymmetric request signing with key rotation.
 */
export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export function hmacHex(secret: string, data: string): string {
  return createHmac('sha256', secret).update(data).digest('hex');
}

export function canonicalString(method: string, path: string, timestamp: string, nonce: string, body: string | Buffer): string {
  return [method.toUpperCase(), path, timestamp, nonce, sha256Hex(body)].join('\n');
}

export function safeEqualHex(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return ab.length === bb.length && ab.length > 0 && timingSafeEqual(ab, bb);
}

/** Records a nonce; resolves false if it was already used within its validity window. */
export interface NonceStore {
  use(nonce: string, now?: number): boolean | Promise<boolean>;
}

/** In-process replay cache (single instance; used in unit tests). The service uses PgNonceStore. */
export class NonceCache implements NonceStore {
  private seen = new Map<string, number>();
  constructor(private ttlMs: number) {}

  /** Returns false if the nonce was already used. */
  use(nonce: string, now = Date.now()): boolean {
    for (const [n, exp] of this.seen) if (exp < now) this.seen.delete(n);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, now + this.ttlMs);
    return true;
  }
}

export interface VerifyInput {
  /** Accepted secrets, current first. Several during a signing-secret rotation. */
  secret: string | string[];
  method: string;
  path: string;
  body: string | Buffer;
  headers: Record<string, string | string[] | undefined>;
  nonces: NonceStore;
  maxSkewMs: number;
  now?: number;
}

/** On success, `secret` is the one that matched: answer with it, so a rotation needs no ordering beyond "webhook first". */
export type VerifyResult = { ok: true; nonce: string; secret: string; secretIndex: number } | { ok: false; reason: string };

export async function verifySignedRequest(input: VerifyInput): Promise<VerifyResult> {
  const now = input.now ?? Date.now();
  const ts = String(input.headers['x-tv-timestamp'] ?? '');
  const nonce = String(input.headers['x-tv-nonce'] ?? '');
  const sig = String(input.headers['x-tv-signature'] ?? '');
  if (!ts || !nonce || !sig) return { ok: false, reason: 'missing_signature_headers' };
  if (!/^\d+$/.test(ts) || Math.abs(now - Number(ts)) > input.maxSkewMs) return { ok: false, reason: 'timestamp_outside_window' };
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) return { ok: false, reason: 'invalid_nonce' };
  if (!/^[0-9a-f]{64}$/.test(sig)) return { ok: false, reason: 'bad_signature' };
  const canonical = canonicalString(input.method, input.path, ts, nonce, input.body);
  const secrets = Array.isArray(input.secret) ? input.secret : [input.secret];
  const secretIndex = secrets.findIndex((s) => safeEqualHex(hmacHex(s, canonical), sig));
  if (secretIndex < 0) return { ok: false, reason: 'bad_signature' };
  // Only consume the nonce once the signature is proven, so attackers cannot burn nonces.
  if (!(await input.nonces.use(nonce, now))) return { ok: false, reason: 'replayed_nonce' };
  return { ok: true, nonce, secret: secrets[secretIndex]!, secretIndex };
}

/** Signature the webhook attaches to its response so the control plane can verify origin. */
export function signResponse(secret: string, nonce: string, body: string): string {
  return hmacHex(secret, ['response', nonce, sha256Hex(body)].join('\n'));
}
