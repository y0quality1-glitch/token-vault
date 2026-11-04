import { randomBytes, randomUUID } from 'node:crypto';

/** Prefixed, non-guessable identifiers, e.g. agt_3f9c1a7e2b4d6f80. */
export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(8).toString('hex')}`;
}

export function correlationId(): string {
  return `corr_${randomUUID()}`;
}

export function requestId(): string {
  return `req_${randomBytes(10).toString('hex')}`;
}

export function nonce(): string {
  return randomBytes(18).toString('base64url');
}
