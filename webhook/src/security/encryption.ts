import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';

/** AES-256-GCM authenticated encryption. The credential_ref is bound as AAD. */
export interface Sealed {
  iv: string;
  ciphertext: string;
  authTag: string;
}

export function seal(key: Buffer, plaintext: string, aad: string): Sealed {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64'), authTag: cipher.getAuthTag().toString('base64') };
}

export function open(key: Buffer, sealed: Sealed, aad: string): string {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(sealed.authTag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(sealed.ciphertext, 'base64')), decipher.final()]).toString('utf8');
}

/** Keyed fingerprint (not a plain hash) so the fingerprint cannot be brute-forced offline. */
export function fingerprint(key: Buffer, secret: string): string {
  return 'fp_' + createHmac('sha256', key).update('fingerprint:' + secret).digest('hex').slice(0, 16);
}

/** Masked identifier safe to show in the control plane, e.g. "ghp_••••••••3f9a". */
export function mask(secret: string): string {
  if (secret.length < 16) return '••••••••';
  const prefixMatch = secret.match(/^([a-z]+_)+/i);
  const prefix = prefixMatch ? prefixMatch[0].slice(0, 12) : '';
  return `${prefix}••••••••${secret.slice(-4)}`;
}
