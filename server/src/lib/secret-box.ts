import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { config } from '../config';

/**
 * Encryption at rest for secrets Token Vault itself needs (its Slack bot token and signing
 * secret). Not for customer provider credentials: those never reach the control plane.
 *
 * AES-256-GCM; the key is SETTINGS_ENCRYPTION_KEY, or derived (HKDF) from AUDIT_SIGNING_KEY with
 * its own label when unset. Format: "v1:<iv>:<tag>:<ciphertext>" (base64url). The organization id
 * is bound as additional data, so a value copied to another organization does not decrypt.
 */
function key(): Buffer {
  const material = config.settingsEncryptionKey || config.auditSigningKey;
  return Buffer.from(hkdfSync('sha256', material, 'token-vault', 'token-vault/settings-encryption/v1', 32));
}

export function seal(plaintext: string, organizationId: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(), iv);
  cipher.setAAD(Buffer.from(organizationId));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ct.toString('base64url')].join(':');
}

export function open(sealed: string, organizationId: string): string {
  const [v, iv, tag, ct] = sealed.split(':');
  if (v !== 'v1' || !iv || !tag || ct === undefined) throw new Error('Unsupported sealed value');
  const decipher = createDecipheriv('aes-256-gcm', key(), Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(organizationId));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8');
}
