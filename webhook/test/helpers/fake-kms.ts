import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { KeyAccessDeniedError, KeyServiceUnavailableError, type KeyProvider } from '../../src/security/key-provider';

/** In-memory stand-in for a KMS: AES-GCM under a key only it holds, with the context authenticated. */
export function fakeKms(ref = 'vault-transit:transit/test') {
  const master = randomBytes(32);
  const state = { down: false, unwraps: 0 };
  const provider: KeyProvider = {
    kind: 'vault-transit',
    ref,
    handles: (r) => r.startsWith('vault-transit:transit/'),
    async wrap(dataKey, context) {
      if (state.down) throw new KeyServiceUnavailableError('fake KMS is down');
      const iv = randomBytes(12);
      const c = createCipheriv('aes-256-gcm', master, iv).setAAD(Buffer.from(JSON.stringify(context)));
      const ct = Buffer.concat([c.update(dataKey), c.final()]);
      return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
    },
    async unwrap(wrapped, context) {
      if (state.down) throw new KeyServiceUnavailableError('fake KMS is down');
      state.unwraps++;
      const b = Buffer.from(wrapped, 'base64');
      try {
        const d = createDecipheriv('aes-256-gcm', master, b.subarray(0, 12)).setAAD(Buffer.from(JSON.stringify(context)));
        d.setAuthTag(b.subarray(12, 28));
        return Buffer.concat([d.update(b.subarray(28)), d.final()]);
      } catch {
        throw new KeyAccessDeniedError('fake KMS: invalid ciphertext or context');
      }
    },
  };
  return { provider, state };
}
