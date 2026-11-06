import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { seal } from '../src/security/encryption';
import { LEGACY_KEY_REF, buildKeyring, idInRef, keyIdOf, openWith, parseKey, sealWith } from '../src/security/keyring';

describe('credential encryption keyring', () => {
  const a = randomBytes(32);
  const b = randomBytes(32);

  it('names keys by a one-way id and records it in the key ref', () => {
    const ring = buildKeyring(b, [a]);
    expect(ring.current.id).toMatch(/^kid_[0-9a-f]{16}$/);
    expect(ring.current.id).toBe(keyIdOf(b));
    expect(ring.current.ref).toBe(`env:VAULT_ENCRYPTION_KEY#${ring.current.id}`);
    expect(ring.current.ref).not.toContain(b.toString('base64'));
    expect(idInRef(ring.previous[0]!.ref)).toBe(keyIdOf(a));
    expect(idInRef(LEGACY_KEY_REF)).toBeNull();
    // The current key listed as a previous key, and duplicates, are ignored.
    expect(buildKeyring(b, [b, a, a]).previous.map((k) => k.id)).toEqual([keyIdOf(a)]);
  });

  it('encrypts with the current key and opens records of previous and legacy keys', () => {
    const ring = buildKeyring(b, [a]);
    const fresh = sealWith(ring, 'sk_new_secret', 'cref_1');
    expect(openWith(ring, fresh.sealed, 'cref_1', fresh.ref)).toMatchObject({ plaintext: 'sk_new_secret', key: { id: keyIdOf(b) } });

    const old = sealWith(buildKeyring(a), 'sk_old_secret', 'cref_2');
    expect(openWith(ring, old.sealed, 'cref_2', old.ref)).toMatchObject({ plaintext: 'sk_old_secret', key: { id: keyIdOf(a) } });

    const legacy = seal(a, 'sk_legacy_secret', 'cref_3');
    expect(openWith(ring, legacy, 'cref_3', LEGACY_KEY_REF)?.plaintext).toBe('sk_legacy_secret');
  });

  it('cannot open a record whose key was removed, or one bound to another reference', () => {
    const old = sealWith(buildKeyring(a), 'sk_old_secret', 'cref_2');
    expect(openWith(buildKeyring(b), old.sealed, 'cref_2', old.ref)).toBeNull();
    expect(openWith(buildKeyring(b, [a]), old.sealed, 'cref_other', old.ref)).toBeNull();
  });

  it('accepts only 32-byte base64 keys', () => {
    expect(parseKey(a.toString('base64'), 'K')).toEqual(a);
    expect(() => parseKey(randomBytes(16).toString('base64'), 'VAULT_PREVIOUS_ENCRYPTION_KEYS (entry 1)')).toThrow(/VAULT_PREVIOUS_ENCRYPTION_KEYS \(entry 1\) must be base64 of exactly 32 bytes/);
  });
});
