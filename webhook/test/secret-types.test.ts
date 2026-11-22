import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import {
  BUILTIN_SECRET_TYPES,
  MASKED_SECRET_VALUE,
  SECRET_CATEGORIES,
  SecretTypeError,
  githubDefinition,
  signaturePayload,
  signaturePayloadFor,
  summarizeSecretPayload,
  validateSecretPayload,
  validateSecretTypeDefinition,
  type SignedDefinition,
} from '@token-vault/shared';
import { definitionDigest, publicKeyId, SignatureError, verifySignedDefinition, verifySignedSecretType } from '@token-vault/shared/signing';
import { SecretTypeRegistry, SecretTypeSync } from '@token-vault/shared/secret-type-sync';
import type { CatalogCache, CatalogState } from '@token-vault/shared/catalog-sync';

/** Secret types (spec 4.9.3): schema, payload validation, signatures and the catalog sync. */

const cms = generateKeyPairSync('ed25519');
const PUBLIC_PEM = cms.publicKey.export({ type: 'spki', format: 'pem' }).toString();

const type = (key: string) => validateSecretTypeDefinition(BUILTIN_SECRET_TYPES.find((t) => t.key === key));

function signed(definition: unknown, payload: (digest: string) => string, key: KeyObject = cms.privateKey): SignedDefinition {
  const digest = definitionDigest(definition);
  return { definition, digest, signature: sign(null, Buffer.from(payload(digest)), key).toString('base64'), key_id: publicKeyId(cms.publicKey), published_at: new Date().toISOString(), published_by: 'Elena Editor', approved_by: 'Priya Publisher' };
}
const asSecretType = (def: unknown, key?: KeyObject) => signed(validateSecretTypeDefinition(def), (d) => signaturePayloadFor('secret_type', d), key);

const token = (version: number, extra: object = {}) => ({ key: 'notes-token', version, name: 'Notes token', category: 'api', fields: { token: { label: 'Token', required: true } }, ...extra });

function fakeCatalog(initial: SignedDefinition[]) {
  let types = initial;
  const etag = () => `"${types.map((d) => d.digest.slice(0, 8)).join('')}"`;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    expect(url).toBe('http://cms/catalog/v1/secret-types');
    if ((init?.headers as Record<string, string>)['if-none-match'] === etag()) return new Response(null, { status: 304 });
    return new Response(JSON.stringify({ secret_types: types }), { status: 200, headers: { etag: etag() } });
  }) as typeof fetch;
  return { fetchImpl, set: (t: SignedDefinition[]) => (types = t) };
}

describe('secret type definitions', () => {
  it('covers every predefined category of the spec with valid, unique types', () => {
    const keys = BUILTIN_SECRET_TYPES.map((t) => t.key);
    expect(new Set(keys).size).toBe(keys.length);
    const defs = BUILTIN_SECRET_TYPES.map((t) => validateSecretTypeDefinition(t));
    // A–I are predefined; dynamic (J) comes with its generators and custom (K) per organization.
    expect(new Set(defs.map((d) => d.category))).toEqual(new Set(SECRET_CATEGORIES.filter((c) => c !== 'dynamic' && c !== 'custom')));
    for (const d of defs) expect(Object.values(d.fields).some((f) => f.sensitive)).toBe(true);
  });

  it('refuses types that would hold nothing secret, unanchored patterns and inconsistent settings', () => {
    const problems = (def: object) => {
      try {
        validateSecretTypeDefinition(def);
        return [];
      } catch (e) {
        return (e as SecretTypeError).issues;
      }
    };
    expect(problems(token(1, { fields: { token: { label: 'Token', sensitive: false } } }))).toContain('fields: at least one field must be sensitive');
    expect(problems(token(1, { fields: { token: { label: 'Token', pattern: '[a-z]+' } } }))).toContain('fields.token.pattern: must be anchored with ^ and $');
    expect(problems(token(1, { fields: { token: { label: 'T', kind: 'enum' } } }))).toContain('fields.token.values: an enum field needs its values');
    expect(problems(token(1, { metadata: { token: { label: 'Token' } } }))).toContain('metadata.token: also a payload field (use one or the other)');
    expect(problems(token(1, { lifecycle: { rotation: false }, defaults: { rotationIntervalDays: 30 } }))).toContain('defaults.rotationIntervalDays: the type does not support rotation');
    expect(problems(token(1, { lifecycle: { dynamic: true } }))).toContain('lifecycle.dynamic: only types in the dynamic category generate credentials');
    expect(problems(token(1, { surprise: true })).length).toBeGreaterThan(0);
  });
});

describe('secret payloads', () => {
  it('normalizes valid values and reports problems by field, never echoing the value', () => {
    const pg = type('postgresql');
    expect(validateSecretPayload(pg, { username: '  app  ', password: 'correct horse battery' })).toEqual({ value: { username: 'app', password: 'correct horse battery' }, issues: {} });
    const bad = validateSecretPayload(pg, { username: 'app', password: '', extra: 'x' });
    expect(bad.issues).toEqual({ password: 'Password is required', extra: 'is not a field of this secret type' });

    const aws = validateSecretPayload(type('aws-access-key'), { accessKeyId: 'AKIA-not-a-key', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' });
    expect(aws.issues).toEqual({ accessKeyId: 'Access key ID does not have the expected format' });
    expect(JSON.stringify(aws.issues)).not.toContain('wJalr');

    expect(validateSecretPayload(type('gcp-service-account'), { clientEmail: 'ci@proj.iam.gserviceaccount.com', keyJson: '{not json' }).issues).toEqual({ keyJson: 'Key file (JSON) must be valid JSON' });
    expect(validateSecretPayload(type('tls-certificate'), { certificate: 'hello', privateKey: 'x' }).issues.certificate).toMatch(/PEM/);
    expect(validateSecretPayload(type('env-vars'), { variables: { DATABASE_URL: 'postgres://u:p@h/db', '1BAD': 'x' } }).issues.variables).toMatch(/1BAD is not a valid name/);
    expect(validateSecretPayload(type('env-vars'), { variables: { DATABASE_URL: 'postgres://u:p@h/db', LOG_LEVEL: 'info' } }).issues).toEqual({});
  });

  it('summaries show non-sensitive fields and never any character of a sensitive one', () => {
    const summary = summarizeSecretPayload(type('postgresql'), { username: 'app', password: 'correct horse battery staple' });
    expect(summary).toEqual({ username: 'app', password: MASKED_SECRET_VALUE });
    const env = summarizeSecretPayload(type('env-vars'), { variables: { DATABASE_URL: 'postgres://u:secret@h/db', LOG_LEVEL: 'debug' } });
    expect(env.variables).toBe('2 entries: DATABASE_URL, LOG_LEVEL');
    expect(JSON.stringify(env)).not.toMatch(/secret@|debug/);
  });
});

describe('secret type signatures', () => {
  it('accepts a secret type signed under the secret-type context', () => {
    expect(verifySignedSecretType(asSecretType(token(1)), PUBLIC_PEM).key).toBe('notes-token');
  });

  it('never accepts a provider signature as a secret type signature, or the other way round', () => {
    // Same key, same digest, other context: refused.
    const def = validateSecretTypeDefinition(token(1));
    expect(() => verifySignedSecretType(signed(def, signaturePayload), PUBLIC_PEM)).toThrow(SignatureError);
    const provider = signed(githubDefinition, (d) => signaturePayloadFor('secret_type', d));
    expect(() => verifySignedDefinition(provider, PUBLIC_PEM)).toThrow(SignatureError);
  });

  it('refuses tampered definitions and unknown keys', () => {
    const env = asSecretType(token(1));
    const tampered = { ...env, definition: { ...(env.definition as object), fields: { token: { label: 'Token', required: true, sensitive: false }, other: { label: 'x' } } } };
    expect(() => verifySignedSecretType(tampered, PUBLIC_PEM)).toThrow('digest does not match the definition');
    const other = generateKeyPairSync('ed25519');
    expect(() => verifySignedSecretType(asSecretType(token(1), other.privateKey), PUBLIC_PEM)).toThrow('signature does not verify');
  });
});

describe('secret type catalog sync', () => {
  it('applies verified types, keeps them on 304 and removes unpublished ones', async () => {
    const cat = fakeCatalog([asSecretType(token(1)), asSecretType(BUILTIN_SECRET_TYPES[0])]);
    const sync = new SecretTypeSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, fetchImpl: cat.fetchImpl });
    await sync.refresh();
    expect(sync.registry.list().map((t) => t.key).sort()).toEqual(['api-key', 'notes-token']);
    await sync.refresh(); // 304
    expect(sync.status.lastError).toBeNull();
    expect(sync.registry.list()).toHaveLength(2);
    cat.set([asSecretType(token(2, { description: 'v2' }))]);
    await sync.refresh();
    expect(sync.registry.list().map((t) => [t.key, t.version])).toEqual([['notes-token', 2]]);
  });

  it('rejects a whole snapshot when one entry fails, and refuses a version downgrade', async () => {
    const cat = fakeCatalog([asSecretType(token(2))]);
    const sync = new SecretTypeSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, fetchImpl: cat.fetchImpl });
    await sync.refresh();
    const good = asSecretType(BUILTIN_SECRET_TYPES[0]);
    cat.set([good, { ...asSecretType(token(3)), signature: good.signature }]);
    await sync.refresh();
    expect(sync.status.lastError).toMatch(/notes-token rejected: signature does not verify/);
    expect(sync.registry.list().map((t) => [t.key, t.version])).toEqual([['notes-token', 2]]);
    // An older, validly signed version (e.g. a replayed catalog) is refused.
    cat.set([asSecretType(token(1))]);
    await sync.refresh();
    expect(sync.status.refused).toEqual(['notes-token v1 (already accepted v2)']);
    expect(sync.registry.get('notes-token')?.version).toBe(2);
  });

  it('restores persisted types after a restart, still refusing downgrades', async () => {
    let saved: CatalogState | null = null;
    const cache: CatalogCache = { load: async () => saved, save: async (s) => void (saved = s) };
    const first = new SecretTypeSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, cache, fetchImpl: fakeCatalog([asSecretType(token(3))]).fetchImpl });
    await first.refresh();
    expect(saved!.highWater).toEqual({ 'notes-token': 3 });

    // The CMS is unreachable after the restart: the persisted types apply.
    const down = (async () => {
      throw new Error('connect ECONNREFUSED');
    }) as typeof fetch;
    const second = new SecretTypeSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, cache, fetchImpl: down });
    await second.restore();
    await second.refresh();
    expect(second.registry.get('notes-token')?.version).toBe(3);
    expect(second.status.lastError).toMatch(/ECONNREFUSED/);

    const third = new SecretTypeSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, cache, fetchImpl: fakeCatalog([asSecretType(token(2))]).fetchImpl });
    await third.restore();
    await third.refresh();
    expect(third.registry.get('notes-token')?.version).toBe(3);
  });

  it('falls back to the predefined types only without a CMS', () => {
    const r = SecretTypeRegistry.bundled(BUILTIN_SECRET_TYPES);
    expect(r.list()).toHaveLength(BUILTIN_SECRET_TYPES.length);
    expect(r.entry('postgresql')?.digest).toBe(definitionDigest(validateSecretTypeDefinition(BUILTIN_SECRET_TYPES.find((t) => t.key === 'postgresql'))));
  });
});
