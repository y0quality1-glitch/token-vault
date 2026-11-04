import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { BUNDLED_DEFINITIONS, ProviderRegistry, githubDefinition, signaturePayload, validateProviderDefinition, type SignedDefinition } from '@token-vault/shared';
import { definitionDigest, publicKeyId } from '@token-vault/shared/signing';
import { CatalogSync } from '@token-vault/shared/catalog-sync';

const cms = generateKeyPairSync('ed25519');
const PUBLIC_PEM = cms.publicKey.export({ type: 'spki', format: 'pem' }).toString();

function envelope(def: unknown, key: KeyObject = cms.privateKey, pub = cms.publicKey): SignedDefinition {
  const definition = validateProviderDefinition(def);
  const digest = definitionDigest(definition);
  return {
    definition,
    digest,
    signature: sign(null, Buffer.from(signaturePayload(digest)), key).toString('base64'),
    key_id: publicKeyId(pub),
    published_at: new Date().toISOString(),
    published_by: 'Elena Editor',
    approved_by: 'Priya Publisher',
  };
}

const notes = (version: number, label = 'List notes') => ({
  key: 'notes',
  version,
  name: 'Notes',
  api: { baseUrl: 'https://api.notes.example.com', allowedHosts: ['api.notes.example.com'] },
  resource: { name: 'project', label: 'Project', pattern: '^[a-z]+$' },
  auth: [{ id: 'API_KEY', label: 'API key', kind: 'bearer' }],
  credentialTest: { request: { method: 'GET', path: '/me' }, response: { fields: { id: 'id' } } },
  operations: [{ id: 'notes.notes.list', label, risk: 'read', request: { method: 'GET', path: '/projects/{resource.project}/notes' }, response: { fields: { id: 'id' } } }],
});

/** A fake CMS catalog endpoint with ETag support. */
function fakeCatalog(initial: SignedDefinition[]) {
  let defs = initial;
  let calls = 0;
  const etag = () => `"${defs.map((d) => d.digest).join(',').length}-${defs.length}-${defs.map((d) => d.digest.slice(0, 4)).join('')}"`;
  const fetchImpl = (async (_url: string, init?: RequestInit) => {
    calls++;
    const headers = init?.headers as Record<string, string>;
    if (headers['if-none-match'] === etag()) return new Response(null, { status: 304 });
    return new Response(JSON.stringify({ definitions: defs }), { status: 200, headers: { etag: etag() } });
  }) as typeof fetch;
  return { fetchImpl, set: (d: SignedDefinition[]) => (defs = d), calls: () => calls };
}

describe('provider registry + catalog sync', () => {
  it('adds CMS-published providers and overrides bundled ones by key', async () => {
    const registry = new ProviderRegistry(BUNDLED_DEFINITIONS);
    const github2 = { ...githubDefinition, version: 2, description: 'From the CMS' };
    const cat = fakeCatalog([envelope(github2), envelope(notes(1))]);
    const sync = new CatalogSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, registry, fetchImpl: cat.fetchImpl });
    await sync.refresh();
    expect(registry.list().map((e) => [e.definition.key, e.definition.version, e.source])).toEqual([
      ['github', 2, 'catalog'],
      ['notes', 1, 'catalog'],
    ]);
    expect(registry.findOperation('notes.notes.list')?.definition.key).toBe('notes');
    expect(sync.status).toMatchObject({ lastError: null, lastUpdate: { added: ['notes v1'], updated: ['github v2'] } });

    await sync.refresh(); // unchanged: served as 304
    expect(cat.calls()).toBe(2);
  });

  it('rejects the whole snapshot if any definition fails verification', async () => {
    const registry = new ProviderRegistry(BUNDLED_DEFINITIONS);
    const tampered = envelope(notes(1));
    (tampered.definition as { api: { baseUrl: string } }).api.baseUrl = 'https://evil.example.net';
    const foreign = generateKeyPairSync('ed25519');
    for (const bad of [tampered, envelope(notes(1), foreign.privateKey, foreign.publicKey)]) {
      const sync = new CatalogSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, registry, fetchImpl: fakeCatalog([envelope(githubDefinition), bad]).fetchImpl });
      await sync.refresh();
      expect(sync.status.lastError).toMatch(/definition notes rejected/);
      expect(registry.list().map((e) => e.definition.key)).toEqual(['github']);
      expect(registry.get('github')?.version).toBe(1);
    }
  });

  it('refuses to roll a provider back to an older signed version', async () => {
    const registry = new ProviderRegistry(BUNDLED_DEFINITIONS);
    const cat = fakeCatalog([envelope(notes(2, 'New label'))]);
    const sync = new CatalogSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, registry, fetchImpl: cat.fetchImpl });
    await sync.refresh();
    cat.set([envelope(notes(1, 'Old label'))]); // validly signed, but older
    await sync.refresh();
    expect(registry.get('notes')?.operations[0]?.label).toBe('New label');
    expect(sync.status.lastUpdate?.refused).toEqual(['notes v1 (already accepted v2)']);
  });

  it('removes archived providers and falls back to the bundled version', async () => {
    const registry = new ProviderRegistry(BUNDLED_DEFINITIONS);
    const cat = fakeCatalog([envelope({ ...githubDefinition, version: 2 }), envelope(notes(1))]);
    const sync = new CatalogSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, registry, fetchImpl: cat.fetchImpl });
    await sync.refresh();
    cat.set([]);
    await sync.refresh();
    expect(registry.list().map((e) => [e.definition.key, e.definition.version, e.source])).toEqual([['github', 1, 'bundled']]);
  });

  it('keeps the known definitions when the CMS is unreachable', async () => {
    const registry = new ProviderRegistry(BUNDLED_DEFINITIONS);
    const sync = new CatalogSync({ url: 'http://cms/catalog/v1', publicKeyPem: PUBLIC_PEM, registry, fetchImpl: (async () => Promise.reject(new Error('ECONNREFUSED'))) as typeof fetch });
    await sync.refresh();
    expect(sync.status.lastError).toBe('ECONNREFUSED');
    expect(registry.get('github')).toBeDefined();
  });
});
