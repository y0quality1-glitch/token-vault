import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import type { SignedDefinition } from '@token-vault/shared';
import { SignatureError, verifySignedDefinition } from '@token-vault/shared/signing';

/**
 * End-to-end tests of the CMS API against a real PostgreSQL database. Skipped unless
 * CMS_TEST_DATABASE_URL is set. The database is wiped and reseeded.
 */
const url = process.env.CMS_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('provider CMS workflow', () => {
  let server: Server;
  let base = '';
  let m: { client: typeof import('../src/db/client'); seed: typeof import('../src/seed') };
  let publicKeyPem = '';

  type Session = { cookie: string };
  async function call(s: Session | null, method: string, path: string, body?: unknown) {
    const res = await fetch(base + path, {
      method,
      headers: { ...(s ? { cookie: s.cookie } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
  }
  async function login(email: string): Promise<Session> {
    const res = await fetch(base + '/api/v1/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password: 'TokenVault-Demo-2026' }) });
    expect(res.status).toBe(200);
    return { cookie: res.headers.get('set-cookie')!.split(';')[0]! };
  }
  let editor: Session, publisher: Session, admin: Session;
  const catalog = async () => (await call(null, 'GET', '/catalog/v1/definitions')).body as { definitions: SignedDefinition[] };
  const version = (key: string, v: number) => `/api/v1/applications/${key}/versions/${v}`;

  beforeAll(async () => {
    process.env.CMS_DATABASE_URL = url;
    process.env.CMS_SIGNING_PRIVATE_KEY = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    process.env.DB_POOL_MAX = '4';
    m = { client: await import('../src/db/client'), seed: await import('../src/seed') };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    const { createApp } = await import('../src/app');
    server = createApp().listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    publicKeyPem = (await call(null, 'GET', '/catalog/v1/public-key')).body.public_key_pem;
    [editor, publisher, admin] = await Promise.all([login('editor@cms.test'), login('publisher@cms.test'), login('admin@cms.test')]);
  }, 60_000);

  afterAll(async () => {
    server?.close();
    await m?.client.closeDatabase();
  });

  it('serves GitHub v1 as a signed definition that verifies against the public key', async () => {
    const { definitions } = await catalog();
    expect(definitions.map((d) => (d.definition as { key: string }).key)).toEqual(['github']);
    expect(verifySignedDefinition(definitions[0]!, publicKeyPem).operations.length).toBeGreaterThan(3);

    const first = await call(null, 'GET', '/catalog/v1/definitions');
    const again = await fetch(base + '/catalog/v1/definitions', { headers: { 'if-none-match': first.headers.get('etag')! } });
    expect(again.status).toBe(304);
  });

  it('rejects tampered or foreign-signed envelopes', async () => {
    const [gh] = (await catalog()).definitions;
    const tampered = structuredClone(gh!);
    (tampered.definition as { api: { baseUrl: string } }).api.baseUrl = 'https://evil.example.net';
    expect(() => verifySignedDefinition(tampered, publicKeyPem)).toThrow(SignatureError);
    const otherKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
    expect(() => verifySignedDefinition(gh!, otherKey)).toThrow(/unknown key/);
  });

  it('requires a session and the right role', async () => {
    expect((await call(null, 'GET', '/api/v1/applications')).status).toBe(401);
    expect((await call(publisher, 'POST', '/api/v1/applications', { key: 'notes', name: 'Notes' })).status).toBe(403);
  });

  it('takes a new application from draft to signed publication with separation of duties', async () => {
    const created = await call(editor, 'POST', '/api/v1/applications', { key: 'notes', name: 'Notes', description: 'Team notes' });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    expect((await call(editor, 'POST', '/api/v1/applications', { key: 'notes', name: 'Again' })).body.error.code).toBe('KEY_TAKEN');

    const draft = (await call(editor, 'GET', version('notes', 1))).body;
    expect(draft).toMatchObject({ status: 'DRAFT', issues: [], diff: { againstVersion: null, hostChange: true } });

    // An unsafe edit is saved as a draft but cannot be submitted.
    const bad = { ...draft.definition, api: { ...draft.definition.api, baseUrl: 'http://api.notes.example.com' } };
    const saved = await call(editor, 'PUT', version('notes', 1), { definition: bad });
    expect(saved.body.issues.join()).toMatch(/https/);
    expect((await call(editor, 'POST', version('notes', 1) + '/submit')).body.error.code).toBe('DEFINITION_INVALID');

    const good = { ...draft.definition, key: 'ignored', api: { baseUrl: 'https://api.notes.example.com/v2', allowedHosts: ['api.notes.example.com'], headers: {} } };
    const fixed = (await call(editor, 'PUT', version('notes', 1), { definition: good })).body;
    expect(fixed.definition.key).toBe('notes'); // the CMS owns key and version
    expect((await call(editor, 'POST', version('notes', 1) + '/submit')).body.status).toBe('IN_REVIEW');
    expect((await call(editor, 'PUT', version('notes', 1), { definition: good })).body.error.code).toBe('NOT_EDITABLE');

    expect((await call(editor, 'POST', version('notes', 1) + '/approve', {})).status).toBe(403); // editors cannot publish
    const noAck = await call(publisher, 'POST', version('notes', 1) + '/approve', {});
    expect(noAck.body.error).toMatchObject({ code: 'HOST_CHANGE_UNACKNOWLEDGED', details: { allowedHosts: ['api.notes.example.com'] } });

    const published = await call(publisher, 'POST', version('notes', 1) + '/approve', { acknowledgeHostChange: true, note: 'Hosts checked' });
    expect(published.body).toMatchObject({ status: 'PUBLISHED', digest: expect.stringMatching(/^[0-9a-f]{64}$/) });

    const notes = (await catalog()).definitions.find((d) => (d.definition as { key: string }).key === 'notes')!;
    expect(notes.approved_by).toBe('Priya Publisher');
    expect(verifySignedDefinition(notes, publicKeyPem).api.allowedHosts).toEqual(['api.notes.example.com']);
  });

  it('blocks a publisher from approving a version they edited', async () => {
    expect((await call(admin, 'POST', '/api/v1/applications/notes/versions', {})).body).toEqual({ key: 'notes', version: 2 });
    const v2 = (await call(admin, 'GET', version('notes', 2))).body;
    const relabeled = { ...v2.definition, operations: v2.definition.operations.map((o: { label: string }) => ({ ...o, label: 'List all items' })) };
    await call(admin, 'PUT', version('notes', 2), { definition: relabeled });
    await call(admin, 'POST', version('notes', 2) + '/submit');
    const self = await call(admin, 'POST', version('notes', 2) + '/approve', {});
    expect(self.body.error.code).toBe('SEPARATION_OF_DUTIES');
    expect((await call(admin, 'GET', version('notes', 2))).body.can).toMatchObject({ review: false, reviewBlockedReason: expect.stringMatching(/separation of duties/) });

    // A label change does not touch hosts, so no acknowledgement is needed; v1 is superseded.
    const ok = await call(publisher, 'POST', version('notes', 2) + '/approve', {});
    expect(ok.body.status).toBe('PUBLISHED');
    expect(ok.body.diff.changes).toEqual([{ area: 'operation notes.items.list', kind: 'changed' }]);
    expect((await call(editor, 'GET', version('notes', 1))).body.status).toBe('SUPERSEDED');
    expect((await catalog()).definitions.find((d) => (d.definition as { key: string }).key === 'notes')!.definition).toMatchObject({ version: 2 });
  });

  it('flags host changes and returns rejected versions to draft with the reviewer note', async () => {
    await call(editor, 'POST', '/api/v1/applications/notes/versions', {});
    const v3 = (await call(editor, 'GET', version('notes', 3))).body;
    const moved = { ...v3.definition, api: { ...v3.definition.api, baseUrl: 'https://notes-proxy.example.org', allowedHosts: ['notes-proxy.example.org'] } };
    expect((await call(editor, 'PUT', version('notes', 3), { definition: moved })).body.diff.hostChange).toBe(true);
    await call(editor, 'POST', version('notes', 3) + '/submit');
    expect((await call(publisher, 'POST', version('notes', 3) + '/reject', { note: 'Unknown proxy host' })).body).toMatchObject({ status: 'DRAFT', reviewNote: 'Unknown proxy host' });
    expect((await call(editor, 'POST', '/api/v1/applications/notes/versions', {})).body.error.code).toBe('OPEN_VERSION_EXISTS');
  });

  it('previews the request an operation would send, without any credential', async () => {
    const r = await call(editor, 'POST', version('notes', 2) + '/preview', { operation: 'notes.items.list', resource: { project: 'ops' } });
    expect(r.body.request).toMatchObject({ method: 'GET', url: 'https://api.notes.example.com/v2/projects/ops/items?limit=10' });
    expect(r.body.request.headers).toContain('Authorization (injected by the customer webhook)');
    expect(r.body.mockResponse).toEqual({ status: 200, body: [{ id: 'item_1', name: 'First item' }] });
    expect((await call(editor, 'POST', version('notes', 2) + '/preview', { operation: 'notes.items.list', resource: { project: '..' } })).body.error).toMatch(/invalid path segment/);
  });

  it('keeps published versions and the audit log immutable in the database', async () => {
    await expect(m.client.pool.query(`update application_versions set definition = '{}'::jsonb where status = 'PUBLISHED'`)).rejects.toThrow(/immutable/);
    await expect(m.client.pool.query(`delete from application_versions where status = 'SUPERSEDED'`)).rejects.toThrow(/cannot be deleted/);
    await expect(m.client.pool.query(`delete from cms_audit_events`)).rejects.toThrow(/append-only/);
    const actions = (await call(admin, 'GET', '/api/v1/audit?application=notes')).body.items.map((e: { action: string }) => e.action);
    expect(actions).toEqual(expect.arrayContaining(['application.created', 'version.submitted', 'version.published', 'version.rejected']));
  });

  it('removes archived applications from the catalog', async () => {
    expect((await call(editor, 'POST', '/api/v1/applications/notes/archive', { reason: 'test' })).status).toBe(403);
    expect((await call(admin, 'POST', '/api/v1/applications/notes/archive', { reason: 'Replaced' })).status).toBe(200);
    expect((await catalog()).definitions.map((d) => (d.definition as { key: string }).key)).toEqual(['github']);
  });

  it('rotates the signing key: every published version is signed by both keys, consumers pinning either accept', async () => {
    const { config } = await import('../src/config');
    const signing = await import('../src/modules/signing');
    const { createPublicKey } = await import('node:crypto');
    const { publicKeyId } = await import('@token-vault/shared/signing');
    const oldPem = publicKeyPem;
    const oldKeyId = config.keyId;

    // Restart the CMS with a new key (the old private key is no longer available).
    const next = generateKeyPairSync('ed25519');
    config.signingKey = next.privateKey;
    config.publicKeyPem = next.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    config.keyId = publicKeyId(createPublicKey(config.publicKeyPem));
    await signing.initSigning();
    expect(await signing.signPublishedWithActiveKey(m.client.db)).toBe(0); // idempotent

    const keys = (await call(null, 'GET', '/catalog/v1/public-key')).body;
    expect(keys).toMatchObject({ key_id: config.keyId });
    expect(keys.keys.map((k: { key_id: string; active: boolean }) => [k.key_id, k.active])).toEqual([
      [oldKeyId, false],
      [config.keyId, true],
    ]);

    const [gh] = (await catalog()).definitions;
    expect(gh!.key_id).toBe(config.keyId); // the active key's signature is primary
    expect(gh!.signatures!.map((x) => x.key_id)).toEqual([config.keyId, oldKeyId]);
    expect(verifySignedDefinition(gh!, oldPem).key).toBe('github'); // a consumer still pinning the old key
    expect(verifySignedDefinition(gh!, config.publicKeyPem).key).toBe('github'); // one that already switched

    // Versions published from now on carry only the new key's signature.
    await call(editor, 'POST', '/api/v1/applications', { key: 'rotated', name: 'Rotated' });
    await call(editor, 'POST', version('rotated', 1) + '/submit');
    await call(publisher, 'POST', version('rotated', 1) + '/approve', { acknowledgeHostChange: true });
    const rotated = (await catalog()).definitions.find((d) => (d.definition as { key: string }).key === 'rotated')!;
    expect(rotated.signatures!.map((x) => x.key_id)).toEqual([config.keyId]);
    expect(() => verifySignedDefinition(rotated, oldPem)).toThrow(SignatureError);
    expect((await call(editor, 'GET', version('rotated', 1))).body.signatures).toEqual([{ keyId: config.keyId, signedAt: expect.any(String), active: true }]);

    // Signatures are append-only.
    await expect(m.client.pool.query(`delete from cms_version_signatures`)).rejects.toThrow(/append-only/);
    const actions = (await call(admin, 'GET', '/api/v1/audit')).body.items.map((e: { action: string }) => e.action);
    expect(actions).toEqual(expect.arrayContaining(['signing.key_activated', 'signing.versions_signed']));
  });
});

