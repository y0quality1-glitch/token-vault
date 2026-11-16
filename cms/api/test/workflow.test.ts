import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import type { SignedDefinition } from '@token-vault/shared';
import { SignatureError, verifySignedDefinition } from '@token-vault/shared/signing';

/**
 * End-to-end tests of the CMS API against a real PostgreSQL database. Skipped unless
 * CMS_TEST_DATABASE_URL is set. The database is wiped and reseeded.
 *
 * Admin routes answer with the envelope { status: "10000" | "10001", msg, error, code?, details, totalRecords }.
 */
const url = process.env.CMS_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('provider CMS workflow', () => {
  let server: Server;
  let base = '';
  let m: {
    db: typeof import('../src/databases/database');
    seed: typeof import('../src/seed/seed');
    config: typeof import('../src/config');
    signing: typeof import('../src/services/signingService/signingService.service');
  };
  let publicKeyPem = '';
  const sql = (q: string) => m.db.default.getInstance().executeExternalQuery(q);

  type Session = { cookie: string; token: string };
  type Envelope = { status: string; msg: string; error: string | null; code?: string; details: any; totalRecords: number };
  async function call(s: Session | null, method: string, path: string, body?: unknown, auth: 'cookie' | 'bearer' = 'cookie') {
    const res = await fetch(base + path, {
      method,
      headers: { ...(s ? (auth === 'cookie' ? { cookie: s.cookie } : { authorization: `Bearer ${s.token}` }) : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, body: (text ? JSON.parse(text) : null) as Envelope, headers: res.headers };
  }
  /** POST to an admin route and return `details` (asserting success). */
  async function ok(s: Session, path: string, body: unknown = {}) {
    const r = await call(s, 'POST', `/api/v1${path}`, body);
    expect(r.body.status, `${path}: ${JSON.stringify(r.body)}`).toBe('10000');
    return r.body.details;
  }
  /** POST to an admin route and return the failure envelope. */
  const fails = async (s: Session | null, path: string, body: unknown = {}) => (await call(s, 'POST', `/api/v1${path}`, body)).body;
  async function login(email: string): Promise<Session> {
    const res = await fetch(base + '/api/v1/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password: 'TokenVault-Demo-2026' }) });
    expect(res.status).toBe(200);
    const cookie = res.headers.get('set-cookie')!.split(';')[0]!;
    return { cookie, token: decodeURIComponent(cookie.split('=')[1]!) };
  }
  let editor: Session, publisher: Session, admin: Session;
  const catalog = async () => (await call(null, 'GET', '/catalog/v1/definitions')).body as unknown as { definitions: SignedDefinition[] };
  const version = (s: Session, key: string, v: number) => ok(s, '/version/getdatabyid', { key, version: v });

  beforeAll(async () => {
    process.env.CMS_DATABASE_URL = url;
    process.env.CMS_SIGNING_PRIVATE_KEY = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    process.env.DB_POOL_MAX = '4';
    await import('reflect-metadata');
    m = {
      db: await import('../src/databases/database'),
      seed: await import('../src/seed/seed'),
      config: await import('../src/config'),
      signing: await import('../src/services/signingService/signingService.service'),
    };
    const db = m.db.default.getInstance();
    await db.connectToDB();
    await db.runMigrations();
    await m.seed.resetDatabase();
    const { App } = await import('../src/app');
    const { controllers } = await import('../src/controllers');
    server = (await new App(controllers()).build()).listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    publicKeyPem = ((await call(null, 'GET', '/catalog/v1/public-key')).body as unknown as { public_key_pem: string }).public_key_pem;
    [editor, publisher, admin] = await Promise.all([login('editor@cms.test'), login('publisher@cms.test'), login('admin@cms.test')]);
  }, 60_000);

  afterAll(async () => {
    server?.close();
    await m?.db.default.getInstance().close();
  });

  it('serves GitHub v1 as a signed definition that verifies against the public key', async () => {
    const { definitions } = await catalog();
    expect(definitions.map((d) => (d.definition as { key: string }).key)).toEqual(['github', 'google', 'openai', 'slack']);
    for (const d of definitions) verifySignedDefinition(d, publicKeyPem);
    expect(definitions.map((d) => (d.definition as { catalog: { availability: string } }).catalog.availability)).toEqual(['available', 'coming_soon', 'coming_soon', 'coming_soon']);
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

  it('answers with the template envelope, 405 for a wrong method, and field errors for bad input', async () => {
    const health = await call(null, 'GET', '/api/v1/apiHealthCheck/apihealth');
    expect(health.body).toMatchObject({ status: '10000', msg: 'API Server is up and running successfully!', error: null, details: { database: 'ok' }, totalRecords: 0 });

    const list = await call(admin, 'POST', '/api/v1/application/getall', { pageSize: 2 });
    expect(list.body).toMatchObject({ status: '10000', msg: 'Application Fetched Successfully', totalRecords: 4 });
    expect(list.body.details.map((a: { key: string }) => a.key)).toEqual(['github', 'google']);
    expect((await ok(admin, '/application/getall', { pageNumber: 2, pageSize: 2 })).map((a: { key: string }) => a.key)).toEqual(['openai', 'slack']);
    expect((await ok(admin, '/application/getall', { search: 'SLA' })).map((a: { key: string }) => a.key)).toEqual(['slack']);
    // pageSize is clamped: never a whole table.
    expect((await call(admin, 'POST', '/api/v1/application/getall', { pageSize: 1_000_000 })).body.details).toHaveLength(4);

    expect((await call(admin, 'GET', '/api/v1/application/getall')).status).toBe(405);
    expect((await call(admin, 'GET', '/api/v1/application/getall')).body).toMatchObject({ status: '10001', code: 'METHOD_NOT_ALLOWED' });
    expect((await call(admin, 'GET', '/api/v1/nope')).body).toMatchObject({ status: '10001', code: 'NOT_FOUND' });

    const bad = await call(editor, 'POST', '/api/v1/application/save', { key: 'Bad Key', name: '' });
    expect(bad.status).toBe(400);
    expect(bad.body).toMatchObject({ status: '10001', code: 'VALIDATION_ERROR', details: { fields: { key: expect.stringMatching(/Lower-case/), name: expect.stringMatching(/Name is required/) } } });

    const malformed = await fetch(base + '/api/v1/application/save', { method: 'POST', headers: { cookie: editor.cookie, 'content-type': 'application/json' }, body: '{"key":' });
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toMatchObject({ status: '10001', code: 'MALFORMED_JSON' });
    expect((await call(null, 'GET', '/api-docs.json')).body).toMatchObject({ openapi: '3.0.3' });
  });

  it('requires a session and the right role; a Bearer token works too, and logout ends the session', async () => {
    expect((await call(null, 'POST', '/api/v1/application/getall', {})).status).toBe(401);
    expect((await call(null, 'POST', '/api/v1/application/getall', {})).body.code).toBe('UNAUTHENTICATED');
    expect((await call(publisher, 'POST', '/api/v1/application/save', { key: 'notes', name: 'Notes' })).status).toBe(403);
    expect((await call(publisher, 'POST', '/api/v1/application/save', { key: 'notes', name: 'Notes' })).body.code).toBe('ROLE_REQUIRED');

    expect((await call(admin, 'GET', '/api/v1/auth/me', undefined, 'bearer')).body.details).toMatchObject({ user: { email: 'admin@cms.test', role: 'ADMIN' } });
    const forged = { ...admin, token: `${admin.token.slice(0, -4)}AAAA` };
    expect((await call(forged, 'GET', '/api/v1/auth/me', undefined, 'bearer')).body.code).toBe('SESSION_EXPIRED');

    // The login response never carries the token (httpOnly cookie only).
    const res = await fetch(base + '/api/v1/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'editor@cms.test', password: 'TokenVault-Demo-2026' }) });
    const temp = res.headers.get('set-cookie')!.split(';')[0]!;
    expect(JSON.stringify(await res.json())).not.toContain(decodeURIComponent(temp.split('=')[1]!));
    expect((await call({ cookie: temp, token: '' }, 'POST', '/api/v1/auth/logout')).body.status).toBe('10000');
    expect((await call({ cookie: temp, token: '' }, 'GET', '/api/v1/auth/me')).body.code).toBe('SESSION_EXPIRED');
    expect((await fails(null, '/auth/login', { email: 'editor@cms.test', password: 'wrong' })).code).toBe('INVALID_CREDENTIALS');
  });

  it('takes a new application from draft to signed publication with separation of duties', async () => {
    const created = await call(editor, 'POST', '/api/v1/application/save', { key: 'notes', name: 'Notes', description: 'Team notes', extra: 'dropped' });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    expect(created.body).toMatchObject({ msg: 'Application Added Successfully', details: { key: 'notes', version: 1 } });
    expect(await fails(editor, '/application/save', { key: 'notes', name: 'Again' })).toMatchObject({ code: 'KEY_TAKEN', details: { fields: { key: 'This key is already in use' } } });

    const draft = await version(editor, 'notes', 1);
    expect(draft).toMatchObject({ status: 'DRAFT', issues: [], diff: { againstVersion: null, hostChange: true } });

    // An unsafe edit is saved as a draft but cannot be submitted.
    const bad = { ...draft.definition, api: { ...draft.definition.api, baseUrl: 'http://api.notes.example.com' } };
    expect((await ok(editor, '/version/save', { key: 'notes', version: 1, definition: bad })).issues.join()).toMatch(/https/);
    expect((await fails(editor, '/version/submit', { key: 'notes', version: 1 })).code).toBe('DEFINITION_INVALID');

    const good = { ...draft.definition, key: 'ignored', api: { baseUrl: 'https://api.notes.example.com/v2', allowedHosts: ['api.notes.example.com'], headers: {} } };
    const fixed = await ok(editor, '/version/save', { key: 'notes', version: 1, definition: good });
    expect(fixed.definition.key).toBe('notes'); // the CMS owns key and version
    expect((await ok(editor, '/version/submit', { key: 'notes', version: 1 })).status).toBe('IN_REVIEW');
    expect((await fails(editor, '/version/save', { key: 'notes', version: 1, definition: good })).code).toBe('NOT_EDITABLE');

    expect((await call(editor, 'POST', '/api/v1/version/approve', { key: 'notes', version: 1 })).status).toBe(403); // editors cannot publish
    expect(await fails(publisher, '/version/approve', { key: 'notes', version: 1 })).toMatchObject({ code: 'HOST_CHANGE_UNACKNOWLEDGED', details: { allowedHosts: ['api.notes.example.com'] } });

    const published = await ok(publisher, '/version/approve', { key: 'notes', version: 1, acknowledgeHostChange: true, note: 'Hosts checked' });
    expect(published).toMatchObject({ status: 'PUBLISHED', digest: expect.stringMatching(/^[0-9a-f]{64}$/) });

    const notes = (await catalog()).definitions.find((d) => (d.definition as { key: string }).key === 'notes')!;
    expect(notes.approved_by).toBe('Priya Publisher');
    expect(verifySignedDefinition(notes, publicKeyPem).api.allowedHosts).toEqual(['api.notes.example.com']);

    const detail = (await call(editor, 'GET', '/api/v1/application/getbyid/notes')).body.details;
    expect(detail).toMatchObject({ key: 'notes', publishedVersion: 1, versions: [{ version: 1, status: 'PUBLISHED' }] });
    expect((await call(editor, 'GET', '/api/v1/application/getbyid/missing')).body).toMatchObject({ status: '10001', code: 'RECORD_NOT_FOUND' });
  });

  it('blocks a publisher from approving a version they edited', async () => {
    expect(await ok(admin, '/application/newversion', { key: 'notes' })).toEqual({ key: 'notes', version: 2 });
    const v2 = await version(admin, 'notes', 2);
    const relabeled = { ...v2.definition, operations: v2.definition.operations.map((o: { label: string }) => ({ ...o, label: 'List all items' })) };
    await ok(admin, '/version/save', { key: 'notes', version: 2, definition: relabeled });
    await ok(admin, '/version/submit', { key: 'notes', version: 2 });
    expect((await fails(admin, '/version/approve', { key: 'notes', version: 2 })).code).toBe('SEPARATION_OF_DUTIES');
    expect((await version(admin, 'notes', 2)).can).toMatchObject({ review: false, reviewBlockedReason: expect.stringMatching(/separation of duties/) });

    // A label change does not touch hosts, so no acknowledgement is needed; v1 is superseded.
    const approved = await ok(publisher, '/version/approve', { key: 'notes', version: 2 });
    expect(approved.status).toBe('PUBLISHED');
    expect(approved.diff.changes).toEqual([{ area: 'operation notes.items.list', kind: 'changed' }]);
    expect((await version(editor, 'notes', 1)).status).toBe('SUPERSEDED');
    expect((await catalog()).definitions.find((d) => (d.definition as { key: string }).key === 'notes')!.definition).toMatchObject({ version: 2 });
  });

  it('flags host changes and returns rejected versions to draft with the reviewer note', async () => {
    await ok(editor, '/application/newversion', { key: 'notes' });
    const v3 = await version(editor, 'notes', 3);
    const moved = { ...v3.definition, api: { ...v3.definition.api, baseUrl: 'https://notes-proxy.example.org', allowedHosts: ['notes-proxy.example.org'] } };
    expect((await ok(editor, '/version/save', { key: 'notes', version: 3, definition: moved })).diff.hostChange).toBe(true);
    await ok(editor, '/version/submit', { key: 'notes', version: 3 });
    expect((await fails(publisher, '/version/reject', { key: 'notes', version: 3, note: 'no' })).details.fields.note).toBe('Explain what needs to change');
    expect(await ok(publisher, '/version/reject', { key: 'notes', version: 3, note: 'Unknown proxy host' })).toMatchObject({ status: 'DRAFT', reviewNote: 'Unknown proxy host' });
    expect((await fails(editor, '/application/newversion', { key: 'notes' })).code).toBe('OPEN_VERSION_EXISTS');
  });

  it('previews the request an operation would send, without any credential', async () => {
    const r = await ok(editor, '/version/preview', { key: 'notes', version: 2, operation: 'notes.items.list', resource: { project: 'ops' } });
    expect(r.request).toMatchObject({ method: 'GET', url: 'https://api.notes.example.com/v2/projects/ops/items?limit=10' });
    expect(r.request.headers).toContain('Authorization (injected by the customer webhook)');
    expect(r.mockResponse).toEqual({ status: 200, body: [{ id: 'item_1', name: 'First item' }] });
    expect((await ok(editor, '/version/preview', { key: 'notes', version: 2, operation: 'notes.items.list', resource: { project: '..' } })).error).toMatch(/invalid path segment/);
    expect((await fails(editor, '/version/preview', { key: 'notes', version: 2, operation: 'x', resource: { project: 5 } })).code).toBe('VALIDATION_ERROR');
  });

  it('keeps published versions and the audit log immutable in the database', async () => {
    await expect(sql(`update application_versions set definition = '{}'::jsonb where status = 'PUBLISHED'`)).rejects.toThrow(/immutable/);
    await expect(sql(`delete from application_versions where status = 'SUPERSEDED'`)).rejects.toThrow(/cannot be deleted/);
    await expect(sql(`delete from cms_audit_events`)).rejects.toThrow(/append-only/);
    const actions = (await ok(admin, '/audit/getall', { application: 'notes', pageSize: 200 })).map((e: { action: string }) => e.action);
    expect(actions).toEqual(expect.arrayContaining(['application.created', 'version.submitted', 'version.published', 'version.rejected']));
  });

  it('removes archived applications from the catalog', async () => {
    expect((await call(editor, 'POST', '/api/v1/application/archive', { key: 'notes', reason: 'test' })).status).toBe(403);
    expect(await ok(admin, '/application/archive', { key: 'notes', reason: 'Replaced' })).toEqual({ ok: true });
    expect((await catalog()).definitions.map((d) => (d.definition as { key: string }).key)).toEqual(['github', 'google', 'openai', 'slack']);
  });

  it('rotates the signing key: every published version is signed by both keys, consumers pinning either accept', async () => {
    const { SIGNING } = m.config;
    const { createPublicKey } = await import('node:crypto');
    const { publicKeyId } = await import('@token-vault/shared/signing');
    const oldPem = publicKeyPem;
    const oldKeyId = SIGNING.keyId;

    // Restart the CMS with a new key (the old private key is no longer available).
    const next = generateKeyPairSync('ed25519');
    SIGNING.key = next.privateKey;
    SIGNING.publicKeyPem = next.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    SIGNING.keyId = publicKeyId(createPublicKey(SIGNING.publicKeyPem));
    await m.signing.initSigning();
    expect(await m.signing.signPublishedWithActiveKey(m.db.default.getInstance().manager)).toBe(0); // idempotent

    const keys = (await call(null, 'GET', '/catalog/v1/public-key')).body as unknown as { key_id: string; keys: { key_id: string; active: boolean }[] };
    expect(keys).toMatchObject({ key_id: SIGNING.keyId });
    expect(keys.keys.map((k) => [k.key_id, k.active])).toEqual([
      [oldKeyId, false],
      [SIGNING.keyId, true],
    ]);

    const [gh] = (await catalog()).definitions;
    expect(gh!.key_id).toBe(SIGNING.keyId); // the active key's signature is primary
    expect(gh!.signatures!.map((x) => x.key_id)).toEqual([SIGNING.keyId, oldKeyId]);
    expect(verifySignedDefinition(gh!, oldPem).key).toBe('github'); // a consumer still pinning the old key
    expect(verifySignedDefinition(gh!, SIGNING.publicKeyPem).key).toBe('github'); // one that already switched

    // Versions published from now on carry only the new key's signature.
    await ok(editor, '/application/save', { key: 'rotated', name: 'Rotated' });
    await ok(editor, '/version/submit', { key: 'rotated', version: 1 });
    await ok(publisher, '/version/approve', { key: 'rotated', version: 1, acknowledgeHostChange: true });
    const rotated = (await catalog()).definitions.find((d) => (d.definition as { key: string }).key === 'rotated')!;
    expect(rotated.signatures!.map((x) => x.key_id)).toEqual([SIGNING.keyId]);
    expect(() => verifySignedDefinition(rotated, oldPem)).toThrow(SignatureError);
    expect((await version(editor, 'rotated', 1)).signatures).toEqual([{ keyId: SIGNING.keyId, signedAt: expect.any(String), active: true }]);

    // Signatures are append-only.
    await expect(sql(`delete from cms_version_signatures`)).rejects.toThrow(/append-only/);
    const actions = (await ok(admin, '/audit/getall', { pageSize: 200 })).map((e: { action: string }) => e.action);
    expect(actions).toEqual(expect.arrayContaining(['signing.key_activated', 'signing.versions_signed']));
  });

  it('lets an administrator change only the availability in one click, as a signed new version', async () => {
    expect((await call(editor, 'POST', '/api/v1/application/availability', { key: 'google', availability: 'available' })).status).toBe(403);
    expect((await call(publisher, 'POST', '/api/v1/application/availability', { key: 'google', availability: 'available' })).status).toBe(403);

    const before = (await catalog()).definitions.find((d) => (d.definition as { key: string }).key === 'google')!;
    expect(await ok(admin, '/application/availability', { key: 'google', availability: 'available', note: 'Launch' })).toEqual({ key: 'google', version: 2, availability: 'available' });

    const after = (await catalog()).definitions.find((d) => (d.definition as { key: string }).key === 'google')!;
    const { publicKeyId } = await import('@token-vault/shared/signing');
    const { createPublicKey } = await import('node:crypto');
    const { SIGNING } = m.config;
    expect(publicKeyId(createPublicKey(SIGNING.publicKeyPem))).toBe(after.key_id);
    expect(verifySignedDefinition(after, SIGNING.publicKeyPem)).toMatchObject({ version: 2, catalog: { availability: 'available' } });
    // Nothing but the version and availability changed.
    const strip = (x: unknown) => ({ ...(x as object), version: 0, catalog: { ...(x as { catalog: object }).catalog, availability: 'x' } });
    expect(strip(after.definition)).toEqual(strip(before.definition));
    expect((await version(admin, 'google', 1)).status).toBe('SUPERSEDED');
    expect((await version(admin, 'google', 2)).reviewNote).toMatch(/Availability changed to available by an administrator.*Launch/);

    expect((await fails(admin, '/application/availability', { key: 'google', availability: 'available' })).code).toBe('UNCHANGED');
    expect((await fails(admin, '/application/availability', { key: 'google', availability: 'soon' })).details.fields.availability).toBe('Choose available or coming_soon');
    await ok(editor, '/application/newversion', { key: 'google' });
    expect((await fails(admin, '/application/availability', { key: 'google', availability: 'coming_soon' })).code).toBe('OPEN_VERSION_EXISTS');
    const events = await ok(admin, '/audit/getall', { application: 'google' });
    expect(events[1]).toMatchObject({ action: 'version.published', version: 2, details: { oneClick: true, availability: 'available' } });
  });

  it('lets an administrator edit a seeded application (from its published v1) and publish it directly', async () => {
    const v1 = await version(admin, 'slack', 1);
    expect(v1.can).toMatchObject({ edit: false, editAsNewVersion: true, publishDirectly: false });
    expect(v1.openVersion).toBeNull();
    expect((await version(publisher, 'slack', 1)).can.editAsNewVersion).toBe(false);

    expect(await ok(admin, '/application/newversion', { key: 'slack', from: 1 })).toEqual({ key: 'slack', version: 2 });
    expect((await version(admin, 'slack', 1)).openVersion).toBe(2);
    const draft = await version(admin, 'slack', 2);
    const edited = { ...draft.definition, description: 'Edited by the admin', catalog: { ...draft.definition.catalog, availability: 'available' } };
    expect((await ok(admin, '/version/save', { key: 'slack', version: 2, definition: edited })).can).toMatchObject({ edit: true, publishDirectly: true });

    // Only administrators, and only for open versions.
    expect((await call(editor, 'POST', '/api/v1/version/publish', { key: 'slack', version: 2 })).status).toBe(403);
    expect((await fails(admin, '/version/publish', { key: 'slack', version: 1 })).code).toBe('INVALID_STATE');

    expect(await ok(admin, '/version/publish', { key: 'slack', version: 2, note: 'Pilot' })).toMatchObject({ status: 'PUBLISHED', reviewNote: 'Published directly by an administrator (no separate review): Pilot' });
    expect((await version(admin, 'slack', 1)).status).toBe('SUPERSEDED');

    const served = (await catalog()).definitions.find((d) => (d.definition as { key: string }).key === 'slack')!;
    expect(verifySignedDefinition(served, m.config.SIGNING.publicKeyPem)).toMatchObject({ version: 2, description: 'Edited by the admin', catalog: { availability: 'available' } });
    const [published] = await ok(admin, '/audit/getall', { application: 'slack' });
    expect(published).toMatchObject({ action: 'version.published', version: 2, details: { direct: true } });
  });

  it('still asks to confirm new hosts when publishing directly, and can be turned off', async () => {
    await ok(admin, '/application/newversion', { key: 'openai' });
    const draft = await version(admin, 'openai', 2);
    await ok(admin, '/version/save', { key: 'openai', version: 2, definition: { ...draft.definition, api: { ...draft.definition.api, allowedHosts: ['api.openai.com', 'files.openai.com'] } } });
    expect((await fails(admin, '/version/publish', { key: 'openai', version: 2 })).code).toBe('HOST_CHANGE_UNACKNOWLEDGED');

    m.config.SETTINGS.adminDirectPublish = false;
    try {
      expect((await version(admin, 'openai', 2)).can.publishDirectly).toBe(false);
      expect((await fails(admin, '/version/publish', { key: 'openai', version: 2, acknowledgeHostChange: true })).code).toBe('DIRECT_PUBLISH_DISABLED');
    } finally {
      m.config.SETTINGS.adminDirectPublish = true;
    }
    expect((await ok(admin, '/version/publish', { key: 'openai', version: 2, acknowledgeHostChange: true })).status).toBe('PUBLISHED');
  });
});
