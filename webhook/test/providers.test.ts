import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DefinitionError,
  getProviderDefinition,
  githubDefinition,
  mapResponse,
  renderBody,
  renderPath,
  validateProviderDefinition,
  type ProviderDefinitionInput,
} from '@token-vault/shared';
import { executeOperation, testCredential } from '../src/providers/executor';

/** A provider that exists only as data: no simulator, no code. */
const notes: ProviderDefinitionInput = {
  key: 'notes',
  version: 1,
  name: 'Notes',
  api: { baseUrl: 'https://api.notes.example.com/v2', allowedHosts: ['*.notes.example.com'], headers: { Accept: 'application/json' } },
  resource: { name: 'project', label: 'Project', pattern: '^[A-Z][A-Z0-9]{1,9}$' },
  auth: [{ id: 'API_KEY', label: 'API key', kind: 'header', header: 'X-Api-Key', secretPattern: '^nk_[a-z0-9]{16,}$' }],
  credentialTest: { request: { method: 'GET', path: '/me' }, response: { fields: { name: 'name' } } },
  operations: [
    {
      id: 'notes.notes.create',
      label: 'Create note',
      risk: 'write',
      input: { text: { type: 'string', required: true, maxLength: 100 }, pinned: { type: 'boolean' } },
      request: { method: 'POST', path: '/projects/{resource.project}/notes', body: { text: '{input.text}', pinned: '{input.pinned}', source: 'token-vault' } },
      response: { fields: { id: 'id', text: 'text' } },
      mock: { status: 201, body: { id: 'n_1', text: 'mocked', internal_token: 'should-not-leak' } },
    },
    { id: 'notes.projects.delete', label: 'Delete project', risk: 'destructive', request: { method: 'DELETE', path: '/projects/{resource.project}' }, response: { fields: { ok: 'ok' } } },
  ],
};

const API_KEY = 'nk_0123456789abcdef';
const auth = { kind: 'header' as const, header: 'X-Api-Key', secret: API_KEY };

function expectInvalid(patch: (d: any) => void, message: RegExp) {
  const d = structuredClone(notes) as any;
  patch(d);
  expect(() => validateProviderDefinition(d)).toThrow(DefinitionError);
  try {
    validateProviderDefinition(d);
  } catch (e) {
    expect((e as DefinitionError).issues.join('\n')).toMatch(message);
  }
}

describe('provider definitions', () => {
  it('accepts the bundled GitHub definition and a data-only provider', () => {
    expect(validateProviderDefinition(githubDefinition).operations.length).toBeGreaterThan(3);
    expect(validateProviderDefinition(notes).key).toBe('notes');
  });

  it('refuses definitions that could send credentials somewhere unexpected', () => {
    expectInvalid((d) => (d.api.baseUrl = 'http://api.notes.example.com'), /https/);
    expectInvalid((d) => (d.api.baseUrl = 'https://evil.example.net'), /not in api.allowedHosts/);
    expectInvalid((d) => (d.api.headers.Authorization = 'Bearer x'), /injected by auth/);
    expectInvalid((d) => (d.api.headers['X-Trace'] = '{input.text}'), /placeholders are not allowed in headers/);
    expectInvalid((d) => (d.operations[0].request.path = '/x/{secret.value}'), /unknown placeholder \{secret.value\}/);
    expectInvalid((d) => (d.operations[0].request.body.extra = '{input.undeclared}'), /unknown placeholder \{input.undeclared\}/);
    expectInvalid((d) => (d.operations[0].request.path = 'https://evil.example.net/x'), /start with \//);
    expectInvalid((d) => (d.operations[0].request.path = '/a/../b'), /plain path/);
  });

  it('checks ids, patterns and method/body consistency', () => {
    expectInvalid((d) => (d.operations[0].id = 'github.notes.create'), /must start with "notes\."/);
    expectInvalid((d) => (d.resource.pattern = '[A-Z]+'), /anchored/);
    expectInvalid((d) => (d.operations[0].request.method = 'GET'), /GET requests cannot have a body/);
    expectInvalid((d) => d.operations.push(structuredClone(d.operations[0])), /duplicate id/);
  });
});

describe('templates', () => {
  const vars = { resource: { repository: 'demo-org/demo repo', path: undefined }, input: { title: 'Hi', n: 3 } };

  it('encodes each path segment and refuses traversal', () => {
    expect(renderPath('/repos/{resource.repository}/contents/{resource.path|README.md}', vars)).toBe('/repos/demo-org/demo%20repo/contents/README.md');
    expect(() => renderPath('/repos/{resource.repository}', { ...vars, resource: { repository: 'demo-org/..' } })).toThrow(/invalid path segment/);
    expect(() => renderPath('/repos/{resource.repository}', { ...vars, resource: {} })).toThrow(/missing value/);
  });

  it('keeps value types in bodies and omits missing optional inputs', () => {
    expect(renderBody({ title: '{input.title}', n: '{input.n}', body: '{input.body}', label: 'by {input.title}' }, vars)).toEqual({ title: 'Hi', n: 3, label: 'by Hi' });
  });

  it('returns only allow-listed response fields', () => {
    const map = { fields: { login: 'user.login', tags: { path: 'labels', pluck: 'name' }, text: { path: 'content', decode: 'base64' as const }, kind: { const: 'x' } }, limit: 2 };
    expect(mapResponse({ user: { login: 'a' }, labels: [{ name: 'bug' }], content: Buffer.from('héllo').toString('base64'), token: 'secret' }, map)).toEqual({ login: 'a', tags: ['bug'], text: 'héllo', kind: 'x' });
    expect(mapResponse([{ user: { login: 'a' } }, { user: { login: 'b' } }, { user: { login: 'c' } }], map)).toHaveLength(2);
  });
});

describe('generic executor', () => {
  const def = validateProviderDefinition(notes);
  const call = { operation: 'notes.notes.create', resource: { project: 'OPS' }, input: { text: 'Deploy done', pinned: true, undeclared: 'ignored' } };
  afterEach(() => vi.unstubAllGlobals());

  it('runs a data-only provider in mock mode from its declared mock response', async () => {
    const r = await executeOperation('mock', def, call, auth);
    expect(r).toEqual({ upstreamStatus: 201, simulated: true, body: { id: 'n_1', text: 'mocked' } });
  });

  it('builds the live request from the definition and injects the credential last', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: 'n_9', text: 'Deploy done', owner_token: 'x' }), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    const r = await executeOperation('live', def, call, auth);
    expect(r.body).toEqual({ id: 'n_9', text: 'Deploy done' });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(String(url)).toBe('https://api.notes.example.com/v2/projects/OPS/notes');
    expect(init.redirect).toBe('manual');
    expect(init.headers).toMatchObject({ 'x-api-key': API_KEY, accept: 'application/json', 'content-type': 'application/json' });
    expect(JSON.parse(String(init.body))).toEqual({ text: 'Deploy done', pinned: true, source: 'token-vault' }); // undeclared input is never forwarded
  });

  it('never follows redirects (they could carry the credential elsewhere)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 302, headers: { location: 'https://evil.example.net' } })));
    await expect(executeOperation('live', def, call, auth)).rejects.toMatchObject({ code: 'REDIRECT_REFUSED' });
  });

  it('validates resources and inputs, and never executes destructive operations', async () => {
    await expect(executeOperation('mock', def, { ...call, resource: { project: 'ops/../x' } }, auth)).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(executeOperation('mock', def, { ...call, input: { pinned: true } }, auth)).rejects.toMatchObject({ code: 'INVALID_REQUEST', message: /text is required/ });
    await expect(executeOperation('mock', def, { ...call, input: { text: 5 } }, auth)).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await expect(executeOperation('mock', def, { ...call, operation: 'notes.projects.delete' }, auth)).rejects.toMatchObject({ code: 'UNSUPPORTED_OPERATION' });
    await expect(executeOperation('mock', def, { ...call, operation: 'github.issues.create' }, auth)).rejects.toMatchObject({ code: 'UNSUPPORTED_OPERATION' });
  });

  it('returns only the message of an upstream error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ message: 'Nope', debug: { token: API_KEY } }), { status: 403 })));
    const r = await executeOperation('live', def, call, auth);
    expect(r).toEqual({ upstreamStatus: 403, simulated: false, body: { message: 'Nope' } });
  });
});

describe('GitHub through the generic executor (mock)', () => {
  const github = getProviderDefinition('github')!;
  const pat = { kind: 'bearer' as const, secret: 'mock_ghp_ExecutorTestToken1234567890' };
  const run = (operation: string, resource: Record<string, string>, input: Record<string, unknown> = {}) => executeOperation('mock', github, { operation, resource, input }, pat);

  it('reads files, lists issues and creates issues like the previous hand-written connector', async () => {
    const file = await run('github.contents.read', { repository: 'demo-org/demo-repo' });
    expect(file.body).toMatchObject({ path: 'README.md', encoding: 'utf-8', content: expect.stringContaining('# demo-repo') });
    const issues = (await run('github.issues.list', { repository: 'Demo-Org/Demo-Repo' })).body as { labels: string[]; user: string }[];
    expect(issues[0]).toMatchObject({ labels: ['security'], user: 'octo-admin' });
    const created = await run('github.issues.create', { repository: 'demo-org/demo-repo' }, { title: 'From the generic executor' });
    expect(created.upstreamStatus).toBe(201);
    expect(created.body).toMatchObject({ title: 'From the generic executor', html_url: expect.stringContaining('/issues/') });
    expect((await run('github.issues.create', { repository: 'demo-org/demo-repo' }, { title: '' })).upstreamStatus).toBe(422);
    expect((await run('github.repositories.read', { repository: 'demo-org/missing' })).upstreamStatus).toBe(404);
  });

  it('tests credentials with the definition test request', async () => {
    const ok = await testCredential('mock', github, github.auth.find((a) => a.id === 'PAT')!, pat);
    expect(ok).toMatchObject({ upstreamStatus: 200, body: { login: 'demo-bot', type: 'Bot' } });
    const bad = await testCredential('mock', github, github.auth.find((a) => a.id === 'PAT')!, { kind: 'bearer', secret: 'nope' });
    expect(bad.upstreamStatus).toBe(401);
  });
});
