import { describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { AgentCapabilitiesBody, AgentOperationsBody, ExecuteResponseBody } from '@token-vault/shared';
import { TokenVault } from '@token-vault/sdk';
import { createServer } from '../src/server';
import { resolveIntegration } from '../src/resolve';
import { catalogTools } from '../src/catalog-tools';

const slackProvider: AgentOperationsBody['providers'][number] = {
  key: 'slack',
  name: 'Slack',
  description: 'Chat',
  version: 2,
  resource: { name: 'channel', label: 'Channel', pattern: '^[CG][A-Z0-9]{8,12}$', case_insensitive: false, example: 'C0123456789' },
  resource_fields: [],
  operations: [
    { id: 'slack.messages.post', label: 'Post a message', description: '', risk: 'write', requires_resource: true, input: [{ name: 'text', type: 'string', label: 'Message', required: true, max_length: 4000 }] },
    { id: 'slack.channels.archive', label: 'Archive channel', description: '', risk: 'destructive', requires_resource: true, input: [] },
  ],
};
const githubProvider: AgentOperationsBody['providers'][number] = {
  key: 'github',
  name: 'GitHub',
  description: '',
  version: 1,
  resource: { name: 'repository', label: 'Repository', pattern: '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$', case_insensitive: true, example: 'demo-org/demo-repo' },
  resource_fields: [{ name: 'path', label: 'Path', pattern: '^.{1,240}$', case_insensitive: false, example: 'README.md' }],
  operations: [
    { id: 'github.issues.create', label: 'Create issue', description: '', risk: 'write', requires_resource: true, input: [] },
    { id: 'github.contents.write', label: 'Write file', description: '', risk: 'write', requires_resource: true, input: [{ name: 'content', type: 'string', label: null, required: true, max_length: null }, { name: 'path', type: 'string', label: null, required: false, max_length: null }] },
  ],
};
const operationsBody = (providers = [githubProvider, slackProvider], version = 'v1'): AgentOperationsBody => ({ version, providers });

describe('catalogTools', () => {
  it('makes one typed tool per non-destructive operation, skipping the hand-written GitHub ones', () => {
    const tools = catalogTools(operationsBody());
    expect(tools.map((t) => t.name)).toEqual(['github_contents_write', 'slack_messages_post']);
    const write = tools[0]!;
    // "path" is both a resource field and an input: the input is renamed, and both reach Token Vault where they belong.
    expect(Object.keys(write.inputSchema).sort()).toEqual(['content', 'input_path', 'integration', 'path', 'repository']);
    expect(write.split({ repository: 'a/b', path: 'docs/x.md', content: 'hi', input_path: 'y' })).toEqual({ resource: { repository: 'a/b', path: 'docs/x.md' }, input: { content: 'hi', path: 'y' }, integration: undefined });
    expect(tools[1]!.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false });
  });
});

const KEY = 'tvak_0123456789ab_abcdefghijklmnopqrstuvwxyz012345';

function grant(over: Partial<AgentCapabilitiesBody['grants'][number]> = {}): AgentCapabilitiesBody['grants'][number] {
  return {
    grant_id: 'grt_1',
    name: 'GitHub Issue Creation',
    status: 'ACTIVE',
    integration_id: 'int_github_001',
    integration_name: 'Demo GitHub',
    provider: 'github',
    integration_available: true,
    operations: ['github.repositories.read', 'github.issues.create'],
    repositories: ['demo-org/demo-repo'],
    rate_limit_per_minute: 10,
    valid_from: '2026-11-01T00:00:00.000Z',
    expires_at: '2026-11-11T00:00:00.000Z',
    ...over,
  };
}
const caps = (grants = [grant()]): AgentCapabilitiesBody => ({ agent: { id: 'agt_1', name: 'GitHub Assistant', status: 'ACTIVE', organization: 'demo-org' }, grants });

describe('resolveIntegration', () => {
  it('uses the only integration, an explicit ID or name, or the one whose grant covers the call', () => {
    expect(resolveIntegration(caps(), { provider: 'github', operation: 'github.issues.list' })).toEqual({ ok: true, integrationId: 'int_github_001' });
    const two = caps([grant(), grant({ grant_id: 'grt_2', integration_id: 'int_github_002', integration_name: 'GitHub Staging', operations: ['github.issues.list'], repositories: [] })]);
    expect(resolveIntegration(two, { provider: 'github', operation: 'github.issues.list', integration: 'github staging' })).toEqual({ ok: true, integrationId: 'int_github_002' });
    expect(resolveIntegration(two, { provider: 'github', operation: 'github.issues.create', repository: 'demo-org/demo-repo' })).toEqual({ ok: true, integrationId: 'int_github_001' });
    expect(resolveIntegration(two, { provider: 'github', operation: 'github.repositories.read', repository: 'x/y' })).toMatchObject({ ok: false });
    expect(resolveIntegration(caps([]), { provider: 'github', operation: 'github.issues.list' })).toMatchObject({ ok: false });
    // A revoked grant still identifies the integration, so the call reaches Token Vault and its denial is audited.
    expect(resolveIntegration(caps([grant({ status: 'REVOKED' })]), { provider: 'github', operation: 'github.issues.create' })).toEqual({ ok: true, integrationId: 'int_github_001' });
  });
});

describe('MCP tools', () => {
  const ops = { current: operationsBody() };
  const capsNow = { current: caps() };
  async function connect(execute: Partial<ExecuteResponseBody> & { httpStatus?: number }) {
    ops.current = operationsBody();
    capsNow.current = caps([grant(), grant({ grant_id: 'grt_s', name: 'Slack posting', integration_id: 'int_slack_1', integration_name: 'Team Slack', provider: 'slack', operations: ['slack.messages.post'], repositories: ['C0123456789'] })]);
    const { httpStatus = 200, ...over } = execute;
    const body: ExecuteResponseBody = {
      request_id: 'req_abc',
      correlation_id: 'corr_1',
      decision: 'ALLOW',
      decision_code: 'ALLOWED',
      reason: 'Authorized by grant "GitHub Issue Creation".',
      matched_rule: { type: 'grant', id: 'grt_1' },
      grant_id: 'grt_1',
      execution: { status: 'SUCCEEDED', webhook_status: 'OK', upstream_status: 201, duration_ms: 50, simulated: true, idempotent_replay: false },
      result: { number: 44, html_url: 'https://github.com/demo-org/demo-repo/issues/44' },
      checks: [],
      ...over,
    };
    const calls: { url: string; body: unknown }[] = [];
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      calls.push({ url: u, body: init?.body ? JSON.parse(String(init.body)) : null });
      if (u.endsWith('/operations')) return new Response(JSON.stringify(ops.current), { status: 200 });
      if (u.endsWith('/access-requests')) return new Response(JSON.stringify({ access_request_id: 'gr_1', status: 'PENDING', expires_at: '2026-11-07T00:00:00.000Z' }), { status: 201 });
      const payload = u.endsWith('/capabilities') ? capsNow.current : body;
      return new Response(JSON.stringify(payload), { status: u.endsWith('/capabilities') ? 200 : httpStatus });
    });
    const tv = new TokenVault({ apiKey: KEY, baseUrl: 'http://tv.test', fetch: fetchMock as unknown as typeof fetch });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const server = createServer(tv);
    await server.connect(serverT);
    const client = new Client({ name: 'test', version: '1.0.0' });
    const listChanged: number[] = [];
    await client.connect(clientT);
    client.fallbackNotificationHandler = async (n) => void (n.method === 'notifications/tools/list_changed' && listChanged.push(Date.now()));
    return { client, calls, server, listChanged };
  }
  const textOf = (r: unknown) => ((r as { content?: { text: string }[] }).content ?? []).map((c) => c.text).join('\n');

  it('exposes the brokered GitHub tools', async () => {
    const { client } = await connect({});
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual(['github_create_issue', 'github_get_repository', 'github_list_issues', 'github_read_file', 'token_vault_check_access_request', 'token_vault_list_access', 'token_vault_request_access']);
  });

  it('creates an issue through Token Vault and returns the sanitized result with its request ID', async () => {
    const { client, calls } = await connect({});
    const r = await client.callTool({ name: 'github_create_issue', arguments: { repository: 'demo-org/demo-repo', title: 'Hello from an agent' } });
    expect(r.isError).toBeFalsy();
    expect(textOf(r)).toContain('req_abc');
    expect(textOf(r)).toContain('issues/44');
    expect(calls.at(-1)).toMatchObject({ url: 'http://tv.test/agent/v1/execute', body: { integration_id: 'int_github_001', operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input: { title: 'Hello from an agent' } } });
    expect(JSON.stringify(r)).not.toContain(KEY);
  });

  it('reports a denial as a tool error with the reason, and tells the model not to work around it', async () => {
    const { client } = await connect({ httpStatus: 403, decision: 'DENY', decision_code: 'GRANT_REVOKED', reason: 'Grant "GitHub Issue Creation" was revoked.', result: null, execution: { status: 'NOT_EXECUTED', webhook_status: 'NOT_CALLED', upstream_status: null, duration_ms: 3, simulated: true, idempotent_replay: false } });
    const r = await client.callTool({ name: 'github_create_issue', arguments: { repository: 'demo-org/demo-repo', title: 'x' } });
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/Access denied by Token Vault: Revoked grant \(GRANT_REVOKED/);
    expect(textOf(r)).toMatch(/cannot be resolved by requesting access/); // revocation is not requestable
  });

  it('offers a just-in-time request for denials a human can resolve', async () => {
    const { client } = await connect({ httpStatus: 403, decision: 'DENY', decision_code: 'SCOPE_DENIED', reason: 'Operation github.contents.read is not included in grant scopes.', result: null, execution: { status: 'NOT_EXECUTED', webhook_status: 'NOT_CALLED', upstream_status: null, duration_ms: 3, simulated: true, idempotent_replay: false } });
    const r = await client.callTool({ name: 'github_read_file', arguments: { repository: 'demo-org/demo-repo', path: 'README.md' } });
    expect(textOf(r)).toMatch(/token_vault_request_access/);
    expect(textOf(r)).toContain('denied_request_id: "req_abc"');
  });

  it('validates arguments before calling Token Vault', async () => {
    const { client, calls } = await connect({});
    const r = await client.callTool({ name: 'github_list_issues', arguments: { repository: 'not a repo' } });
    expect(r.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it('adds tools for the applications in the catalog, typed from their definitions', async () => {
    const { client, calls, server, listChanged } = await connect({ result: { ok: true, ts: '1767600000.000100' } });
    expect(await server.refreshTools()).toBe(true);
    const tools = (await client.listTools()).tools;
    expect(tools.map((t) => t.name)).toContain('slack_messages_post');
    expect(tools.map((t) => t.name)).not.toContain('slack_channels_archive'); // destructive operations never become tools
    const post = tools.find((t) => t.name === 'slack_messages_post')!;
    expect(post.inputSchema.required).toEqual(['channel', 'text']);
    await vi.waitFor(() => expect(listChanged.length).toBeGreaterThan(0));

    const bad = await client.callTool({ name: 'slack_messages_post', arguments: { channel: 'general', text: 'hi' } });
    expect(bad.isError).toBe(true);
    expect(calls.some((c) => c.url.endsWith('/execute'))).toBe(false);

    const r = await client.callTool({ name: 'slack_messages_post', arguments: { channel: 'C0123456789', text: 'Deploy finished' } });
    expect(r.isError).toBeFalsy();
    expect(textOf(r)).toContain('Post a message succeeded (simulated Slack)');
    expect(calls.at(-1)).toMatchObject({ url: 'http://tv.test/agent/v1/execute', body: { integration_id: 'int_slack_1', operation: 'slack.messages.post', resource: { channel: 'C0123456789' }, input: { text: 'Deploy finished' } } });
  });

  it('follows catalog changes: unchanged versions are free, removed applications lose their tools', async () => {
    const { client, server } = await connect({});
    await server.refreshTools();
    expect(await server.refreshTools()).toBe(false);
    ops.current = operationsBody([githubProvider], 'v2');
    expect(await server.refreshTools()).toBe(true);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).not.toContain('slack_messages_post');
    expect(names).toContain('github_contents_write');
    expect(names).toContain('github_create_issue'); // hand-written tools are unaffected
  });

  it('requests access for any application, narrowed to a resource', async () => {
    const { client, calls } = await connect({});
    const r = await client.callTool({ name: 'token_vault_request_access', arguments: { operations: ['slack.messages.post'], resource: 'C0123456789', justification: 'Post the release notes to the team channel' } });
    expect(r.isError).toBeFalsy();
    expect(calls.at(-1)).toMatchObject({ url: 'http://tv.test/agent/v1/access-requests', body: { integration_id: 'int_slack_1', operations: ['slack.messages.post'], repositories: ['C0123456789'] } });
    const mixed = await client.callTool({ name: 'token_vault_request_access', arguments: { operations: ['slack.messages.post', 'github.issues.create'], justification: 'Needs both for the release' } });
    expect(textOf(mixed)).toMatch(/one application at a time/);
  });
});
