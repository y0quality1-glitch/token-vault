import { describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { AgentCapabilitiesBody, ExecuteResponseBody } from '@token-vault/shared';
import { TokenVault } from '@token-vault/sdk';
import { createServer } from '../src/server';
import { resolveIntegration } from '../src/resolve';

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
  async function connect(execute: Partial<ExecuteResponseBody> & { httpStatus?: number }) {
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
      const payload = u.endsWith('/capabilities') ? caps() : body;
      return new Response(JSON.stringify(payload), { status: u.endsWith('/capabilities') ? 200 : httpStatus });
    });
    const tv = new TokenVault({ apiKey: KEY, baseUrl: 'http://tv.test', fetch: fetchMock as unknown as typeof fetch });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    await createServer(tv).connect(serverT);
    const client = new Client({ name: 'test', version: '1.0.0' });
    await client.connect(clientT);
    return { client, calls };
  }
  const textOf = (r: unknown) => ((r as { content?: { text: string }[] }).content ?? []).map((c) => c.text).join('\n');

  it('exposes the brokered GitHub tools', async () => {
    const { client } = await connect({});
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual(['github_create_issue', 'github_get_repository', 'github_list_issues', 'github_read_file', 'token_vault_list_access']);
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
    expect(textOf(r)).toMatch(/Do not retry/);
  });

  it('validates arguments before calling Token Vault', async () => {
    const { client, calls } = await connect({});
    const r = await client.callTool({ name: 'github_list_issues', arguments: { repository: 'not a repo' } });
    expect(r.isError).toBe(true);
    expect(calls).toHaveLength(0);
  });
});
