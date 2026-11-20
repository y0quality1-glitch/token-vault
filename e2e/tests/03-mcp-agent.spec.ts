import { expect, test, type APIRequestContext } from '@playwright/test';
import { resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { DEMO_PASSWORD, details } from './helpers';

/**
 * A real MCP client drives the real Token Vault MCP server process against the running
 * stack, exactly as an AI agent (e.g. Claude) would. The agent process only ever holds
 * its Token Vault API key; GitHub calls are brokered through the customer webhook.
 */
const API = 'http://localhost:4000';
const MCP_BIN = resolve(import.meta.dirname, '../../mcp/bin/token-vault-mcp.mjs');

test.describe.serial('AI agent via MCP (Demo Organization)', () => {
  let admin: APIRequestContext;
  let client: Client;
  let apiKey = '';
  let grantId = '';
  let stderr = '';

  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { type: string; text: string }[] };
    return { isError: !!r.isError, text: r.content.map((c) => c.text).join('\n') };
  };

  test.beforeAll(async ({ playwright }) => {
    // Admin setup through the control-plane API: a dedicated agent with its own grant.
    admin = await playwright.request.newContext({ baseURL: API });
    expect((await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    expect((await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } })).ok()).toBe(true);
    const agent = await details(await admin.post('/api/v1/agent/save', { data: { name: 'Claude MCP Agent', environment: 'development', ownerTeam: 'Platform AI', agentType: 'AI_AGENT' } }));
    apiKey = agent.credential.apiKey;
    const now = Date.now();
    const grant = await admin.post('/api/v1/grant/save', {
      data: {
        name: 'MCP agent issue access',
        agentId: agent.agent.id,
        integrationId: 'int_github_001',
        environment: 'development',
        scopes: ['github.repositories.read', 'github.issues.list', 'github.issues.create'],
        repositories: ['demo-org/demo-repo'],
        validFrom: new Date(now - 60_000).toISOString(),
        expiresAt: new Date(now + 86_400_000).toISOString(),
        rateLimitPerMinute: 30,
      },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    grantId = (await details(grant)).id;

    // Launch the MCP server exactly as an MCP host would: credential via environment only.
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [MCP_BIN],
      env: { PATH: process.env.PATH ?? '', TOKEN_VAULT_URL: API, TOKEN_VAULT_API_KEY: apiKey },
      stderr: 'pipe',
    });
    transport.stderr?.on('data', (d) => (stderr += String(d)));
    client = new Client({ name: 'e2e-agent', version: '1.0.0' });
    await client.connect(transport);
  });

  test.afterAll(async () => {
    await client?.close();
    await admin?.dispose();
  });

  test('lists the brokered GitHub tools', async () => {
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(['token_vault_list_access', 'github_create_issue', 'github_list_issues', 'github_get_repository', 'github_read_file']));
  });

  test('the agent can see exactly what it is granted', async () => {
    const r = await call('token_vault_list_access');
    expect(r.isError).toBe(false);
    expect(r.text).toContain('MCP agent issue access [ACTIVE]');
    expect(r.text).toContain('demo-org/demo-repo');
  });

  test('creates an issue through Token Vault, recorded in the audit log', async () => {
    const r = await call('github_create_issue', { repository: 'demo-org/demo-repo', title: 'Filed by an AI agent via MCP', body: 'Brokered by Token Vault.' });
    expect(r.isError, r.text).toBe(false);
    expect(r.text).toContain('demo-org/demo-repo/issues/');
    const requestId = /Token Vault request (req_[0-9a-f]+)/.exec(r.text)?.[1];
    expect(requestId).toBeTruthy();
    const audit = await details(await admin.get(`/api/v1/accessRequest/getbyid/${requestId}`));
    expect(audit).toMatchObject({ agentName: 'Claude MCP Agent', operation: 'github.issues.create', decision: 'ALLOW', executionStatus: 'SUCCEEDED', source: 'agent-api' });
  });

  test('is denied outside its repository restriction and scopes', async () => {
    const other = await call('github_create_issue', { repository: 'demo-org/other-repo', title: 'x' });
    expect(other.isError).toBe(true);
    expect(other.text).toContain('RESOURCE_DENIED');
    const scope = await call('github_read_file', { repository: 'demo-org/demo-repo', path: 'README.md' });
    expect(scope.isError).toBe(true);
    expect(scope.text).toContain('SCOPE_DENIED');
  });

  test('revocation takes effect on the agent’s very next tool call', async () => {
    expect((await admin.post('/api/v1/grant/revoke', { data: { id: grantId, reason: 'MCP e2e revocation' } })).ok()).toBe(true);
    const r = await call('github_create_issue', { repository: 'demo-org/demo-repo', title: 'after revoke' });
    expect(r.isError).toBe(true);
    expect(r.text).toContain('GRANT_REVOKED');
    expect((await call('token_vault_list_access')).text).toContain('MCP agent issue access [REVOKED]');
  });

  test('the agent process never prints its credential', async () => {
    expect(stderr).toContain('[token-vault-mcp] ready');
    expect(stderr).not.toContain(apiKey);
  });
});
