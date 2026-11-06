import { expect, test, type APIRequestContext } from '@playwright/test';
import { resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { DEMO_PASSWORD } from './helpers';

/**
 * MCP tools come from the catalog: an application published in the CMS becomes typed MCP
 * tools for agents granted on it, with no code change. Publishing a new version with a
 * new operation adds its tool to a running MCP server (tools/list_changed).
 */
const API = 'http://localhost:4000';
const CMS_API = 'http://localhost:4200';
const MCP_BIN = resolve(import.meta.dirname, '../../mcp/bin/token-vault-mcp.mjs');
const STATUS_KEY = 'sp_0123456789abcdefghij';

const list = {
  id: 'statuspage.incidents.list',
  label: 'List incidents',
  risk: 'read',
  request: { method: 'GET', path: '/pages/{resource.page}/incidents' },
  response: { fields: { id: 'id', title: 'title', status: 'status' } },
  mock: { status: 200, body: [{ id: 'inc_1', title: 'API latency', status: 'investigating', internal: 'on-call: dana' }] },
};
const create = {
  id: 'statuspage.incidents.create',
  label: 'Open an incident',
  risk: 'write',
  input: { title: { type: 'string', required: true, maxLength: 200 } },
  request: { method: 'POST', path: '/pages/{resource.page}/incidents', body: { title: '{input.title}' } },
  response: { fields: { id: 'id', title: 'title' } },
  mock: { status: 201, body: { id: 'inc_2', title: 'created' } },
};
const definition = (operations: object[]) => ({
  key: 'statuspage',
  name: 'Status Page',
  description: 'Public status page incidents.',
  api: { baseUrl: 'https://api.statuspage.example.com/v1', allowedHosts: ['api.statuspage.example.com'] },
  resource: { name: 'page', label: 'Page', pattern: '^[a-z][a-z0-9-]{1,30}$', example: 'acme' },
  auth: [{ id: 'API_KEY', label: 'API key', kind: 'header', header: 'X-Api-Key', secretPattern: '^sp_[a-z0-9]{16,}$' }],
  credentialTest: { request: { method: 'GET', path: '/me' }, response: { fields: { id: 'id' } } },
  operations,
});

test.describe.serial('MCP tools generated from the catalog', () => {
  let admin: APIRequestContext;
  let cms: APIRequestContext;
  let client: Client;
  let listChanged = 0;
  let stderr = '';

  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { type: string; text: string }[]; structuredContent?: { result?: unknown } };
    return { isError: !!r.isError, text: r.content.map((c) => c.text).join('\n'), result: r.structuredContent?.result };
  };
  const toolNames = async () => (await client.listTools()).tools.map((t) => t.name);

  async function publish(operations: object[], version: number) {
    if (version > 1) expect((await cms.post('/api/v1/applications/statuspage/versions', { data: {} })).status()).toBe(201);
    const saved = await (await cms.put(`/api/v1/applications/statuspage/versions/${version}`, { data: { definition: definition(operations) } })).json();
    expect(saved.issues).toEqual([]);
    const r = await cms.post(`/api/v1/applications/statuspage/versions/${version}/publish`, { data: { acknowledgeHostChange: true } });
    expect((await r.json()).status).toBe('PUBLISHED');
  }

  test.beforeAll(async ({ playwright }) => {
    cms = await playwright.request.newContext({ baseURL: CMS_API });
    expect((await cms.post('/api/v1/auth/login', { data: { email: 'admin@cms.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    admin = await playwright.request.newContext({ baseURL: API });
    expect((await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    await admin.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
  });
  test.afterAll(async () => {
    await client?.close();
    await Promise.all([admin?.dispose(), cms?.dispose()]);
  });

  test('a CMS application, connected and granted, becomes a typed MCP tool', async () => {
    expect((await cms.post('/api/v1/applications', { data: { key: 'statuspage', name: 'Status Page' } })).status()).toBe(201);
    await publish([list], 1);
    await expect.poll(async () => ((await (await admin.get('/api/v1/providers')).json()).providers as { key: string }[]).some((p) => p.key === 'statuspage'), { timeout: 15_000 }).toBe(true);

    const integration = await admin.post('/api/v1/integrations', { data: { provider: 'statuspage', authType: 'API_KEY', displayName: 'Acme Status', webhookId: 'wh_local0000000001', secret: STATUS_KEY, allowedResources: ['acme', 'beta'], environment: 'development' } });
    expect(integration.status(), await integration.text()).toBe(201);
    const integrationId = (await integration.json()).id;
    const agent = await (await admin.post('/api/v1/agents', { data: { name: 'Status Agent', environment: 'development', ownerTeam: 'SRE', agentType: 'AI_AGENT' } })).json();
    const now = Date.now();
    const grant = await admin.post('/api/v1/grants', {
      data: { name: 'Status read', agentId: agent.agent.id, integrationId, environment: 'development', scopes: ['statuspage.incidents.list'], repositories: ['acme'], validFrom: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 86_400_000).toISOString(), rateLimitPerMinute: 30 },
    });
    expect(grant.ok(), await grant.text()).toBe(true);

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [MCP_BIN],
      env: { PATH: process.env.PATH ?? '', TOKEN_VAULT_URL: API, TOKEN_VAULT_API_KEY: agent.credential.apiKey, TOKEN_VAULT_TOOLS_REFRESH_S: '1' },
      stderr: 'pipe',
    });
    transport.stderr?.on('data', (d) => (stderr += String(d)));
    client = new Client({ name: 'e2e-catalog-agent', version: '1.0.0' });
    client.setNotificationHandler(ToolListChangedNotificationSchema, async () => void listChanged++);
    await client.connect(transport);

    const tool = (await client.listTools()).tools.find((t) => t.name === 'statuspage_incidents_list');
    expect(tool, `tools: ${(await toolNames()).join(', ')}`).toBeTruthy();
    expect(tool!.title).toBe('Status Page: List incidents');
    expect(tool!.inputSchema.properties).toHaveProperty('page');

    const ok = await call('statuspage_incidents_list', { page: 'acme' });
    expect(ok.isError, ok.text).toBe(false);
    expect(ok.text).toContain('List incidents succeeded (simulated Status Page)');
    expect(ok.result).toEqual([{ id: 'inc_1', title: 'API latency', status: 'investigating' }]); // allow-listed fields only

    const other = await call('statuspage_incidents_list', { page: 'beta' });
    expect(other.isError).toBe(true);
    expect(other.text).toMatch(/RESOURCE_DENIED/);
    const invalid = await call('statuspage_incidents_list', { page: 'Not A Page' });
    expect(invalid.isError).toBe(true);
  });

  test('publishing a new operation adds its tool to the running MCP server', async () => {
    const before = listChanged;
    await publish([list, create], 2);
    await expect.poll(toolNames, { timeout: 30_000 }).toContain('statuspage_incidents_create');
    expect(listChanged).toBeGreaterThan(before);
    expect(stderr).toContain('[token-vault-mcp] application tools updated');

    // Not granted yet: denied, and the agent may ask a human for it.
    const denied = await call('statuspage_incidents_create', { page: 'acme', title: 'Checkout errors' });
    expect(denied.isError).toBe(true);
    expect(denied.text).toMatch(/SCOPE_DENIED/);
    expect(denied.text).toContain('token_vault_request_access');
    const req = await call('token_vault_request_access', { operations: ['statuspage.incidents.create'], resource: 'acme', justification: 'Open an incident for the checkout errors the user reported' });
    expect(req.isError, req.text).toBe(false);
    expect(req.text).toMatch(/is PENDING/);
  });

  test('the agent process never prints its credential', async () => {
    expect(stderr).not.toMatch(/tvak_[0-9a-f]{12}_[A-Za-z0-9_-]{20,}/);
    expect(stderr).not.toContain(STATUS_KEY);
  });
});
