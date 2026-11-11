import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { DEMO_PASSWORD, login } from './helpers';

/**
 * Human approval of risky operations, end to end: a REQUIRE_APPROVAL policy holds a real
 * MCP agent's request, a Security Administrator approves that exact request in the console,
 * and the agent's token_vault_check_approval call runs it, once.
 * The policy names only this spec's agent, so other specs are unaffected.
 */
const API = 'http://localhost:4000';
const MCP_BIN = resolve(import.meta.dirname, '../../mcp/bin/token-vault-mcp.mjs');

test.describe.serial('human approval of risky operations (Demo Organization)', () => {
  let admin: APIRequestContext;
  let client: Client;
  let page: Page;
  let approvalId = '';

  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { text: string }[] };
    return { isError: !!r.isError, text: r.content.map((c) => c.text).join('\n') };
  };

  test.beforeAll(async ({ playwright, browser }) => {
    // The owner registers the agent, so only another administrator may approve its requests.
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
    const agent = await (await admin.post('/api/v1/agents', { data: { name: 'Approval Agent', environment: 'development', ownerTeam: 'Platform AI', agentType: 'AI_AGENT' } })).json();
    const now = Date.now();
    const grant = await admin.post('/api/v1/grants', {
      data: {
        name: 'Approval agent issues',
        agentId: agent.agent.id,
        integrationId: 'int_github_001',
        environment: 'development',
        scopes: ['github.repositories.read', 'github.issues.create'],
        repositories: ['demo-org/demo-repo'],
        validFrom: new Date(now - 60_000).toISOString(),
        expiresAt: new Date(now + 86_400_000).toISOString(),
        rateLimitPerMinute: 30,
      },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    const policy = await admin.post('/api/v1/policies', {
      data: {
        name: 'Approve issues from Approval Agent',
        description: 'A human checks every issue this agent files.',
        effect: 'REQUIRE_APPROVAL',
        priority: 40,
        enabled: true,
        conditions: { agentSelector: { type: 'agent', value: agent.agent.id }, integrationSelector: { type: 'any' }, operations: ['github.issues.create'], environment: 'any' },
      },
    });
    expect(policy.ok(), await policy.text()).toBe(true);

    const transport = new StdioClientTransport({ command: process.execPath, args: [MCP_BIN], env: { PATH: process.env.PATH ?? '', TOKEN_VAULT_URL: API, TOKEN_VAULT_API_KEY: agent.credential.apiKey } });
    client = new Client({ name: 'e2e-approval-agent', version: '1.0.0' });
    await client.connect(transport);
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await client?.close();
    await admin?.dispose();
    await page?.close();
  });

  test('reads still run; creating an issue waits for a human', async () => {
    const read = await call('github_get_repository', { repository: 'demo-org/demo-repo' });
    expect(read.isError, read.text).toBe(false);

    const held = await call('github_create_issue', { repository: 'demo-org/demo-repo', title: 'Quarterly dependency review' });
    expect(held.isError, held.text).toBe(false); // waiting is not a failure
    expect(held.text).toContain('a human must approve this exact request');
    expect(held.text).toContain('token_vault_check_approval');
    approvalId = /Approval ID: (apv_[0-9a-f]+)/.exec(held.text)![1]!;

    const status = await call('token_vault_check_approval', { approval_id: approvalId });
    expect(status.text).toMatch(/PENDING\. Still waiting/);
  });

  test('a Security Administrator sees exactly what will run, and approves it', async () => {
    await login(page, 'security@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await page.goto('/access/policies');
    await expect(page.getByRole('row', { name: /Approve issues from Approval Agent/ }).getByText('Require approval')).toBeVisible();

    await page.goto(`/access/approvals?approval=${approvalId}`);
    await expect(page.getByText('What will run (written by the agent)')).toBeVisible();
    await expect(page.getByText('"title": "Quarterly dependency review"')).toBeVisible();
    await page.getByRole('button', { name: 'Approve…' }).click();
    const dialog = page.getByRole('dialog').filter({ hasText: 'Approve this request' });
    await dialog.getByRole('textbox').fill('Looks fine');
    await dialog.getByRole('button', { name: 'Approve request' }).click();
    await expect(page.getByText('Request approved')).toBeVisible();
    await expect(page.getByText(/Approved by Sam Okafor/)).toBeVisible();
  });

  test('the agent runs the approved request once', async () => {
    const run = await call('token_vault_check_approval', { approval_id: approvalId });
    expect(run.isError, run.text).toBe(false);
    expect(run.text).toContain('Create issue succeeded');

    const again = await call('token_vault_check_approval', { approval_id: approvalId });
    expect(again.text).toContain('EXECUTED');
    expect(again.text).toContain('Each approval runs one request');
    // A new issue needs a new approval.
    expect((await call('github_create_issue', { repository: 'demo-org/demo-repo', title: 'Another issue' })).text).toContain('token_vault_check_approval');
  });
});
