import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { DEMO_PASSWORD, login } from './helpers';

/**
 * Just-in-time access, end to end: a real MCP agent is denied, asks for access with
 * token_vault_request_access, a Security Administrator approves it in the console, and the
 * agent's next call succeeds. Also covers separation of duties and rejection.
 */
const API = 'http://localhost:4000';
const MCP_BIN = resolve(import.meta.dirname, '../../mcp/bin/token-vault-mcp.mjs');

test.describe.serial('just-in-time access requests (Demo Organization)', () => {
  let admin: APIRequestContext;
  let client: Client;
  let page: Page;
  let requestId = '';

  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { text: string }[] };
    return { isError: !!r.isError, text: r.content.map((c) => c.text).join('\n') };
  };

  test.beforeAll(async ({ playwright, browser }) => {
    // The owner registers the agent, so the owner may NOT approve its requests (separation of duties).
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
    const agent = await (await admin.post('/api/v1/agents', { data: { name: 'JIT Agent', environment: 'development', ownerTeam: 'Platform AI', agentType: 'AI_AGENT' } })).json();
    const now = Date.now();
    const grant = await admin.post('/api/v1/grants', {
      data: {
        name: 'JIT agent read-only',
        agentId: agent.agent.id,
        integrationId: 'int_github_001',
        environment: 'development',
        scopes: ['github.repositories.read'],
        repositories: ['demo-org/demo-repo'],
        validFrom: new Date(now - 60_000).toISOString(),
        expiresAt: new Date(now + 86_400_000).toISOString(),
        rateLimitPerMinute: 30,
      },
    });
    expect(grant.ok(), await grant.text()).toBe(true);

    const transport = new StdioClientTransport({ command: process.execPath, args: [MCP_BIN], env: { PATH: process.env.PATH ?? '', TOKEN_VAULT_URL: API, TOKEN_VAULT_API_KEY: agent.credential.apiKey } });
    client = new Client({ name: 'e2e-jit-agent', version: '1.0.0' });
    await client.connect(transport);
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await client?.close();
    await admin?.dispose();
    await page?.close();
  });

  test('a denied agent is told it may ask for access, and asks once', async () => {
    const denied = await call('github_read_file', { repository: 'demo-org/demo-repo', path: 'README.md' });
    expect(denied.isError).toBe(true);
    expect(denied.text).toContain('SCOPE_DENIED');
    expect(denied.text).toContain('token_vault_request_access');
    const deniedId = /Request ID: (req_[0-9a-f]+)/.exec(denied.text)![1];

    const asked = await call('token_vault_request_access', {
      operations: ['github.contents.read'],
      repository: 'demo-org/demo-repo',
      justification: 'Need the README to summarise the project for the user.',
      duration_minutes: 30,
      denied_request_id: deniedId,
    });
    expect(asked.isError, asked.text).toBe(false);
    expect(asked.text).toMatch(/Access request arq_[0-9a-f]+ is PENDING/);
    requestId = /(arq_[0-9a-f]+)/.exec(asked.text)![1]!;

    // Asking again does not create a duplicate.
    const again = await call('token_vault_request_access', { operations: ['github.contents.read'], repository: 'demo-org/demo-repo', justification: 'Need the README to summarise the project for the user.', duration_minutes: 30 });
    expect(again.text).toContain(requestId);
    expect(again.text).toContain('already pending');
    // Still denied until a human decides.
    expect((await call('github_read_file', { repository: 'demo-org/demo-repo' })).text).toContain('SCOPE_DENIED');
  });

  test('the agent’s owner sees the request but cannot approve it', async () => {
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await expect(page.getByLabel(/1 pending/)).toBeVisible(); // sidebar badge
    await page.goto(`/access/requests?request=${requestId}`);
    await expect(page.getByText('Need the README to summarise the project for the user.')).toBeVisible();
    await expect(page.getByText('Separation of duties')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Approve…' })).toHaveCount(0);
  });

  test('a Security Administrator approves it for 30 minutes', async () => {
    await page.context().clearCookies();
    await login(page, 'security@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await expect(page.getByText(/1 agent access request awaiting approval/)).toBeVisible(); // dashboard alert
    await page.goto('/access/requests');
    await page.getByRole('cell', { name: 'JIT Agent' }).click();
    await page.getByRole('button', { name: 'Approve…' }).click();
    const dialog = page.getByRole('dialog').filter({ hasText: 'Approve access request' });
    await dialog.getByRole('textbox').last().fill('OK for this session');
    await dialog.getByRole('button', { name: /^Approve .*for 30 min$/ }).click();
    await expect(page.getByText('Access approved')).toBeVisible();
    await expect(page.getByText(/Approved by Sam Okafor/)).toBeVisible();
  });

  test('the agent’s next call succeeds, and it can see the decision', async () => {
    const status = await call('token_vault_check_access_request', { access_request_id: requestId });
    expect(status.text).toContain('APPROVED');
    const r = await call('github_read_file', { repository: 'demo-org/demo-repo', path: 'README.md' });
    expect(r.isError, r.text).toBe(false);
    expect(r.text).toContain('demo-repo');
    const list = await call('token_vault_list_access');
    expect(list.text).toContain('JIT: JIT Agent');
  });

  test('a rejected request stays denied and the agent is told not to resubmit', async () => {
    const asked = await call('token_vault_request_access', { operations: ['github.issues.create'], repository: 'demo-org/demo-repo', justification: 'Would like to file a summary issue.' });
    const id = /(arq_[0-9a-f]+)/.exec(asked.text)![1]!;
    // Rejected by the Security Administrator's browser session (through the console's API proxy).
    const sec = await page.context().request.post(`http://localhost:5173/api/v1/grant-requests/${id}/reject`, { data: { note: 'Not needed for read-only summaries.' } });
    expect(sec.ok(), await sec.text()).toBe(true);
    const status = await call('token_vault_check_access_request', { access_request_id: id });
    expect(status.text).toContain('REJECTED');
    expect(status.text).toContain('Not needed for read-only summaries.');
    expect(status.text).toContain('Do not resubmit');
  });
});
