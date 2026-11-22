import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, details, login } from './helpers';

/**
 * Destructive operations with human approval, end to end:
 *  - granting one is refused until a Require approval policy covers it;
 *  - the policy is written in the console with the "All destructive operations" selector;
 *  - the seeded Deny policy still wins; with it disabled the request waits for a human;
 *  - after approval in the console, the agent's request runs once (the e2e webhook allows destructive operations).
 * The seeded Deny policy is re-enabled at the end, so later specs see the demo data as seeded.
 */
const API = 'http://localhost:4000';
const SEEDED_DENY = 'pol_block_destructive';

test.describe.serial('destructive operations need human approval (Demo Organization)', () => {
  let admin: APIRequestContext;
  let agentApi: APIRequestContext;
  let page: Page;
  let agentId = '';
  let agentName = '';
  let approvalId = '';

  const writeFile = () =>
    agentApi
      .post('/agent/v1/request/execute', {
        data: { integration_id: 'int_github_001', operation: 'github.contents.write', resource: { repository: 'demo-org/demo-repo', path: 'docs/cleanup.md' }, input: { message: 'Add cleanup notes', content: Buffer.from('# Cleanup\n').toString('base64') } },
      })
      .then(async (r) => ({ status: r.status(), body: await details(r) }));
  const grantBody = () => ({
    name: `${agentName} files`,
    agentId,
    integrationId: 'int_github_001',
    environment: 'development',
    scopes: ['github.repositories.read', 'github.contents.write'],
    repositories: ['demo-org/demo-repo'],
    validFrom: new Date(Date.now() - 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    rateLimitPerMinute: 30,
  });
  async function setSeededDeny(enabled: boolean) {
    const { items } = await details(await admin.post('/api/v1/policy/getall'));
    const { id, organizationId: _o, createdAt: _c, updatedAt: _u, ...body } = items.find((p: { id: string }) => p.id === SEEDED_DENY);
    const r = await admin.post('/api/v1/policy/save', { data: { id, ...body, enabled } });
    expect(r.ok(), await r.text()).toBe(true);
  }

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });
    agentName = `Cleanup Agent ${Date.now() % 100000}`;
    const agent = await details(await admin.post('/api/v1/agent/save', { data: { name: agentName, environment: 'development', ownerTeam: 'Platform AI', agentType: 'AI_AGENT' } }));
    agentId = agent.agent.id;
    agentApi = await playwright.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${agent.credential.apiKey}` } });
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await setSeededDeny(true).catch(() => undefined);
    await admin?.dispose();
    await agentApi?.dispose();
    await page?.close();
  });

  test('a destructive operation cannot be granted until a Require approval policy covers it', async () => {
    const refused = await admin.post('/api/v1/grant/save', { data: grantBody() });
    expect(refused.status()).toBe(400);
    expect(JSON.stringify(await refused.json())).toContain('can be granted only with human approval');
  });

  test('a Security Administrator writes the approval policy with the "All destructive operations" selector', async () => {
    await login(page, 'security@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await page.goto('/access/policies');
    await page.getByRole('button', { name: 'New policy' }).click();
    const dialog = page.getByRole('dialog').filter({ hasText: 'New policy' });
    await dialog.getByRole('textbox').first().fill(`Approve destructive actions of ${agentName}`);
    await dialog.getByRole('combobox').first().selectOption('REQUIRE_APPROVAL');
    await dialog.getByRole('radio', { name: 'Specific agent' }).click();
    await dialog.getByRole('textbox', { name: 'Search agents' }).fill(agentName);
    await dialog.getByRole('option', { name: new RegExp(agentName) }).click();
    await dialog.getByRole('checkbox', { name: /^All destructive operations/ }).check();
    await dialog.getByRole('button', { name: 'Create policy' }).click();
    await expect(page.getByText('Policy created')).toBeVisible();
    await expect(page.getByRole('row', { name: new RegExp(`Approve destructive actions of ${agentName}`) }).getByText('All destructive operations')).toBeVisible();

    const granted = await admin.post('/api/v1/grant/save', { data: grantBody() });
    expect(granted.status(), await granted.text()).toBe(201);
  });

  test('the seeded Deny policy still wins; without it the request waits for a human', async () => {
    expect((await writeFile()).body).toMatchObject({ decision: 'DENY', decision_code: 'POLICY_DENIED' });
    await setSeededDeny(false);
    const held = await writeFile();
    expect(held.status).toBe(202);
    expect(held.body).toMatchObject({ decision_code: 'APPROVAL_REQUIRED', execution: { status: 'NOT_EXECUTED' } });
    approvalId = held.body.approval.approval_id;
  });

  test('approved in the console, the destructive request runs once', async () => {
    await page.goto(`/access/approvals?approval=${approvalId}`);
    await expect(page.getByText('Destructive', { exact: true })).toBeVisible(); // badge in the approval drawer
    await expect(page.getByText('"message": "Add cleanup notes"')).toBeVisible();
    await page.getByRole('button', { name: 'Approve…' }).click();
    await page.getByRole('dialog').filter({ hasText: 'Approve this request' }).getByRole('button', { name: 'Approve request' }).click();
    await expect(page.getByText('Request approved')).toBeVisible();

    const ran = await writeFile();
    expect(ran.body).toMatchObject({ decision: 'ALLOW', execution: { status: 'SUCCEEDED', upstream_status: 201 }, result: { path: 'docs/cleanup.md' }, approval: { approval_id: approvalId, status: 'EXECUTED' } });
    // The next one needs a new approval.
    expect((await writeFile()).body.decision_code).toBe('APPROVAL_REQUIRED');
  });
});
