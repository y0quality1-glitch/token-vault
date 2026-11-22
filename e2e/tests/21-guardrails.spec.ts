import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, details, login } from './helpers';

/**
 * Phase 1 guardrails, end to end: an argument rule written in the policy editor, a grant
 * budget, and the organization-wide emergency stop, each checked against real agent requests.
 * Every rule here names only this spec's agent (the emergency stop is lifted again at the end).
 */
const API = 'http://localhost:4000';

test.describe.serial('guardrails: argument rules, budgets, emergency stop (Demo Organization)', () => {
  let admin: APIRequestContext;
  let agentApi: APIRequestContext;
  let page: Page;
  let agentName = '';

  const createIssue = (title: string) =>
    agentApi.post('/agent/v1/request/execute', { data: { integration_id: 'int_github_001', operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input: { title, body: '' } } }).then(async (r) => ({ status: r.status(), body: await details(r) }));
  const readRepo = () =>
    agentApi.post('/agent/v1/request/execute', { data: { integration_id: 'int_github_001', operation: 'github.repositories.read', resource: { repository: 'demo-org/demo-repo' } } }).then(async (r) => ({ status: r.status(), body: await details(r) }));

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });
    agentName = `Guardrail Agent ${Date.now() % 100000}`;
    const agent = await details(await admin.post('/api/v1/agent/save', { data: { name: agentName, environment: 'development', ownerTeam: 'Platform AI', agentType: 'AI_AGENT' } }));
    const now = Date.now();
    const grant = await admin.post('/api/v1/grant/save', {
      data: {
        name: `${agentName} issues`,
        agentId: agent.agent.id,
        integrationId: 'int_github_001',
        environment: 'development',
        scopes: ['github.repositories.read', 'github.issues.create'],
        repositories: ['demo-org/demo-repo'],
        validFrom: new Date(now - 60_000).toISOString(),
        expiresAt: new Date(now + 86_400_000).toISOString(),
        rateLimitPerMinute: 60,
        maxWritesPerHour: 2,
      },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    agentApi = await playwright.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${agent.credential.apiKey}` } });
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await admin?.post('/api/v1/organization/liftEmergencyStop', { data: {} }).catch(() => undefined);
    await admin?.dispose();
    await agentApi?.dispose();
    await page?.close();
  });

  test('a Security Administrator writes an argument rule in the policy editor, and it denies matching requests only', async () => {
    await login(page, 'security@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await page.goto('/access/policies');
    await page.getByRole('button', { name: 'New policy' }).click();
    const dialog = page.getByRole('dialog').filter({ hasText: 'New policy' });
    await dialog.getByRole('textbox').first().fill('No secrets in issue titles');
    await dialog.getByRole('radio', { name: 'Specific agent' }).click();
    await dialog.getByRole('textbox', { name: 'Search agents' }).fill(agentName);
    await dialog.getByRole('option', { name: new RegExp(agentName) }).click();
    await dialog.getByRole('button', { name: 'Expand GitHub operations' }).click(); // applications start collapsed
    await dialog.getByRole('checkbox', { name: /^Create issue github\.issues\.create/ }).check();
    await dialog.getByRole('button', { name: 'Add rule' }).click();
    await dialog.getByLabel('Rule 1 field').fill('input.title');
    await dialog.getByLabel('Rule 1 operator').selectOption('matches');
    await dialog.getByLabel('Rule 1 value').fill('pass(word)?|secret');
    await dialog.getByRole('button', { name: 'Create policy' }).click();
    await expect(page.getByText('Policy created')).toBeVisible();
    await expect(page.getByText(/when input\.title matches pattern \/pass\(word\)\?\|secret\//)).toBeVisible();

    const denied = await createIssue('Rotate the Secret key');
    expect(denied.status).toBe(403);
    expect(denied.body).toMatchObject({ decision: 'DENY', decision_code: 'POLICY_DENIED', matched_rule: { name: 'No secrets in issue titles' } });
    expect((await createIssue('Release checklist')).body.decision).toBe('ALLOW');
  });

  test('the hourly write budget stops further writes but not reads, and the grant page shows usage', async () => {
    // One write is already used by the previous test; the budget is 2 per hour.
    expect((await createIssue('Second write')).body.decision).toBe('ALLOW');
    const over = await createIssue('Third write');
    expect(over.status).toBe(429);
    expect(over.body.decision_code).toBe('BUDGET_EXCEEDED');
    expect((await readRepo()).body.decision).toBe('ALLOW');

    await page.goto('/access/grants');
    await page.getByRole('cell', { name: `${agentName} issues` }).click();
    await expect(page.getByText('2 of 2 writes used in the last hour')).toBeVisible();
  });

  test('the emergency stop denies every agent request, shows a banner everywhere, and resuming restores access', async () => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Stop all agent access…' }).click();
    const stop = page.getByRole('dialog').filter({ hasText: 'Stop all agent access?' });
    await stop.getByRole('textbox').fill('E2E incident drill');
    await stop.getByRole('button', { name: 'Stop all agent access' }).click();
    await expect(page.getByText('All agent access stopped')).toBeVisible();
    await expect(page.getByRole('alert').filter({ hasText: 'All agent access is stopped.' })).toContainText('E2E incident drill');

    const stopped = await readRepo();
    expect(stopped.status).toBe(403);
    expect(stopped.body).toMatchObject({ decision_code: 'EMERGENCY_STOP', reason: expect.stringContaining('E2E incident drill') });

    await page.goto('/access/grants'); // the banner is on every page
    await expect(page.getByRole('alert').filter({ hasText: 'All agent access is stopped.' })).toBeVisible();

    await page.goto('/');
    await page.getByRole('button', { name: 'Resume agent access…' }).click();
    await page.getByRole('dialog').filter({ hasText: 'Resume agent access?' }).getByRole('button', { name: 'Resume agent access' }).click();
    await expect(page.getByText('Agent access resumed')).toBeVisible();
    await expect(page.getByRole('alert').filter({ hasText: 'All agent access is stopped.' })).toHaveCount(0);
    expect((await readRepo()).body.decision).toBe('ALLOW');
  });
});
