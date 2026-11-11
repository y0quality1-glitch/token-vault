import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, login } from './helpers';

/**
 * One agent, several applications: the grant wizard creates one grant per selected
 * integration in a single all-or-nothing request, each with its own operations, resources
 * and name, sharing validity, limits and user settings. The agent then uses all of them with
 * its one API key. Everything here belongs to this spec's own agents.
 */
const API = 'http://localhost:4000';

test.describe.serial('grants for several applications at once (Demo Organization)', () => {
  let admin: APIRequestContext;
  let page: Page;
  const run = Date.now() % 100000;
  const agentName = `Multi App Agent ${run}`;
  let agentId = '';
  let agentKey = '';
  const contexts: APIRequestContext[] = [];

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
    const agent = await (await admin.post('/api/v1/agents', { data: { name: agentName, environment: 'development', ownerTeam: 'Platform AI', agentType: 'AI_AGENT' } })).json();
    agentId = agent.agent.id;
    agentKey = agent.credential.apiKey;
    contexts.push(await playwright.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${agentKey}` } }));
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    for (const c of contexts) await c.dispose();
    await admin?.dispose();
    await page?.close();
  });

  test('the API creates all grants or none, and names the item that failed', async () => {
    const window = { validFrom: new Date(Date.now() - 60_000).toISOString(), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), rateLimitPerMinute: 30 };
    const refused = await admin.post('/api/v1/grants/batch', {
      data: {
        agentId,
        ...window,
        items: [
          { integrationId: 'int_github_001', scopes: ['github.issues.list'], repositories: ['demo-org/demo-repo'] },
          { integrationId: 'int_github_003', scopes: ['github.repositories.read'], repositories: ['demo-org/demo-repo'] }, // Partner GitHub allows only partner-org/shared-repo
        ],
      },
    });
    expect(refused.status()).toBe(400);
    const body = await refused.json();
    expect(Object.keys(body.error.details.fields)).toContain('items.1.repositories');
    const { items } = await (await admin.get(`/api/v1/grants?agentId=${agentId}`)).json();
    expect(items).toHaveLength(0); // the valid first item was not created either
  });

  test('the wizard grants one agent three applications in one go', async () => {
    await login(page, 'vault.admin@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await page.goto(`/access/grants/new?agentId=${agentId}`);
    await expect(page.getByText('Step 2: Select integrations')).toBeVisible();
    for (const name of [/^Demo GitHub (?!App)/, /^Partner GitHub /, /^GitHub Staging /]) await page.getByRole('button', { name }).click();
    await expect(page.getByText('3 selected: one grant will be created for each')).toBeVisible();
    await page.getByRole('button', { name: 'Continue' }).click();

    // Operations per application.
    const section = (name: string) => page.locator('section').filter({ has: page.getByRole('heading', { name }) });
    await page.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByText('Select at least one permission for Demo GitHub')).toBeVisible();
    await section('Demo GitHub').getByLabel('Create issue').check();
    await section('Partner GitHub').getByLabel('Read repository metadata').check();
    await section('GitHub Staging').getByLabel('List issues').check();
    await page.getByRole('button', { name: 'Continue' }).click();

    // Resources per application; limits once for all.
    await page.getByLabel('Allowed resource for Demo GitHub').fill('demo-org/demo-repo');
    await page.getByLabel('Allowed resource for Partner GitHub').fill('partner-org/shared-repo');
    await page.getByLabel('Maximum requests per minute').fill('20');
    await page.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByText('Step 5: Review and create')).toBeVisible();
    await expect(page.getByText('3 separate grants will be created, all or none.')).toBeVisible();
    await page.getByRole('button', { name: 'Create 3 grants' }).click();

    await expect(page.getByRole('heading', { name: '3 grants created' })).toBeVisible();
    for (const name of ['Demo GitHub', 'Partner GitHub', 'GitHub Staging']) await expect(page.getByRole('link', { name: `${agentName} → ${name}` })).toBeVisible();
  });

  test('each application got its own grant, and the agent uses them all with one key', async () => {
    const { items } = await (await admin.get(`/api/v1/grants?agentId=${agentId}`)).json();
    const byIntegration = Object.fromEntries(items.map((g: { integrationId: string }) => [g.integrationId, g]));
    expect(byIntegration.int_github_001).toMatchObject({ scopes: ['github.issues.create'], resourceConstraints: { repositories: ['demo-org/demo-repo'] }, rateLimitPerMinute: 20, environment: 'development' });
    expect(byIntegration.int_github_003).toMatchObject({ scopes: ['github.repositories.read'], resourceConstraints: { repositories: ['partner-org/shared-repo'] } });
    expect(byIntegration.int_github_002).toMatchObject({ scopes: ['github.issues.list'], environment: 'staging' });

    const agentApi = contexts[0]!;
    const caps = await (await agentApi.get('/agent/v1/capabilities')).json();
    expect(caps.grants.map((g: { integration_id: string }) => g.integration_id).sort()).toEqual(['int_github_001', 'int_github_002', 'int_github_003']);
    const created = await agentApi.post('/agent/v1/execute', { data: { integration_id: 'int_github_001', operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input: { title: 'Multi-app grant', body: '' } } });
    expect((await created.json()).decision).toBe('ALLOW');
    const read = await agentApi.post('/agent/v1/execute', { data: { integration_id: 'int_github_003', operation: 'github.repositories.read', resource: { repository: 'partner-org/shared-repo' } } });
    expect((await read.json()).decision).toBe('ALLOW');
  });
});
