import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, details, login } from './helpers';

/**
 * Delegation to sub-agents, end to end:
 *  - an agent hands a narrower, request-capped slice of its grant to a sub-agent (widening is refused);
 *  - the sub-agent can do only that, cannot ask for more, and can delegate further (only narrower);
 *  - a Security Administrator revokes the delegation on the grant page, which stops the sub-agent
 *    and everything delegated from it, while the agent itself keeps its access;
 *  - the access log names the sub-agent.
 * Everything here belongs to this spec's own agent.
 */
const API = 'http://localhost:4000';

test.describe.serial('delegation to sub-agents (Demo Organization)', () => {
  let admin: APIRequestContext;
  let page: Page;
  let playwrightRef: { request: { newContext: (o: object) => Promise<APIRequestContext> } };
  const run = Date.now() % 100000;
  const agentName = `Coordinator Agent ${run}`;
  const label = `Triage helper ${run}`;
  let agentKey = '';
  let grantId = '';
  let subToken = '';
  let nestedToken = '';
  const contexts: APIRequestContext[] = [];

  async function as(token: string) {
    const c = await playwrightRef.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${token}` } });
    contexts.push(c);
    return c;
  }
  const execute = async (token: string, operation: string) => {
    const r = await (await as(token)).post('/agent/v1/request/execute', { data: { integration_id: 'int_github_001', operation, resource: { repository: 'demo-org/demo-repo' }, input: { title: 'From a sub-agent', body: '' } } });
    return { status: r.status(), body: await details(r) };
  };

  test.beforeAll(async ({ playwright, browser }) => {
    playwrightRef = playwright;
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });
    const agent = await details(await admin.post('/api/v1/agent/save', { data: { name: agentName, environment: 'development', ownerTeam: 'Platform AI', agentType: 'AI_AGENT' } }));
    agentKey = agent.credential.apiKey;
    const grant = await admin.post('/api/v1/grant/save', {
      data: {
        name: `${agentName} issues`,
        agentId: agent.agent.id,
        integrationId: 'int_github_001',
        environment: 'development',
        scopes: ['github.issues.list', 'github.issues.create'],
        repositories: ['demo-org/demo-repo'],
        validFrom: new Date(Date.now() - 60_000).toISOString(),
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
        rateLimitPerMinute: 60,
      },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    grantId = (await details(grant)).id;
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    for (const c of contexts) await c.dispose();
    await admin?.dispose();
    await page?.close();
  });

  test('the agent delegates a narrower slice of its grant; widening it is refused', async () => {
    const agentApi = await as(agentKey);
    const wider = await agentApi.post('/agent/v1/delegation/save', { data: { grant_id: grantId, label, operations: ['github.contents.read'] } });
    expect(wider.status()).toBe(400);
    expect(JSON.stringify(await wider.json())).toContain('a delegation can only narrow');

    const created = await agentApi.post('/agent/v1/delegation/save', { data: { grant_id: grantId, label, operations: ['github.issues.list'], max_requests: 5, expires_in_seconds: 1800 } });
    expect(created.status(), await created.text()).toBe(201);
    const body = await details(created);
    expect(body).toMatchObject({ label, operations: ['github.issues.list'], resources: ['demo-org/demo-repo'], max_requests: 5, status: 'ACTIVE', depth: 1 });
    subToken = body.token;
    expect(subToken).toMatch(/^tvdt_/);
  });

  test('the sub-agent can do only what it was delegated, and cannot ask for more', async () => {
    expect((await execute(subToken, 'github.issues.list')).body).toMatchObject({ decision: 'ALLOW', delegation: { label, used: 1, max_requests: 5 } });
    expect((await execute(subToken, 'github.issues.create')).body).toMatchObject({ decision: 'DENY', decision_code: 'DELEGATION_DENIED' });
    const ask = await (await as(subToken)).post('/agent/v1/accessRequest/save', { data: { integration_id: 'int_github_001', operations: ['github.issues.create'], justification: 'Need to file the issue myself', duration_minutes: 30 } });
    expect(ask.status()).toBe(403);

    const nested = await (await as(subToken)).post('/agent/v1/delegation/save', { data: { label: `Reader ${run}`, operations: ['github.issues.list'], max_requests: 2 } });
    expect(nested.status(), await nested.text()).toBe(201);
    nestedToken = (await details(nested)).token;
    expect((await execute(nestedToken, 'github.issues.list')).body.decision).toBe('ALLOW');
  });

  test('a Security Administrator revokes the delegation on the grant page; everything below it stops, the agent keeps its access', async () => {
    await login(page, 'security@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await page.goto(`/access/grants/${grantId}`);
    const row = page.getByRole('row', { name: new RegExp(`^${label}`) });
    await expect(row.getByText('Active')).toBeVisible();
    await expect(page.getByRole('row', { name: new RegExp(`Reader ${run}`) })).toBeVisible();
    await row.getByRole('button', { name: 'Revoke' }).click();
    const dialog = page.getByRole('dialog').filter({ hasText: 'Revoke this delegation?' });
    await dialog.getByLabel('Reason').fill('E2E: sub-agent no longer needed');
    await dialog.getByRole('button', { name: 'Revoke delegation' }).click();
    await expect(page.getByText('Delegation revoked')).toBeVisible();
    await expect(page.getByRole('row', { name: new RegExp(`Reader ${run}`) }).getByText('Revoked (parent)')).toBeVisible();

    expect((await execute(subToken, 'github.issues.list')).body.decision_code).toBe('DELEGATION_REVOKED');
    const nested = await execute(nestedToken, 'github.issues.list');
    expect(nested.status).toBe(403);
    expect(nested.body).toMatchObject({ decision_code: 'DELEGATION_REVOKED', reason: expect.stringContaining('came from') });
    expect((await execute(agentKey, 'github.issues.create')).body.decision).toBe('ALLOW');
  });

  test('the access log names the sub-agent', async () => {
    await page.goto('/audit/access-logs');
    await page.getByPlaceholder('Request ID, correlation ID, agent…').fill(agentName);
    await expect(page.getByRole('row').filter({ hasText: `via sub-agent ${label}` }).first()).toBeVisible();
  });
});
