import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, expectNoSecretsInBrowser, login } from './helpers';

/**
 * The point of the CMS: a new application becomes usable in Token Vault without any code
 * change or deploy. It is defined and published in the CMS, Token Vault and the customer
 * webhook pick up the signed definition, an admin connects it with the form the definition
 * describes, and an agent calls it under a normal, resource-scoped grant.
 */
const CMS_API = 'http://localhost:4200';
const API = 'http://localhost:4000';
const API_KEY = 'td_0123456789abcdefghij';

const ticketDesk = {
  key: 'ticketdesk',
  name: 'Ticket Desk',
  description: 'Support tickets (defined only in the CMS).',
  api: { baseUrl: 'https://api.ticketdesk.example.com/v1', allowedHosts: ['api.ticketdesk.example.com'], headers: { Accept: 'application/json' } },
  resource: { name: 'queue', label: 'Queue', pattern: '^[A-Z]{2,10}$', example: 'OPS' },
  auth: [{ id: 'API_KEY', label: 'API key', description: 'A Ticket Desk API key, sent in the X-Api-Key header.', kind: 'header', header: 'X-Api-Key', secretPattern: '^td_[a-z0-9]{16,}$', secretHint: 'Starts with td_' }],
  credentialTest: { request: { method: 'GET', path: '/me' }, response: { fields: { id: 'id' } } },
  operations: [
    {
      id: 'ticketdesk.tickets.list',
      label: 'List tickets',
      description: 'GET /queues/{queue}/tickets',
      risk: 'read',
      request: { method: 'GET', path: '/queues/{resource.queue}/tickets', query: { limit: 5 } },
      response: { fields: { id: 'id', subject: 'subject', status: 'status' }, limit: 5 },
      mock: { status: 200, body: [{ id: 'T-1', subject: 'Printer on fire', status: 'open', internal_note: 'customer is VIP' }] },
    },
  ],
};

async function cmsSession(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }, email: string) {
  const ctx = await playwright.request.newContext({ baseURL: CMS_API });
  expect((await ctx.post('/api/v1/auth/login', { data: { email, password: DEMO_PASSWORD } })).ok()).toBe(true);
  return ctx;
}

test.describe.serial('no-code provider: published in the CMS, used through Token Vault', () => {
  let admin: APIRequestContext;
  let page: Page;
  let integrationId = '';
  let agentKey = '';

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
    page = await browser.newPage();
  });
  test.afterAll(async () => {
    await admin?.dispose();
    await page?.close();
  });

  test('an editor and a publisher define and publish Ticket Desk in the CMS', async ({ playwright }) => {
    const editor = await cmsSession(playwright, 'editor@cms.test');
    expect((await editor.post('/api/v1/applications', { data: { key: 'ticketdesk', name: 'Ticket Desk' } })).status()).toBe(201);
    const saved = await (await editor.put('/api/v1/applications/ticketdesk/versions/1', { data: { definition: ticketDesk } })).json();
    expect(saved.issues).toEqual([]);
    expect((await editor.post('/api/v1/applications/ticketdesk/versions/1/submit')).ok()).toBe(true);

    const publisher = await cmsSession(playwright, 'publisher@cms.test');
    const published = await publisher.post('/api/v1/applications/ticketdesk/versions/1/approve', { data: { acknowledgeHostChange: true } });
    expect((await published.json()).status).toBe('PUBLISHED');
    await Promise.all([editor.dispose(), publisher.dispose()]);
  });

  test('Token Vault picks up the signed definition without a deploy', async () => {
    await expect
      .poll(async () => ((await (await admin.get('/api/v1/providers')).json()).providers as { key: string; source: string }[]).find((p) => p.key === 'ticketdesk')?.source, { timeout: 15_000 })
      .toBe('catalog');
    const catalog = (await (await admin.get('/api/v1/providers')).json()).catalog;
    expect(catalog).toMatchObject({ url: 'http://localhost:4200/catalog/v1', lastError: null });
  });

  test('an admin connects it with the form the definition describes', async () => {
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await page.goto('/integrations/catalog');
    const card = page.locator('div.rounded-xl').filter({ hasText: 'Ticket Desk' });
    await expect(card.getByText('CMS v1')).toBeVisible();
    await card.getByRole('button', { name: 'Connect', exact: true }).click();

    await expect(page.getByRole('heading', { name: /Connect Ticket Desk/ })).toBeVisible();
    await page.locator('#displayName').fill('Support Desk');
    await expect(page.getByText('Starts with td_')).toBeVisible(); // the hint comes from the definition
    await page.locator('#secret').fill('not-a-ticketdesk-key');
    await page.getByRole('button', { name: 'Store in customer vault' }).click();
    await expect(page.getByText('Starts with td_')).toBeVisible();
    await page.locator('#secret').fill(API_KEY);
    await page.locator('#allowedResources').fill('OPS, SALES');
    await page.getByRole('button', { name: 'Store in customer vault' }).click();
    await expect(page.getByText('Support Desk is connected')).toBeVisible();
    await expectNoSecretsInBrowser(page, [API_KEY]);

    const list = await (await admin.get('/api/v1/integrations')).json();
    const created = list.items.find((i: { displayName: string }) => i.displayName === 'Support Desk');
    expect(created).toMatchObject({ provider: 'ticketdesk', authType: 'API_KEY', credentialStatus: 'CONNECTED', allowedResources: ['OPS', 'SALES'] });
    integrationId = created.id;

    // Resource values are checked against the definition's pattern.
    const bad = await admin.patch(`/api/v1/integrations/${integrationId}`, { data: { displayName: 'Support Desk', accountLabel: '', description: '', allowedResources: ['ops-lowercase'] } });
    expect((await bad.json()).error.details.fields.allowedResources).toMatch(/Not a valid queue for Ticket Desk/);
  });

  test('an agent calls it under a queue-scoped grant', async () => {
    const agent = await (await admin.post('/api/v1/agents', { data: { name: 'Support Agent', environment: 'development', ownerTeam: 'Support', agentType: 'AI_AGENT' } })).json();
    agentKey = agent.credential.apiKey;
    const now = Date.now();
    const crossProvider = await admin.post('/api/v1/grants', {
      data: { name: 'Mixed', agentId: agent.agent.id, integrationId, environment: 'development', scopes: ['github.issues.list'], repositories: [], validFrom: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 86_400_000).toISOString(), rateLimitPerMinute: 30 },
    });
    expect((await crossProvider.json()).error.details.fields.scopes).toMatch(/Not operations of this integration's provider/);
    const grant = await admin.post('/api/v1/grants', {
      data: { name: 'Support reads OPS', agentId: agent.agent.id, integrationId, environment: 'development', scopes: ['ticketdesk.tickets.list'], repositories: ['OPS'], validFrom: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 86_400_000).toISOString(), rateLimitPerMinute: 30 },
    });
    expect(grant.ok(), await grant.text()).toBe(true);

    const call = async (operation: string, queue: string, resource: Record<string, string> = { queue }) => {
      const r = await admin.post('/agent/v1/execute', { headers: { authorization: `Bearer ${agentKey}` }, data: { integration_id: integrationId, operation, resource, idempotency_key: `e2e-td-${operation}-${queue}-${Date.now()}` } });
      return { status: r.status(), body: await r.json() };
    };

    const ok = await call('ticketdesk.tickets.list', 'OPS');
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.result).toEqual([{ id: 'T-1', subject: 'Printer on fire', status: 'open' }]); // internal_note is not in the allow-list
    expect(JSON.stringify(ok.body)).not.toContain(API_KEY);

    const other = await call('ticketdesk.tickets.list', 'SALES');
    expect(other.body).toMatchObject({ decision: 'DENY', decision_code: 'RESOURCE_DENIED' });
    expect(other.body.reason).toMatch(/^Queue SALES is outside the grant resource restriction/);

    // A GitHub operation (with a valid GitHub resource) can never run on a Ticket Desk credential.
    const wrongProvider = await call('github.issues.list', 'OPS', { repository: 'demo-org/demo-repo' });
    expect(wrongProvider.body).toMatchObject({ decision: 'DENY', decision_code: 'UNKNOWN_OPERATION' });
  });
});
