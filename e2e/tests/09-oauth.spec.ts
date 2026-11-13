import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, details, expectNoSecretsInBrowser, login } from './helpers';

/**
 * OAuth 2.0 (simulated provider): an application whose definition uses the oauth2 auth kind
 * is connected through the provider's sign-in. The client secret, the PKCE verifier and the
 * tokens stay in the customer webhook, which refreshes expiring access tokens (the e2e
 * webhook issues 2-second tokens, so every call refreshes, with refresh-token rotation).
 */
const CMS_API = 'http://localhost:4200';
const API = 'http://localhost:4000';
const CLIENT_SECRET = 'cal-secret-value-123';

const calendarx = {
  key: 'calendarx',
  name: 'CalendarX',
  description: 'Team calendars (OAuth 2.0).',
  api: { baseUrl: 'https://api.calendarx.example.com/v1', allowedHosts: ['api.calendarx.example.com'], headers: { Accept: 'application/json' } },
  resource: { name: 'calendar', label: 'Calendar', pattern: '^[a-z-]{2,30}$', example: 'team' },
  auth: [
    {
      id: 'OAUTH',
      label: 'Sign in with CalendarX',
      description: 'OAuth 2.0 with PKCE; tokens are held and refreshed by your webhook.',
      kind: 'oauth2',
      oauth: { authorizeUrl: 'https://login.calendarx.example.com/authorize', tokenUrl: 'https://api.calendarx.example.com/oauth/token', scopes: ['events.read', 'offline_access'] },
    },
  ],
  credentialTest: { request: { method: 'GET', path: '/me' }, response: { fields: { id: 'id' } } },
  operations: [
    {
      id: 'calendarx.events.list',
      label: 'List events',
      risk: 'read',
      request: { method: 'GET', path: '/calendars/{resource.calendar}/events' },
      response: { fields: { id: 'id', title: 'title' } },
      mock: { status: 200, body: [{ id: 'e1', title: 'Standup', organizer_email: 'lead@example.com' }] },
    },
  ],
};

async function session(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }, base: string, email: string, orgId?: string) {
  const ctx = await playwright.request.newContext({ baseURL: base });
  expect((await ctx.post('/api/v1/auth/login', { data: { email, password: DEMO_PASSWORD } })).ok()).toBe(true);
  if (orgId) await ctx.post('/api/v1/auth/selectOrganization', { data: { organizationId: orgId } });
  return ctx;
}

test.describe.serial('OAuth 2.0 connection (simulated provider)', () => {
  let owner: APIRequestContext;
  let page: Page;
  let integrationId = '';

  test.beforeAll(async ({ playwright, browser }) => {
    owner = await session(playwright, API, 'owner@demo.test', 'org_demo0000000001');
    page = await browser.newPage();
  });
  test.afterAll(async () => {
    await owner?.dispose();
    await page?.close();
  });

  test('CalendarX is published in the CMS with an OAuth 2.0 auth method', async ({ playwright }) => {
    const editor = await session(playwright, CMS_API, 'editor@cms.test');
    await editor.post('/api/v1/applications', { data: { key: 'calendarx', name: 'CalendarX' } });
    expect((await (await editor.put('/api/v1/applications/calendarx/versions/1', { data: { definition: calendarx } })).json()).issues).toEqual([]);
    await editor.post('/api/v1/applications/calendarx/versions/1/submit');
    const publisher = await session(playwright, CMS_API, 'publisher@cms.test');
    expect((await (await publisher.post('/api/v1/applications/calendarx/versions/1/approve', { data: { acknowledgeHostChange: true } })).json()).status).toBe('PUBLISHED');
    await Promise.all([editor.dispose(), publisher.dispose()]);
    await expect.poll(async () => ((await details(await owner.post('/api/v1/provider/getall'))).providers as { key: string }[]).some((p) => p.key === 'calendarx'), { timeout: 15_000 }).toBe(true);
  });

  test('an admin connects it through the provider sign-in; secrets and tokens stay in the webhook', async () => {
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await page.goto('/integrations/connect/calendarx');
    await expect(page.getByText(/oauth\/callback/).first()).toBeVisible(); // the redirect URI to register
    await page.locator('#displayName').fill('Team Calendar');
    await page.locator('#clientId').fill('cal-client-001');
    await page.locator('#clientSecret').fill(CLIENT_SECRET);
    await page.locator('#allowedResources').fill('team');
    await page.getByRole('button', { name: /Continue to login\.calendarx\.example\.com/ }).click();

    // The simulated provider consents at once and redirects to /oauth/callback, which completes the connection.
    await expect(page).toHaveURL(/\/integrations\/int_[0-9a-f]+$/);
    await expect(page.getByRole('heading', { name: 'Team Calendar' })).toBeVisible();
    await expect(page.getByRole('button', { name: /Rotate \/ replace/ })).toHaveCount(0); // OAuth is renewed by reconnecting
    await expectNoSecretsInBrowser(page, [CLIENT_SECRET]);

    const list = await details(await owner.post('/api/v1/integration/getall'));
    const created = list.items.find((i: { displayName: string }) => i.displayName === 'Team Calendar');
    expect(created).toMatchObject({ provider: 'calendarx', authType: 'OAUTH', credentialStatus: 'CONNECTED', maskedIdentifier: 'OAuth client cal-cl…-001' });
    expect(JSON.stringify(created)).not.toContain(CLIENT_SECRET);
    integrationId = created.id;
  });

  test('an agent calls it; the webhook refreshes the short-lived access token each time', async () => {
    const agent = await details(await owner.post('/api/v1/agent/save', { data: { name: 'Calendar Agent', environment: 'development', ownerTeam: 'Ops', agentType: 'AI_AGENT' } }));
    const now = Date.now();
    const grant = await owner.post('/api/v1/grant/save', {
      data: { name: 'Calendar read', agentId: agent.agent.id, integrationId, environment: 'development', scopes: ['calendarx.events.list'], repositories: ['team'], validFrom: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 86_400_000).toISOString(), rateLimitPerMinute: 30 },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    const call = async (n: number) => {
      const r = await owner.post('/agent/v1/request/execute', { headers: { authorization: `Bearer ${agent.credential.apiKey}` }, data: { integration_id: integrationId, operation: 'calendarx.events.list', resource: { calendar: 'team' }, idempotency_key: `e2e-oauth-${n}-${Date.now()}` } });
      return { status: r.status(), body: await details(r) };
    };
    for (const n of [1, 2]) {
      const r = await call(n);
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      expect(r.body.result).toEqual([{ id: 'e1', title: 'Standup' }]);
      expect(r.body.execution.credential).toMatchObject({ type: 'oauth2_access_token', refreshed: true, scopes: ['events.read', 'offline_access'] });
      expect(JSON.stringify(r.body)).not.toMatch(/mock_o[ar]t_/); // tokens never leave the webhook
    }
  });

  test('a callback is accepted only for a state the same admin started', async ({ playwright }) => {
    const forged = await owner.post('/api/v1/integration/oauthComplete', { data: { code: 'mock_code_x', state: 'forged-state' } });
    expect((await forged.json()).code).toBe('OAUTH_STATE_INVALID');

    // The owner starts a connection; another administrator cannot finish it with the owner's state.
    const start = await owner.post('/api/v1/integration/oauthStart', {
      data: { provider: 'calendarx', authType: 'OAUTH', webhookId: 'wh_local0000000001', displayName: 'Second Calendar', environment: 'development', clientId: 'cal-client-001', clientSecret: CLIENT_SECRET, allowedResources: [] },
    });
    expect(start.status(), await start.text()).toBe(201);
    const redirect = new URL((await details(start)).authorizeUrl);
    const code = redirect.searchParams.get('code')!;
    const state = redirect.searchParams.get('state')!;
    const other = await session(playwright, API, 'vault.admin@demo.test', 'org_demo0000000001');
    expect((await (await other.post('/api/v1/integration/oauthComplete', { data: { code, state } })).json()).code).toBe('OAUTH_STATE_INVALID');
    await other.dispose();
    // The other admin's attempt did not consume it: the owner can still finish, exactly once.
    expect((await owner.post('/api/v1/integration/oauthComplete', { data: { code, state } })).status()).toBe(201);
    expect((await (await owner.post('/api/v1/integration/oauthComplete', { data: { code, state } })).json()).code).toBe('OAUTH_STATE_INVALID');
  });
});
