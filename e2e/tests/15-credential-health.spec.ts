import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, login, trackPageErrors } from './helpers';

/**
 * Credential health. A provider revoking a stored credential is simulated by publishing
 * definition versions whose simulated answers are 401 (mock mode):
 * - an agent request answered with 401 marks the integration invalid at once;
 * - the credential check (scheduled, or "Check all now") marks a recovered credential
 *   connected again, and catches a revoked one even when no agent is calling.
 * Every change is in the audit log.
 */
const API = 'http://localhost:4000';
const CMS_API = 'http://localhost:4200';
const KEY = 'pd_0123456789abcdefghij';

const definition = (status: number) => ({
  key: 'pingdesk',
  name: 'Ping Desk',
  description: 'Uptime checks.',
  api: { baseUrl: 'https://api.pingdesk.example.com/v1', allowedHosts: ['api.pingdesk.example.com'] },
  resource: { name: 'check', label: 'Check', pattern: '^[a-z0-9-]{2,30}$', example: 'homepage' },
  auth: [{ id: 'API_KEY', label: 'API key', kind: 'header', header: 'X-Api-Key', secretPattern: '^pd_[a-z0-9]{16,}$' }],
  credentialTest: { request: { method: 'GET', path: '/me' }, response: { fields: { id: 'id' } }, mock: status === 200 ? { status: 200, body: { id: 'acct_1' } } : { status, body: { message: 'Invalid API key' } } },
  operations: [
    {
      id: 'pingdesk.checks.read',
      label: 'Read check',
      risk: 'read',
      request: { method: 'GET', path: '/checks/{resource.check}' },
      response: { fields: { id: 'id', status: 'status' } },
      mock: status === 200 ? { status: 200, body: { id: 'homepage', status: 'up' } } : { status, body: { message: 'Invalid API key' } },
    },
  ],
});

test.describe.serial('credential health: revoked credentials are detected', () => {
  let cms: APIRequestContext;
  let admin: APIRequestContext;
  let page: Page;
  let errors: string[] = [];
  let integrationId = '';
  let agentKey = '';
  let version = 0;

  async function publish(status: number) {
    version++;
    if (version > 1) expect((await cms.post('/api/v1/applications/pingdesk/versions', { data: {} })).status()).toBe(201);
    expect((await (await cms.put(`/api/v1/applications/pingdesk/versions/${version}`, { data: { definition: definition(status) } })).json()).issues).toEqual([]);
    expect((await (await cms.post(`/api/v1/applications/pingdesk/versions/${version}/publish`, { data: { acknowledgeHostChange: true } })).json()).status).toBe('PUBLISHED');
  }
  const integration = async () => (await (await admin.get(`/api/v1/integrations/${integrationId}`)).json()) as { credentialStatus: string };
  const execute = async () => {
    const r = await admin.post('/agent/v1/execute', { headers: { authorization: `Bearer ${agentKey}` }, data: { integration_id: integrationId, operation: 'pingdesk.checks.read', resource: { check: 'homepage' }, idempotency_key: `e2e-ping-${Date.now()}-${Math.random()}` } });
    return { status: r.status(), body: await r.json() };
  };
  const events = async (type: string) => ((await (await admin.get(`/api/v1/audit-events?eventType=${type}&targetId=${integrationId}`)).json()).items as { eventType: string; targetId: string; actorType: string; metadata: Record<string, unknown> }[]).filter((e) => e.eventType === type && e.targetId === integrationId);

  test.beforeAll(async ({ playwright, browser }) => {
    cms = await playwright.request.newContext({ baseURL: CMS_API });
    expect((await cms.post('/api/v1/auth/login', { data: { email: 'admin@cms.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    admin = await playwright.request.newContext({ baseURL: API });
    expect((await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    await admin.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
    page = await browser.newPage();
    errors = trackPageErrors(page);
  });
  test.afterAll(async () => {
    expect(errors, 'no uncaught page errors').toEqual([]);
    await Promise.all([cms?.dispose(), admin?.dispose(), page?.close()]);
  });

  test('a working credential is connected and used', async () => {
    expect((await cms.post('/api/v1/applications', { data: { key: 'pingdesk', name: 'Ping Desk' } })).status()).toBe(201);
    await publish(200);
    await expect.poll(async () => ((await (await admin.get('/api/v1/providers')).json()).providers as { key: string }[]).some((p) => p.key === 'pingdesk'), { timeout: 15_000 }).toBe(true);
    const created = await admin.post('/api/v1/integrations', { data: { provider: 'pingdesk', authType: 'API_KEY', displayName: 'Ping Desk Prod', webhookId: 'wh_local0000000001', secret: KEY, allowedResources: ['homepage'], environment: 'development' } });
    expect(created.status(), await created.text()).toBe(201);
    integrationId = (await created.json()).id;
    expect(await integration()).toMatchObject({ credentialStatus: 'CONNECTED' });

    const agent = await (await admin.post('/api/v1/agents', { data: { name: 'Uptime Agent', environment: 'development', ownerTeam: 'SRE', agentType: 'AI_AGENT' } })).json();
    agentKey = agent.credential.apiKey;
    const now = Date.now();
    const grant = await admin.post('/api/v1/grants', { data: { name: 'Read checks', agentId: agent.agent.id, integrationId, environment: 'development', scopes: ['pingdesk.checks.read'], repositories: ['homepage'], validFrom: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 86_400_000).toISOString(), rateLimitPerMinute: 60 } });
    expect(grant.ok(), await grant.text()).toBe(true);
    const ok = await execute();
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
  });

  test('the provider revokes it: the next agent request marks the integration invalid', async () => {
    await publish(401); // from now on, the (simulated) provider answers 401
    // The webhook picks up the new version within a second or two.
    let last: Awaited<ReturnType<typeof execute>> | null = null;
    await expect
      .poll(async () => {
        last = await execute();
        return last.body.decision_code;
      }, { timeout: 20_000 })
      .not.toBe('ALLOWED');
    // The first refused call is the one the provider answered with 401.
    const rejected = last!;
    expect(rejected.body.decision_code).toBe('UPSTREAM_ERROR');
    expect(rejected.body.reason).toContain('Ping Desk returned HTTP 401');
    expect(rejected.body.reason).toContain('is now marked invalid');
    expect(await integration()).toMatchObject({ credentialStatus: 'INVALID' });

    // Further requests are refused before the credential is used again.
    const after = await execute();
    expect(after.body).toMatchObject({ decision: 'DENY', decision_code: 'INTEGRATION_UNAVAILABLE' });

    const [event] = await events('integration.credential_rejected');
    expect(event).toMatchObject({ actorType: 'SYSTEM', metadata: { source: 'agent_request', upstreamStatus: 401 } });
  });

  test('once the credential works again, the check marks it connected', async () => {
    await publish(200);
    await expect
      .poll(async () => {
        await admin.post('/api/v1/integrations/check-credentials');
        return (await integration()).credentialStatus;
      }, { timeout: 20_000 })
      .toBe('CONNECTED');
    expect((await events('integration.credential_recovered'))[0]).toMatchObject({ actorType: 'SYSTEM', metadata: { source: 'scheduled_check' } });
    expect((await execute()).status).toBe(200);
  });

  test('the check catches a revoked credential even when no agent is calling (console)', async () => {
    await publish(401);
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await page.goto('/integrations/credentials');
    const row = page.getByRole('row', { name: /Ping Desk Prod/ });
    await expect(row).toContainText('Connected');
    await expect
      .poll(async () => {
        await page.getByRole('button', { name: 'Check all now' }).click();
        await expect(page.getByRole('button', { name: 'Check all now' })).toBeEnabled();
        return (await integration()).credentialStatus;
      }, { timeout: 20_000 })
      .toBe('INVALID');
    await expect(row).toContainText('Invalid');
    expect((await events('integration.credential_rejected'))[0]).toMatchObject({ metadata: { source: 'scheduled_check', upstreamStatus: 401 } });

    // The dashboard raises an alert for it.
    await page.goto('/');
    await expect(page.getByText('Integration "Ping Desk Prod" is invalid')).toBeVisible();
  });
});
