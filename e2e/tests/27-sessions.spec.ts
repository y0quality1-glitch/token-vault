import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, login } from './helpers';

/**
 * Session tracing, end to end: an agent tags its calls with a session id and W3C trace
 * context; Token Vault records them (denials too) and passes the trace to the webhook; an
 * auditor follows the session in Audit → Sessions and from the access log.
 */
const API = 'http://localhost:4000';

test.describe.serial('agent sessions (Demo Organization)', () => {
  let admin: APIRequestContext;
  let agentApi: APIRequestContext;
  let page: Page;
  const run = Date.now() % 100000;
  const agentName = `Traced Agent ${run}`;
  const sessionId = `task-${run}`;
  const label = `Triage bugs ${run}`;
  const traceId = `${String(run).padStart(8, '0')}aaaabbbbccccddddeeeeffff`;

  const call = (operation: string, span: string) =>
    agentApi
      .post('/agent/v1/execute', {
        headers: { traceparent: `00-${traceId}-${span}-01` },
        data: { integration_id: 'int_github_001', operation, resource: { repository: 'demo-org/demo-repo', path: 'README.md' }, session_id: sessionId, session_label: label },
      })
      .then(async (r) => ({ status: r.status(), body: await r.json() }));

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
    const agent = await (await admin.post('/api/v1/agents', { data: { name: agentName, environment: 'development', ownerTeam: 'Platform AI', agentType: 'AI_AGENT' } })).json();
    const grant = await admin.post('/api/v1/grants', {
      data: { name: `${agentName} read`, agentId: agent.agent.id, integrationId: 'int_github_001', environment: 'development', scopes: ['github.repositories.read'], repositories: ['demo-org/demo-repo'], validFrom: new Date(Date.now() - 60_000).toISOString(), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), rateLimitPerMinute: 60 },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    agentApi = await playwright.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${agent.credential.apiKey}` } });
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await admin?.dispose();
    await agentApi?.dispose();
    await page?.close();
  });

  test('every call of the session is recorded under its session and trace, denials too', async () => {
    const read = await call('github.repositories.read', '1111111111111111');
    expect(read.body).toMatchObject({ decision: 'ALLOW', trace: { session_id: sessionId, trace_id: traceId, parent_span_id: '1111111111111111' } });
    const denied = await call('github.contents.read', '2222222222222222'); // not granted
    expect(denied.body).toMatchObject({ decision: 'DENY', decision_code: 'SCOPE_DENIED', trace: { session_id: sessionId, trace_id: traceId } });

    const { items } = await (await admin.get(`/api/v1/sessions?search=${encodeURIComponent(label)}`)).json();
    expect(items).toEqual([expect.objectContaining({ sessionId, sessionLabel: label, agentName, requests: 2, allowed: 1, denied: 1 })]);
  });

  test('an auditor follows the session from Audit → Sessions to a single request', async () => {
    await login(page, 'auditor@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await page.getByRole('link', { name: 'Sessions' }).click();
    await page.getByLabel('Search sessions').fill(label);
    await page.getByRole('row', { name: new RegExp(label) }).click();

    await expect(page.getByRole('heading', { name: label })).toBeVisible();
    await expect(page.getByText('1 allowed · 1 denied · 0 held for approval')).toBeVisible();
    await expect(page.getByText(traceId)).toBeVisible();
    await expect(page.getByText(/Scope denied: Operation github\.contents\.read is not included/)).toBeVisible();

    await page.getByRole('link', { name: 'Read repository metadata' }).click();
    await expect(page.getByText('Audit detail')).toBeVisible();
    await expect(page.getByRole('link', { name: `${label} (${sessionId})` })).toBeVisible();
    await expect(page.getByText(new RegExp(`${traceId} · span [0-9a-f]{16} \\(parent 1111111111111111\\)`))).toBeVisible();
  });
});
