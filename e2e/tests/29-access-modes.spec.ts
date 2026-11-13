import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { DEMO_PASSWORD, details, login } from './helpers';

/**
 * Access modes, end to end (mock GitHub): an administrator switches a GitHub App integration
 * from Brokered to Decision only in the console. The agent's allowed request then comes back
 * with a decision token (verified here with the public keys at /.well-known/jwks.json) and no
 * result. In Short-lived credential mode the webhook issues a GitHub App token limited to the
 * repository and the operation's permission. A personal access token can't use that mode.
 */
const API = 'http://localhost:4000';
const PEM = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();

test.describe.serial('access modes (Demo Organization)', () => {
  let admin: APIRequestContext;
  let agentApi: APIRequestContext;
  let page: Page;
  let integrationId = '';
  const run = Date.now() % 100000;
  const input = { title: `Handed off ${run}`, body: '' };

  const createIssue = async () => {
    const r = await agentApi.post('/agent/v1/request/execute', { data: { integration_id: integrationId, operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input } });
    return { status: r.status(), body: await details(r) };
  };

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });
    const integration = await admin.post('/api/v1/integration/save', {
      data: { provider: 'github', authType: 'GITHUB_APP', displayName: `Handoff App ${run}`, environment: 'development', webhookId: 'wh_local0000000001', appId: '123456', installationId: '', keySource: 'stored', privateKey: PEM, allowedResources: ['demo-org/demo-repo'] },
    });
    expect(integration.ok(), await integration.text()).toBe(true);
    integrationId = (await details(integration)).id;
    const agent = await details(await admin.post('/api/v1/agent/save', { data: { name: `Handoff Agent ${run}`, environment: 'development', ownerTeam: 'Release', agentType: 'AI_AGENT' } }));
    const grant = await admin.post('/api/v1/grant/save', {
      data: { name: `Handoff ${run}`, agentId: agent.agent.id, integrationId, environment: 'development', scopes: ['github.issues.create'], repositories: ['demo-org/demo-repo'], validFrom: new Date(Date.now() - 60_000).toISOString(), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), rateLimitPerMinute: 60 },
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

  test('brokered by default: the webhook creates the issue', async () => {
    const r = await createIssue();
    expect(r.body).toMatchObject({ decision: 'ALLOW', execution: { status: 'SUCCEEDED' } });
    expect(r.body.authorization).toBeUndefined();
  });

  test('an administrator switches the integration to Decision only in the console', async () => {
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await page.goto(`/integrations/${integrationId}`);
    const modes = page.getByRole('radiogroup', { name: 'Access mode' });
    await expect(modes.getByRole('button', { name: /^Brokered/ })).toHaveClass(/ring-1/);
    await modes.getByRole('button', { name: /^Decision only/ }).click();
    await page.getByRole('button', { name: 'Switch' }).click();
    await expect(page.getByText('Access mode: Decision only')).toBeVisible();
    await expect(modes.getByRole('button', { name: /^Decision only/ })).toHaveClass(/ring-1/);
    await expect(page.getByText(/Filter responses policies cannot apply/)).toBeVisible();
  });

  test('the agent gets a decision token it can show, verifiable with the published keys, and no result', async () => {
    const r = await createIssue();
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ decision: 'ALLOW', execution: { status: 'HANDED_OFF', webhook_status: 'NOT_CALLED' }, result: null, authorization: { mode: 'DECISION_ONLY' } });

    const jwks = await (await fetch(`${API}/.well-known/jwks.json`)).json();
    const [h, p, s] = r.body.authorization.decision_token.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    const jwk = jwks.keys.find((k: { kid: string }) => k.kid === header.kid);
    expect(verify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(s, 'base64url'))).toBe(true);
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    expect(claims).toMatchObject({ integration_id: integrationId, operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, jti: r.body.request_id });
    expect(claims.input_sha256).toBe(createHash('sha256').update(JSON.stringify({ body: '', title: input.title })).digest('hex'));
  });

  test('short-lived credential: the webhook issues a GitHub App token for this repository and permission only', async () => {
    const set = await admin.post('/api/v1/integration/setAccessMode', { data: { id: integrationId, accessMode: 'SHORT_LIVED_CREDENTIAL' } });
    expect(set.ok(), await set.text()).toBe(true);
    const r = await createIssue();
    expect(r.body).toMatchObject({
      decision: 'ALLOW',
      execution: { status: 'HANDED_OFF', webhook_status: 'OK', credential: { type: 'github_app_installation_token', repositories: ['demo-org/demo-repo'], permissions: { issues: 'write' }, revoked: false } },
      authorization: { mode: 'SHORT_LIVED_CREDENTIAL', credential: { type: 'github_app_installation_token', token_type: 'Bearer', repositories: ['demo-org/demo-repo'], permissions: { issues: 'write' } } },
    });
    expect(r.body.authorization.credential.token).toMatch(/^ghs_/);

    // The audit names what was issued, never the token.
    const record = await (await admin.get(`/api/v1/accessRequest/getbyid/${r.body.request_id}`)).text();
    expect(record).not.toContain(r.body.authorization.credential.token);
  });

  test('a personal access token cannot be handed out', async () => {
    const r = await admin.post('/api/v1/integration/setAccessMode', { data: { id: 'int_github_001', accessMode: 'SHORT_LIVED_CREDENTIAL' } });
    expect(r.status()).toBe(400);
    expect(JSON.stringify(await r.json())).toContain('GitHub App or OAuth');
  });

  test('back to Brokered', async () => {
    expect((await admin.post('/api/v1/integration/setAccessMode', { data: { id: integrationId, accessMode: 'BROKERED' } })).ok()).toBe(true);
    expect((await createIssue()).body).toMatchObject({ decision: 'ALLOW', execution: { status: 'SUCCEEDED' } });
  });
});
