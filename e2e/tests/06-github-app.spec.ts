import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { generateKeyPairSync } from 'node:crypto';
import { DEMO_PASSWORD, details, expectNoSecretsInBrowser, login } from './helpers';

/**
 * GitHub App connector (mock GitHub): an admin connects a GitHub App by uploading its
 * private key in the console. Each authorized agent request then gets its own installation
 * token, minted for that one repository and the one permission the operation needs, and
 * revoked straight after use. The private key never comes back to the browser.
 */
const API = 'http://localhost:4000';
const PEM = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
const PEM_BODY = PEM.split('\n')[1]!; // a line of key material, to search for leaks

test.describe.serial('GitHub App connector (Demo Organization)', () => {
  let admin: APIRequestContext;
  let page: Page;
  let integrationId = '';
  let apiKey = '';

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await admin?.dispose();
    await page?.close();
  });

  test('an admin connects a GitHub App with an uploaded private key', async () => {
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await expect(page).not.toHaveURL(/select-org/);
    await page.goto('/integrations/connect/github');
    await page.locator('#displayName').fill('Demo GitHub App');
    await expect(page.getByRole('button', { name: /^GitHub App/ })).toHaveClass(/ring-1/); // the recommended default
    await page.locator('#appId').fill('123456');
    await page.locator('#privateKey').fill(PEM);
    await page.locator('#allowedResources').fill('demo-org/demo-repo');
    await page.getByRole('button', { name: 'Store in customer vault' }).click();

    await expect(page.getByText('Demo GitHub App is connected')).toBeVisible();
    await expect(page.getByText('GitHub App 123456 · installation 1')).toBeVisible();
    await expectNoSecretsInBrowser(page, [PEM_BODY]);

    const list = await details(await admin.post('/api/v1/integration/getall'));
    const created = list.items.find((i: { displayName: string }) => i.displayName === 'Demo GitHub App');
    expect(created).toMatchObject({ authType: 'GITHUB_APP', accountLabel: 'demo-org', maskedIdentifier: 'GitHub App 123456 · installation 1' });
    expect(JSON.stringify(created)).not.toContain(PEM_BODY);
    integrationId = created.id;
  });

  test('a bad key or unknown installation is rejected before anything is stored', async () => {
    const bad = await admin.post('/api/v1/integration/save', {
      data: { provider: 'github', authType: 'GITHUB_APP', displayName: 'Bad key', environment: 'development', webhookId: 'wh_local0000000001', appId: '1', installationId: '', keySource: 'stored', privateKey: '-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----', allowedResources: [] },
    });
    expect(bad.status()).toBe(400);
    expect((await bad.json()).code).toBe('INVALID_PRIVATE_KEY');

    const missing = await admin.post('/api/v1/integration/save', {
      data: { provider: 'github', authType: 'GITHUB_APP', displayName: 'Wrong install', environment: 'development', webhookId: 'wh_local0000000001', appId: '1', installationId: '999', keySource: 'stored', privateKey: PEM, allowedResources: [] },
    });
    expect(missing.status()).toBe(400);
    expect((await missing.json()).code).toBe('INSTALLATION_NOT_FOUND');
  });

  test('each request uses a token minted for one repository and one permission, then revoked', async () => {
    const agent = await details(await admin.post('/api/v1/agent/save', { data: { name: 'App Agent', environment: 'development', ownerTeam: 'Platform AI', agentType: 'AI_AGENT' } }));
    apiKey = agent.credential.apiKey;
    const now = Date.now();
    const grant = await admin.post('/api/v1/grant/save', {
      data: {
        name: 'App agent issues',
        agentId: agent.agent.id,
        integrationId,
        environment: 'development',
        scopes: ['github.repositories.read', 'github.issues.create'],
        repositories: ['demo-org/demo-repo'],
        validFrom: new Date(now - 60_000).toISOString(),
        expiresAt: new Date(now + 86_400_000).toISOString(),
        rateLimitPerMinute: 30,
      },
    });
    expect(grant.ok(), await grant.text()).toBe(true);

    const execute = async (operation: string, input: Record<string, unknown> = {}) => {
      const r = await admin.post('/agent/v1/request/execute', {
        headers: { authorization: `Bearer ${apiKey}` },
        data: { integration_id: integrationId, operation, resource: { repository: 'demo-org/demo-repo' }, input, idempotency_key: `e2e-app-${operation}-${now}` },
      });
      return { status: r.status(), body: await details(r) };
    };

    const read = await execute('github.repositories.read');
    expect(read.status, JSON.stringify(read.body)).toBe(200);
    expect(read.body.execution.credential).toMatchObject({ type: 'github_app_installation_token', repositories: ['demo-org/demo-repo'], permissions: { metadata: 'read' }, revoked: true });

    const create = await execute('github.issues.create', { title: 'Opened with a minted App token' });
    expect(create.status, JSON.stringify(create.body)).toBe(200);
    expect(create.body.execution.credential).toMatchObject({ repositories: ['demo-org/demo-repo'], permissions: { issues: 'write' }, revoked: true });
    expect(JSON.stringify(create.body)).not.toMatch(/ghs_[0-9a-f]{36}/); // the minted token itself never leaves the webhook
  });

  test('the integration page offers key rotation, not token entry', async () => {
    await page.goto(`/integrations/${integrationId}`);
    await expect(page.getByText('GitHub App (per-request installation tokens)')).toBeVisible();
    await page.getByRole('button', { name: /Rotate \/ replace/ }).click();
    await expect(page.getByLabel('New App private key (PEM)')).toBeVisible();
    await page.getByRole('button', { name: 'Cancel' }).click();
  });
});
