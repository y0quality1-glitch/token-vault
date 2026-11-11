import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { DEMO_PASSWORD, login } from './helpers';

/**
 * Acting on behalf of a user, end to end:
 *  - a Security Administrator registers the customer's identity provider under Settings → User Identity
 *    (public key only) and checks a user token there;
 *  - a grant that only works on behalf of a signed-in user denies the agent acting for itself,
 *    allows it for a verified user, and the user's own permissions narrow it;
 *  - the access log records which user each request was for, and can be filtered by user.
 * The issuer is unique to this run and deleted at the end.
 */
const API = 'http://localhost:4000';
const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const PUBLIC_KEY = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();

test.describe.serial('acting on behalf of a user (Demo Organization)', () => {
  let admin: APIRequestContext;
  let agentApi: APIRequestContext;
  let page: Page;
  const run = Date.now() % 100000;
  const ISSUER = `https://login.acme-${run}.test`;
  const agentName = `Support Agent ${run}`;
  const ada = `ada.${run}@acme.test`;

  function userToken(sub: string, extra: Record<string, unknown> = {}) {
    const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const h = b64({ alg: 'ES256', typ: 'JWT' });
    const p = b64({ iss: ISSUER, aud: 'token-vault', sub, email: sub === 'u_ada' ? ada : `${sub}@acme.test`, name: sub === 'u_ada' ? 'Ada Lovelace' : sub, groups: ['support'], iat: now, exp: now + 600, ...extra });
    return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  }
  const listIssues = (onBehalfOf?: string) =>
    agentApi
      .post('/agent/v1/execute', { data: { integration_id: 'int_github_001', operation: 'github.issues.list', resource: { repository: 'demo-org/demo-repo' }, ...(onBehalfOf ? { on_behalf_of: onBehalfOf } : {}) } })
      .then(async (r) => ({ status: r.status(), body: await r.json() }));

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
    const agent = await (await admin.post('/api/v1/agents', { data: { name: agentName, environment: 'development', ownerTeam: 'Support', agentType: 'AI_AGENT' } })).json();
    const grant = await admin.post('/api/v1/grants', {
      data: {
        name: `${agentName} issues`,
        agentId: agent.agent.id,
        integrationId: 'int_github_001',
        environment: 'development',
        scopes: ['github.issues.list'],
        repositories: ['demo-org/demo-repo'],
        validFrom: new Date(Date.now() - 60_000).toISOString(),
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
        rateLimitPerMinute: 60,
        onBehalfOf: 'REQUIRED',
        allowedUserGroups: ['support'],
      },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    agentApi = await playwright.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${agent.credential.apiKey}` } });
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    const { items } = await (await admin.get('/api/v1/user-issuers')).json();
    for (const i of items.filter((x: { issuer: string }) => x.issuer === ISSUER)) await admin.delete(`/api/v1/user-issuers/${i.id}`);
    await admin?.dispose();
    await agentApi?.dispose();
    await page?.close();
  });

  test('a user token is refused until its issuer is registered', async () => {
    const r = await listIssues(userToken('u_ada'));
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ decision_code: 'USER_TOKEN_INVALID', reason: expect.stringContaining('not registered') });
  });

  test('a Security Administrator registers the identity provider and checks a token', async () => {
    await login(page, 'security@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await page.getByRole('link', { name: 'User Identity' }).click();
    await page.getByRole('button', { name: 'Add issuer' }).click();
    const dialog = page.getByRole('dialog').filter({ hasText: 'Add issuer' });
    await dialog.getByLabel('Name').fill(`Acme login ${run}`);
    await dialog.getByLabel('Issuer (iss)').fill(ISSUER);
    await dialog.getByLabel('Audience (aud)').fill('token-vault');
    // A private key is refused: Token Vault must never hold one.
    await dialog.getByLabel('Public key').fill(keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
    await dialog.getByRole('button', { name: 'Add issuer' }).click();
    await expect(dialog.getByText(/This is a private key/)).toBeVisible();
    await dialog.getByLabel('Public key').fill(PUBLIC_KEY);
    await dialog.getByRole('button', { name: 'Add issuer' }).click();
    await expect(page.getByText('Issuer added')).toBeVisible();
    await expect(page.getByRole('row', { name: new RegExp(`Acme login ${run}`) }).getByText('Enabled')).toBeVisible();

    await page.getByRole('button', { name: 'Check a user token' }).click();
    const check = page.getByRole('dialog').filter({ hasText: 'Check a user token' });
    await check.getByLabel('User token (JWT)').fill(userToken('u_ada', { token_vault: { resources: ['demo-org/*'] } }));
    await check.getByRole('button', { name: 'Check token' }).click();
    await expect(check.getByText(`Valid: Ada Lovelace (${ada})`)).toBeVisible();
    await expect(check.getByText('resources: demo-org/*')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(check).toHaveCount(0);
  });

  test('the grant works only on behalf of a verified user in an allowed group, within that user’s permissions', async () => {
    expect((await listIssues()).body).toMatchObject({ decision: 'DENY', decision_code: 'USER_REQUIRED' });
    const allowed = await listIssues(userToken('u_ada'));
    expect(allowed.body).toMatchObject({ decision: 'ALLOW', acting_for: { sub: 'u_ada', email: ada, issuer: ISSUER } });
    expect((await listIssues(userToken('u_bob', { groups: ['sales'] }))).body.decision_code).toBe('USER_NOT_ALLOWED');
    expect((await listIssues(userToken('u_ada', { token_vault: { resources: ['other-org/*'] } }))).body.decision_code).toBe('USER_PERMISSION_DENIED');
  });

  test('the access log shows who each request was for, and filters by user', async () => {
    await page.goto('/audit/access-logs');
    await page.getByLabel('On behalf of user').fill(ada);
    const row = page.getByRole('row', { name: new RegExp(agentName) }).filter({ hasText: `for Ada Lovelace (${ada})` });
    await expect(row.first()).toBeVisible();
    await expect(page.getByRole('row', { name: /USER_REQUIRED|User required/ })).toHaveCount(0); // the request without a user is filtered out
    await row.filter({ hasText: 'Allow' }).first().click();
    await expect(page.getByText(`Ada Lovelace (${ada}) · u_ada`)).toBeVisible();
    await expect(page.getByText(ISSUER).first()).toBeVisible();
  });
});
