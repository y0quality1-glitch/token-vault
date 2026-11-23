import { expect, test, type APIRequestContext } from '@playwright/test';
import { DEMO_PASSWORD, details, login, trackPageErrors } from './helpers';

/**
 * Secret Management phase 3 through the real stack: an application (agent) reads a secret with
 * its own key, only under a grant, only the fields and version the grant allows; a grant can
 * hold each retrieval for a human, who must not be the agent's owner; revoking ends access.
 */
const API = 'http://localhost:4000';
const PASSWORD = 'e2e-agent-db-password-93ad';

async function member(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }, email: string) {
  const ctx = await playwright.request.newContext({ baseURL: API });
  expect((await ctx.post('/api/v1/auth/login', { data: { email, password: DEMO_PASSWORD } })).ok()).toBe(true);
  expect((await ctx.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } })).ok()).toBe(true);
  return ctx;
}

test.describe.serial('secret access: applications read secrets under grants', () => {
  let owner: APIRequestContext;
  let security: APIRequestContext;
  let app: APIRequestContext;
  let agentId = '';
  let dbId = '';
  let keyId = '';
  let grantId = '';

  const retrieve = (data: Record<string, unknown>) => app.post('/agent/v1/secret/retrieve', { data });

  test.beforeAll(async ({ playwright }) => {
    [owner, security] = await Promise.all([member(playwright, 'owner@demo.test'), member(playwright, 'security@demo.test')]);
    const agent = await details(await owner.post('/api/v1/agent/save', { data: { name: 'Orders Service', environment: 'production', ownerTeam: 'Shop', agentType: 'SERVICE' } }));
    agentId = agent.agent.id;
    app = await playwright.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${agent.credential.apiKey}` } });
    dbId = (await details(await owner.post('/api/v1/secret/save', { data: { name: 'orders-service-db', typeKey: 'postgresql', project: 'orders', environment: 'production', metadata: { host: 'db.internal' }, payload: { username: 'orders', password: PASSWORD } } }))).id;
    keyId = (await details(await owner.post('/api/v1/secret/save', { data: { name: 'release-signing', typeKey: 'hmac-secret', project: 'orders', environment: 'production', payload: { secret: 's'.repeat(40) } } }))).id;
  });
  test.afterAll(async () => {
    await Promise.all([owner?.dispose(), security?.dispose(), app?.dispose()]);
  });

  test('without a grant the application reads nothing', async () => {
    expect((await details(await app.post('/agent/v1/secret/getall'))).items).toEqual([]);
    const r = await retrieve({ secret_id: dbId });
    expect(r.status()).toBe(403);
    expect((await r.json()).code).toBe('SECRET_ACCESS_DENIED');
  });

  test('a grant limited to the password lets it read the password, by name, and nothing else', async () => {
    const g = await owner.post('/api/v1/secretAccess/save', { data: { agentId, secretId: dbId, fields: ['password'], description: 'Orders service connects to its database' } });
    expect(g.status(), await g.text()).toBe(201);
    grantId = (await details(g)).id;

    const listed = (await details(await app.post('/agent/v1/secret/getall'))).items;
    expect(listed).toEqual([expect.objectContaining({ secret_id: dbId, name: 'orders-service-db', fields: ['password'], requires_approval: false })]);

    const r = await details(await retrieve({ name: 'orders-service-db', project: 'orders', environment: 'production', reason: 'startup' }));
    expect(r).toMatchObject({ secret_id: dbId, version: 1, payload: { password: PASSWORD }, grant_id: grantId });
    expect(Object.keys(r.payload)).toEqual(['password']);
    expect((await (await retrieve({ secret_id: dbId, fields: ['username'] })).json()).code).toBe('SECRET_FIELDS_NOT_PERMITTED');

    const usage = (await details(await owner.post('/api/v1/secretAccess/getall', { data: { secretId: dbId } }))).items[0];
    expect(usage).toMatchObject({ id: grantId, useCount: 1 });
    const events = await details(await owner.post('/api/v1/auditEvent/getall', { data: { eventType: 'secret.', targetId: dbId } }));
    expect((events.items as { eventType: string; actor?: { type: string } }[]).map((e) => e.eventType)).toEqual(expect.arrayContaining(['secret.access_denied', 'secret.retrieved']));
    expect(JSON.stringify(events)).not.toContain(PASSWORD);
  });

  test('a grant that requires approval holds each retrieval for someone other than the agent owner', async () => {
    expect((await owner.post('/api/v1/secretAccess/save', { data: { agentId, secretId: keyId, requireApproval: true } })).status()).toBe(201);
    const held = await retrieve({ secret_id: keyId, reason: 'sign release 1.4' });
    expect(held.status()).toBe(202);
    const approvalId = (await details(held)).approval_id;

    // The owner created (and so owns) the agent: they may not approve its request.
    const own = await owner.post('/api/v1/secretAccess/approve', { data: { id: approvalId } });
    expect(own.status()).toBe(403);
    const approved = await details(await security.post('/api/v1/secretAccess/approve', { data: { id: approvalId, note: 'release window' } }));
    expect(approved).toMatchObject({ status: 'APPROVED', decidedBy: { name: 'Sam Okafor' } });

    const r = await details(await retrieve({ secret_id: keyId, approval_id: approvalId }));
    expect(r.payload.secret).toBe('s'.repeat(40));
    expect((await (await retrieve({ secret_id: keyId, approval_id: approvalId })).json()).code).toBe('APPROVAL_USED');
  });

  test('in the console, a security admin approves a held retrieval on Retrieval Approvals', async ({ page }) => {
    const errors = trackPageErrors(page);
    const held = await details(await retrieve({ secret_id: keyId, reason: 'sign release 1.5' }));
    await login(page, 'security@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await expect(page).not.toHaveURL(/select-org/);
    await page.goto('/secrets/approvals');
    const row = page.locator(`[data-testid="secret-approval-row"][data-approval-id="${held.approval_id}"]`);
    await expect(row).toBeVisible();
    await page.locator('tr', { has: row }).getByTestId('secret-approval-approve').click();
    await page.getByTestId('secret-approval-note').fill('approved in e2e');
    await page.getByTestId('secret-approval-confirm').click();
    await expect(row).toHaveAttribute('data-status', 'APPROVED');
    expect((await details(await retrieve({ secret_id: keyId, approval_id: held.approval_id }))).payload.secret).toBe('s'.repeat(40));
    expect(errors).toEqual([]);
  });

  test('revoking the grant ends access at once', async () => {
    await details(await owner.post('/api/v1/secretAccess/revoke', { data: { id: grantId, reason: 'service retired' } }));
    expect((await (await retrieve({ secret_id: dbId })).json()).code).toBe('SECRET_ACCESS_DENIED');
    const g = (await details(await owner.post('/api/v1/secretAccess/getall', { data: { agentId } }))).items.find((x: { id: string }) => x.id === grantId);
    expect(g).toMatchObject({ status: 'REVOKED', revocationReason: 'service retired' });
  });
});
