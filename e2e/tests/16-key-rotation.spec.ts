import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, details, login, trackPageErrors } from './helpers';

/**
 * Key rotation without downtime.
 * - Agent keys: rotating with a grace period keeps the old key working until it expires.
 *   Requests made with it say so (Token-Vault-Key-Expires), the console shows when it was
 *   last used, and an administrator can end the grace period early.
 * - Credential encryption key: the webhook reports which key encrypts the stored credentials.
 */
const API = 'http://localhost:4000';

test.describe.serial('key rotation', () => {
  let admin: APIRequestContext;
  let page: Page;
  let errors: string[] = [];
  let agentId = '';
  let oldKey = '';
  let newKey = '';

  const call = async (key: string, operation = 'github.repositories.read') => {
    const r = await admin.post('/agent/v1/request/execute', {
      headers: { authorization: `Bearer ${key}` },
      data: { integration_id: 'int_github_001', operation, resource: { repository: 'demo-org/demo-repo' }, idempotency_key: `e2e-rot-${Date.now()}-${Math.random()}` },
    });
    return { status: r.status(), expires: r.headers()['token-vault-key-expires'] ?? null, body: await details(r) };
  };

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    expect((await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });
    page = await browser.newPage();
    errors = trackPageErrors(page);
  });
  test.afterAll(async () => {
    expect(errors, 'no uncaught page errors').toEqual([]);
    await Promise.all([admin?.dispose(), page?.close()]);
  });

  test('rotating with a grace period keeps the old key working until it expires', async () => {
    const created = await details(await admin.post('/api/v1/agent/save', { data: { name: 'Rotation Service', environment: 'development', ownerTeam: 'Platform', agentType: 'SERVICE' } }));
    agentId = created.agent.id;
    oldKey = created.credential.apiKey;
    const now = Date.now();
    const grant = await admin.post('/api/v1/grant/save', {
      data: { name: 'Rotation read', agentId, integrationId: 'int_github_001', environment: 'development', scopes: ['github.repositories.read'], repositories: ['demo-org/demo-repo'], validFrom: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 86_400_000).toISOString(), rateLimitPerMinute: 60 },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    expect((await call(oldKey)).status).toBe(200);

    const rotated = await details(await admin.post('/api/v1/agent/rotateCredential', { data: { id: agentId, graceMinutes: 15 } }));
    newKey = rotated.credential.apiKey;
    expect(newKey).not.toBe(oldKey);
    const until = rotated.agent.previousCredentialExpiresAt as string;
    expect(Date.parse(until) - Date.now()).toBeGreaterThan(14 * 60_000);

    // Both keys work; only the old one carries the expiry notice.
    const viaOld = await call(oldKey);
    expect(viaOld.status, JSON.stringify(viaOld.body)).toBe(200);
    expect(viaOld.expires).toBe(until);
    expect(viaOld.body.checks[0].detail).toContain('this key was rotated and stops working at');
    const viaNew = await call(newKey);
    expect(viaNew.status).toBe(200);
    expect(viaNew.expires).toBeNull();

    // The other agent endpoints accept it too, with the same notice.
    const caps = await admin.post('/agent/v1/capability/getdata', { headers: { authorization: `Bearer ${oldKey}` } });
    expect(caps.status()).toBe(200);
    expect(caps.headers()['token-vault-key-expires']).toBe(until);

    const [event] = (await details(await admin.post('/api/v1/auditEvent/getall', { data: { eventType: 'agent.credential_rotated', targetId: agentId } }))).items;
    expect(event.metadata).toMatchObject({ graceMinutes: 15, previousKeyValidUntil: until });
  });

  test('the console shows the old key and its last use, and can end the grace period now', async () => {
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await page.goto(`/agents/${agentId}`);
    const panel = page.getByTestId('previous-key');
    await expect(panel).toContainText('Old key still accepted until');
    await expect(panel).toContainText('last used');
    await panel.getByRole('button', { name: 'Revoke old key now' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Revoke old key' }).click();
    await expect(page.getByText('Old key revoked')).toBeVisible();
    await expect(panel).toHaveCount(0);

    const refused = await call(oldKey);
    expect(refused.status).toBe(401);
    expect(refused.body.decision_code).toBe('AGENT_UNAUTHENTICATED');
    expect((await call(newKey)).status).toBe(200);
    const [event] = (await details(await admin.post('/api/v1/auditEvent/getall', { data: { eventType: 'agent.previous_credential_revoked', targetId: agentId } }))).items;
    expect(event).toBeTruthy();
  });

  test('the rotate dialog offers the grace period; without one the old key stops at once', async () => {
    await page.getByRole('button', { name: 'Rotate API credential' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByLabel('Keep the old key working for')).toHaveValue('15');
    await dialog.getByLabel('Keep the old key working for').selectOption('0');
    await dialog.getByRole('button', { name: 'Rotate credential' }).click();
    await expect(page.getByText('This secret will not be shown again.')).toBeVisible();
    // The key that was current a moment ago is refused immediately.
    expect((await call(newKey)).status).toBe(401);
  });

  test('the webhook reports which key encrypts the stored credentials', async () => {
    const r = await details(await admin.post('/api/v1/webhook/test', { data: { id: 'wh_local0000000001' } }));
    expect(r.result.ok).toBe(true);
    expect(r.result.detail).toMatch(/Credentials encrypted with key kid_[0-9a-f]{16}/);
    expect(r.result.detail).not.toContain('older key');
  });
});
