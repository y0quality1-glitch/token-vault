import { expect, test, type APIRequestContext } from '@playwright/test';
import { DEMO_PASSWORD, details, expectNoSecretsInBrowser, login, trackPageErrors } from './helpers';

/**
 * Secret Management phase 2 through the real stack: the control plane keeps metadata and
 * versions, the customer webhook validates and encrypts every value (it is the only place a
 * value is stored), and only an authorized retrieval returns one. Roles decide who may do what.
 */
const API = 'http://localhost:4000';
const PASSWORD = 'e2e-orders-password-7f3a9c';
const NEW_PASSWORD = 'e2e-orders-password-rotated-41b2';

async function member(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }, email: string) {
  const ctx = await playwright.request.newContext({ baseURL: API });
  expect((await ctx.post('/api/v1/auth/login', { data: { email, password: DEMO_PASSWORD } })).ok()).toBe(true);
  expect((await ctx.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } })).ok()).toBe(true);
  return ctx;
}

test.describe.serial('secrets: metadata in the control plane, values on the customer webhook', () => {
  let owner: APIRequestContext;
  let auditor: APIRequestContext;
  let developer: APIRequestContext;
  let id = '';

  test.beforeAll(async ({ playwright }) => {
    [owner, auditor, developer] = await Promise.all([member(playwright, 'owner@demo.test'), member(playwright, 'auditor@demo.test'), member(playwright, 'developer@demo.test')]);
  });
  test.afterAll(async () => {
    await Promise.all([owner?.dispose(), auditor?.dispose(), developer?.dispose()]);
  });

  test('an owner stores a PostgreSQL login; the webhook validates and encrypts it', async () => {
    const invalid = await owner.post('/api/v1/secret/save', { data: { name: 'orders-db', typeKey: 'postgresql', environment: 'production', metadata: { host: 'db.internal' }, payload: { username: 'orders', password: '' } } });
    expect(invalid.status()).toBe(400);
    expect((await invalid.json()).details.fields).toMatchObject({ 'payload.password': 'Password is required' });

    const created = await owner.post('/api/v1/secret/save', {
      data: { name: 'orders-db', description: 'Orders service database', typeKey: 'postgresql', project: 'shop', environment: 'production', tags: ['pci'], metadata: { host: 'db.internal', port: 5432 }, payload: { username: 'orders', password: PASSWORD } },
    });
    expect(created.status(), await created.text()).toBe(201);
    const s = await details(created);
    id = s.id;
    expect(s).toMatchObject({ status: 'ACTIVE', activeVersion: 1, webhookId: 'wh_local0000000001', summary: { username: 'orders', password: '••••••••' }, fingerprint: expect.stringMatching(/^fp_/) });
    expect(JSON.stringify(s)).not.toContain(PASSWORD);
  });

  test('lists and details never contain the value; every role with secret:read_metadata sees them', async () => {
    for (const ctx of [owner, auditor, developer]) {
      const list = await details(await ctx.post('/api/v1/secret/getall', { data: { project: 'shop', tag: 'pci' } }));
      expect(list.items.map((x: { id: string }) => x.id)).toContain(id);
      expect(JSON.stringify(list)).not.toContain(PASSWORD);
    }
    const d = await details(await auditor.get(`/api/v1/secret/getbyid/${id}`));
    expect(d.can).toMatchObject({ retrieve: false, updateValue: false, revoke: false });
    expect(JSON.stringify(d)).not.toContain(PASSWORD);
  });

  test('only members with secret:retrieve can reveal a value, and each retrieval is audited', async () => {
    expect((await auditor.post('/api/v1/secret/retrieve', { data: { id } })).status()).toBe(403);
    expect((await developer.post('/api/v1/secret/retrieve', { data: { id } })).status()).toBe(403);
    expect((await developer.post('/api/v1/secret/save', { data: { name: 'x', typeKey: 'api-key', environment: 'development', payload: { apiKey: 'k' } } })).status()).toBe(403);

    const r = await details(await owner.post('/api/v1/secret/retrieve', { data: { id, fields: ['password'], reason: 'e2e check' } }));
    expect(r).toMatchObject({ id, version: 1, payload: { password: PASSWORD } });
    expect(Object.keys(r.payload)).toEqual(['password']);

    const events = await details(await auditor.post('/api/v1/auditEvent/getall', { data: { eventType: 'secret.', targetId: id } }));
    const types = (events.items as { eventType: string }[]).map((e) => e.eventType);
    expect(types).toEqual(expect.arrayContaining(['secret.created', 'secret.access_denied', 'secret.retrieved']));
    expect(JSON.stringify(events)).not.toContain(PASSWORD);
  });

  test('a new value is a new version; rollback copies an old value into a newer version', async () => {
    const v2 = await details(await owner.post('/api/v1/secret/rotate', { data: { id, payload: { username: 'orders', password: NEW_PASSWORD }, reason: 'e2e rotation' } }));
    expect(v2.activeVersion).toBe(2);
    expect(v2.versions.map((v: { version: number; state: string }) => [v.version, v.state])).toEqual([
      [2, 'ACTIVE'],
      [1, 'PREVIOUS'],
    ]);
    expect((await details(await owner.post('/api/v1/secret/retrieve', { data: { id } }))).payload.password).toBe(NEW_PASSWORD);

    const v3 = await details(await owner.post('/api/v1/secret/rollback', { data: { id, version: 1 } }));
    expect(v3.versions[0]).toMatchObject({ version: 3, state: 'ACTIVE', copiedFrom: 1 });
    expect(v3.versions[0].fingerprint).toBe(v3.versions.find((v: { version: number }) => v.version === 1).fingerprint);
    expect((await details(await owner.post('/api/v1/secret/retrieve', { data: { id } }))).payload.password).toBe(PASSWORD);

    const destroyed = await details(await owner.post('/api/v1/secret/destroyVersion', { data: { id, version: 2 } }));
    expect(destroyed.versions.find((v: { version: number }) => v.version === 2).state).toBe('DESTROYED');
    expect((await owner.post('/api/v1/secret/retrieve', { data: { id, version: 2 } })).status()).toBe(410);
  });

  test('a revoked secret is never returned again; deleting it destroys every value on the webhook', async () => {
    expect((await details(await owner.post('/api/v1/secret/revoke', { data: { id, reason: 'e2e' } }))).status).toBe('REVOKED');
    const refused = await owner.post('/api/v1/secret/retrieve', { data: { id } });
    expect(refused.status()).toBe(409);
    expect((await refused.json()).code).toBe('SECRET_NOT_ACTIVE');

    const deleted = await details(await owner.delete(`/api/v1/secret/delete/${id}`));
    expect(deleted).toMatchObject({ status: 'DELETED', destroyedVersions: 2 });
    const tomb = await details(await owner.get(`/api/v1/secret/getbyid/${id}`));
    expect(tomb.versions.every((v: { state: string }) => v.state === 'DESTROYED')).toBe(true);
    // The name can be used again.
    const again = await owner.post('/api/v1/secret/save', { data: { name: 'orders-db', typeKey: 'postgresql', project: 'shop', environment: 'production', metadata: { host: 'db.internal' }, payload: { username: 'orders', password: PASSWORD } } });
    expect(again.status()).toBe(201);
  });
  test('in the console: create a secret from its type form, see it masked, reveal it on request', async ({ page }) => {
    const errors = trackPageErrors(page);
    const API_KEY = 'e2e-console-api-key-0123456789';
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await expect(page).not.toHaveURL(/select-org/);
    await page.goto('/secrets');
    await expect(page.getByTestId('secret-list')).toBeVisible();
    await page.getByTestId('secret-new').click();
    await page.getByTestId('secret-type-search').fill('API key');
    await page.getByTestId('secret-type-api-key').click();
    await expect(page.getByTestId('secret-create-form')).toBeVisible();
    await page.getByTestId('secret-name').fill('stripe-console');
    await page.getByTestId('secret-environment').selectOption('production');
    await page.getByTestId('secret-field-payload.apiKey').fill(API_KEY);
    await page.getByTestId('secret-create-submit').click();

    await expect(page).toHaveURL(/\/secrets\/sec_/);
    await expect(page.getByTestId('secret-detail')).toBeVisible();
    await expect(page.getByTestId('secret-summary-apiKey')).toContainText('••••••••');
    await expectNoSecretsInBrowser(page, [API_KEY]);

    await page.getByTestId('secret-reveal').click();
    await page.getByTestId('secret-reveal-reason').fill('e2e console check');
    await page.getByTestId('secret-reveal-confirm').click();
    await expect(page.getByTestId('secret-revealed-values')).toBeVisible();
    await expect(page.getByTestId('secret-value-text-apiKey')).toHaveText(API_KEY);
    await page.getByTestId('secret-reveal-hide').click();
    await expect(page.getByTestId('secret-revealed-values')).toHaveCount(0);
    await expectNoSecretsInBrowser(page, [API_KEY]);
    expect(errors).toEqual([]);
  });
});
