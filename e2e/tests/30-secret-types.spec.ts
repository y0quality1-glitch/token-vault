import { expect, test, type APIRequestContext } from '@playwright/test';
import { DEMO_PASSWORD, details } from './helpers';

/**
 * Secret types (spec 4.9.3, Secret Management phase 1): the classification model is data,
 * published in the CMS through review, signed under its own context, and picked up by the
 * control plane without a deploy. The predefined types cover categories A–I.
 */
const CMS_API = 'http://localhost:4200';
const API = 'http://localhost:4000';

async function cmsSession(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }, email: string) {
  const ctx = await playwright.request.newContext({ baseURL: CMS_API });
  expect((await ctx.post('/api/v1/auth/login', { data: { email, password: DEMO_PASSWORD } })).ok()).toBe(true);
  return ctx;
}

test.describe.serial('secret types: published in the CMS, trusted by Token Vault', () => {
  let admin: APIRequestContext;

  test.beforeAll(async ({ playwright }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });
  });
  test.afterAll(async () => {
    await admin?.dispose();
  });

  test('Token Vault trusts the predefined types, verified from the CMS catalog', async () => {
    const list = await details(await admin.post('/api/v1/secretType/getall'));
    expect(list.catalog).toMatchObject({ lastError: null });
    expect(list.types.length).toBeGreaterThan(40);
    expect(list.types.every((t: { source: string }) => t.source === 'catalog')).toBe(true);
    expect(list.categories.map((c: { key: string }) => c.key)).toEqual(['api', 'database', 'auth', 'cloud', 'crypto', 'certificate', 'infrastructure', 'application', 'webhook']);
    const pg = await details(await admin.get('/api/v1/secretType/getbyid/postgresql'));
    expect(pg).toMatchObject({ category: 'database', categoryLabel: 'Database secrets', fields: { username: { sensitive: false }, password: { sensitive: true, required: true } }, metadata: { host: { kind: 'hostname' } } });
    const aws = await details(await admin.post('/api/v1/secretType/getall', { data: { search: 'aws', filters: { category: 'cloud' } } }));
    expect(aws.types.map((t: { key: string }) => t.key)).toEqual(['aws-access-key', 'aws-session-credentials']);
  });

  test('a secret type published in the CMS becomes available in Token Vault without a deploy', async ({ playwright }) => {
    const editor = await cmsSession(playwright, 'editor@cms.test');
    expect((await editor.post('/api/v1/secretType/save', { data: { key: 'payments-gateway', name: 'Payment gateway' } })).status()).toBe(201);
    const definition = {
      key: 'payments-gateway',
      version: 1,
      name: 'Payment gateway',
      description: 'API key, API secret and webhook signing secret of a payment provider.',
      category: 'api',
      fields: {
        apiKey: { label: 'API key', required: true, order: 10 },
        apiSecret: { label: 'API secret', required: true, order: 20 },
        webhookSecret: { label: 'Webhook signing secret', order: 30 },
        merchantId: { label: 'Merchant ID', sensitive: false, order: 40 },
      },
      identifiedBy: ['merchantId'],
      metadata: { endpoint: { label: 'API endpoint', kind: 'url', order: 10 } },
      defaults: { rotationIntervalDays: 90 },
    };
    expect((await details(await editor.post('/api/v1/version/save', { data: { key: 'payments-gateway', version: 1, definition } }))).issues).toEqual([]);
    expect((await editor.post('/api/v1/version/submit', { data: { key: 'payments-gateway', version: 1 } })).ok()).toBe(true);
    const publisher = await cmsSession(playwright, 'publisher@cms.test');
    expect((await details(await publisher.post('/api/v1/version/approve', { data: { key: 'payments-gateway', version: 1 } }))).status).toBe('PUBLISHED');
    await Promise.all([editor.dispose(), publisher.dispose()]);

    await expect
      .poll(async () => (await admin.get('/api/v1/secretType/getbyid/payments-gateway')).status(), { timeout: 20_000 })
      .toBe(200);
    const t = await details(await admin.get('/api/v1/secretType/getbyid/payments-gateway'));
    expect(t).toMatchObject({ version: 1, source: 'catalog', fields: { webhookSecret: { sensitive: true, required: false }, merchantId: { sensitive: false } }, defaults: { rotationIntervalDays: 90, expiryWarningDays: 14 } });
  });

  test('archiving a type in the CMS removes it from Token Vault', async ({ playwright }) => {
    const cmsAdmin = await cmsSession(playwright, 'admin@cms.test');
    expect((await cmsAdmin.post('/api/v1/secretType/archive', { data: { key: 'payments-gateway', reason: 'e2e clean-up' } })).ok()).toBe(true);
    await cmsAdmin.dispose();
    await expect
      .poll(async () => (await admin.get('/api/v1/secretType/getbyid/payments-gateway')).status(), { timeout: 20_000 })
      .toBe(404);
  });

  test('the CMS console lists secret types by category', async ({ page }) => {
    await page.goto(`http://localhost:5174/`);
    await page.getByLabel('Email').fill('editor@cms.test');
    await page.getByLabel('Password').fill(DEMO_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByRole('link', { name: 'Secret types' }).click();
    await expect(page).toHaveURL(/\/secret-types$/);
    await expect(page.getByText('PostgreSQL credentials')).toBeVisible();
    await page.getByText('PostgreSQL credentials').click();
    await expect(page).toHaveURL(/\/secret-types\/postgresql$/);
  });
});

