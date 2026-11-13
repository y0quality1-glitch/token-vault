import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, details, login, trackPageErrors } from './helpers';

/**
 * Rotation reminders: an integration can have a rotation interval. The console shows when
 * its credential is next due, Credential Status lists it, and the dashboard reminds ahead
 * of time. Rotating resets the clock. Reminders never block agents.
 */
const API = 'http://localhost:4000';

test.describe.serial('credential rotation reminders', () => {
  let admin: APIRequestContext;
  let page: Page;
  let errors: string[] = [];
  let integrationId = '';

  test.beforeAll(async ({ playwright, browser }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    expect((await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });
    const created = await admin.post('/api/v1/integration/save', {
      data: { provider: 'github', authType: 'PAT', displayName: 'Release Bot GitHub', accountLabel: 'demo-org', webhookId: 'wh_local0000000001', secret: 'mock_ghp_releaseBotToken1234567890', allowedResources: ['demo-org/demo-repo'], environment: 'development' },
    });
    expect(created.status(), await created.text()).toBe(201);
    integrationId = (await details(created)).id;
    page = await browser.newPage();
    errors = trackPageErrors(page);
  });
  test.afterAll(async () => {
    expect(errors, 'no uncaught page errors').toEqual([]);
    await Promise.all([admin?.dispose(), page?.close()]);
  });

  test('an administrator sets a reminder; the console shows when rotation is due', async () => {
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await page.goto(`/integrations/${integrationId}`);
    const reminder = page.getByTestId('rotation-reminder');
    await expect(reminder).toContainText('No rotation schedule');
    await reminder.getByLabel('Rotation reminder').selectOption('90');
    await expect(page.getByText('Reminder set: every 90 days')).toBeVisible();
    await expect(reminder).toContainText('Next rotation due');
    await expect(reminder).toContainText('(in 90 days), counted from the connection');

    await page.goto('/integrations/credentials');
    await expect(page.getByRole('row', { name: /Release Bot GitHub/ })).toContainText('In 90d');

    const [event] = (await details(await admin.post('/api/v1/auditEvent/getall', { data: { eventType: 'integration.rotation_policy_updated', targetId: integrationId } }))).items;
    expect(event.metadata).toMatchObject({ intervalDays: 90, previousIntervalDays: null });
  });

  test('the dashboard reminds when rotation is due within a week, and rotating resets it', async () => {
    // Shortest allowed interval: due in 7 days, so the reminder starts right away.
    const r = await admin.post('/api/v1/integration/setRotationPolicy', { data: { id: integrationId, intervalDays: 7 } });
    expect((await details(r)).rotationIntervalDays).toBe(7);
    expect((await admin.post('/api/v1/integration/setRotationPolicy', { data: { id: integrationId, intervalDays: 3 } })).status()).toBe(400);

    await page.goto('/');
    await expect(page.getByText('"Release Bot GitHub" is due for rotation in 7 days')).toBeVisible();

    const rotated = await admin.post('/api/v1/integration/rotate', { data: { id: integrationId, secret: 'mock_ghp_releaseBotTokenRotated12345' } });
    expect(rotated.ok(), await rotated.text()).toBe(true);
    await page.goto(`/integrations/${integrationId}`);
    await expect(page.getByTestId('rotation-reminder')).toContainText('counted from the last rotation');

    // Removing the reminder removes the alert; the credential was never blocked.
    await page.getByTestId('rotation-reminder').getByLabel('Rotation reminder').selectOption('');
    await expect(page.getByText('Reminder removed')).toBeVisible();
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await expect(page.getByText('"Release Bot GitHub" is due for rotation')).toHaveCount(0);
  });
});
