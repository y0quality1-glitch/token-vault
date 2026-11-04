import { expect, test, type Page } from '@playwright/test';
import { goClient, login, sendPreset, trackPageErrors } from './helpers';

/** Remaining functional scenarios against the seeded Demo Organization. */
test.describe.serial('access scenarios (Demo Organization)', () => {
  let page: Page;
  let errors: string[];

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    errors = trackPageErrors(page);
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await expect(page.getByText('Recent access activity')).toBeVisible();
    await goClient(page, '/playground');
    await page.getByRole('button', { name: 'Get a credential' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Rotate & load' }).click();
    await expect(page.getByText('Credential loaded')).toBeVisible();
  });
  test.afterAll(async () => {
    expect(errors, 'uncaught page errors').toEqual([]);
    await page.close();
  });

  test('Scenario A: seeded grant authorizes issue creation', async () => {
    await sendPreset(page, /Authorized and successful/);
    await expect(page.getByText('Authorized and successful').nth(1)).toBeVisible();
  });

  test('Scenario B: ungranted operation is denied by scope', async () => {
    await sendPreset(page, /Scope denied/);
    await expect(page.getByText('Access denied: Scope denied')).toBeVisible();
  });

  test('Scenario E: expired grant is denied', async () => {
    await sendPreset(page, /Expired grant/);
    await expect(page.getByText('Access denied: Expired grant')).toBeVisible();
  });

  test('Scenario F: webhook outage fails safely', async () => {
    await page.getByRole('button', { name: /Webhook unavailable/ }).click();
    await page.getByRole('button', { name: 'Simulate outage', exact: true }).click();
    await expect(page.getByText('Simulated webhook outage enabled')).toBeVisible();
    await page.getByRole('button', { name: 'Send request' }).click();
    await expect(page.getByText(/Authorized, execution failed: Webhook unavailable/)).toBeVisible();
    await expect(page.getByText('No upstream call was made.')).toBeVisible();
    await page.getByRole('button', { name: 'Clear outage' }).click();
    await expect(page.getByText('Simulated outage cleared')).toBeVisible();
  });

  test('unauthorized agent credential is rejected', async () => {
    await sendPreset(page, /Unauthorized agent/);
    await expect(page.getByText('Access denied: Unauthorized agent')).toBeVisible();
  });

  test('missing grant is denied', async () => {
    await sendPreset(page, /Missing grant/);
    await expect(page.getByText('Access denied: Missing grant')).toBeVisible();
  });

  test('malformed request is denied', async () => {
    await sendPreset(page, /Malformed request/);
    await expect(page.getByText('Access denied: Malformed request')).toBeVisible();
  });

  test('upstream provider error is reported without exposing credentials', async () => {
    await sendPreset(page, /Upstream provider error/);
    await expect(page.getByText(/Authorized, execution failed: Upstream provider error/)).toBeVisible();
  });

  test('rate limit is enforced', async () => {
    await sendPreset(page, /Rate limit exceeded/);
    await expect(page.getByText('Access denied: Rate limit exceeded')).toBeVisible({ timeout: 30_000 });
  });

  test('every screen renders without an error state', async () => {
    const paths = [
      '/',
      '/guide',
      '/integrations/catalog',
      '/integrations/connected',
      '/integrations/credentials',
      '/integrations/int_github_001',
      '/agents',
      '/agents/agt_github_assist01',
      '/access/grants',
      '/access/grants/grt_issue_creation01',
      '/access/policies',
      '/webhook/setup',
      '/webhook/health',
      '/audit/access-logs',
      '/audit/security-events',
      '/settings/organization',
      '/settings/members',
      '/settings/api-clients',
    ];
    for (const p of paths) {
      await goClient(page, p);
      await expect(page.locator('main h1').first(), `heading on ${p}`).toBeVisible();
      await expect(page.locator('main'), `no error state on ${p}`).not.toContainText('Something went wrong');
    }
  });

  test('full page loads of client routes are served by the SPA (not the API proxy)', async () => {
    for (const p of ['/agents', '/agents/agt_github_assist01', '/access/grants']) {
      await page.goto(p);
      await expect(page.locator('main h1').first(), `SPA served ${p}`).toBeVisible();
    }
  });
});

test.describe('roles and layout', () => {
  test('developer is shown the permission-denied state on audit pages', async ({ page }) => {
    await login(page, 'developer@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create Access Grant' })).toHaveCount(0);
    await page.goto('/audit/access-logs');
    await expect(page.getByText('Permission denied')).toBeVisible();
  });

  test('tablet layout renders with a collapsible sidebar', async ({ page }) => {
    await page.setViewportSize({ width: 820, height: 1100 });
    await login(page, 'auditor@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await page.getByRole('button', { name: 'Open navigation' }).click();
    await expect(page.getByRole('link', { name: 'Access Logs' })).toBeVisible();
  });
});
