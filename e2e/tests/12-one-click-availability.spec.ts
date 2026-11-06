import { expect, test, type Page } from '@playwright/test';
import { DEMO_PASSWORD, login, trackPageErrors } from './helpers';

/**
 * One-click availability: a CMS administrator makes a "coming soon" application available
 * (and back). Each click publishes a signed version that changes nothing but the listing,
 * and the console's open catalog follows without a reload.
 */
const CMS = 'http://localhost:5174';

test.describe.serial('one-click availability in the CMS', () => {
  let cms: Page;
  let consolePage: Page;
  let errors: string[] = [];

  test.beforeAll(async ({ browser }) => {
    cms = await browser.newPage();
    consolePage = await browser.newPage();
    errors = [...trackPageErrors(cms), ...trackPageErrors(consolePage)];
  });
  test.afterAll(async () => {
    expect(errors, 'no uncaught page errors').toEqual([]);
    await cms?.close();
    await consolePage?.close();
  });

  async function cmsLogin(email: string) {
    await cms.goto(CMS + '/');
    await cms.getByLabel('Email').fill(email);
    await cms.getByLabel('Password').fill(DEMO_PASSWORD);
    await cms.getByRole('button', { name: 'Sign in' }).click();
    await expect(cms.getByRole('heading', { name: 'Applications' })).toBeVisible();
  }

  test('editors do not get the button', async () => {
    await cmsLogin('editor@cms.test');
    await cms.getByRole('row', { name: /OpenAI/ }).click();
    await expect(cms.getByRole('heading', { level: 1, name: /OpenAI/ })).toBeVisible();
    await expect(cms.getByRole('button', { name: 'Make available' })).toHaveCount(0);
    await cms.getByRole('button', { name: 'Sign out' }).click();
  });

  test('an administrator makes OpenAI available; the open console catalog follows', async () => {
    await login(consolePage, 'owner@demo.test');
    await consolePage.getByRole('button', { name: /Demo Organization/ }).click();
    await consolePage.goto('/integrations/catalog');
    const tile = consolePage.getByTestId('catalog-openai');
    await expect(tile.getByRole('button', { name: 'Coming soon' })).toBeDisabled();

    await cmsLogin('admin@cms.test');
    await cms.getByRole('row', { name: /OpenAI/ }).click();
    await cms.getByRole('button', { name: 'Make available' }).click();
    const dialog = cms.getByRole('dialog');
    await expect(dialog).toContainText('Publishes v2 right away with only the availability changed');
    await dialog.getByLabel('Note (optional)').fill('Launch for the pilot');
    await dialog.getByRole('button', { name: 'Make available' }).click();
    await expect(cms.getByRole('heading', { level: 1, name: /OpenAI/ })).toContainText('Published v2');
    await expect(cms.getByRole('heading', { level: 1, name: /OpenAI/ })).toContainText('Available');
    await expect(cms.getByRole('button', { name: 'Mark as coming soon' })).toBeVisible();

    // No reload of the console: it refreshes the catalog by itself.
    await expect(tile.getByRole('button', { name: 'Connect', exact: true })).toBeEnabled({ timeout: 30_000 });
    await expect(tile).toContainText('CMS v2');
  });

  test('and back to coming soon', async () => {
    await cms.getByRole('button', { name: 'Mark as coming soon' }).click();
    await cms.getByRole('dialog').getByRole('button', { name: 'Mark as coming soon' }).click();
    await expect(cms.getByRole('heading', { level: 1, name: /OpenAI/ })).toContainText('Published v3');
    await expect(cms.getByRole('heading', { level: 1, name: /OpenAI/ })).toContainText('Coming soon');
    await expect(consolePage.getByTestId('catalog-openai').getByRole('button', { name: 'Coming soon' })).toBeDisabled({ timeout: 30_000 });

    await cms.getByRole('complementary').getByRole('link', { name: 'Audit log' }).click();
    await expect(cms.getByRole('row', { name: /openai v3/ })).toContainText('version.published');
  });
});
