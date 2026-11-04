import { expect, test, type Page } from '@playwright/test';
import { login } from './helpers';

/**
 * Access reviews and the tamper-evident audit chain, through the console. Runs last: it
 * deliberately tampers with an audit record (demo control) to prove detection works.
 */
test.describe.serial('access reviews and audit integrity (Demo Organization)', () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  });
  test.afterAll(async () => {
    await page.close();
  });

  test('a grant not reviewed in 30 days is flagged and can be kept', async () => {
    await expect(page.getByText(/grant due for access review/)).toBeVisible(); // Overview alert
    await expect(page.getByLabel('1 due')).toBeVisible(); // sidebar badge
    await page.goto('/access/reviews');
    const row = page.getByRole('row', { name: /Release Notes Read/ });
    await expect(row.getByText('Review due')).toBeVisible();
    await row.getByRole('button', { name: 'Keep' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Keep access' }).click();
    await expect(page.getByText('1 grant certified')).toBeVisible();
    await expect(page.getByText('No grants are due for review')).toBeVisible();
    await page.getByRole('button', { name: /All active/ }).click();
    await expect(page.getByRole('row', { name: /Release Notes Read/ }).getByText(/Reviewed/)).toBeVisible();
  });

  test('the audit chain verifies after every earlier test wrote to it', async () => {
    await page.goto('/audit/security-events');
    await page.getByRole('button', { name: 'Verify integrity' }).click();
    await expect(page.getByText('Chain intact: no records were modified, removed or forged.')).toBeVisible();
  });

  test('an audit record edited directly in the database is detected', async () => {
    await page.getByRole('button', { name: 'Simulate tampering' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Edit a record in the database' }).click();
    await expect(page.getByText('Audit record edited directly in the database')).toBeVisible();
    await page.getByRole('button', { name: 'Verify integrity' }).click();
    await expect(page.getByText(/Tampering detected/)).toBeVisible();
    await expect(page.getByText(/content no longer matches its hash: it was modified after being written/)).toBeVisible();
  });
});
