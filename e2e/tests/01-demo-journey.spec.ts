import { expect, test, type Page } from '@playwright/test';
import { MOCK_TOKEN, expectNoSecretsInBrowser, goClient, login, sendPreset, trackPageErrors } from './helpers';

/**
 * The 14-step POC demo script (spec section 13), run against the empty Sandbox
 * Organization: first-time setup through revocation. Steps share one page because the
 * agent credential is held in memory, exactly as in a live demo.
 */
test.describe.serial('demo script: first-time setup to revocation (Sandbox Organization)', () => {
  let page: Page;
  let errors: string[];

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    errors = trackPageErrors(page);
  });
  test.afterAll(async () => {
    expect(errors, 'uncaught page errors').toEqual([]);
    await page.close();
  });

  test('1. owner signs in and is asked to choose an organization', async () => {
    await login(page, 'owner@demo.test');
    await expect(page).toHaveURL(/\/select-org$/);
  });

  test('2. sandbox organization shows the empty initial state', async () => {
    await page.getByRole('button', { name: /Sandbox Organization/ }).click();
    await expect(page.getByText('Get started')).toBeVisible();
  });

  test('3. register and verify the customer webhook', async () => {
    await goClient(page, '/webhook/setup');
    await page.getByRole('button', { name: 'Register endpoint' }).click();
    await expect(page.getByText('One-time registration challenge')).toBeVisible();
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('button', { name: 'Send signed health challenge' }).click();
    await expect(page.getByText('Signed health challenge verified').first()).toBeVisible();
    await page.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByText('Webhook connected')).toBeVisible();
    await page.getByRole('button', { name: 'Next: connect an integration' }).click();
    await expect(page).toHaveURL(/\/integrations\/catalog$/);
  });

  test('4. connect GitHub through the customer webhook', async () => {
    await page.getByRole('button', { name: 'Connect', exact: true }).first().click();
    await page.locator('#displayName').fill('Demo GitHub');
    await page.locator('#accountLabel').fill('demo-org');
    await page.getByRole('button', { name: /^Personal Access Token/i }).click();
    await page.locator('#secret').fill(MOCK_TOKEN);
    await page.locator('#allowedResources').fill('demo-org/demo-repo, demo-org/other-repo');
    await page.getByRole('button', { name: 'Store in customer vault' }).click();
    await expect(page.getByText('is connected')).toBeVisible();
    await expect(page.getByText(/^cref_/).first()).toBeVisible();
  });

  test('5. the raw credential is never displayed after submission', async () => {
    await goClient(page, '/integrations/connected');
    await expect(page.getByText('Demo GitHub')).toBeVisible();
    await expectNoSecretsInBrowser(page, [MOCK_TOKEN]);
  });

  test('6. register the agent and receive a one-time credential', async () => {
    await goClient(page, '/agents?register=1');
    const dialog = page.getByRole('dialog');
    await dialog.getByPlaceholder('GitHub Assistant').fill('GitHub Assistant');
    await dialog.getByPlaceholder('Platform AI').fill('Platform AI');
    await dialog.getByRole('button', { name: 'Register agent' }).click();
    await expect(page.getByText('This secret will not be shown again')).toBeVisible();
    await expect(page.locator('code').filter({ hasText: /^tvak_[0-9a-f]{12}_/ })).toBeVisible();
    const useInPlayground = page.getByRole('button', { name: 'Use in Playground' });
    await expect(useInPlayground).toBeDisabled(); // acknowledgement required first
    await page.getByLabel('I have copied and securely stored this credential').check();
    await useInPlayground.click();
    await expect(page).toHaveURL(/\/playground$/);
  });

  test('7. create a scoped grant with the 5-step wizard', async () => {
    await goClient(page, '/access/grants/new');
    await page.getByRole('button', { name: /GitHub Assistant/ }).click();
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('button', { name: /Demo GitHub/ }).click();
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('Read repository metadata').check();
    await page.getByLabel('Create issue').check();
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByPlaceholder('demo-org/demo-repo').fill('demo-org/demo-repo');
    await page.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByText('Step 5: Review and create')).toBeVisible();
    await page.getByRole('button', { name: 'Create grant' }).click();
    await expect(page.getByText('Grant created').first()).toBeVisible();
  });

  test('8-9. Scenario A: permitted operation succeeds', async () => {
    await page.getByRole('button', { name: 'Test in playground' }).click();
    await sendPreset(page, /Authorized and successful/);
    await expect(page.getByText('Authorized and successful').nth(1)).toBeVisible();
    await expect(page.getByText('demo-org/demo-repo/issues/')).toBeVisible();
  });

  test('10. Scenario B/C: out-of-scope and out-of-resource requests are denied', async () => {
    await sendPreset(page, /Destructive operation/);
    await expect(page.getByText('Access denied: Denied by policy')).toBeVisible();
    await sendPreset(page, /Resource restriction/);
    await expect(page.getByText('Access denied: Resource restriction')).toBeVisible();
  });

  test('11. audit log shows both allowed and denied decisions', async () => {
    await goClient(page, '/audit/access-logs');
    const rows = page.locator('tbody tr');
    await expect(rows.first()).toBeVisible();
    await expect(page.locator('tbody')).toContainText('Allowed');
    await expect(page.locator('tbody')).toContainText('Denied');
    await rows.first().click();
    await expect(page.getByText('Audit detail')).toBeVisible();
    await page.keyboard.press('Escape');
  });

  test('12. revoke the grant', async () => {
    await goClient(page, '/access/grants');
    await page.getByRole('cell', { name: /GitHub Assistant → Demo GitHub/ }).click();
    await page.getByRole('button', { name: 'Revoke grant' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Revoke grant' }).click();
    await expect(page.getByText(/^Revoked /).first()).toBeVisible();
  });

  test('13. Scenario D: the previously permitted request is now denied', async () => {
    await goClient(page, '/playground');
    await sendPreset(page, /Revoked grant/);
    await expect(page.getByText('Access denied: Revoked grant')).toBeVisible();
  });

  test('14. security events trace the revocation', async () => {
    await goClient(page, '/audit/security-events');
    await expect(page.getByText('grant.revoked').first()).toBeVisible();
    await expectNoSecretsInBrowser(page, [MOCK_TOKEN]);
  });
});
