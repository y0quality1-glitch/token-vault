import { expect, test, type Page } from '@playwright/test';
import { verifySignedDefinition } from '@token-vault/shared/signing';
import type { SignedDefinition } from '@token-vault/shared';
import { DEMO_PASSWORD, trackPageErrors } from './helpers';

/**
 * Provider CMS: an editor defines a new application as data, a different person
 * (a publisher) reviews and publishes it, and the catalog serves it signed with the
 * CMS key so Token Vault can trust it without new code.
 */
const CMS = 'http://localhost:5174';
const CMS_API = 'http://localhost:4200';

async function cmsLogin(page: Page, email: string) {
  await page.goto(CMS + '/');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(DEMO_PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Applications' })).toBeVisible();
}

async function editDefinition(page: Page, change: (d: any) => void) {
  await page.getByRole('tab', { name: 'JSON', exact: true }).click(); // the form view is the default
  const editor = page.getByLabel('Definition JSON');
  const def = JSON.parse(await editor.inputValue());
  change(def);
  await editor.fill(JSON.stringify(def, null, 2));
  await page.getByRole('button', { name: 'Save draft' }).click();
}

test.describe.serial('provider CMS: define, review and publish an application', () => {
  let page: Page;
  let versionUrl = '';
  let errors: string[] = [];

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    errors = trackPageErrors(page);
  });
  test.afterAll(async () => {
    expect(errors, 'no uncaught page errors').toEqual([]);
    await page?.close();
  });

  test('the seeded definitions are published and signed', async ({ request }) => {
    const { public_key_pem } = await (await request.get(`${CMS_API}/catalog/v1/public-key`)).json();
    const { definitions } = (await (await request.get(`${CMS_API}/catalog/v1/definitions`)).json()) as { definitions: SignedDefinition[] };
    // GitHub, plus the catalog entries the CMS seeds as "coming soon".
    expect(definitions.map((d) => verifySignedDefinition(d, public_key_pem).key)).toEqual(['github', 'google', 'openai', 'slack']);
  });

  test('an editor drafts a new application and must fix validation problems before submitting', async () => {
    await cmsLogin(page, 'editor@cms.test');
    await page.getByRole('button', { name: 'New application' }).click();
    await page.locator('#appKey').fill('tracker');
    await page.locator('#appName').fill('Issue Tracker');
    await page.getByRole('button', { name: 'Create draft' }).click();
    await expect(page.getByRole('heading', { name: /Issue Tracker v1/ })).toBeVisible();
    versionUrl = page.url();

    // Credentials must never go over plain http, or to a host outside the allow-list.
    await editDefinition(page, (d) => {
      d.api.baseUrl = 'http://tracker.example.com/api';
    });
    await expect(page.getByTestId('validation-issues')).toContainText('must use https');
    await expect(page.getByRole('button', { name: 'Submit for review' })).toHaveCount(0);

    await editDefinition(page, (d) => {
      d.api.baseUrl = 'https://tracker.example.com/api';
      d.api.allowedHosts = ['tracker.example.com'];
    });
    await expect(page.getByText('The saved definition is valid.')).toBeVisible();

    await page.getByRole('tab', { name: /Request preview/ }).click();
    await page.getByRole('button', { name: 'Preview request' }).click();
    await expect(page.getByTestId('preview-url')).toContainText('GET https://tracker.example.com/api/projects/demo-project/items?limit=10');
    await expect(page.getByText('Authorization (injected by the customer webhook)')).toBeVisible();

    await page.getByRole('button', { name: 'Submit for review' }).click();
    await expect(page.getByText('In review').first()).toBeVisible();
    // Editors cannot publish.
    await expect(page.getByRole('button', { name: 'Approve & publish' })).toBeDisabled();
    await page.getByRole('button', { name: 'Sign out' }).click();
  });

  test('a publisher confirms the hosts and publishes; the catalog serves it signed', async ({ request }) => {
    await cmsLogin(page, 'publisher@cms.test');
    await page.goto(versionUrl);
    await expect(page.getByText('First publication')).toBeVisible();
    await page.getByRole('button', { name: 'Approve & publish' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('tracker.example.com').first()).toBeVisible();
    const confirm = dialog.getByRole('button', { name: 'Approve & publish' });
    await expect(confirm).toBeDisabled(); // the hosts must be confirmed first
    await dialog.getByLabel('I confirm these hosts belong to the provider').check();
    await confirm.click();
    await expect(page.getByText('Published and signed')).toBeVisible();

    const { public_key_pem } = await (await request.get(`${CMS_API}/catalog/v1/public-key`)).json();
    const { definitions } = (await (await request.get(`${CMS_API}/catalog/v1/definitions`)).json()) as { definitions: SignedDefinition[] };
    const tracker = definitions.find((d) => (d.definition as { key: string }).key === 'tracker')!;
    expect(tracker.approved_by).toBe('Priya Publisher');
    expect(verifySignedDefinition(tracker, public_key_pem).api.allowedHosts).toEqual(['tracker.example.com']);

    await page.getByRole('link', { name: 'Audit log' }).click();
    await expect(page.getByText('version.published').first()).toBeVisible();
  });
});
