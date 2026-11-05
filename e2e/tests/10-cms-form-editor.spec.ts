import { expect, test, type Page } from '@playwright/test';
import { DEMO_PASSWORD, trackPageErrors } from './helpers';

/**
 * The CMS form editor: an editor defines an application without writing JSON. The form and
 * the JSON view edit the same document, and validation runs live on unsaved changes.
 */
const CMS = 'http://localhost:5174';

test.describe.serial('CMS form editor', () => {
  let page: Page;
  let errors: string[] = [];

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    errors = trackPageErrors(page);
  });
  test.afterAll(async () => {
    expect(errors, 'no uncaught page errors').toEqual([]);
    await page?.close();
  });

  test('an editor builds an application in the form, with live validation', async () => {
    await page.goto(CMS + '/');
    await page.getByLabel('Email').fill('editor@cms.test');
    await page.getByLabel('Password').fill(DEMO_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByRole('button', { name: 'New application' }).click();
    await page.locator('#appKey').fill('formdesk');
    await page.locator('#appName').fill('Form Desk');
    await page.getByRole('button', { name: 'Create draft' }).click();

    const form = page.getByTestId('definition-form');
    await expect(form).toBeVisible(); // the form is the default view

    // API section
    await form.getByLabel('Base URL').fill('https://api.formdesk.example.com/v2');
    await form.getByLabel('Allowed hosts').fill('api.formdesk.example.com');

    // Switch the auth method to a custom header with a secret format.
    await form.getByLabel('Kind of method 1').selectOption('header');
    await form.getByLabel('Credential header').fill('X-Desk-Key');
    await form.getByLabel('Secret format (regex)').fill('^fd_[a-z0-9]{12,}$');

    // A new operation: a mistake in the path is reported live, in its own section.
    await form.getByRole('button', { name: 'Add operation' }).click();
    // The expanded operation (its accessible name follows its id, which we are about to change).
    const op = form.locator('[aria-label^="Operation "]').filter({ has: page.getByRole('textbox', { name: 'Request path' }) });
    await op.getByLabel('Operation id').fill('formdesk.tickets.create');
    await op.getByLabel('Label', { exact: true }).fill('Create ticket');
    await op.getByLabel('Risk').selectOption('write');
    await op.getByLabel('Request method').selectOption('POST');
    await op.getByLabel('Request path').fill('projects/{resource.project}/tickets');
    await expect(op.getByTestId('section-issues')).toContainText('must start with /');
    await expect(page.getByTestId('live-validation')).toContainText('1 problem');
    await op.getByLabel('Request path').fill('/projects/{resource.project}/tickets');

    // Using an input that is not declared is caught too; declaring it fixes it.
    await op.getByLabel('Request body (JSON template)').fill('{"subject": "{input.subject}"}');
    await expect(op.getByTestId('section-issues')).toContainText('unknown placeholder {input.subject}');
    await op.getByRole('button', { name: 'Add input' }).click();
    await op.getByLabel('Input name 1').fill('subject');
    await expect(page.getByTestId('live-validation')).toContainText('Unsaved changes are valid');

    await page.getByRole('button', { name: 'Save draft' }).click();
    await expect(page.getByText('The saved definition is valid.')).toBeVisible();
  });

  test('the JSON view shows the same document, and the request preview uses it', async () => {
    await page.getByRole('tab', { name: 'JSON', exact: true }).click();
    const json = JSON.parse(await page.getByLabel('Definition JSON').inputValue());
    expect(json.api).toMatchObject({ baseUrl: 'https://api.formdesk.example.com/v2', allowedHosts: ['api.formdesk.example.com'] });
    expect(json.auth[0]).toMatchObject({ kind: 'header', header: 'X-Desk-Key', secretPattern: '^fd_[a-z0-9]{12,}$' });
    expect(json.operations[1]).toMatchObject({ id: 'formdesk.tickets.create', risk: 'write', request: { method: 'POST', path: '/projects/{resource.project}/tickets', body: { subject: '{input.subject}' } }, input: { subject: { type: 'string' } } });

    await page.getByRole('tab', { name: /Request preview/ }).click();
    await page.getByLabel('Operation').selectOption('formdesk.tickets.create');
    await page.getByLabel('input (JSON)').fill('{"subject": "Printer jam"}');
    await page.getByRole('button', { name: 'Preview request' }).click();
    await expect(page.getByTestId('preview-url')).toContainText('POST https://api.formdesk.example.com/v2/projects/demo-project/tickets');
    await expect(page.getByText('X-Desk-Key (injected by the customer webhook)')).toBeVisible();
  });

  test('published versions are shown read-only in the form', async () => {
    await page.getByRole('complementary').getByRole('link', { name: 'Applications' }).click();
    await page.getByRole('row', { name: /GitHub/ }).click();
    await page.getByRole('row', { name: /v1/ }).click();
    const form = page.getByTestId('definition-form');
    await expect(form.getByLabel('Base URL')).toBeDisabled();
    await expect(form.getByRole('button', { name: 'Add operation' })).toHaveCount(0);
  });
});
