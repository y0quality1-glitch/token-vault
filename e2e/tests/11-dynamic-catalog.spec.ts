import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, login, trackPageErrors } from './helpers';

/**
 * The console's Integration Catalog is entirely data from the provider CMS: categories,
 * icons, availability and docs links come from signed definitions, and the open page
 * picks up publications and archivals without a reload.
 */
const CMS_API = 'http://localhost:4200';
const API = 'http://localhost:4000';

const kanban = {
  key: 'kanban',
  name: 'Kanban Board',
  description: 'Boards and cards for project teams.',
  catalog: { category: 'Project management', icon: 'briefcase', docsUrl: 'https://docs.kanban.example.com/api', tags: ['boards', 'cards'] },
  api: { baseUrl: 'https://api.kanban.example.com', allowedHosts: ['api.kanban.example.com'] },
  resource: { name: 'board', label: 'Board', pattern: '^[a-z0-9-]{2,40}$', example: 'roadmap' },
  auth: [{ id: 'API_KEY', label: 'API key', kind: 'bearer' }],
  credentialTest: { request: { method: 'GET', path: '/me' }, response: { fields: { id: 'id' } } },
  operations: [{ id: 'kanban.cards.list', label: 'List cards', risk: 'read', request: { method: 'GET', path: '/boards/{resource.board}/cards' }, response: { fields: { id: 'id' } }, mock: { status: 200, body: [] } }],
};

async function cms(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }, email: string) {
  const ctx = await playwright.request.newContext({ baseURL: CMS_API });
  expect((await ctx.post('/api/v1/auth/login', { data: { email, password: DEMO_PASSWORD } })).ok()).toBe(true);
  return ctx;
}

test.describe.serial('dynamic Integration Catalog', () => {
  let page: Page;
  let owner: APIRequestContext;
  let errors: string[] = [];

  test.beforeAll(async ({ browser, playwright }) => {
    page = await browser.newPage();
    errors = trackPageErrors(page);
    owner = await playwright.request.newContext({ baseURL: API });
    await owner.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await owner.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
  });
  test.afterAll(async () => {
    expect(errors, 'no uncaught page errors').toEqual([]);
    await owner?.dispose();
    await page?.close();
  });

  test('tiles, categories and "coming soon" entries come from the CMS', async () => {
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await page.goto('/integrations/catalog');

    const github = page.getByTestId('catalog-github');
    await expect(github).toContainText('Developer tools');
    await expect(github.getByRole('link', { name: /API documentation/ })).toHaveAttribute('href', 'https://docs.github.com/en/rest');

    const slack = page.getByTestId('catalog-slack');
    await expect(slack).toContainText('Communication');
    await expect(slack.getByRole('button', { name: 'Coming soon' })).toBeDisabled();
    await expect(page.getByTestId('catalog-google').getByText('Coming soon').first()).toBeVisible();

    // Search and category filters are built from the data.
    await page.getByLabel('Search integrations').fill('chat');
    await expect(page.locator('[data-testid^="catalog-"]')).toHaveCount(1);
    await expect(slack).toBeVisible();
    await page.getByLabel('Search integrations').fill('');
    await page.getByRole('group', { name: 'Categories' }).getByRole('button', { name: /^AI/ }).click();
    await expect(page.locator('[data-testid^="catalog-"]')).toHaveCount(1);
    await expect(page.getByTestId('catalog-openai')).toBeVisible();
    await page.getByRole('group', { name: 'Categories' }).getByRole('button', { name: /^All categories/ }).click();
  });

  test('a "coming soon" application cannot be connected', async () => {
    const res = await owner.post('/api/v1/integrations', {
      data: { provider: 'slack', authType: 'BOT_TOKEN', webhookId: 'wh_local0000000001', displayName: 'Early Slack', environment: 'development', secret: 'placeholder-not-a-token', allowedResources: [] },
    });
    expect(res.status()).toBe(400);
    expect((await res.json()).error.code).toBe('PROVIDER_NOT_AVAILABLE');
    await page.goto('/integrations/connect/slack');
    await expect(page.getByText('Slack is coming soon')).toBeVisible();
    await page.goto('/integrations/catalog');
  });

  test('an application published in the CMS appears on the open page, and leaves when archived', async ({ playwright }) => {
    await expect(page.getByTestId('catalog-github')).toBeVisible();
    await expect(page.getByTestId('catalog-kanban')).toHaveCount(0);

    const editor = await cms(playwright, 'editor@cms.test');
    await editor.post('/api/v1/application/save', { data: { key: 'kanban', name: 'Kanban Board' } });
    expect((await (await editor.post('/api/v1/version/save', { data: { key: 'kanban', version: 1, definition: kanban } })).json()).details.issues).toEqual([]);
    await editor.post('/api/v1/version/submit', { data: { key: 'kanban', version: 1 } });
    const publisher = await cms(playwright, 'publisher@cms.test');
    expect((await (await publisher.post('/api/v1/version/approve', { data: { key: 'kanban', version: 1, acknowledgeHostChange: true } })).json()).details.status).toBe('PUBLISHED');

    // No reload: the page refreshes itself.
    const tile = page.getByTestId('catalog-kanban');
    await expect(tile).toBeVisible({ timeout: 30_000 });
    await expect(tile).toContainText('Project management');
    await expect(tile).toContainText('CMS v1');
    await expect(tile.getByRole('button', { name: 'Connect', exact: true })).toBeEnabled();
    await expect(page.getByRole('group', { name: 'Categories' }).getByRole('button', { name: /^Project management/ })).toBeVisible();

    const admin = await cms(playwright, 'admin@cms.test');
    expect((await admin.post('/api/v1/application/archive', { data: { key: 'kanban', reason: 'Replaced' } })).ok()).toBe(true);
    await expect(tile).toHaveCount(0, { timeout: 30_000 });
    await Promise.all([editor.dispose(), publisher.dispose(), admin.dispose()]);
  });
});
