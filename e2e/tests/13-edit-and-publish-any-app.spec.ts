import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { DEMO_PASSWORD, details, expectNoSecretsInBrowser, login, trackPageErrors } from './helpers';

/**
 * Every application in the CMS is editable, not just GitHub: a single administrator opens
 * a seeded "coming soon" entry (Google Workspace v1), edits it (a new draft copied from v1),
 * publishes it directly and makes it available. End users then connect it in the console
 * and an agent calls it (simulated upstream response from the definition).
 */
const CMS = 'http://localhost:5174';
const API = 'http://localhost:4000';
const CLIENT_SECRET = 'google-secret-value-123';

test.describe.serial('edit and publish any application from the CMS', () => {
  let cms: Page;
  let consolePage: Page;
  let owner: APIRequestContext;
  let errors: string[] = [];

  test.beforeAll(async ({ browser, playwright }) => {
    cms = await browser.newPage();
    consolePage = await browser.newPage();
    errors = [...trackPageErrors(cms), ...trackPageErrors(consolePage)];
    owner = await playwright.request.newContext({ baseURL: API });
    await owner.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await owner.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });
  });
  test.afterAll(async () => {
    expect(errors, 'no uncaught page errors').toEqual([]);
    await Promise.all([cms?.close(), consolePage?.close(), owner?.dispose()]);
  });

  test('an administrator edits Google Workspace v1 and publishes it as available, alone', async () => {
    await cms.goto(CMS + '/');
    await cms.getByLabel('Email').fill('admin@cms.test');
    await cms.getByLabel('Password').fill(DEMO_PASSWORD);
    await cms.getByRole('button', { name: 'Sign in' }).click();
    await cms.getByRole('row', { name: /Google Workspace/ }).click();
    await cms.getByRole('row', { name: /v1/ }).click();

    // v1 is published and frozen: Edit starts v2 as a draft copied from it.
    await expect(cms.getByText('This version is frozen: Edit starts a new draft')).toBeVisible();
    await cms.getByRole('button', { name: 'Edit', exact: true }).click();
    await expect(cms.getByRole('heading', { level: 1 })).toContainText('Google Workspace v2');
    const form = cms.getByTestId('definition-form');
    await form.getByRole('textbox', { name: 'Description', exact: true }).first().fill('Calendar events for your team.');
    await form.getByLabel('Availability').selectOption('available');
    await cms.getByRole('button', { name: 'Save draft' }).click();
    await expect(cms.getByRole('button', { name: 'Save draft' })).toBeDisabled();

    // Publish directly: no second reviewer needed for an administrator.
    await cms.getByRole('button', { name: 'Publish now' }).click();
    const dialog = cms.getByRole('dialog');
    await expect(dialog).toContainText('without a second reviewer');
    await dialog.getByRole('button', { name: 'Publish now' }).click();
    await expect(cms.getByRole('heading', { level: 1 })).toContainText('Published');

    await cms.getByRole('complementary').getByRole('link', { name: 'Applications' }).click();
    await expect(cms.getByTestId('availability-google')).toContainText('v2');
    await expect(cms.getByTestId('availability-google')).toContainText('Available');
  });

  test('end users can connect it and an agent can call it', async () => {
    await login(consolePage, 'owner@demo.test');
    await consolePage.getByRole('button', { name: /Demo Organization/ }).click();
    await consolePage.goto('/integrations/catalog');
    const tile = consolePage.getByTestId('catalog-google');
    await expect(tile).toContainText('Calendar events for your team.', { timeout: 30_000 });
    await tile.getByRole('button', { name: 'Connect', exact: true }).click();

    await consolePage.locator('#displayName').fill('Team Google');
    await consolePage.locator('#clientId').fill('google-client-001');
    await consolePage.locator('#clientSecret').fill(CLIENT_SECRET);
    await consolePage.locator('#allowedResources').fill('primary');
    await consolePage.getByRole('button', { name: /Continue to accounts\.google\.com/ }).click();
    await expect(consolePage).toHaveURL(/\/integrations\/int_[0-9a-f]+$/);
    await expect(consolePage.getByRole('heading', { name: 'Team Google' })).toBeVisible();
    await expectNoSecretsInBrowser(consolePage, [CLIENT_SECRET]);

    const list = await details(await owner.post('/api/v1/integration/getall'));
    const integration = list.items.find((i: { displayName: string }) => i.displayName === 'Team Google');
    expect(integration).toMatchObject({ provider: 'google', authType: 'OAUTH', credentialStatus: 'CONNECTED' });

    const agent = await details(await owner.post('/api/v1/agent/save', { data: { name: 'Calendar Bot', environment: 'development', ownerTeam: 'Ops', agentType: 'AI_AGENT' } }));
    const now = Date.now();
    const grant = await owner.post('/api/v1/grant/save', {
      data: { name: 'Read primary calendar', agentId: agent.agent.id, integrationId: integration.id, environment: 'development', scopes: ['google.events.list'], repositories: ['primary'], validFrom: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 86_400_000).toISOString(), rateLimitPerMinute: 30 },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    const r = await owner.post('/agent/v1/request/execute', {
      headers: { authorization: `Bearer ${agent.credential.apiKey}` },
      data: { integration_id: integration.id, operation: 'google.events.list', resource: { calendar: 'primary' }, idempotency_key: `e2e-google-${now}` },
    });
    const body = await details(r);
    expect(r.status(), JSON.stringify(body)).toBe(200);
    expect(body.result).toEqual({ items: [{ id: 'evt1', summary: 'Team standup', start: { dateTime: '2026-01-05T09:00:00Z' } }] });
  });
});
