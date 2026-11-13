import { expect, type APIResponse, type Page } from '@playwright/test';

/**
 * Reads the payload of a control-plane response. Every /api/v1 and /agent/v1 route answers
 * `{ status, msg, error, code?, details, totalRecords }`; `details` is the route's own body.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function details(response: APIResponse): Promise<any> {
  return (await response.json()).details;
}

export const DEMO_PASSWORD = 'TokenVault-Demo-2026';
export const MOCK_TOKEN = 'mock_ghp_E2EtestTokenValue1234567890';

export async function login(page: Page, email: string) {
  await page.goto('/login');
  await page.getByLabel('Email').first().fill(email);
  await page.getByLabel('Password').fill(DEMO_PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

/**
 * Client-side navigation. The playground's agent credential lives in React memory only
 * (by design), so a full page load would discard it.
 */
export async function goClient(page: Page, path: string) {
  await page.evaluate((p) => {
    window.history.pushState({}, '', p);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }, path);
  await expect(page).toHaveURL(new RegExp(path.replace(/[?]/g, '\\?') + '$'));
}

export async function sendPreset(page: Page, preset: RegExp) {
  await page.getByRole('button', { name: preset }).click();
  await page.getByRole('button', { name: 'Send request' }).click();
}

/** Asserts no secret value is present in the DOM or in browser storage. */
export async function expectNoSecretsInBrowser(page: Page, secrets: string[]) {
  const html = await page.content();
  for (const s of secrets) expect(html, 'secret must not appear in the DOM').not.toContain(s);
  const storage = await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }));
  expect(storage).toEqual({ local: [], session: [] });
}

/** Collects uncaught page errors (React crashes etc.) for the lifetime of a page. */
export function trackPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  return errors;
}
