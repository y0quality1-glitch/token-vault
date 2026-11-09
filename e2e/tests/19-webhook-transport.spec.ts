import { expect, test } from '@playwright/test';
import { login, trackPageErrors } from './helpers';

/**
 * Changing a webhook's URL or authentication from its page. The e2e stack runs without TLS
 * certificates, so mutual TLS is offered but disabled, with the reason; the TLS paths themselves
 * are covered by the server and webhook tests and by the compose mTLS run in CI.
 */
test('the webhook page changes the URL with a signed check, and explains when mTLS is unavailable', async ({ page }) => {
  const errors = trackPageErrors(page);
  await login(page, 'owner@demo.test');
  await page.getByRole('button', { name: /Demo Organization/ }).click();
  await page.goto('/webhook/setup');
  await page.getByRole('button', { name: 'Change URL or authentication' }).first().click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('Mutual TLS needs a control-plane client certificate')).toBeVisible();
  await expect(dialog.locator('option[value="MTLS"]')).toBeDisabled();

  // Same webhook at another address that reaches it: saved and verified.
  await dialog.getByLabel('Endpoint URL').fill('http://127.0.0.1:4100');
  await dialog.getByRole('button', { name: 'Save and verify' }).click();
  await expect(page.getByText('Saved and verified')).toBeVisible();
  await expect(page.getByText('Transport: plain HTTP (no TLS)').first()).toBeVisible();

  // Back to the original address.
  await page.getByRole('button', { name: 'Change URL or authentication' }).first().click();
  await page.getByRole('dialog').getByLabel('Endpoint URL').fill('http://localhost:4100');
  await page.getByRole('dialog').getByRole('button', { name: 'Save and verify' }).click();
  await expect(page.getByText('Saved and verified').last()).toBeVisible();
  expect(errors).toEqual([]);
});
