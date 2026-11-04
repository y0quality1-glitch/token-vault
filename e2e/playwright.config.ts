import { defineConfig, devices } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Starts the full stack (control plane, customer webhook, client) with secrets passed
 * as runtime environment variables only, then drives the admin console in Chromium.
 *
 * Secrets are generated per run unless provided. They are written back to process.env so
 * that every Playwright process (main + workers) sees the same values.
 */
process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
process.env.VAULT_ENCRYPTION_KEY ??= randomBytes(32).toString('base64');
// Dedicated database, wiped and reseeded when the control plane starts (SEED_MODE=reset).
const databaseUrl = process.env.E2E_DATABASE_URL ?? 'postgres://token_vault:token_vault@localhost:5432/token_vault_e2e';
// Customer-zone database for the webhook (separate role), also wiped on start.
const webhookDatabaseUrl = process.env.E2E_WEBHOOK_DATABASE_URL ?? 'postgres://token_vault_customer:token_vault_customer@localhost:5432/token_vault_customer_e2e';

const root = resolve(import.meta.dirname, '..');
export const LOG_DIR = resolve(import.meta.dirname, '.logs');
mkdirSync(LOG_DIR, { recursive: true });

const isCI = !!process.env.CI;

export default defineConfig({
  testDir: './tests',
  // The tests share one stateful backend (in-memory store), so run them in order.
  fullyParallel: false,
  workers: 1,
  forbidOnly: isCI,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: isCI ? [['list'], ['html', { open: 'never' }], ['github']] : [['list'], ['html', { open: 'never' }]],
  globalTeardown: './global-teardown.ts',
  use: {
    baseURL: 'http://localhost:5173',
    viewport: { width: 1440, height: 1000 },
    actionTimeout: 10_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 1000 } } }],
  webServer: [
    {
      name: 'webhook',
      command: `npm run start -w webhook 2>&1 | tee "${LOG_DIR}/webhook.log"`,
      cwd: root,
      port: 4100,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        PORT: '4100',
        WEBHOOK_SIGNING_SECRET: process.env.WEBHOOK_SIGNING_SECRET,
        VAULT_ENCRYPTION_KEY: process.env.VAULT_ENCRYPTION_KEY,
        WEBHOOK_INSTANCE_ID: 'whi_local_customer_vault',
        WEBHOOK_DATABASE_URL: webhookDatabaseUrl,
        SEED_MODE: 'reset',
        // Points the one-time legacy JSON import at a path that never exists.
        WEBHOOK_DATA_FILE: resolve(LOG_DIR, 'no-legacy-store.json'),
        GITHUB_MODE: 'mock',
      },
    },
    {
      name: 'control-plane',
      command: `npm run start -w server 2>&1 | tee "${LOG_DIR}/server.log"`,
      cwd: root,
      url: 'http://localhost:4000/healthz',
      reuseExistingServer: false,
      timeout: 60_000,
      // The control plane deliberately does NOT receive VAULT_ENCRYPTION_KEY.
      env: {
        PORT: '4000',
        WEBHOOK_SIGNING_SECRET: process.env.WEBHOOK_SIGNING_SECRET,
        DEFAULT_WEBHOOK_URL: 'http://localhost:4100',
        DATABASE_URL: databaseUrl,
        SEED_MODE: 'reset',
        HEARTBEAT_INTERVAL_MS: '30000',
        VAULT_ENCRYPTION_KEY: '',
      },
    },
    {
      name: 'client',
      command: 'npm run dev -w client -- --port 5173 --strictPort',
      cwd: root,
      url: 'http://localhost:5173',
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
