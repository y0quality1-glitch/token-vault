import { expect, test, type APIRequestContext } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import { DEMO_PASSWORD, details } from './helpers';

/**
 * The Kubernetes example (examples/kubernetes): a Node service that gets its configuration as
 * environment variables at boot and calls Slack only through Token Vault. Run here as a plain
 * process with that environment (or as the built image: ORDERS_API_IMAGE=orders-api:dev).
 */
const API = 'http://localhost:4000';
const CMS_API = 'http://localhost:4200';
const ROOT = resolve(import.meta.dirname, '../..');
const PORT = 8099;
const APP = `http://localhost:${PORT}`;
// Matches the Slack definition's secret format (xoxb-…), assembled so it is plainly not a real token.
const BOT_TOKEN = ['xoxb', 'example', 'not', 'a', 'real', 'token'].join('-');

function start(env: Record<string, string>): { proc: ChildProcess; output: () => string } {
  let out = '';
  const image = process.env.ORDERS_API_IMAGE;
  const proc = image
    ? spawn('docker', ['run', '--rm', '--network', 'host', ...Object.entries(env).flatMap(([k, v]) => ['-e', `${k}=${v}`]), image], { stdio: ['ignore', 'pipe', 'pipe'] })
    : spawn(resolve(ROOT, 'node_modules/.bin/tsx'), [resolve(ROOT, 'examples/kubernetes/orders-api/src/server.ts')], { env: { PATH: process.env.PATH ?? '', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  proc.stdout!.on('data', (d) => (out += String(d)));
  proc.stderr!.on('data', (d) => (out += String(d)));
  return { proc, output: () => out };
}
const exited = (p: ChildProcess) => new Promise<number | null>((r) => (p.exitCode !== null ? r(p.exitCode) : p.once('exit', (code) => r(code))));

test.describe.serial('Kubernetes example: orders-api', () => {
  let admin: APIRequestContext;
  let app: ReturnType<typeof start> | null = null;
  let env: Record<string, string> = {};
  let grantId = '';

  test.beforeAll(async ({ playwright }) => {
    admin = await playwright.request.newContext({ baseURL: API });
    expect((await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    await admin.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } });

    // Slack must be available in the catalog: publish its open version, or switch it on.
    const cms = await playwright.request.newContext({ baseURL: CMS_API });
    await cms.post('/api/v1/auth/login', { data: { email: 'admin@cms.test', password: DEMO_PASSWORD } });
    const slack = await (await cms.get('/api/v1/applications/slack')).json();
    if (slack.openVersion) {
      const v = await (await cms.get(`/api/v1/applications/slack/versions/${slack.openVersion.version}`)).json();
      await cms.put(`/api/v1/applications/slack/versions/${v.version}`, { data: { definition: { ...v.definition, catalog: { ...v.definition.catalog, availability: 'available' } } } });
      expect((await cms.post(`/api/v1/applications/slack/versions/${v.version}/publish`, { data: { acknowledgeHostChange: true } })).ok()).toBe(true);
    } else if (slack.availability !== 'available') {
      expect((await cms.post('/api/v1/applications/slack/availability', { data: { availability: 'available' } })).ok()).toBe(true);
    }
    await cms.dispose();
    await expect.poll(async () => ((await details(await admin.post('/api/v1/provider/getall'))).providers as { key: string; catalog: { availability: string } }[]).find((p) => p.key === 'slack')?.catalog.availability, { timeout: 20_000 }).toBe('available');
  });
  test.afterAll(async () => {
    if (app && app.proc.exitCode === null) {
      app.proc.kill('SIGTERM');
      await exited(app.proc);
    }
    await admin?.dispose();
  });

  test('boots from its environment, like a pod with envFrom, and reports ready', async () => {
    let integration = await admin.post('/api/v1/integration/save', { data: { provider: 'slack', authType: 'BOT_TOKEN', displayName: 'Orders Slack', webhookId: 'wh_local0000000001', secret: BOT_TOKEN, allowedResources: ['C0123456789'], environment: 'development' } });
    // The webhook may need a moment to see the newly available version.
    for (let i = 0; i < 10 && integration.status() !== 201; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      integration = await admin.post('/api/v1/integration/save', { data: { provider: 'slack', authType: 'BOT_TOKEN', displayName: 'Orders Slack', webhookId: 'wh_local0000000001', secret: BOT_TOKEN, allowedResources: ['C0123456789'], environment: 'development' } });
    }
    expect(integration.status(), await integration.text()).toBe(201);
    const integrationId = (await details(integration)).id;
    const agent = await details(await admin.post('/api/v1/agent/save', { data: { name: 'orders-api (k8s)', environment: 'development', ownerTeam: 'Commerce', agentType: 'SERVICE' } }));
    const now = Date.now();
    const grant = await admin.post('/api/v1/grant/save', { data: { name: 'Order notifications', agentId: agent.agent.id, integrationId, environment: 'development', scopes: ['slack.messages.post'], repositories: ['C0123456789'], validFrom: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 86_400_000).toISOString(), rateLimitPerMinute: 30 } });
    expect(grant.ok(), await grant.text()).toBe(true);
    grantId = (await details(grant)).id;

    // Exactly what the ExternalSecret (or the local secretGenerator) puts into the pod.
    env = { PORT: String(PORT), TOKEN_VAULT_URL: API, TOKEN_VAULT_API_KEY: agent.credential.apiKey, DATABASE_URL: 'postgres://orders:orders@db.example:5432/orders', SLACK_INTEGRATION_ID: integrationId, SLACK_CHANNEL: 'C0123456789' };
    app = start(env);
    await expect.poll(async () => (await fetch(`${APP}/healthz`).catch(() => null))?.status ?? 0, { timeout: 60_000 }).toBe(200);
    const ready = await (await fetch(`${APP}/readyz`)).json();
    expect(ready).toEqual({ ready: true, detail: 'Token Vault reachable; Slack grant active' });
  });

  test('posts to Slack through Token Vault, with no Slack token in the pod', async () => {
    const r = await fetch(`${APP}/orders/A100/paid`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ amount: 'EUR 42.00' }) });
    const body = await r.json();
    expect(r.status, JSON.stringify(body)).toBe(200);
    expect(body).toMatchObject({ notified: true, simulated: true, slack: { ok: true } });
    expect(body.tokenVaultRequestId).toMatch(/^req_/);
    expect(Object.values(env).join(' ')).not.toContain(BOT_TOKEN);
    expect(JSON.stringify(body)).not.toContain(BOT_TOKEN);
    expect(app!.output()).not.toContain(env.TOKEN_VAULT_API_KEY);
    expect(app!.output()).toContain('[orders-api] listening on :8099');
  });

  test('a revoked grant stops it on the next request, without crashing the service', async () => {
    expect((await admin.post('/api/v1/grant/revoke', { data: { id: grantId, reason: 'e2e: example revoked' } })).ok()).toBe(true);
    const r = await fetch(`${APP}/orders/A101/paid`, { method: 'POST', body: '{}' });
    expect(r.status).toBe(202);
    expect(await r.json()).toMatchObject({ notified: false, reason: 'GRANT_REVOKED' });
    expect((await fetch(`${APP}/healthz`)).status).toBe(200);
  });

  test('stops cleanly on SIGTERM, and refuses to boot without its configuration', async () => {
    app!.proc.kill('SIGTERM');
    expect(await exited(app!.proc)).toBe(0);
    if (!process.env.ORDERS_API_IMAGE) expect(app!.output()).toContain('SIGTERM: draining');

    const { DATABASE_URL: _missing, ...partial } = env;
    const broken = start({ ...partial, SLACK_BOT_TOKEN: BOT_TOKEN });
    expect(await exited(broken.proc)).toBe(1);
    expect(broken.output()).toContain('missing required environment variable DATABASE_URL');
    expect(broken.output()).not.toContain(BOT_TOKEN);
  });
});
