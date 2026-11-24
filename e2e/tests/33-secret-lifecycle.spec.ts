import { createHmac } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { expect, test, type APIRequestContext } from '@playwright/test';
import { DEMO_PASSWORD, details, login, trackPageErrors } from './helpers';

/**
 * Secret Management phase 4 through the real stack: the customer webhook generates a rotated
 * value itself; the lifecycle job (every 2 s in this suite) marks secrets EXPIRING and applies a
 * retention policy on the webhook; a notification channel receives signed webhooks for those
 * events, never a value.
 */
const API = 'http://localhost:4000';

test.describe.serial('secret lifecycle: rotation, expiry, retention and notifications', () => {
  let owner: APIRequestContext;
  let receiver: Server;
  let receiverUrl = '';
  const received: { headers: Record<string, string | string[] | undefined>; body: string }[] = [];
  let channelId = '';
  let signingSecret = '';
  let keyId = '';

  const waitFor = async <T>(what: string, fn: () => Promise<T | undefined | null | false>, timeoutMs = 20_000): Promise<T> => {
    const until = Date.now() + timeoutMs;
    for (;;) {
      const r = await fn();
      if (r) return r;
      if (Date.now() > until) throw new Error(`Timed out waiting for ${what}`);
      await new Promise((ok) => setTimeout(ok, 500));
    }
  };
  const secret = async (id: string) => details(await owner.get(`/api/v1/secret/getbyid/${id}`));
  const value = async (id: string, version?: number) => (await details(await owner.post('/api/v1/secret/retrieve', { data: { id, ...(version ? { version } : {}), reason: 'e2e check' } }))).payload;
  const notification = (event: string, secretId: string) => waitFor(`${event} notification`, async () => received.find((r) => r.headers['token-vault-event'] === event && JSON.parse(r.body).secret?.id === secretId));

  test.beforeAll(async ({ playwright }) => {
    owner = await playwright.request.newContext({ baseURL: API });
    expect((await owner.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    expect((await owner.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } })).ok()).toBe(true);
    receiver = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        received.push({ headers: req.headers, body });
        res.writeHead(204).end();
      });
    });
    await new Promise<void>((ok) => receiver.listen(0, '127.0.0.1', ok));
    receiverUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/token-vault/events`;
  });
  test.afterAll(async () => {
    if (channelId) await owner?.delete(`/api/v1/notificationChannel/delete/${channelId}`);
    await owner?.post('/api/v1/secretPolicy/save', { data: { scope: 'PROJECT', project: 'lifecycle' } });
    receiver?.close();
    await owner?.dispose();
  });

  test('a notification channel posts signed events for its project; its signing secret is shown once', async () => {
    const r = await owner.post('/api/v1/notificationChannel/save', {
      data: { name: 'Lifecycle receiver', kind: 'WEBHOOK', enabled: true, url: receiverUrl, scope: { project: 'lifecycle' }, events: ['secret.rotation_succeeded', 'secret.expiring', 'secret.created'] },
    });
    expect(r.status(), await r.text()).toBe(201);
    const ch = await details(r);
    channelId = ch.id;
    signingSecret = ch.signingSecret;
    expect(signingSecret).toMatch(/^whsec_/);
    const listed = (await details(await owner.post('/api/v1/notificationChannel/getall'))).items.find((c: { id: string }) => c.id === channelId);
    expect(listed).toMatchObject({ kind: 'WEBHOOK', url: receiverUrl, signingSecretHint: expect.stringMatching(/^whsec_…/) });
    expect(JSON.stringify(listed)).not.toContain(signingSecret);
    const test1 = await details(await owner.post('/api/v1/notificationChannel/test', { data: { id: channelId } }));
    expect(test1).toMatchObject({ event: 'notification.test', status: 'DELIVERED' });
  });

  test('generated rotation: the customer webhook creates the new value; the event is notified, signed, without the value', async () => {
    const created = await owner.post('/api/v1/secret/save', { data: { name: 'partner-api', typeKey: 'api-key', project: 'lifecycle', environment: 'production', payload: { apiKey: 'partner-key-version-one-0123456789' }, rotationStrategy: 'generated', rotationIntervalDays: 30 } });
    expect(created.status(), await created.text()).toBe(201);
    keyId = (await details(created)).id;
    expect((await secret(keyId)).rotation).toMatchObject({ strategy: 'generated', generatable: true });

    const rotated = await details(await owner.post('/api/v1/secret/rotate', { data: { id: keyId, reason: 'e2e rotation' } }));
    expect(rotated).toMatchObject({ activeVersion: 2, rotationJobs: [{ trigger: 'MANUAL', strategy: 'generated', status: 'SUCCEEDED', fromVersion: 1, toVersion: 2 }] });
    const v2 = (await value(keyId)).apiKey as string;
    expect(v2).not.toBe('partner-key-version-one-0123456789');
    expect(v2).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect((await details(await owner.post('/api/v1/secret/getRotations', { data: { secretId: keyId } }))).items[0]).toMatchObject({ status: 'SUCCEEDED', secret: { name: 'partner-api' } });

    const n = await notification('secret.rotation_succeeded', keyId);
    const [, t, v1] = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(String(n.headers['token-vault-signature']))!;
    expect(v1).toBe(createHmac('sha256', signingSecret).update(`${t}.${n.body}`).digest('hex'));
    expect(JSON.parse(n.body)).toMatchObject({ event: 'secret.rotation_succeeded', secret: { name: 'partner-api', activeVersion: 2 }, details: { version: 2, trigger: 'MANUAL' } });
    expect(n.body).not.toContain(v2);
    expect(n.body).not.toContain('partner-key-version-one');
  });

  test('the lifecycle job marks a secret EXPIRING inside its warning window and notifies', async () => {
    const id = (await details(await owner.post('/api/v1/secret/save', { data: { name: 'short-lived-hmac', typeKey: 'hmac-secret', project: 'lifecycle', environment: 'staging', payload: { secret: 'h'.repeat(40) }, expiresAt: new Date(Date.now() + 2 * 86_400_000).toISOString(), rotationEnabled: false } }))).id;
    await waitFor('EXPIRING', async () => (await secret(id)).status === 'EXPIRING');
    expect(JSON.parse((await notification('secret.expiring', id)).body).details).toMatchObject({ daysLeft: 2, actorType: 'SYSTEM' });
    // Still retrievable while expiring.
    expect((await value(id)).secret).toBe('h'.repeat(40));
  });

  test('a retention policy destroys old versions on the customer webhook', async () => {
    const id = (await details(await owner.post('/api/v1/secret/save', { data: { name: 'retained-token', typeKey: 'bearer-token', project: 'lifecycle', environment: 'development', payload: { token: 'token-version-1' }, rotationEnabled: false, rotationGraceHours: 0 } }))).id;
    for (const v of [2, 3]) await details(await owner.post('/api/v1/secret/updateValue', { data: { id, payload: { token: `token-version-${v}` } } }));
    const policy = await details(await owner.post('/api/v1/secretPolicy/save', { data: { scope: 'PROJECT', project: 'lifecycle', keepVersions: 1, keepDays: null, expiryWarningDays: null, defaultExpiresInDays: null } }));
    expect(policy).toMatchObject({ scope: 'PROJECT', project: 'lifecycle', keepVersions: 1 });
    expect((await secret(id)).policy.keepVersions).toEqual({ value: 1, source: 'PROJECT' });

    const versions = await waitFor('version 1 destroyed', async () => {
      const d = await secret(id);
      return d.versions.find((v: { version: number; state: string }) => v.version === 1)?.state === 'DESTROYED' && d.versions;
    });
    expect(versions.map((v: { version: number; state: string }) => `${v.version}:${v.state}`)).toEqual(['3:ACTIVE', '2:PREVIOUS', '1:DESTROYED']);
    // Gone on the webhook too: reading it is refused.
    expect((await owner.post('/api/v1/secret/retrieve', { data: { id, version: 1 } })).status()).toBe(410);
    expect((await value(id, 2)).token).toBe('token-version-2');
  });

  test('in the console: rotate with a generated value, see the history, the policy and the notification channel', async ({ page }) => {
    const errors = trackPageErrors(page);
    await login(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await expect(page).not.toHaveURL(/select-org/);

    await page.goto(`/secrets/${keyId}`);
    await expect(page.getByTestId('secret-rotation-card')).toHaveAttribute('data-strategy', 'generated');
    await page.getByTestId('secret-rotate-now').click();
    await page.getByTestId('secret-rotate-generate').click();
    await page.getByTestId('secret-rotate-confirm').click();
    await expect(page.locator('[data-testid="secret-rotation-job-row"][data-status="SUCCEEDED"]')).toHaveCount(2);
    expect((await secret(keyId)).activeVersion).toBe(3);
    await expect(page.getByTestId('secret-policy-info-keepVersions')).toHaveAttribute('data-source', 'PROJECT');

    await page.goto('/secrets/rotations');
    await expect(page.locator(`[data-testid="rotation-row"][data-secret-id="${keyId}"]`)).toHaveCount(2);
    await page.goto('/secrets/policies');
    await expect(page.locator('[data-testid="secret-policy-row"][data-scope="PROJECT"]')).toBeVisible();
    await page.goto('/settings/notifications');
    const row = page.locator(`[data-testid="notification-channel-row"][data-channel-id="${channelId}"]`);
    await expect(row).toHaveAttribute('data-kind', 'WEBHOOK');
    await expect(page.locator(`[data-testid="notification-delivery-row"][data-channel-id="${channelId}"]`).first()).toBeVisible();
    await expect(page.getByText(signingSecret)).toHaveCount(0);
    expect(errors).toEqual([]);
  });
});
