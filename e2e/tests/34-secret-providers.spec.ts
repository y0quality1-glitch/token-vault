import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import pg from 'pg';
import { expect, test, type APIRequestContext } from '@playwright/test';
import { DEMO_PASSWORD, details, login as signIn, trackPageErrors } from './helpers';

/**
 * Secret Management phase 5 through the real stack and a real PostgreSQL server: an application
 * leases a short-lived database login (created by the customer webhook, dropped when the lease
 * ends); the webhook rotates a static login's password at the database; an organization-defined
 * type; import of JSON and .env files; and an export that someone else approves, encrypted with
 * a passphrase and opened with scripts/decrypt-export.mjs.
 */
const API = 'http://localhost:4000';
const pgPort = Number(process.env.E2E_PG_PORT ?? process.env.POSTGRES_PORT ?? 5432);
const DB = 'token_vault_e2e';
const admin = { host: '127.0.0.1', port: pgPort, database: DB, user: 'token_vault', password: 'token_vault' };

async function member(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }, email: string) {
  const ctx = await playwright.request.newContext({ baseURL: API });
  expect((await ctx.post('/api/v1/auth/login', { data: { email, password: DEMO_PASSWORD } })).ok()).toBe(true);
  expect((await ctx.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } })).ok()).toBe(true);
  return ctx;
}

async function login(user: string, password: string): Promise<string> {
  const c = new pg.Client({ ...admin, user, password, connectionTimeoutMillis: 3000 });
  c.on('error', () => undefined);
  try {
    await c.connect();
    return (await c.query<{ who: string }>('SELECT current_user AS who')).rows[0]!.who;
  } finally {
    await c.end().catch(() => undefined);
  }
}

async function adminQuery(sql: string, params: unknown[] = []) {
  const c = new pg.Client(admin);
  await c.connect();
  try {
    return (await c.query(sql, params)).rows;
  } finally {
    await c.end();
  }
}

test.describe.serial('secret providers: leases, provider rotation, custom types, import and export', () => {
  let owner: APIRequestContext;
  let security: APIRequestContext;
  let app: APIRequestContext;
  let agentId = '';
  let dynamicId = '';

  test.beforeAll(async ({ playwright }) => {
    [owner, security] = await Promise.all([member(playwright, 'owner@demo.test'), member(playwright, 'security@demo.test')]);
    const agent = await details(await owner.post('/api/v1/agent/save', { data: { name: 'Reporting Job', environment: 'production', ownerTeam: 'Data', agentType: 'SERVICE' } }));
    agentId = agent.agent.id;
    app = await playwright.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${agent.credential.apiKey}` } });
    await adminQuery('DROP OWNED BY tv_e2e_rotation').catch(() => undefined);
    await adminQuery('DROP ROLE IF EXISTS tv_e2e_rotation');
    await adminQuery(`CREATE ROLE tv_e2e_rotation LOGIN PASSWORD 'e2e-first-password'`);
    await adminQuery(`GRANT CONNECT ON DATABASE ${DB} TO tv_e2e_rotation`);
  });
  test.afterAll(async () => {
    await adminQuery('DROP OWNED BY tv_e2e_rotation').catch(() => undefined);
    await adminQuery('DROP ROLE IF EXISTS tv_e2e_rotation').catch(() => undefined);
    await Promise.all([owner?.dispose(), security?.dispose(), app?.dispose()]);
  });

  test('an application leases a short-lived PostgreSQL login; ending the lease drops it', async () => {
    const created = await owner.post('/api/v1/secret/save', {
      data: {
        name: 'reporting-db',
        typeKey: 'postgresql-dynamic',
        project: 'data',
        environment: 'production',
        metadata: { defaultTtlMinutes: 15, maxTtlMinutes: 60 },
        payload: { host: '127.0.0.1', port: pgPort, database: DB, username: admin.user, password: admin.password, creationStatements: `GRANT CONNECT ON DATABASE ${DB} TO {{name}};\nGRANT USAGE ON SCHEMA public TO {{name}}` },
      },
    });
    expect(created.status(), await created.text()).toBe(201);
    dynamicId = (await details(created)).id;
    expect((await details(await owner.post('/api/v1/secret/checkProvider', { data: { id: dynamicId } })))).toMatchObject({ ok: true, detail: `connected as ${admin.user}` });

    expect((await (await app.post('/agent/v1/secret/lease', { data: { secret_id: dynamicId } })).json()).code).toBe('SECRET_ACCESS_DENIED');
    expect((await owner.post('/api/v1/secretAccess/save', { data: { agentId, secretId: dynamicId, description: 'Nightly report' } })).status()).toBe(201);
    // The stored administrative login is never handed to the application.
    expect((await (await app.post('/agent/v1/secret/retrieve', { data: { secret_id: dynamicId } })).json()).code).toBe('SECRET_IS_DYNAMIC');

    const r = await app.post('/agent/v1/secret/lease', { data: { name: 'reporting-db', ttl_seconds: 600, reason: 'nightly report' } });
    expect(r.status(), await r.text()).toBe(201);
    const lease = await details(r);
    expect(lease.credentials).toMatchObject({ username: `tv_${lease.lease_id}`, host: '127.0.0.1', database: DB });
    expect(await login(lease.credentials.username, lease.credentials.password)).toBe(lease.credentials.username);
    expect(JSON.stringify(await details(await owner.post('/api/v1/secretLease/getall', { data: { secretId: dynamicId } })))).not.toContain(lease.credentials.password);

    const renewed = await details(await app.post('/agent/v1/secret/lease/renew', { data: { lease_id: lease.lease_id, ttl_seconds: 1800 } }));
    expect(renewed).toMatchObject({ status: 'ACTIVE', renew_count: 1 });
    const [role] = await adminQuery('SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1', [lease.credentials.username]);
    expect(Math.abs(new Date(role.rolvaliduntil).getTime() - Date.parse(renewed.expires_at))).toBeLessThan(1000);

    expect(await details(await app.post('/agent/v1/secret/lease/revoke', { data: { lease_id: lease.lease_id } }))).toMatchObject({ status: 'REVOKED' });
    expect(await adminQuery('SELECT 1 FROM pg_roles WHERE rolname = $1', [lease.credentials.username])).toEqual([]);
    await expect(login(lease.credentials.username, lease.credentials.password)).rejects.toThrow();
  });

  test('the lifecycle job ends an expired lease at the database', async () => {
    const r = await details(await app.post('/agent/v1/secret/lease', { data: { secret_id: dynamicId, ttl_seconds: 60 } }));
    expect(await login(r.credentials.username, r.credentials.password)).toBe(r.credentials.username);
    // A member with secret:retrieve can also take a lease (audited the same way).
    const mine = await owner.post('/api/v1/secretLease/issue', { data: { secretId: dynamicId, ttlSeconds: 60, reason: 'debugging' } });
    expect(mine.status()).toBe(201);
    // Make both leases due: the role keeps VALID UNTIL, the job drops it.
    await adminQuery(`UPDATE secret_leases SET expires_at = now() - interval '1 second' WHERE secret_id = $1 AND status = 'ACTIVE'`, [dynamicId]);
    await expect.poll(async () => (await details(await owner.post('/api/v1/secretLease/getall', { data: { secretId: dynamicId, status: 'ACTIVE' } }))).items.length, { timeout: 20_000 }).toBe(0);
    const usernames = (await details(await owner.post('/api/v1/secretLease/getall', { data: { secretId: dynamicId } }))).items.map((l: { username: string }) => l.username);
    expect(usernames.length).toBeGreaterThanOrEqual(3);
    expect(await adminQuery('SELECT rolname FROM pg_roles WHERE rolname = ANY($1)', [usernames])).toEqual([]);
    const events = (await details(await owner.post('/api/v1/auditEvent/getall', { data: { eventType: 'secret.lease', targetId: dynamicId } }))).items.map((e: { eventType: string }) => e.eventType);
    expect(events).toEqual(expect.arrayContaining(['secret.lease_created', 'secret.lease_renewed', 'secret.lease_revoked', 'secret.lease_expired']));
  });

  test('provider rotation: the webhook changes a login’s password at the database and stores the new one', async () => {
    const created = await owner.post('/api/v1/secret/save', { data: { name: 'e2e-rotating-login', typeKey: 'postgresql', project: 'data', environment: 'staging', metadata: { host: '127.0.0.1', port: pgPort, database: DB }, payload: { username: 'tv_e2e_rotation', password: 'e2e-first-password' }, rotationStrategy: 'provider' } });
    expect(created.status(), await created.text()).toBe(201);
    const id = (await details(created)).id;
    const rotated = await details(await owner.post('/api/v1/secret/rotate', { data: { id, reason: 'e2e' } }));
    expect(rotated).toMatchObject({ activeVersion: 2, rotationJobs: [{ strategy: 'provider', status: 'SUCCEEDED' }] });
    const password = (await details(await owner.post('/api/v1/secret/retrieve', { data: { id } }))).payload.password;
    expect(password).not.toBe('e2e-first-password');
    expect(await login('tv_e2e_rotation', password)).toBe('tv_e2e_rotation');
    await expect(login('tv_e2e_rotation', 'e2e-first-password')).rejects.toThrow();
  });

  test('an organization-defined type: validated by the same rules; its secrets work like any other', async () => {
    const bad = await owner.post('/api/v1/secretType/saveCustom', { data: { key: 'custom-kiosk', name: 'Kiosk', fields: { note: { label: 'Note', sensitive: false } } } });
    expect(bad.status()).toBe(400);
    expect(JSON.stringify(await bad.json())).toContain('at least one field must be sensitive');
    const t = await details(await owner.post('/api/v1/secretType/saveCustom', { data: { key: 'custom-kiosk', name: 'Kiosk unlock code', fields: { kioskId: { label: 'Kiosk ID', sensitive: false, required: true }, code: { label: 'Unlock code', pattern: '^[0-9]{8}$', required: true } } } }));
    expect(t).toMatchObject({ key: 'custom-kiosk', version: 1, source: 'custom', category: 'custom' });
    const invalid = await owner.post('/api/v1/secret/save', { data: { name: 'lobby-kiosk', typeKey: 'custom-kiosk', environment: 'production', payload: { kioskId: 'K-1', code: '12' } } });
    expect(invalid.status()).toBe(400);
    const s = await details(await owner.post('/api/v1/secret/save', { data: { name: 'lobby-kiosk', typeKey: 'custom-kiosk', environment: 'production', payload: { kioskId: 'K-1', code: '12345678' } } }));
    expect(s).toMatchObject({ customType: true, summary: { kioskId: 'K-1', code: '••••••••' } });
    expect((await details(await owner.post('/api/v1/secret/retrieve', { data: { id: s.id } }))).payload.code).toBe('12345678');
  });

  test('import: a JSON list and a .env file; a name already used is skipped; an identical value is reported', async () => {
    const content = JSON.stringify([
      { name: 'partner-a-key', typeKey: 'api-key', project: 'imports', environment: 'production', payload: { apiKey: 'e2e-imported-api-key-001' } },
      { name: 'partner-a-key-copy', typeKey: 'api-key', project: 'imports', environment: 'staging', payload: { apiKey: 'e2e-imported-api-key-001' } },
      { name: 'not-valid', typeKey: 'postgresql', environment: 'production', payload: { username: 'x' } },
    ]);
    const dry = await details(await owner.post('/api/v1/secret/import', { data: { format: 'json', content, dryRun: true } }));
    expect(dry.counts).toMatchObject({ valid: 2, invalid: 1, created: 0 });
    const done = await details(await owner.post('/api/v1/secret/import', { data: { format: 'json', content } }));
    expect(done.counts).toMatchObject({ created: 2, invalid: 1 });
    expect(done.results[1].sameValueAs).toEqual([{ id: done.results[0].secretId, name: 'partner-a-key' }]);
    expect((await details(await owner.post('/api/v1/secret/import', { data: { format: 'json', content } }))).counts).toMatchObject({ skipped: 2, invalid: 1 });

    const env = await details(await owner.post('/api/v1/secret/import', { data: { format: 'env', name: 'imports-env', project: 'imports', environment: 'development', content: 'API_URL=https://api.example\nexport TOKEN="e2e-env-token"\n' } }));
    expect(env.results[0]).toMatchObject({ outcome: 'created' });
    expect((await details(await owner.post('/api/v1/secret/retrieve', { data: { id: env.results[0].secretId } }))).payload.variables).toEqual({ API_URL: 'https://api.example', TOKEN: 'e2e-env-token' });
  });

  test('export: requested by an owner, approved by a security admin, encrypted with a passphrase, downloaded once', async () => {
    const id = (await details(await owner.post('/api/v1/secret/getall', { data: { search: 'partner-a-key' } }))).items.find((x: { name: string }) => x.name === 'partner-a-key').id;
    const req = await details(await owner.post('/api/v1/secretExport/request', { data: { secretIds: [id], reason: 'Moving partner keys to the new region' } }));
    expect((await owner.post('/api/v1/secretExport/approve', { data: { id: req.id } })).status()).toBe(403);
    expect(await details(await security.post('/api/v1/secretExport/approve', { data: { id: req.id, note: 'approved for the move' } }))).toMatchObject({ status: 'APPROVED' });
    const { downloadUrl } = await details(await owner.post('/api/v1/secretExport/prepare', { data: { id: req.id, passphrase: 'e2e export passphrase 42' } }));
    const file = await details(await owner.get(downloadUrl));
    expect(file).toMatchObject({ format: 'token-vault-secret-export/v1', exportId: req.id });
    expect(JSON.stringify(file)).not.toContain('e2e-imported-api-key-001');
    expect((await owner.get(downloadUrl)).status()).toBe(404); // the link is erased once used

    const dir = mkdtempSync(join(tmpdir(), 'tv-export-'));
    writeFileSync(join(dir, 'export.json'), JSON.stringify(file));
    const out = execFileSync(process.execPath, [resolve(import.meta.dirname, '../../scripts/decrypt-export.mjs'), join(dir, 'export.json')], { env: { ...process.env, TV_EXPORT_PASSPHRASE: 'e2e export passphrase 42' } }).toString();
    expect(JSON.parse(out).secrets).toEqual([expect.objectContaining({ name: 'partner-a-key', typeKey: 'api-key', payload: { apiKey: 'e2e-imported-api-key-001' } })]);
    expect(() => execFileSync(process.execPath, [resolve(import.meta.dirname, '../../scripts/decrypt-export.mjs'), join(dir, 'export.json')], { env: { ...process.env, TV_EXPORT_PASSPHRASE: 'wrong passphrase!!' }, stdio: 'pipe' })).toThrow();
  });

  test('in the console: check the provider, take a lease, see its login once, end it; leases, import, exports and types pages', async ({ page }) => {
    const errors = trackPageErrors(page);
    await signIn(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await expect(page).not.toHaveURL(/select-org/);

    await page.goto(`/secrets/${dynamicId}`);
    await page.getByTestId('secret-provider-check').click();
    await expect(page.getByTestId('secret-provider-status')).toHaveAttribute('data-status', 'OK');
    await expect(page.getByTestId('secret-dynamic-note')).toBeVisible();

    await page.getByTestId('secret-lease-issue').click();
    await page.getByTestId('secret-lease-reason').fill('checking a report by hand');
    await page.getByTestId('secret-lease-issue-confirm').click();
    const shown = page.getByTestId('secret-lease-credentials');
    await expect(shown).toBeVisible();
    const leaseId = (await shown.getAttribute('data-lease-id'))!;
    const username = (await page.getByTestId('secret-lease-credential-username').locator('code').textContent())!.trim();
    const password = (await page.getByTestId('secret-lease-credential-password').locator('code').textContent())!.trim();
    expect(username).toBe(`tv_${leaseId}`);
    expect(await login(username, password)).toBe(username);
    await page.getByTestId('secret-lease-credentials-done').click();
    await expect(page.getByText(password)).toHaveCount(0);

    const row = page.locator(`[data-testid="secret-lease-row"][data-lease-id="${leaseId}"]`);
    await expect(row).toHaveAttribute('data-status', 'ACTIVE');
    await page.locator('tr', { has: row }).getByTestId('secret-lease-revoke').click();
    await page.getByTestId('secret-lease-revoke-confirm').click();
    await expect(row).toHaveAttribute('data-status', 'REVOKED');
    expect(await adminQuery('SELECT 1 FROM pg_roles WHERE rolname = $1', [username])).toEqual([]);

    await page.goto('/secrets/leases');
    await expect(page.locator(`[data-testid="lease-row"][data-lease-id="${leaseId}"]`)).toHaveAttribute('data-status', 'REVOKED');

    await page.goto('/secrets/import');
    await page.getByTestId('secret-import-format-json').click();
    await page.getByTestId('secret-import-content').fill(JSON.stringify([{ name: 'console-import-key', typeKey: 'api-key', project: 'partners', environment: 'production', payload: { apiKey: 'console-imported-value-1' } }]));
    await page.getByTestId('secret-import-check').click();
    await expect(page.getByTestId('secret-import-report')).toHaveAttribute('data-dry-run', 'true');
    await page.getByTestId('secret-import-run').click();
    await expect(page.locator('[data-testid="secret-import-result"][data-name="console-import-key"]')).toHaveAttribute('data-outcome', 'created');

    await page.goto('/secrets/exports');
    await expect(page.locator('[data-testid="secret-export-row"]').first()).toBeVisible();
    await page.goto('/secrets/types');
    await expect(page.locator('[data-testid="secret-type-row"][data-key="postgresql-dynamic"]')).toBeVisible();
    await expect(page.locator('[data-testid="secret-type-row"][data-source="custom"]').first()).toBeVisible();
    expect(errors).toEqual([]);
  });
});
