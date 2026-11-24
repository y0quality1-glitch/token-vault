import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import pg from 'pg';

/**
 * Provider engines on the customer webhook (Secret Management phase 5), against a real
 * PostgreSQL server: dynamic credentials (a role per lease, lengthened and dropped), password
 * rotation at the database (checked, and undone when needed), the host allow-list, connection
 * checks, organization-defined types, and AWS STS session credentials from a stand-in STS.
 *
 * Needs WEBHOOK_TEST_DATABASE_URL (the webhook's own store) and PROVIDER_TEST_DATABASE_URL: a
 * login allowed to create roles on the same server (the docker-compose superuser). Skipped otherwise.
 */
const url = process.env.WEBHOOK_TEST_DATABASE_URL;
const adminUrl = process.env.PROVIDER_TEST_DATABASE_URL;
const suite = url && adminUrl ? describe : describe.skip;

suite('secret provider engines (PostgreSQL, AWS STS)', () => {
  const signingSecret = randomBytes(32).toString('base64url');
  const admin = adminUrl ? new URL(adminUrl) : new URL('postgres://x@localhost/x');
  const target = { host: admin.hostname, port: Number(admin.port || 5432), database: admin.pathname.slice(1) };
  let server: Server;
  let sts: Server;
  let base = '';
  const stsCalls: string[] = [];
  let m: { client: typeof import('../src/db/client'); store: typeof import('../src/store/credential-store'); sig: typeof import('../src/security/signature') };

  async function call(path: string, body: unknown) {
    const raw = JSON.stringify(body);
    const ts = String(Date.now());
    const nonce = randomUUID();
    const res = await fetch(base + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-tv-timestamp': ts, 'x-tv-nonce': nonce, 'x-tv-signature': m.sig.hmacHex(signingSecret, m.sig.canonicalString('POST', path, ts, nonce, raw)) },
      body: raw,
    });
    return { status: res.status, body: (await res.json()) as any };
  }
  const store = async (secretId: string, typeKey: string, payload: Record<string, unknown>, extra: object = {}) => {
    const r = await call('/internal/v1/secrets/store', { org_id: 'org_p', secret_id: secretId, version: 1, type_key: typeKey, payload, ...extra });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    return r.body.value_ref as string;
  };
  const login = async (user: string, password: string) => {
    const c = new pg.Client({ ...target, user, password, connectionTimeoutMillis: 3000 });
    c.on('error', () => undefined);
    try {
      await c.connect();
      return (await c.query<{ who: string }>('SELECT current_user AS who')).rows[0]!.who;
    } finally {
      await c.end().catch(() => undefined);
    }
  };
  const adminQuery = async (sql: string, params: unknown[] = []) => {
    const c = new pg.Client({ connectionString: adminUrl });
    await c.connect();
    try {
      return (await c.query(sql, params)).rows;
    } finally {
      await c.end();
    }
  };
  const dynamic = () => ({ host: target.host, port: target.port, database: target.database, username: decodeURIComponent(admin.username), password: decodeURIComponent(admin.password), creationStatements: `GRANT CONNECT ON DATABASE ${target.database} TO {{name}};\nGRANT USAGE ON SCHEMA public TO {{name}}` });

  beforeAll(async () => {
    sts = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const action = new URLSearchParams(body).get('Action') ?? '';
        stsCalls.push(action);
        const ns = 'xmlns="https://sts.amazonaws.com/doc/2011-06-15/"';
        res.writeHead(200, { 'content-type': 'text/xml' });
        if (action === 'AssumeRole')
          res.end(`<AssumeRoleResponse ${ns}><AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLESESSION01</AccessKeyId><SecretAccessKey>sessionSecretKeyFromStandInSts0000000000</SecretAccessKey><SessionToken>stand-in-session-token</SessionToken><Expiration>${new Date(Date.now() + 3600_000).toISOString()}</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/app/tv</Arn><AssumedRoleId>AROA:tv</AssumedRoleId></AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></AssumeRoleResponse>`);
        else res.end(`<GetCallerIdentityResponse ${ns}><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/token-vault</Arn><UserId>AIDA</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>2</RequestId></ResponseMetadata></GetCallerIdentityResponse>`);
      });
    });
    await new Promise<void>((ok) => sts.listen(0, '127.0.0.1', ok));

    process.env.WEBHOOK_DATABASE_URL = url;
    process.env.VAULT_ENCRYPTION_KEY = randomBytes(32).toString('base64');
    process.env.WEBHOOK_SIGNING_SECRET = signingSecret;
    process.env.SEED_MODE = 'reset';
    process.env.CMS_CATALOG_URL = '';
    process.env.PROVIDER_ALLOWED_HOSTS = `${target.host}:${target.port}`;
    process.env.AWS_STS_ENDPOINT = `http://127.0.0.1:${(sts.address() as AddressInfo).port}`;
    m = { client: await import('../src/db/client'), store: await import('../src/store/credential-store'), sig: await import('../src/security/signature') };
    await m.client.runMigrations();
    await m.store.initStore();
    const express = (await import('express')).default;
    const { buildRouter } = await import('../src/routes');
    const app = express();
    app.use(buildRouter());
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    await adminQuery(`DROP OWNED BY tv_rotation_test`).catch(() => undefined);
    await adminQuery(`DROP ROLE IF EXISTS tv_rotation_test`);
    await adminQuery(`CREATE ROLE tv_rotation_test LOGIN PASSWORD 'first-password-for-rotation'`);
    await adminQuery(`GRANT CONNECT ON DATABASE ${target.database} TO tv_rotation_test`);
  }, 60_000);

  afterAll(async () => {
    await adminQuery(`DROP OWNED BY tv_rotation_test`).catch(() => undefined);
    await adminQuery(`DROP ROLE IF EXISTS tv_rotation_test`).catch(() => undefined);
    server?.close();
    sts?.close();
    await m?.client.closeDatabase();
  });

  it('issues a PostgreSQL role per lease, lengthens it, and drops it', async () => {
    const ref = await store('sec_pgdyn', 'postgresql-dynamic', dynamic());
    const leaseId = 'lse_' + randomBytes(8).toString('hex');
    const until = new Date(Date.now() + 15 * 60_000).toISOString();
    const l = await call('/internal/v1/secrets/lease', { org_id: 'org_p', secret_id: 'sec_pgdyn', value_ref: ref, lease_id: leaseId, expires_at: until });
    expect(l.status, JSON.stringify(l.body)).toBe(201);
    expect(l.body).toMatchObject({ username: `tv_${leaseId}`, renewable: true, credentials: { username: `tv_${leaseId}`, host: target.host, database: target.database } });
    expect(await login(l.body.username, l.body.credentials.password)).toBe(l.body.username);
    const [role] = await adminQuery('SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1', [l.body.username]);
    expect(Math.abs(new Date(role.rolvaliduntil).getTime() - Date.parse(until))).toBeLessThan(1000);

    const later = new Date(Date.now() + 60 * 60_000).toISOString();
    expect((await call('/internal/v1/secrets/lease/renew', { org_id: 'org_p', secret_id: 'sec_pgdyn', value_ref: ref, lease_id: leaseId, username: l.body.username, expires_at: later })).body).toEqual({ expires_at: later });

    expect((await call('/internal/v1/secrets/lease/revoke', { org_id: 'org_p', secret_id: 'sec_pgdyn', value_ref: ref, lease_id: leaseId, username: l.body.username })).body).toEqual({ revoked: true });
    expect(await adminQuery('SELECT 1 FROM pg_roles WHERE rolname = $1', [l.body.username])).toEqual([]);
    await expect(login(l.body.username, l.body.credentials.password)).rejects.toThrow();
    // Revoking again is harmless; only lease roles can be dropped.
    expect((await call('/internal/v1/secrets/lease/revoke', { org_id: 'org_p', secret_id: 'sec_pgdyn', value_ref: ref, lease_id: leaseId, username: l.body.username })).body).toEqual({ revoked: true });
    expect((await call('/internal/v1/secrets/lease/revoke', { org_id: 'org_p', secret_id: 'sec_pgdyn', value_ref: ref, lease_id: leaseId, username: 'postgres' })).body.error.code).toBe('LEASE_NOT_FOUND');
  });

  it('a failing grant statement creates nothing', async () => {
    const ref = await store('sec_pgbad', 'postgresql-dynamic', { ...dynamic(), creationStatements: 'GRANT SELECT ON no_such_table TO {{name}}' });
    const leaseId = 'lse_' + randomBytes(8).toString('hex');
    const l = await call('/internal/v1/secrets/lease', { org_id: 'org_p', secret_id: 'sec_pgbad', value_ref: ref, lease_id: leaseId, expires_at: new Date(Date.now() + 60_000).toISOString() });
    expect(l).toMatchObject({ status: 409, body: { error: { code: 'PROVIDER_SQL_ERROR' } } });
    expect(await adminQuery('SELECT 1 FROM pg_roles WHERE rolname = $1', [`tv_${leaseId}`])).toEqual([]);
  });

  it('rotates a login’s password at the database, checks the new one, and stores it as a new version', async () => {
    const ref = await store('sec_pgrot', 'postgresql', { username: 'tv_rotation_test', password: 'first-password-for-rotation' });
    const r = await call('/internal/v1/secrets/provider-rotate', { org_id: 'org_p', secret_id: 'sec_pgrot', from_ref: ref, version: 2, connection: target });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body).toMatchObject({ version: 2, rotated_at_provider: true, summary: { username: 'tv_rotation_test', password: '••••••••' } });
    await expect(login('tv_rotation_test', 'first-password-for-rotation')).rejects.toThrow();
    const stored = await call('/internal/v1/secrets/read', { org_id: 'org_p', secret_id: 'sec_pgrot', value_ref: r.body.value_ref });
    expect(await login('tv_rotation_test', stored.body.payload.password)).toBe('tv_rotation_test');
    // Storing fails (version taken): the password goes back to the one still stored.
    const again = await call('/internal/v1/secrets/provider-rotate', { org_id: 'org_p', secret_id: 'sec_pgrot', from_ref: r.body.value_ref, version: 2, connection: target });
    expect(again.body.error.code).toBe('SECRET_VERSION_EXISTS');
    expect(await login('tv_rotation_test', stored.body.payload.password)).toBe('tv_rotation_test');
    expect((await call('/internal/v1/secrets/provider-check', { org_id: 'org_p', secret_id: 'sec_pgrot', value_ref: r.body.value_ref, connection: target })).body).toMatchObject({ ok: true, detail: 'connected as tv_rotation_test' });
  });

  it('connects only to allowed hosts, and reports a failed check without the credential', async () => {
    const ref = await store('sec_pgelse', 'postgresql', { username: 'tv_rotation_test', password: 'whatever-password-1' });
    const r = await call('/internal/v1/secrets/provider-rotate', { org_id: 'org_p', secret_id: 'sec_pgelse', from_ref: ref, version: 2, connection: { host: 'attacker.example', port: 5432, database: 'x' } });
    expect(r).toMatchObject({ status: 409, body: { error: { code: 'PROVIDER_HOST_NOT_ALLOWED' } } });
    const check = await call('/internal/v1/secrets/provider-check', { org_id: 'org_p', secret_id: 'sec_pgelse', value_ref: ref, connection: target });
    expect(check.body).toMatchObject({ ok: false, code: 'PROVIDER_AUTH_FAILED' });
    expect(JSON.stringify(check.body)).not.toContain('whatever-password-1');
    // Types without a provider engine.
    const key = await store('sec_key', 'api-key', { apiKey: 'some-api-key-value-123' });
    expect((await call('/internal/v1/secrets/lease', { org_id: 'org_p', secret_id: 'sec_key', value_ref: key, lease_id: 'lse_abcdefgh12', expires_at: new Date(Date.now() + 60_000).toISOString() })).body.error.code).toBe('PROVIDER_NOT_SUPPORTED');
  });

  it('AWS STS: session credentials per lease; they cannot be lengthened or ended early', async () => {
    const ref = await store('sec_sts', 'aws-sts-dynamic', { accessKeyId: 'AKIAEXAMPLEKEY000001', secretAccessKey: 'x'.repeat(40), roleArn: 'arn:aws:iam::123456789012:role/app', region: 'eu-west-1' });
    const l = await call('/internal/v1/secrets/lease', { org_id: 'org_p', secret_id: 'sec_sts', value_ref: ref, lease_id: 'lse_sts00000001', expires_at: new Date(Date.now() + 3600_000).toISOString() });
    expect(l.status, JSON.stringify(l.body)).toBe(201);
    expect(l.body).toMatchObject({ username: 'tv-lse_sts00000001', renewable: false, credentials: { accessKeyId: 'ASIAEXAMPLESESSION01', sessionToken: 'stand-in-session-token', region: 'eu-west-1' } });
    expect((await call('/internal/v1/secrets/lease/renew', { org_id: 'org_p', secret_id: 'sec_sts', value_ref: ref, lease_id: 'lse_sts00000001', username: l.body.username, expires_at: new Date(Date.now() + 7200_000).toISOString() })).body.error.code).toBe('LEASE_NOT_RENEWABLE');
    expect((await call('/internal/v1/secrets/lease/revoke', { org_id: 'org_p', secret_id: 'sec_sts', value_ref: ref, lease_id: 'lse_sts00000001', username: l.body.username })).body).toEqual({ revoked: false });
    expect((await call('/internal/v1/secrets/provider-check', { org_id: 'org_p', secret_id: 'sec_sts', value_ref: ref })).body).toMatchObject({ ok: true, detail: 'authenticated as arn:aws:iam::123456789012:user/token-vault' });
    expect(stsCalls).toEqual(['AssumeRole', 'GetCallerIdentity']);
  });

  it('organization-defined types: validated with the definition the control plane sends', async () => {
    const def = { key: 'custom-partner', version: 1, name: 'Partner login', category: 'custom', fields: { account: { label: 'Account', sensitive: false, required: true }, pin: { label: 'PIN', pattern: '^[0-9]{6}$', required: true } } };
    expect((await call('/internal/v1/secrets/store', { org_id: 'org_p', secret_id: 'sec_c', version: 1, type_key: 'custom-partner', payload: { account: 'a1', pin: '12' }, type_definition: def })).body.error).toMatchObject({ code: 'SECRET_INVALID', details: { fields: { pin: expect.any(String) } } });
    const ok = await call('/internal/v1/secrets/store', { org_id: 'org_p', secret_id: 'sec_c', version: 1, type_key: 'custom-partner', payload: { account: 'a1', pin: '123456' }, type_definition: def });
    expect(ok).toMatchObject({ status: 201, body: { summary: { account: 'a1', pin: '••••••••' } } });
    // Without the definition, or with one that tries to be dynamic, the type is unknown.
    expect((await call('/internal/v1/secrets/store', { org_id: 'org_p', secret_id: 'sec_c2', version: 1, type_key: 'custom-partner', payload: { account: 'a1', pin: '123456' } })).body.error.code).toBe('SECRET_TYPE_UNKNOWN');
    expect((await call('/internal/v1/secrets/store', { org_id: 'org_p', secret_id: 'sec_c2', version: 1, type_key: 'custom-partner', payload: { account: 'a1', pin: '123456' }, type_definition: { ...def, category: 'dynamic', lifecycle: { dynamic: true } } })).body.error.code).toBe('SECRET_TYPE_UNKNOWN');
  });
});
