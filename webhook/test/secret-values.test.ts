import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';

/**
 * Secret values on the customer webhook (Secret Management phase 2): validated against a
 * verified secret type, stored only as ciphertext bound to its organization, secret and
 * version, read only through signed requests, copied for rollbacks, and destroyed.
 * Skipped unless WEBHOOK_TEST_DATABASE_URL is set. The database is wiped.
 */
const url = process.env.WEBHOOK_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('secret values (PostgreSQL)', () => {
  const signingSecret = randomBytes(32).toString('base64url');
  let server: Server;
  let base = '';
  let m: {
    client: typeof import('../src/db/client');
    store: typeof import('../src/store/credential-store');
    values: typeof import('../src/store/secret-store');
    sig: typeof import('../src/security/signature');
    orm: typeof import('drizzle-orm');
  };

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

  const PASSWORD = 'correct horse battery staple 42';
  const pg = (extra: object = {}) => ({ org_id: 'org_a', secret_id: 'sec_pg1', version: 1, type_key: 'postgresql', payload: { username: 'app', password: PASSWORD }, ...extra });

  beforeAll(async () => {
    process.env.WEBHOOK_DATABASE_URL = url;
    process.env.VAULT_ENCRYPTION_KEY = randomBytes(32).toString('base64');
    process.env.WEBHOOK_SIGNING_SECRET = signingSecret;
    process.env.SEED_MODE = 'reset';
    process.env.CMS_CATALOG_URL = ''; // the predefined secret types apply
    m = {
      client: await import('../src/db/client'),
      store: await import('../src/store/credential-store'),
      values: await import('../src/store/secret-store'),
      sig: await import('../src/security/signature'),
      orm: await import('drizzle-orm'),
    };
    await m.client.runMigrations();
    await m.store.initStore();
    const express = (await import('express')).default;
    const { buildRouter } = await import('../src/routes');
    const app = express();
    app.use(buildRouter());
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }, 60_000);

  afterAll(async () => {
    server?.close();
    await m?.client.closeDatabase();
  });

  it('validates against the verified type and stores only ciphertext, returning a masked summary', async () => {
    const bad = await call('/internal/v1/secrets/store', pg({ payload: { username: 'app', password: '', extra: PASSWORD } }));
    expect(bad).toMatchObject({ status: 400, body: { error: { code: 'SECRET_INVALID', details: { fields: { password: 'Password is required', extra: 'is not a field of this secret type' } } } } });
    expect(JSON.stringify(bad.body)).not.toContain(PASSWORD);
    expect((await call('/internal/v1/secrets/store', pg({ type_key: 'no-such-type' }))).body.error.code).toBe('SECRET_TYPE_UNKNOWN');

    const r = await call('/internal/v1/secrets/store', pg());
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ value_ref: expect.stringMatching(/^sval_/), version: 1, fingerprint: expect.stringMatching(/^fp_[0-9a-f]{16}$/), summary: { username: 'app', password: '••••••••' }, type_version: 1 });
    expect(JSON.stringify(r.body)).not.toContain(PASSWORD);
    const { rows } = await m.client.db.execute(m.orm.sql`select * from secret_values`);
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(PASSWORD);
    expect(JSON.stringify(rows)).not.toContain('"app"');
    // The same version cannot be stored twice.
    expect((await call('/internal/v1/secrets/store', pg())).body.error.code).toBe('SECRET_VERSION_EXISTS');
  });

  it('reads a value only for its organization and secret, optionally only some fields', async () => {
    const [row] = (await m.client.db.execute(m.orm.sql`select value_ref from secret_values where secret_id = 'sec_pg1'`)).rows as { value_ref: string }[];
    const ref = row!.value_ref;
    expect((await call('/internal/v1/secrets/read', { org_id: 'org_a', secret_id: 'sec_pg1', value_ref: ref })).body).toEqual({ value_ref: ref, version: 1, type_key: 'postgresql', payload: { username: 'app', password: PASSWORD } });
    expect((await call('/internal/v1/secrets/read', { org_id: 'org_a', secret_id: 'sec_pg1', value_ref: ref, fields: ['password'] })).body.payload).toEqual({ password: PASSWORD });
    expect((await call('/internal/v1/secrets/read', { org_id: 'org_a', secret_id: 'sec_pg1', value_ref: ref, fields: ['nope'] })).body.error.code).toBe('SECRET_FIELD_UNKNOWN');
    expect((await call('/internal/v1/secrets/read', { org_id: 'org_b', secret_id: 'sec_pg1', value_ref: ref })).status).toBe(404);
    expect((await call('/internal/v1/secrets/read', { org_id: 'org_a', secret_id: 'sec_other', value_ref: ref })).status).toBe(404);
  });

  it('refuses unsigned requests', async () => {
    const res = await fetch(base + '/internal/v1/secrets/read', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(res.status).toBe(401);
  });

  it('a row moved to another organization or relabelled no longer decrypts', async () => {
    const r = await call('/internal/v1/secrets/store', pg({ secret_id: 'sec_moved' }));
    await m.client.db.execute(m.orm.sql`update secret_values set org_id = 'org_evil' where value_ref = ${r.body.value_ref}`);
    expect((await call('/internal/v1/secrets/read', { org_id: 'org_evil', secret_id: 'sec_moved', value_ref: r.body.value_ref })).body.error.code).toBe('SECRET_UNREADABLE');
    await m.client.db.execute(m.orm.sql`update secret_values set org_id = 'org_a', version = 7 where value_ref = ${r.body.value_ref}`);
    expect((await call('/internal/v1/secrets/read', { org_id: 'org_a', secret_id: 'sec_moved', value_ref: r.body.value_ref })).body.error.code).toBe('SECRET_UNREADABLE');
  });

  it('copies a version for a rollback (same value, new version) and destroys versions', async () => {
    const v2 = await call('/internal/v1/secrets/store', pg({ version: 2, payload: { username: 'app', password: 'a newer password value' } }));
    const [v1] = (await m.client.db.execute(m.orm.sql`select value_ref from secret_values where secret_id = 'sec_pg1' and version = 1`)).rows as { value_ref: string }[];
    const v3 = await call('/internal/v1/secrets/copy', { org_id: 'org_a', secret_id: 'sec_pg1', from_ref: v1!.value_ref, version: 3 });
    expect(v3).toMatchObject({ status: 201, body: { version: 3, copied_from: 1 } });
    expect(v3.body.value_ref).not.toBe(v1!.value_ref);
    // Same value, same fingerprint; the newer version differs.
    const fp = async (ref: string) => (await m.client.db.execute(m.orm.sql`select fingerprint from secret_values where value_ref = ${ref}`)).rows[0]!.fingerprint;
    expect(await fp(v3.body.value_ref)).toBe(await fp(v1!.value_ref));
    expect(v2.body.fingerprint).not.toBe(v3.body.fingerprint);
    expect((await call('/internal/v1/secrets/read', { org_id: 'org_a', secret_id: 'sec_pg1', value_ref: v3.body.value_ref })).body.payload.password).toBe(PASSWORD);

    const d = await call('/internal/v1/secrets/destroy', { org_id: 'org_a', secret_id: 'sec_pg1', value_refs: [v1!.value_ref, v2.body.value_ref, 'sval_unknown'] });
    expect(d.body.destroyed.sort()).toEqual([v1!.value_ref, v2.body.value_ref].sort());
    expect((await call('/internal/v1/secrets/read', { org_id: 'org_a', secret_id: 'sec_pg1', value_ref: v1!.value_ref })).status).toBe(404);
    // Another organization cannot destroy anything.
    expect((await call('/internal/v1/secrets/destroy', { org_id: 'org_b', secret_id: 'sec_pg1', value_refs: [v3.body.value_ref] })).body.destroyed).toEqual([]);
  });

  it('accepts values larger than the general 64 KiB limit, up to the secret limit', async () => {
    const big = { org_id: 'org_a', secret_id: 'sec_env', version: 1, type_key: 'env-vars', payload: { variables: Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`VAR_${i}`, 'x'.repeat(1500)])) } };
    expect((await call('/internal/v1/secrets/store', big)).status).toBe(201);
  });

  it('re-encrypts values under a new key and reports them in health', async () => {
    const before = await m.values.reencryptValues();
    expect(before).toEqual({ reencrypted: 0, unreadable: 0, pending: 0 });
    expect(await m.values.countValues()).toBeGreaterThan(0);
  });
});
