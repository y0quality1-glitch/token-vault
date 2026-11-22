import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import { BUILTIN_SECRET_TYPES, summarizeSecretPayload, validateSecretPayload, validateSecretTypeDefinition, type SecretPayload } from '@token-vault/shared';

/**
 * Secret Management phase 2 against a real PostgreSQL database, with the customer webhook
 * replaced by an in-memory stand-in that behaves like /internal/v1/secrets (validates, keeps
 * values by ref, copies, destroys). The control plane must never store a value, list one, or
 * put one in the audit log. Skipped unless TEST_DATABASE_URL is set. The database is reseeded.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

const vault = vi.hoisted(() => ({
  values: new Map<string, { org: string; secret: string; version: number; type: string; payload: Record<string, unknown> }>(),
  calls: [] as { path: string; body: Record<string, any> }[],
  down: false,
}));
vi.mock('../src/services/webhookService/webhook.client', async (orig) => {
  const real = await orig<typeof import('../src/services/webhookService/webhook.client')>();
  const types = new Map(BUILTIN_SECRET_TYPES.map((t) => [t.key, validateSecretTypeDefinition(t)]));
  let n = 0;
  const stored = (ref: string, v: { version: number; type: string; payload: Record<string, unknown> }, extra = {}) => ({
    status: 201,
    body: { value_ref: ref, version: v.version, fingerprint: `fp_${JSON.stringify(v.payload).length.toString(16).padStart(16, '0')}`, summary: summarizeSecretPayload(types.get(v.type)!, v.payload as SecretPayload), type_version: 1, ...extra },
  });
  return {
    ...real,
    callWebhook: async (_wh: unknown, _method: string, path: string, body: Record<string, any>) => {
      vault.calls.push({ path, body });
      if (vault.down) throw new real.WebhookUnavailableError('UNREACHABLE', 'Customer webhook unreachable');
      const clash = (secret: string, version: number) => [...vault.values.values()].some((x) => x.secret === secret && x.version === version);
      if (path === '/internal/v1/secrets/store') {
        const { issues, value } = validateSecretPayload(types.get(body.type_key)!, body.payload);
        if (Object.keys(issues).length) return { status: 400, latencyMs: 1, body: { error: { code: 'SECRET_INVALID', message: 'invalid', details: { fields: issues } } } };
        if (clash(body.secret_id, body.version)) return { status: 409, latencyMs: 1, body: { error: { code: 'SECRET_VERSION_EXISTS' } } };
        const ref = `sval_${++n}`;
        const v = { org: body.org_id, secret: body.secret_id, version: body.version, type: body.type_key, payload: value };
        vault.values.set(ref, v);
        return { latencyMs: 1, ...stored(ref, v) };
      }
      const v = vault.values.get(body.value_ref ?? body.from_ref);
      const mine = v && v.org === body.org_id && v.secret === body.secret_id;
      if (path === '/internal/v1/secrets/read') {
        if (!mine) return { status: 404, latencyMs: 1, body: { error: { code: 'SECRET_VALUE_NOT_FOUND' } } };
        const payload = body.fields ? Object.fromEntries(Object.entries(v.payload).filter(([k]) => body.fields.includes(k))) : v.payload;
        return { status: 200, latencyMs: 1, body: { version: v.version, payload } };
      }
      if (path === '/internal/v1/secrets/copy') {
        if (!mine) return { status: 404, latencyMs: 1, body: { error: { code: 'SECRET_VALUE_NOT_FOUND' } } };
        const ref = `sval_${++n}`;
        const copy = { ...v, version: body.version };
        vault.values.set(ref, copy);
        return { latencyMs: 1, ...stored(ref, copy, { copied_from: v.version }) };
      }
      if (path === '/internal/v1/secrets/destroy') {
        const destroyed = (body.value_refs as string[]).filter((r) => vault.values.get(r)?.org === body.org_id && vault.values.get(r)?.secret === body.secret_id);
        destroyed.forEach((r) => vault.values.delete(r));
        return { status: 200, latencyMs: 1, body: { destroyed } };
      }
      return { status: 404, latencyMs: 1, body: {} };
    },
  };
});

const PASSWORD = 'correct horse battery staple 42';

suite('Secrets', () => {
  let m: {
    client: typeof import('../src/databases/client');
    seed: typeof import('../src/store/seed');
    entities: typeof import('../src/entities');
    svc: InstanceType<typeof import('../src/services/secretService/secretService.service').default>;
  };
  let ctx: any;
  let sandbox: any;
  const audit = async (secretId: string) => (await m.client.db.find(m.entities.AuditEventEntity, { where: { targetId: secretId }, order: { createdAt: 'ASC' } })) as any[];
  const create = (extra: Record<string, unknown> = {}) =>
    m.svc.create(ctx, { name: 'orders-db', description: 'Orders database', typeKey: 'postgresql', environment: 'production', project: 'shop', tags: ['pci'], metadata: { host: 'db.internal', port: 5432 }, payload: { username: 'orders', password: PASSWORD }, activate: true, ...extra } as any);

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    process.env.CMS_CATALOG_URL = ''; // predefined secret types (an empty value is not overridden by server/.env)
    m = {
      client: await import('../src/databases/client'),
      seed: await import('../src/store/seed'),
      entities: await import('../src/entities'),
      svc: new (await import('../src/services/secretService/secretService.service')).default(),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    const user = { id: m.seed.IDS.owner, fullName: 'Olivia Owner', email: 'owner@demo.test' };
    ctx = { user, org: { id: m.seed.IDS.demoOrg, name: 'Demo Organization' }, role: 'OWNER' };
    sandbox = { ...ctx, org: { id: m.seed.IDS.sandboxOrg, name: 'Sandbox' } };
  }, 60_000);
  beforeEach(() => {
    vault.down = false;
  });
  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('creates a secret: value on the webhook only, metadata and version 1 here, audited without the value', async () => {
    await expect(create({ payload: { username: 'orders', password: '' } })).rejects.toMatchObject({ status: 400, details: { fields: { 'payload.password': 'Password is required' } } });
    await expect(create({ metadata: { host: 'not a host!' } })).rejects.toMatchObject({ status: 400, details: { fields: { 'metadata.host': expect.stringMatching(/host name/) } } });
    await expect(create({ typeKey: 'nope' })).rejects.toMatchObject({ status: 400, details: { fields: { typeKey: 'Unknown secret type' } } });
    expect(vault.calls).toHaveLength(0); // nothing reached the webhook

    const s = await create();
    expect(s).toMatchObject({ name: 'orders-db', typeKey: 'postgresql', typeName: 'PostgreSQL credentials', category: 'database', project: 'shop', workspace: 'default', status: 'ACTIVE', activeVersion: 1, summary: { username: 'orders', password: '••••••••' }, metadata: { host: 'db.internal', port: 5432 } });
    // The type's default rotation (90 days) applies.
    expect(s.rotation).toMatchObject({ enabled: true, intervalDays: 90 });
    expect(s.versions).toMatchObject([{ version: 1, state: 'ACTIVE', reason: 'Initial value' }]);
    expect(s.can).toMatchObject({ retrieve: true, revoke: true, delete: false });

    const rows = await m.client.db.query(`SELECT * FROM secrets s JOIN secret_versions v ON v.secret_id = s.id WHERE s.id = $1`, [s.id]);
    expect(JSON.stringify(rows)).not.toContain(PASSWORD);
    expect(JSON.stringify(await audit(s.id))).not.toContain(PASSWORD);
    expect((await audit(s.id)).map((e) => e.eventType)).toEqual(['secret.created']);

    await expect(create()).rejects.toMatchObject({ status: 409 }); // same name, project, workspace, environment
    await create({ environment: 'staging' }); // another environment is fine
  });

  it('lists and searches metadata only, scoped to the organization', async () => {
    await create({ name: 'stripe', description: 'Card payments', typeKey: 'api-key', project: 'payments', tags: ['pci', 'external'], metadata: { provider: 'Stripe' }, payload: { apiKey: 'test-api-key-abcdefghijklmnopqrstuvwx' } });
    const all = await m.svc.list(m.seed.IDS.demoOrg);
    expect(all.total).toBe(3);
    expect(JSON.stringify(all)).not.toContain(PASSWORD);
    expect(JSON.stringify(all)).not.toContain('test-api-key-');
    expect((await m.svc.list(m.seed.IDS.demoOrg, { project: 'payments' })).items.map((x) => x.name)).toEqual(['stripe']);
    expect((await m.svc.list(m.seed.IDS.demoOrg, { tag: 'pci', environment: 'production' })).items.map((x) => x.name).sort()).toEqual(['orders-db', 'stripe']);
    expect((await m.svc.list(m.seed.IDS.demoOrg, { search: 'orders' })).total).toBe(2);
    expect((await m.svc.list(m.seed.IDS.demoOrg, { sortBy: 'name' })).items.map((x) => x.name)).toEqual(['orders-db', 'orders-db', 'stripe']);
    expect((await m.svc.list(m.seed.IDS.sandboxOrg)).total).toBe(0);
    const id = all.items[0]!.id;
    await expect(m.svc.detail(sandbox, id)).rejects.toMatchObject({ status: 404 });
    await expect(m.svc.retrieve(sandbox, { id } as any)).rejects.toMatchObject({ status: 404 });
  });

  const byName = async (name: string, environment = 'production') => (await m.svc.list(m.seed.IDS.demoOrg, { search: name, environment })).items[0]!;

  it('updates metadata without a new version, and refuses value or scope changes that way', async () => {
    const s = await byName('orders-db');
    const u = await m.svc.updateMetadata(ctx, { id: s.id, name: 'orders-db', description: 'Primary', tags: ['pci', 'tier1'], metadata: { host: 'db2.internal' }, rotationIntervalDays: 30 } as any);
    expect(u).toMatchObject({ description: 'Primary', tags: ['pci', 'tier1'], metadata: { host: 'db2.internal' }, activeVersion: 1, rotation: { enabled: true, intervalDays: 30 } });
    await expect(m.svc.updateMetadata(ctx, { id: s.id, name: 'orders-db', payload: { password: 'x' } } as any)).rejects.toMatchObject({ status: 400, details: { fields: { payload: 'Use /secret/updateValue to change the value' } } });
    await expect(m.svc.updateMetadata(ctx, { id: s.id, name: 'orders-db', environment: 'staging' } as any)).rejects.toMatchObject({ status: 400 });
    expect((await audit(s.id)).at(-1)).toMatchObject({ eventType: 'secret.updated', metadata: { changed: expect.arrayContaining(['description', 'tags', 'metadata', 'rotationIntervalDays']) } });
  });

  it('a new value becomes the active version; retrieval returns only what is asked and is audited', async () => {
    const s = await byName('orders-db');
    const v2 = await m.svc.updateValue(ctx, { id: s.id, payload: { username: 'orders', password: 'second password value' }, reason: 'Quarterly change' } as any);
    expect(v2.activeVersion).toBe(2);
    expect(v2.versions.map((v) => [v.version, v.state])).toEqual([
      [2, 'ACTIVE'],
      [1, 'PREVIOUS'],
    ]);
    const r = await m.svc.retrieve(ctx, { id: s.id, fields: ['password'], reason: 'incident 42' } as any);
    expect(r).toMatchObject({ version: 2, payload: { password: 'second password value' } });
    expect(Object.keys(r.payload)).toEqual(['password']);
    expect((await m.svc.retrieve(ctx, { id: s.id, version: 1 } as any)).payload).toEqual({ username: 'orders', password: PASSWORD });
    await expect(m.svc.retrieve(ctx, { id: s.id, fields: ['nope'] } as any)).rejects.toMatchObject({ status: 400 });
    const events = await audit(s.id);
    expect(events.map((e) => e.eventType)).toEqual(expect.arrayContaining(['secret.version_created', 'secret.retrieved', 'secret.version_retrieved']));
    expect(events.find((e) => e.eventType === 'secret.retrieved')!.metadata).toMatchObject({ version: 2, fieldsRequested: ['password'], reason: 'incident 42' });
    expect(JSON.stringify(events)).not.toMatch(/second password value|correct horse/);
    expect((await m.svc.detail(ctx, s.id)).lastRetrievedAt).not.toBeNull();

    // A role without secret:retrieve is refused, and the refusal is audited.
    await expect(m.svc.retrieve({ ...ctx, role: 'AUDITOR' }, { id: s.id } as any)).rejects.toMatchObject({ status: 403 });
    expect((await audit(s.id)).at(-1)).toMatchObject({ eventType: 'secret.access_denied', outcome: 'DENIED', metadata: { reasonCode: 'PERMISSION_DENIED' } });
  });

  it('rolls back by copying an old value into a new version, and destroys inactive versions', async () => {
    const s = await byName('orders-db');
    const v3 = await m.svc.rollback(ctx, { id: s.id, version: 1, reason: '' } as any);
    expect(v3.versions[0]).toMatchObject({ version: 3, state: 'ACTIVE', copiedFrom: 1, reason: 'Rollback to version 1' });
    expect((await m.svc.retrieve(ctx, { id: s.id } as any)).payload.password).toBe(PASSWORD);
    await expect(m.svc.rollback(ctx, { id: s.id, version: 3 } as any)).rejects.toMatchObject({ status: 409 }); // already active

    await expect(m.svc.destroyVersion(ctx, { id: s.id, version: 3 } as any)).rejects.toMatchObject({ status: 409 });
    const d = await m.svc.destroyVersion(ctx, { id: s.id, version: 1, reason: 'superseded' } as any);
    expect(d.versions.find((v) => v.version === 1)).toMatchObject({ state: 'DESTROYED', destroyedAt: expect.any(String) });
    await expect(m.svc.retrieve(ctx, { id: s.id, version: 1 } as any)).rejects.toMatchObject({ status: 410 });
    await expect(m.svc.rollback(ctx, { id: s.id, version: 1 } as any)).rejects.toMatchObject({ status: 409 });
  });

  it('enforces expiry on retrieval and allows renewal', async () => {
    const s = await byName('orders-db');
    await m.client.db.query(`UPDATE secrets SET expires_at = now() - interval '1 minute' WHERE id = $1`, [s.id]);
    expect((await m.svc.detail(ctx, s.id)).status).toBe('EXPIRED');
    expect((await m.svc.list(m.seed.IDS.demoOrg, { status: 'EXPIRED' })).items.map((x) => x.id)).toEqual([s.id]);
    expect((await m.svc.list(m.seed.IDS.demoOrg, { status: 'ACTIVE' })).items.map((x) => x.id)).not.toContain(s.id);
    await expect(m.svc.retrieve(ctx, { id: s.id } as any)).rejects.toMatchObject({ status: 409, code: 'SECRET_EXPIRED' });
    expect((await audit(s.id)).at(-1)).toMatchObject({ eventType: 'secret.access_denied', outcome: 'DENIED', metadata: { reasonCode: 'SECRET_EXPIRED' } });

    const renewed = await m.svc.updateMetadata(ctx, { id: s.id, name: 'orders-db', expiresAt: new Date(Date.now() + 86_400_000).toISOString() } as any);
    expect(renewed.status).toBe('ACTIVE');
    expect((await audit(s.id)).at(-1)!.eventType).toBe('secret.renewed');
  });

  it('pending secrets are activated before use; revoked ones are never retrieved again; deletion destroys every value', async () => {
    const p = await create({ name: 'pending-one', activate: false });
    expect(p.status).toBe('PENDING');
    await expect(m.svc.retrieve(ctx, { id: p.id } as any)).rejects.toMatchObject({ code: 'SECRET_NOT_ACTIVE' });
    expect((await m.svc.activate(ctx, { id: p.id } as any)).status).toBe('ACTIVE');

    const s = await byName('orders-db');
    await expect(m.svc.remove(ctx, s.id)).rejects.toMatchObject({ status: 409 }); // revoke first
    expect((await m.svc.revoke(ctx, { id: s.id, reason: 'leaked' } as any)).status).toBe('REVOKED');
    await expect(m.svc.retrieve(ctx, { id: s.id } as any)).rejects.toMatchObject({ code: 'SECRET_NOT_ACTIVE' });
    await expect(m.svc.updateValue(ctx, { id: s.id, payload: { username: 'x', password: 'y' } } as any)).rejects.toMatchObject({ code: 'SECRET_NOT_WRITABLE' });

    // The webhook is down: nothing changes.
    vault.down = true;
    await expect(m.svc.remove(ctx, s.id)).rejects.toMatchObject({ status: 503 });
    expect((await m.svc.detail(ctx, s.id)).status).toBe('REVOKED');
    vault.down = false;

    const left = [...vault.values.values()].filter((v) => v.secret === s.id).length;
    expect(left).toBe(2); // versions 2 and 3 (1 was destroyed)
    expect(await m.svc.remove(ctx, s.id)).toEqual({ id: s.id, status: 'DELETED', destroyedVersions: 2 });
    expect([...vault.values.values()].filter((v) => v.secret === s.id)).toEqual([]);
    const tomb = await m.svc.detail(ctx, s.id);
    expect(tomb).toMatchObject({ status: 'DELETED', activeVersion: null });
    expect(tomb.versions.every((v) => v.state === 'DESTROYED')).toBe(true);
    expect((await audit(s.id)).at(-1)).toMatchObject({ eventType: 'secret.deleted', metadata: { destroyedVersions: 2 } });
    // The name is free again; deleted secrets are listed only when asked for.
    await create();
    expect((await m.svc.list(m.seed.IDS.demoOrg, { status: 'DELETED' })).items.map((x) => x.id)).toEqual([s.id]);
  });

  it('when the database write fails after the webhook stored a value, the value is destroyed again', async () => {
    const before = vault.values.size;
    // A name clash the pre-check cannot see: the row appears between the check and the insert.
    const spy = vi.spyOn(m.svc as any, 'nameTaken').mockResolvedValue(false);
    await expect(create()).rejects.toMatchObject({ status: 409 });
    spy.mockRestore();
    expect(vault.values.size).toBe(before);
  });
});
