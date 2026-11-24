import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDecipheriv, createHash, randomBytes, scryptSync } from 'node:crypto';
import { BUILTIN_SECRET_TYPES, summarizeSecretPayload, validateCustomSecretType, validateSecretPayload, validateSecretTypeDefinition, type SecretPayload, type SecretTypeDefinition } from '@token-vault/shared';

/**
 * Secret Management phase 5 against a real PostgreSQL database: leases of dynamic secrets (agent
 * and member, renewal limits, revocation, cleanup of expired leases), provider rotation and
 * health checks, organization-defined types, import with duplicate detection, and export with
 * approval and an encrypted file. The customer webhook is an in-memory stand-in.
 * Skipped unless TEST_DATABASE_URL is set. The database is reseeded.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

const vault = vi.hoisted(() => ({
  values: new Map<string, { org: string; secret: string; version: number; type: string; payload: Record<string, unknown> }>(),
  calls: [] as { path: string; body: Record<string, any> }[],
  down: false,
  providerDown: false,
  check: { ok: true, detail: 'connected as app' } as { ok: boolean; detail: string; code?: string },
}));
vi.mock('../src/services/webhookService/webhook.client', async (orig) => {
  const real = await orig<typeof import('../src/services/webhookService/webhook.client')>();
  const types = new Map<string, SecretTypeDefinition>(BUILTIN_SECRET_TYPES.map((t) => [t.key, validateSecretTypeDefinition(t)]));
  let n = 0;
  const fp = (p: unknown) => `fp_${createHash('sha256').update(JSON.stringify(p)).digest('hex').slice(0, 16)}`;
  const put = (v: { org: string; secret: string; version: number; type: string; payload: Record<string, unknown> }, type: SecretTypeDefinition, extra = {}) => {
    const ref = `sval_${++n}`;
    vault.values.set(ref, v);
    return { status: 201, latencyMs: 1, body: { value_ref: ref, version: v.version, fingerprint: fp(v.payload), summary: summarizeSecretPayload(type, v.payload as SecretPayload), type_version: type.version, ...extra } };
  };
  const err = (status: number, code: string, message = code) => ({ status, latencyMs: 1, body: { error: { code, message } } });
  return {
    ...real,
    callWebhook: async (_wh: unknown, _method: string, path: string, body: Record<string, any>) => {
      vault.calls.push({ path, body });
      if (vault.down) throw new real.WebhookUnavailableError('UNREACHABLE', 'Customer webhook unreachable');
      if (path === '/internal/v1/secrets/store') {
        const type = body.type_key.startsWith('custom-') ? validateCustomSecretType(body.type_definition) : types.get(body.type_key)!;
        const { issues, value } = validateSecretPayload(type, body.payload);
        if (Object.keys(issues).length) return { status: 400, latencyMs: 1, body: { error: { code: 'SECRET_INVALID', details: { fields: issues } } } };
        return put({ org: body.org_id, secret: body.secret_id, version: body.version, type: type.key, payload: value }, type);
      }
      const v = vault.values.get(body.value_ref ?? body.from_ref);
      if (!v || v.org !== body.org_id || v.secret !== body.secret_id) return err(404, 'SECRET_VALUE_NOT_FOUND');
      const type = types.get(v.type);
      switch (path) {
        case '/internal/v1/secrets/read':
          return { status: 200, latencyMs: 1, body: { version: v.version, payload: v.payload } };
        case '/internal/v1/secrets/lease':
          if (vault.providerDown) return err(503, 'PROVIDER_UNAVAILABLE', 'The database could not be reached');
          return { status: 201, latencyMs: 1, body: { username: `tv_${body.lease_id}`, credentials: { username: `tv_${body.lease_id}`, password: `pw-${body.lease_id}` }, expires_at: body.expires_at, renewable: v.type === 'postgresql-dynamic' } };
        case '/internal/v1/secrets/lease/renew':
          return { status: 200, latencyMs: 1, body: { expires_at: body.expires_at } };
        case '/internal/v1/secrets/lease/revoke':
          if (vault.providerDown) return err(503, 'PROVIDER_UNAVAILABLE', 'The database could not be reached');
          return { status: 200, latencyMs: 1, body: { revoked: true } };
        case '/internal/v1/secrets/provider-rotate':
          if (vault.providerDown) return err(503, 'PROVIDER_UNAVAILABLE', 'The database could not be reached');
          return put({ ...v, version: body.version, payload: { ...v.payload, password: `rotated-${body.version}-${randomBytes(4).toString('hex')}` } }, type!, { rotated_at_provider: true });
        case '/internal/v1/secrets/provider-check':
          return { status: 200, latencyMs: 1, body: vault.check };
        default:
          return err(404, 'NOT_FOUND');
      }
    },
  };
});

suite('Secret providers: leases, provider rotation and health, custom types, import, export', () => {
  let m: {
    client: typeof import('../src/databases/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    crypto: typeof import('../src/lib/crypto');
    entities: typeof import('../src/entities');
    config: typeof import('../src/config');
    job: typeof import('../src/services/secretService/secretLifecycle.job');
    secrets: InstanceType<typeof import('../src/services/secretService/secretService.service').default>;
    access: InstanceType<typeof import('../src/services/secretAccessService/secretAccessService.service').default>;
    leases: InstanceType<typeof import('../src/services/secretLeaseService/secretLeaseService.service').default>;
    types: InstanceType<typeof import('../src/services/secretTypeService/secretTypeService.service').default>;
    importer: InstanceType<typeof import('../src/services/secretImportService/secretImportService.service').default>;
    exporter: InstanceType<typeof import('../src/services/secretExportService/secretExportService.service').default>;
    SecretService: typeof import('../src/services/secretService/secretService.service').default;
  };
  let owner: any;
  let security: any;
  let agentId = '';
  let agentKey = '';
  const auth = () => `Bearer ${agentKey}`;
  const lease = (body: Record<string, unknown>) => m.access.agentRetrieve({ authorization: auth(), sourceIp: '127.0.0.1', body, mode: 'lease' });
  const events = async (targetId: string) => ((await m.client.db.find(m.entities.AuditEventEntity, { where: { targetId }, order: { createdAt: 'ASC' } })) as any[]).map((e) => e.eventType);
  const sql = (q: string, p: unknown[] = []) => m.client.db.query(q, p);
  const pgDynamic = { host: 'db.internal', port: 5432, database: 'orders', username: 'vault_admin', password: 'admin-password-123', creationStatements: 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}}' };

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    process.env.CMS_CATALOG_URL = '';
    const svc = await import('../src/services/secretService/secretService.service');
    m = {
      client: await import('../src/databases/client'),
      seed: await import('../src/store/seed'),
      repos: await import('../src/store/repos'),
      crypto: await import('../src/lib/crypto'),
      entities: await import('../src/entities'),
      config: await import('../src/config'),
      job: await import('../src/services/secretService/secretLifecycle.job'),
      secrets: new svc.default(),
      access: new (await import('../src/services/secretAccessService/secretAccessService.service')).default(),
      leases: new (await import('../src/services/secretLeaseService/secretLeaseService.service')).default(),
      types: new (await import('../src/services/secretTypeService/secretTypeService.service')).default(),
      importer: new (await import('../src/services/secretImportService/secretImportService.service')).default(),
      exporter: new (await import('../src/services/secretExportService/secretExportService.service')).default(),
      SecretService: svc.default,
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    agentId = m.seed.IDS.agtAssistant;
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(agentId, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    agentKey = cred.apiKey;
    owner = { user: { id: m.seed.IDS.owner, fullName: 'Avery Chen' }, org: { id: m.seed.IDS.demoOrg, name: 'Demo Organization' }, role: 'OWNER' };
    const sec = (await m.client.db.query(`SELECT u.id, u.full_name FROM users u JOIN organization_members om ON om.user_id = u.id WHERE om.organization_id = $1 AND om.role = 'SECURITY_ADMIN' LIMIT 1`, [m.seed.IDS.demoOrg]))[0];
    security = { user: { id: sec.id, fullName: sec.full_name }, org: owner.org, role: 'SECURITY_ADMIN' };
  }, 60_000);
  beforeEach(() => {
    vault.down = false;
    vault.providerDown = false;
    vault.check = { ok: true, detail: 'connected as app' };
  });
  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('dynamic secrets issue leases to agents under a grant; they are never retrieved', async () => {
    const s = await m.secrets.create(owner, { name: 'orders-dynamic', typeKey: 'postgresql-dynamic', environment: 'production', project: 'orders', metadata: { defaultTtlMinutes: 30, maxTtlMinutes: 60 }, payload: pgDynamic } as any);
    expect(s).toMatchObject({ provider: { capabilities: { lease: true, renew: true, rotate: true }, status: null }, leases: [] });
    await expect(lease({ secret_id: s.id })).rejects.toMatchObject({ code: 'SECRET_ACCESS_DENIED' });
    await m.access.create(owner, { agentId, secretId: s.id, fields: ['host'] });
    await expect(lease({ secret_id: s.id })).rejects.toMatchObject({ code: 'LEASE_NOT_PERMITTED' });
    await m.access.create(owner, { agentId, secretId: s.id });
    await expect(m.access.agentRetrieve({ authorization: auth(), sourceIp: '127.0.0.1', body: { secret_id: s.id } })).rejects.toMatchObject({ code: 'SECRET_IS_DYNAMIC' });
    expect((await m.access.agentList(auth())).items.find((i) => i.secret_id === s.id)).toMatchObject({ dynamic: true });

    const r = await lease({ name: 'orders-dynamic', ttl_seconds: 1200, reason: 'nightly report' });
    expect(r.status).toBe(201);
    const l = r.body as any;
    expect(l).toMatchObject({ lease_id: expect.stringMatching(/^lse_/), credentials: { username: `tv_${l.lease_id}`, password: `pw-${l.lease_id}` }, renewable: true });
    expect(Date.parse(l.expires_at) - Date.now()).toBeGreaterThan(19 * 60_000);
    expect(Date.parse(l.max_expires_at) - Date.now()).toBeLessThan(61 * 60_000);
    const audit = (await m.client.db.find(m.entities.AuditEventEntity, { where: { targetId: s.id, eventType: 'secret.lease_created' } })) as any[];
    expect(audit[0]).toMatchObject({ actorType: 'AGENT', metadata: { leaseId: l.lease_id, username: `tv_${l.lease_id}`, reason: 'nightly report' } });
    expect(JSON.stringify(await m.client.db.query('SELECT * FROM secret_leases'))).not.toContain(`pw-${l.lease_id}`);

    // Renewal: never past the longest lease.
    const renewed = await m.access.agentLeaseAction({ authorization: auth(), action: 'renew', body: { lease_id: l.lease_id, ttl_seconds: 7200 } });
    expect(renewed).toMatchObject({ status: 'ACTIVE', renew_count: 1, expires_at: l.max_expires_at });
    await expect(m.access.agentLeaseAction({ authorization: auth(), action: 'renew', body: { lease_id: l.lease_id } })).rejects.toMatchObject({ code: 'LEASE_AT_MAXIMUM' });
    expect(await m.access.agentLeaseAction({ authorization: auth(), action: 'revoke', body: { lease_id: l.lease_id } })).toMatchObject({ status: 'REVOKED' });
    expect(vault.calls.filter((c) => c.path === '/internal/v1/secrets/lease/revoke').at(-1)!.body).toMatchObject({ lease_id: l.lease_id, username: `tv_${l.lease_id}` });
    expect(await events(s.id)).toEqual(expect.arrayContaining(['secret.lease_created', 'secret.lease_renewed', 'secret.lease_revoked']));

    // A static secret has no leases.
    const key = await m.secrets.create(owner, { name: 'static-key', typeKey: 'api-key', environment: 'production', project: 'orders', payload: { apiKey: 'static-api-key-0123456789' } } as any);
    await m.access.create(owner, { agentId, secretId: key.id });
    await expect(lease({ secret_id: key.id })).rejects.toMatchObject({ code: 'SECRET_NOT_DYNAMIC' });
  });

  it('expired leases are ended at the provider by the lifecycle job; failures are retried', async () => {
    const s = (await m.client.db.findOneByOrFail(m.entities.SecretEntity, { name: 'orders-dynamic' }))!;
    const member = await m.leases.issue(s, { type: 'USER', id: owner.user.id, name: owner.user.fullName, actor: { type: 'USER', id: owner.user.id, name: owner.user.fullName } }, { ttlSeconds: 300 });
    expect(member).toMatchObject({ holder: { type: 'USER' }, credentials: { password: expect.any(String) } });
    await sql(`UPDATE secret_leases SET expires_at = now() - interval '1 second' WHERE id = $1`, [member.id]);
    vault.providerDown = true;
    expect((await m.job.runSecretLifecycle())!.leasesFailed).toBeGreaterThanOrEqual(1);
    expect(await m.client.db.findOneBy(m.entities.SecretLeaseEntity, { id: member.id })).toMatchObject({ status: 'REVOKE_FAILED', lastError: expect.stringMatching(/PROVIDER_UNAVAILABLE/) });
    vault.providerDown = false;
    expect((await m.job.runSecretLifecycle())!.leasesEnded).toBeGreaterThanOrEqual(1);
    expect(await m.client.db.findOneBy(m.entities.SecretLeaseEntity, { id: member.id })).toMatchObject({ status: 'EXPIRED' });
    expect(await events(s.id)).toEqual(expect.arrayContaining(['secret.lease_revoke_failed', 'secret.provider_failure', 'secret.lease_expired']));

    // Revoking the secret ends its live leases; deleting refuses while a lease cannot be ended.
    const live = await lease({ secret_id: s.id });
    await m.secrets.revoke(owner, { id: s.id, reason: 'decommissioned' } as any);
    expect(await m.client.db.findOneBy(m.entities.SecretLeaseEntity, { id: (live.body as any).lease_id })).toMatchObject({ status: 'REVOKED', revocationReason: 'Secret revoked' });
    await expect(lease({ secret_id: s.id })).rejects.toMatchObject({ code: 'SECRET_NOT_ACTIVE' });
  });

  it('provider rotation: the webhook changes the credential at the database; scheduled ones run by themselves', async () => {
    await expect(m.secrets.create(owner, { name: 'k', typeKey: 'api-key', environment: 'staging', payload: { apiKey: 'x-api-key-value-0001' }, rotationStrategy: 'provider' } as any)).rejects.toMatchObject({ details: { fields: { rotationStrategy: expect.stringMatching(/cannot rotate/) } } });
    const s = await m.secrets.create(owner, { name: 'billing-db', typeKey: 'postgresql', environment: 'production', project: 'billing', metadata: { host: 'db.billing.internal', port: 5433, database: 'billing' }, payload: { username: 'billing', password: 'billing-password-1' }, rotationStrategy: 'provider' } as any);
    expect(s.rotation).toMatchObject({ strategy: 'provider', providerRotation: true, generatable: false });

    const d = await m.secrets.rotate(owner, { id: s.id } as any);
    expect(d).toMatchObject({ activeVersion: 2, rotationJobs: [{ strategy: 'provider', status: 'SUCCEEDED', trigger: 'MANUAL' }] });
    expect(vault.calls.filter((c) => c.path === '/internal/v1/secrets/provider-rotate').at(-1)!.body).toMatchObject({ version: 2, connection: { host: 'db.billing.internal', port: 5433, database: 'billing' } });
    expect((await m.secrets.retrieve(owner, { id: s.id } as any)).payload.password).toMatch(/^rotated-2-/);

    // Scheduled: runs without a person; an unreachable database is retried.
    await sql(`UPDATE secrets SET next_rotation_at = now() - interval '1 minute' WHERE id = $1`, [s.id]);
    vault.providerDown = true;
    expect((await m.job.runSecretLifecycle())!.rotationsRetrying).toBeGreaterThanOrEqual(1);
    expect((await m.secrets.detail(owner, s.id)).rotationJobs[0]).toMatchObject({ strategy: 'provider', status: 'PENDING', errorCode: 'PROVIDER_UNAVAILABLE' });
    vault.providerDown = false;
    await sql(`UPDATE rotation_jobs SET next_attempt_at = now() - interval '1 second' WHERE secret_id = $1`, [s.id]);
    expect((await m.job.runSecretLifecycle())!.rotationsSucceeded).toBeGreaterThanOrEqual(1);
    expect((await m.secrets.detail(owner, s.id)).activeVersion).toBe(3);
  });

  it('provider health: a failing check is recorded and notified once; recovery is recorded; unmonitored hosts are not failures', async () => {
    const s = (await m.client.db.findOneByOrFail(m.entities.SecretEntity, { name: 'billing-db' }))!;
    const w = m.SecretService.writer(owner);
    const failures = async () => (await events(s.id)).filter((e) => e === 'secret.provider_failure').length;
    expect(await m.secrets.checkProvider(w, s.id)).toMatchObject({ ok: true });
    const before = await failures();
    vault.check = { ok: false, code: 'PROVIDER_AUTH_FAILED', detail: 'The database refused the stored login' };
    await m.secrets.checkProvider(w, s.id);
    await m.secrets.checkProvider(w, s.id);
    expect((await m.secrets.detail(owner, s.id)).provider).toMatchObject({ status: 'FAILING', error: expect.stringMatching(/PROVIDER_AUTH_FAILED/) });
    expect(await failures()).toBe(before + 1);
    vault.check = { ok: true, detail: 'connected as billing' };
    await m.secrets.checkProvider(w, s.id);
    expect((await events(s.id)).at(-1)).toBe('secret.provider_recovered');
    vault.check = { ok: false, code: 'PROVIDER_HOST_NOT_ALLOWED', detail: 'not allowed' };
    await m.secrets.checkProvider(w, s.id);
    expect((await m.secrets.detail(owner, s.id)).provider!.status).toBeNull();
    expect((await events(s.id)).at(-1)).toBe('secret.provider_recovered');
  });

  it('custom types: the same schema rules; versioned; values validated by the webhook with the definition sent along', async () => {
    await expect(m.types.saveCustom(owner, { key: 'partner', name: 'Partner', fields: { pin: { label: 'PIN' } } })).rejects.toMatchObject({ status: 400, details: { issues: expect.arrayContaining([expect.stringMatching(/custom-/)]) } });
    await expect(m.types.saveCustom(owner, { key: 'custom-plain', name: 'Plain', fields: { note: { label: 'Note', sensitive: false } } })).rejects.toMatchObject({ details: { issues: expect.arrayContaining([expect.stringMatching(/at least one field must be sensitive/)]) } });
    const t = await m.types.saveCustom(owner, { key: 'custom-partner', name: 'Partner portal login', description: 'Login to a partner portal', fields: { account: { label: 'Account', sensitive: false, required: true }, pin: { label: 'PIN', pattern: '^[0-9]{6}$', required: true } }, metadata: { portal: { label: 'Portal URL', kind: 'url' } } });
    expect(t).toMatchObject({ key: 'custom-partner', version: 1, category: 'custom', source: 'custom' });
    expect((await m.types.list(owner.org.id, { category: 'custom' })).types.map((x) => x.key)).toEqual(['custom-partner']);
    // Another organization does not see it.
    expect((await m.types.list(m.seed.IDS.sandboxOrg, { category: 'custom' })).types).toEqual([]);

    await expect(m.secrets.create(owner, { name: 'acme-portal', typeKey: 'custom-partner', environment: 'production', payload: { account: 'acme', pin: '12' } } as any)).rejects.toMatchObject({ details: { fields: { 'payload.pin': expect.any(String) } } });
    const s = await m.secrets.create(owner, { name: 'acme-portal', typeKey: 'custom-partner', environment: 'production', metadata: { portal: 'https://acme.example' }, payload: { account: 'acme', pin: '123456' } } as any);
    expect(s).toMatchObject({ typeName: 'Partner portal login', customType: true, summary: { account: 'acme', pin: '••••••••' } });
    expect(vault.calls.filter((c) => c.path === '/internal/v1/secrets/store').at(-1)!.body.type_definition).toMatchObject({ key: 'custom-partner', version: 1 });

    expect((await m.types.saveCustom(owner, { ...t, description: 'v2' })).version).toBe(2);
    await expect(m.types.archiveCustom(owner, 'custom-partner')).rejects.toMatchObject({ code: 'SECRET_TYPE_IN_USE' });
    expect(await events('custom-partner')).toEqual(['secret_type.created', 'secret_type.updated']);
  });

  it('import: JSON and .env, validated per type; names already used are skipped; identical values are reported', async () => {
    const content = JSON.stringify([
      { name: 'stripe-live', typeKey: 'api-key', project: 'payments', environment: 'production', payload: { apiKey: 'imported-stripe-key-000111' } },
      { name: 'stripe-copy', typeKey: 'api-key', project: 'payments', environment: 'staging', payload: { apiKey: 'imported-stripe-key-000111' } },
      { name: 'broken', typeKey: 'postgresql', environment: 'production', payload: { username: 'x' } },
      { name: 'unknown', typeKey: 'nope', environment: 'production', payload: {} },
    ]);
    const dry = await m.importer.import(owner, { format: 'json', content, dryRun: true });
    expect(dry.counts).toMatchObject({ valid: 2, invalid: 2, created: 0 });
    expect(dry.results[2]!.issues).toMatchObject({ 'payload.password': expect.any(String) });
    expect(await m.client.db.findOneBy(m.entities.SecretEntity, { name: 'stripe-live' })).toBeNull();

    const r = await m.importer.import(owner, { format: 'json', content });
    expect(r.counts).toMatchObject({ created: 2, invalid: 2 });
    expect(r.results[1]!.sameValueAs).toEqual([{ id: r.results[0]!.secretId, name: 'stripe-live' }]);
    const created = (await m.client.db.find(m.entities.AuditEventEntity, { where: { targetId: r.results[0]!.secretId!, eventType: 'secret.created' } })) as any[];
    expect(created[0].metadata).toMatchObject({ source: 'import' });

    const again = await m.importer.import(owner, { format: 'json', content: JSON.stringify([{ name: 'stripe-live', typeKey: 'api-key', project: 'payments', environment: 'production', payload: { apiKey: 'imported-stripe-key-000222' } }]) });
    expect(again.results[0]).toMatchObject({ outcome: 'skipped' });
    const newer = await m.importer.import(owner, { format: 'json', onConflict: 'new_version', content: JSON.stringify([{ name: 'stripe-live', typeKey: 'api-key', project: 'payments', environment: 'production', payload: { apiKey: 'imported-stripe-key-000222' } }]) });
    expect(newer.results[0]).toMatchObject({ outcome: 'new_version' });
    expect((await m.secrets.detail(owner, r.results[0]!.secretId!)).activeVersion).toBe(2);

    const env = await m.importer.import(owner, { format: 'env', name: 'orders-env', project: 'orders', environment: 'staging', content: '# comment\nexport DATABASE_URL="postgres://x"\nAPI_TOKEN=abc123 # inline\nEMPTY=\n' });
    expect(env.results[0]).toMatchObject({ outcome: 'created' });
    expect((await m.secrets.retrieve(owner, { id: env.results[0]!.secretId! } as any)).payload).toEqual({ variables: { DATABASE_URL: 'postgres://x', API_TOKEN: 'abc123', EMPTY: '' } });
    const summary = (await m.client.db.find(m.entities.AuditEventEntity, { where: { eventType: 'secret.import_completed' } })) as any[];
    expect(summary.length).toBe(4);
    expect(JSON.stringify(summary)).not.toContain('imported-stripe-key');
  });

  it('export: off by default; requested, approved by someone else, encrypted with a passphrase, downloaded once', async () => {
    const ids = [(await m.client.db.findOneByOrFail(m.entities.SecretEntity, { name: 'stripe-live' }))!.id];
    await expect(m.exporter.request(owner, { secretIds: ids, reason: 'migrating to a new region' })).rejects.toMatchObject({ code: 'EXPORT_DISABLED' });
    m.config.config.secretExportEnabled = true;
    try {
      await expect(m.exporter.request(owner, { secretIds: ids, reason: 'short' })).rejects.toMatchObject({ details: { fields: { reason: expect.any(String) } } });
      const req = await m.exporter.request(owner, { secretIds: ids, reason: 'migrating to a new region' });
      expect(req).toMatchObject({ status: 'PENDING', secrets: [{ name: 'stripe-live' }], can: { decide: false, prepare: false } });
      await expect(m.exporter.decide(owner, { id: req.id }, 'APPROVED')).rejects.toMatchObject({ code: 'SEPARATION_OF_DUTIES' });
      await expect(m.exporter.prepare(owner, { id: req.id, passphrase: 'long enough passphrase' })).rejects.toMatchObject({ code: 'EXPORT_NOT_APPROVED' });
      expect(await m.exporter.decide(security, { id: req.id, note: 'ok for migration' }, 'APPROVED')).toMatchObject({ status: 'APPROVED', decidedBy: { name: security.user.fullName } });
      await expect(m.exporter.prepare(security, { id: req.id, passphrase: 'long enough passphrase' })).rejects.toMatchObject({ status: 403 });
      await expect(m.exporter.prepare(owner, { id: req.id, passphrase: 'short' })).rejects.toMatchObject({ details: { fields: { passphrase: expect.any(String) } } });
      const { downloadUrl, expiresAt } = await m.exporter.prepare(owner, { id: req.id, passphrase: 'correct horse battery staple' });
      expect(Date.parse(expiresAt) - Date.now()).toBeLessThanOrEqual(10 * 60_000);
      const token = downloadUrl.split('/').pop()!;
      const stored = JSON.stringify(await m.client.db.query('SELECT file FROM secret_export_requests WHERE id = $1', [req.id]));
      expect(stored).not.toContain('imported-stripe-key');

      const file = await m.exporter.download(owner, token);
      const key = scryptSync('correct horse battery staple', Buffer.from(file.kdf.salt, 'base64'), 32, { N: file.kdf.N, r: file.kdf.r, p: file.kdf.p, maxmem: 128 * file.kdf.N * file.kdf.r * 2 });
      const d = createDecipheriv('aes-256-gcm', key, Buffer.from(file.cipher.iv, 'base64'));
      d.setAAD(Buffer.from(file.exportId));
      d.setAuthTag(Buffer.from(file.cipher.tag, 'base64'));
      const plain = JSON.parse(Buffer.concat([d.update(Buffer.from(file.ciphertext, 'base64')), d.final()]).toString('utf8'));
      expect(plain.secrets).toEqual([expect.objectContaining({ name: 'stripe-live', typeKey: 'api-key', version: 2, payload: { apiKey: 'imported-stripe-key-000222' } })]);

      await expect(m.exporter.download(owner, token)).rejects.toMatchObject({ status: 404 });
      expect((await m.exporter.list(owner)).items[0]).toMatchObject({ status: 'DOWNLOADED' });
      expect(await events(ids[0]!)).toContain('secret.exported');
      expect(await events(req.id)).toEqual(['secret_export.requested', 'secret_export.approved', 'secret_export.prepared', 'secret_export.downloaded']);
    } finally {
      m.config.config.secretExportEnabled = false;
    }
  });
});
