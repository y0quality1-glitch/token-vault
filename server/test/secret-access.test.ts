import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import { BUILTIN_SECRET_TYPES, summarizeSecretPayload, validateSecretPayload, validateSecretTypeDefinition, type SecretPayload } from '@token-vault/shared';

/**
 * Secret Management phase 3: agents retrieve secrets with their own key, only under a grant
 * (default deny), limited to the grant's fields, versions and source IPs, optionally held for
 * human approval (single use, not approvable by the agent's owner). Every decision is audited.
 * Real PostgreSQL; the customer webhook is an in-memory stand-in. Skipped without TEST_DATABASE_URL.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

const vault = vi.hoisted(() => ({ values: new Map<string, { org: string; secret: string; version: number; payload: Record<string, unknown> }>(), reads: 0 }));
vi.mock('../src/services/webhookService/webhook.client', async (orig) => {
  const real = await orig<typeof import('../src/services/webhookService/webhook.client')>();
  const types = new Map(BUILTIN_SECRET_TYPES.map((t) => [t.key, validateSecretTypeDefinition(t)]));
  let n = 0;
  return {
    ...real,
    callWebhook: async (_wh: unknown, _m: string, path: string, body: Record<string, any>) => {
      if (path === '/internal/v1/secrets/store') {
        const { value } = validateSecretPayload(types.get(body.type_key)!, body.payload);
        const ref = `sval_${++n}`;
        vault.values.set(ref, { org: body.org_id, secret: body.secret_id, version: body.version, payload: value });
        return { status: 201, latencyMs: 1, body: { value_ref: ref, version: body.version, fingerprint: `fp_${n}`, summary: summarizeSecretPayload(types.get(body.type_key)!, value as SecretPayload), type_version: 1 } };
      }
      if (path === '/internal/v1/secrets/read') {
        vault.reads++;
        const v = vault.values.get(body.value_ref);
        if (!v || v.org !== body.org_id || v.secret !== body.secret_id) return { status: 404, latencyMs: 1, body: {} };
        return { status: 200, latencyMs: 1, body: { version: v.version, payload: Object.fromEntries(Object.entries(v.payload).filter(([k]) => !body.fields || body.fields.includes(k))) } };
      }
      if (path === '/internal/v1/secrets/destroy') {
        const destroyed = (body.value_refs as string[]).filter((r) => vault.values.get(r)?.secret === body.secret_id);
        destroyed.forEach((r) => vault.values.delete(r));
        return { status: 200, latencyMs: 1, body: { destroyed } };
      }
      return { status: 404, latencyMs: 1, body: {} };
    },
  };
});

const PASSWORD = 'agent-visible-password-0001';

suite('Secret access for agents', () => {
  let m: {
    client: typeof import('../src/databases/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    crypto: typeof import('../src/lib/crypto');
    entities: typeof import('../src/entities');
    secrets: InstanceType<typeof import('../src/services/secretService/secretService.service').default>;
    access: InstanceType<typeof import('../src/services/secretAccessService/secretAccessService.service').default>;
  };
  let owner: any;
  let agentKey = '';
  let agentId = '';
  let db: { id: string };
  const auth = () => `Bearer ${agentKey}`;
  const retrieve = (body: Record<string, unknown>, sourceIp = '127.0.0.1') => m.access.agentRetrieve({ authorization: auth(), sourceIp, body });
  const lastEvent = async () => (await m.client.db.find(m.entities.AuditEventEntity, { where: { organizationId: m.seed.IDS.demoOrg }, order: { createdAt: 'DESC' }, take: 1 }))[0] as any;

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    process.env.CMS_CATALOG_URL = '';
    m = {
      client: await import('../src/databases/client'),
      seed: await import('../src/store/seed'),
      repos: await import('../src/store/repos'),
      crypto: await import('../src/lib/crypto'),
      entities: await import('../src/entities'),
      secrets: new (await import('../src/services/secretService/secretService.service')).default(),
      access: new (await import('../src/services/secretAccessService/secretAccessService.service')).default(),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    agentId = m.seed.IDS.agtAssistant;
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(agentId, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    agentKey = cred.apiKey;
    owner = { user: { id: m.seed.IDS.owner, fullName: 'Avery Chen' }, org: { id: m.seed.IDS.demoOrg, name: 'Demo Organization' }, role: 'OWNER' };
    db = await m.secrets.create(owner, { name: 'orders-db', typeKey: 'postgresql', project: 'shop', environment: 'production', metadata: { host: 'db.internal' }, payload: { username: 'orders', password: PASSWORD } } as any);
  }, 60_000);
  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('denies by default: no grant, an unknown secret or a bad key all reveal nothing', async () => {
    await expect(retrieve({ secret_id: db.id })).rejects.toMatchObject({ status: 403, code: 'SECRET_ACCESS_DENIED' });
    expect(await lastEvent()).toMatchObject({ eventType: 'secret.access_denied', actorType: 'AGENT', outcome: 'DENIED', metadata: { reasonCode: 'SECRET_ACCESS_DENIED' } });
    await expect(retrieve({ secret_id: 'sec_doesnotexist0000' })).rejects.toMatchObject({ code: 'SECRET_ACCESS_DENIED' });
    await expect(m.access.agentRetrieve({ authorization: 'Bearer tvak_nope_nope', sourceIp: '127.0.0.1', body: { secret_id: db.id } })).rejects.toMatchObject({ status: 401 });
    expect(vault.reads).toBe(0);
    expect((await m.access.agentList(auth())).items).toEqual([]);
  });

  it('a grant on one secret lets the agent read it (only the allowed fields), and records the use', async () => {
    const g = await m.access.create(owner, { agentId, secretId: db.id, fields: ['password'] });
    expect(g).toMatchObject({ agent: { name: 'GitHub Assistant' }, secret: { id: db.id, name: 'orders-db' }, fields: ['password'], status: 'ACTIVE' });
    expect((await lastEvent()).eventType).toBe('secret.access_granted');

    const r = await retrieve({ name: 'orders-db', reason: 'deploy' });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ secret_id: db.id, version: 1, payload: { password: PASSWORD }, grant_id: g.id });
    expect(Object.keys((r.body as any).payload)).toEqual(['password']);
    const ev = await lastEvent();
    expect(ev).toMatchObject({ eventType: 'secret.retrieved', actorType: 'AGENT', actorId: agentId, metadata: { grantId: g.id, fieldsRequested: ['password'], reason: 'deploy' } });
    expect(JSON.stringify(ev)).not.toContain(PASSWORD);
    await expect(retrieve({ secret_id: db.id, fields: ['username'] })).rejects.toMatchObject({ code: 'SECRET_FIELDS_NOT_PERMITTED' });
    await expect(retrieve({ secret_id: db.id, fields: ['nope'] })).rejects.toMatchObject({ code: 'SECRET_FIELD_UNKNOWN' });

    const listed = (await m.access.agentList(auth())).items;
    expect(listed).toEqual([expect.objectContaining({ secret_id: db.id, fields: ['password'], versions: 'ACTIVE', requires_approval: false })]);
    expect(JSON.stringify(listed)).not.toContain(PASSWORD);
    expect((await m.access.list(m.seed.IDS.demoOrg, { secretId: db.id })).items[0]).toMatchObject({ useCount: 1, lastUsedAt: expect.any(String) });
  });

  it('only the active version unless the grant allows any; older versions need versions ANY', async () => {
    await m.secrets.updateValue(owner, { id: db.id, payload: { username: 'orders', password: 'second-value' } } as any);
    await expect(retrieve({ secret_id: db.id, version: 1 })).rejects.toMatchObject({ code: 'SECRET_VERSION_NOT_PERMITTED' });
    expect(((await retrieve({ secret_id: db.id })).body as any).payload.password).toBe('second-value');

    // A rotation opens a grace period: the version it replaced stays readable (only that one), until the grace ends.
    await m.secrets.rotate(owner, { id: db.id, payload: { username: 'orders', password: 'third-value' } } as any);
    expect(((await retrieve({ secret_id: db.id, version: 2 })).body as any).payload.password).toBe('second-value');
    await expect(retrieve({ secret_id: db.id, version: 1 })).rejects.toMatchObject({ code: 'SECRET_VERSION_NOT_PERMITTED' });
    await m.client.db.query(`UPDATE secrets SET rotation_grace_hours = 0 WHERE id = $1`, [db.id]);
    await expect(retrieve({ secret_id: db.id, version: 2 })).rejects.toMatchObject({ code: 'SECRET_VERSION_NOT_PERMITTED' });
  });

  it('a selector grant covers every matching secret, also ones created later; source IPs are enforced', async () => {
    const g = await m.access.create(owner, { agentId, selector: { project: 'payments', environment: 'production' }, allowedCidrs: ['10.0.0.0/8'] });
    const later = await m.secrets.create(owner, { name: 'stripe', typeKey: 'api-key', project: 'payments', environment: 'production', payload: { apiKey: 'test-api-key-0123456789abcdef' } } as any);
    await expect(retrieve({ secret_id: later.id })).rejects.toMatchObject({ code: 'IP_NOT_ALLOWED' });
    expect(((await retrieve({ secret_id: later.id }, '10.1.2.3')).body as any).payload.apiKey).toBe('test-api-key-0123456789abcdef');
    expect((await m.access.list(m.seed.IDS.demoOrg, { secretId: later.id })).items.map((x) => x.id)).toEqual([g.id]);
    // Another project is not covered.
    const other = await m.secrets.create(owner, { name: 'stripe', typeKey: 'api-key', project: 'billing', environment: 'production', payload: { apiKey: 'test-api-key-other0000000000' } } as any);
    await expect(retrieve({ secret_id: other.id }, '10.1.2.3')).rejects.toMatchObject({ code: 'SECRET_ACCESS_DENIED' });
    // Two secrets share the name across projects: a name alone is ambiguous.
    await expect(retrieve({ name: 'stripe' }, '10.1.2.3')).rejects.toMatchObject({ code: 'SECRET_AMBIGUOUS' });
    await m.access.revoke(owner, { id: g.id, reason: 'done' });
    await expect(retrieve({ secret_id: later.id }, '10.1.2.3')).rejects.toMatchObject({ code: 'SECRET_ACCESS_DENIED' });
  });

  it('held for approval: one exact request, approved by someone other than the agent owner, used once', async () => {
    const tls = await m.secrets.create(owner, { name: 'signing-key', typeKey: 'hmac-secret', project: 'shop', environment: 'production', payload: { secret: 'h'.repeat(40) } } as any);
    await m.access.create(owner, { agentId, secretId: tls.id, requireApproval: true });
    const held = await retrieve({ secret_id: tls.id, reason: 'sign release' });
    expect(held).toMatchObject({ status: 202, body: { decision_code: 'APPROVAL_REQUIRED', status: 'PENDING' } });
    const approvalId = (held.body as any).approval_id;
    expect(vault.reads).toBeGreaterThan(0);
    const readsBefore = vault.reads;
    expect(await retrieve({ secret_id: tls.id, approval_id: approvalId })).toMatchObject({ status: 202 }); // still pending
    expect(vault.reads).toBe(readsBefore); // nothing read while held

    // The agent's owner (the developer) cannot approve, even with a powerful role.
    const agentOwner = { ...owner, user: { id: m.seed.IDS.developer, fullName: 'Riley Morgan' } };
    await expect(m.access.decide(agentOwner, { id: approvalId }, 'APPROVED')).rejects.toMatchObject({ status: 403 });
    expect(await m.access.decide(owner, { id: approvalId, note: 'ok' }, 'APPROVED')).toMatchObject({ status: 'APPROVED', decidedBy: { name: 'Avery Chen' } });

    // Only for the same request.
    await expect(retrieve({ secret_id: tls.id, version: 1, approval_id: approvalId })).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    const ok = await retrieve({ secret_id: tls.id, approval_id: approvalId });
    expect(ok).toMatchObject({ status: 200, body: { payload: { secret: 'h'.repeat(40) } } });
    expect((await lastEvent()).metadata).toMatchObject({ approvalId });
    await expect(retrieve({ secret_id: tls.id, approval_id: approvalId })).rejects.toMatchObject({ code: 'APPROVAL_USED' });

    // Rejected requests stay rejected.
    const again = (await retrieve({ secret_id: tls.id })).body as any;
    await m.access.decide(owner, { id: again.approval_id, note: 'not now' }, 'REJECTED');
    await expect(retrieve({ secret_id: tls.id, approval_id: again.approval_id })).rejects.toMatchObject({ code: 'APPROVAL_REJECTED' });
    expect((await m.access.listApprovals(m.seed.IDS.demoOrg)).items.map((a) => a.status).sort()).toEqual(['REJECTED', 'USED']);
  });

  it('a revoked or deleted secret, a disabled agent and an emergency stop end access', async () => {
    await m.secrets.revoke(owner, { id: db.id } as any);
    await expect(retrieve({ secret_id: db.id })).rejects.toMatchObject({ code: 'SECRET_NOT_ACTIVE' });
    await m.secrets.remove(owner, db.id);
    expect((await m.access.list(m.seed.IDS.demoOrg, { agentId })).items.find((g) => g.secret?.id === db.id)).toMatchObject({ status: 'REVOKED', revocationReason: 'Secret deleted' });

    const s = await m.secrets.create(owner, { name: 'smtp', typeKey: 'smtp', project: 'shop', environment: 'production', metadata: { host: 'mail.internal' }, payload: { username: 'noreply', password: 'mail-password' } } as any);
    await m.access.create(owner, { agentId, secretId: s.id });
    expect((await retrieve({ secret_id: s.id })).status).toBe(200);

    await m.repos.orgRepo.updateOrganization(m.seed.IDS.demoOrg, { emergencyStoppedAt: new Date().toISOString() });
    await expect(retrieve({ secret_id: s.id })).rejects.toMatchObject({ code: 'EMERGENCY_STOP' });
    await m.repos.orgRepo.updateOrganization(m.seed.IDS.demoOrg, { emergencyStoppedAt: null });

    await m.repos.agentRepo.updateAgent(agentId, { status: 'DISABLED' });
    await expect(retrieve({ secret_id: s.id })).rejects.toMatchObject({ code: 'AGENT_DISABLED' });
    expect((await m.access.agentList(auth())).items).toEqual([]);
    await m.repos.agentRepo.updateAgent(agentId, { status: 'ACTIVE' });
  });

  it('refuses inconsistent grants', async () => {
    await expect(m.access.create(owner, { agentId })).rejects.toMatchObject({ status: 400, details: { fields: { secretId: expect.any(String) } } });
    await expect(m.access.create(owner, { agentId, selector: { project: 'shop' }, fields: ['password'] })).rejects.toMatchObject({ details: { fields: { fields: 'Field limits need one secret, or a selector with a secret type' } } });
    await expect(m.access.create(owner, { agentId, selector: { typeKey: 'postgresql' }, fields: ['nope'] })).rejects.toMatchObject({ details: { fields: { fields: 'Not fields of this secret type: nope' } } });
    await expect(m.access.create(owner, { agentId: 'agt_unknown', selector: { project: 'shop' } })).rejects.toMatchObject({ details: { fields: { agentId: 'Unknown agent' } } });
  });
});
