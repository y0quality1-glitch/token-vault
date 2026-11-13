import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';

/**
 * Delegation to sub-agents against a real PostgreSQL database: creation can only narrow,
 * sub-agents are limited to their slice, revoking anything up the chain (or the parent
 * grant) stops them, and every record names the sub-agent. Skipped unless
 * TEST_DATABASE_URL is set. The database is wiped and reseeded. No webhook runs, so
 * authorized requests end in WEBHOOK_UNAVAILABLE (still decided ALLOW).
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

const ISSUER = 'https://login.acme.test';
const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
function userToken(sub: string, ttlS = 600) {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const nowS = Math.floor(Date.now() / 1000);
  const h = b64({ alg: 'ES256', typ: 'JWT' });
  const p = b64({ iss: ISSUER, aud: 'token-vault', sub, groups: [], iat: nowS, exp: nowS + ttlS });
  return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

suite('delegation to sub-agents', () => {
  let m: {
    client: typeof import('../src/databases/client');
    config: typeof import('../src/config');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    broker: typeof import('../src/services/brokerService/brokerService.service');
    crypto: typeof import('../src/lib/crypto');
    chain: typeof import('../src/services/auditService/chain');
    dlg: typeof import('../src/services/delegationService/delegationService.service');
  };
  let apiKey = '';
  let agent: Awaited<ReturnType<typeof import('../src/store/repos').agentRepo.getAgent>>;

  const exec = (token: string, operation = 'github.issues.create', extra: Record<string, unknown> = {}) =>
    m.broker.executeAgentRequest({
      authorization: `Bearer ${token}`,
      orgHint: undefined,
      sourceIp: '127.0.0.1',
      source: 'agent-api',
      body: { integration_id: m.seed.IDS.intDemo, operation, resource: { repository: 'demo-org/demo-repo' }, input: { title: 'From a sub-agent' }, ...extra },
    });
  const delegate = (body: Record<string, unknown>, caller: Parameters<typeof m.dlg.createDelegation>[1] = null) =>
    m.dlg.createDelegation(agent!, caller, { grant_id: m.seed.IDS.grtIssue, label: 'Triage helper', operations: ['github.issues.create'], ...body }) as Promise<{ status: number; body: { token: string; delegation_id: string; expires_at: string; resources: string[]; on_behalf_of: unknown } }>;
  const failure = (p: Promise<unknown>) => p.then(() => 'no error', (e: Error & { details?: unknown }) => `${e.message} ${JSON.stringify(e.details ?? '')}`);

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    m = {
      client: await import('../src/databases/client'),
      config: await import('../src/config'),
      seed: await import('../src/store/seed'),
      repos: await import('../src/store/repos'),
      broker: await import('../src/services/brokerService/brokerService.service'),
      crypto: await import('../src/lib/crypto'),
      chain: await import('../src/services/auditService/chain'),
      dlg: await import('../src/services/delegationService/delegationService.service'),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    m.broker.resetBrokerState();
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    apiKey = cred.apiKey;
    agent = await m.repos.agentRepo.getAgent(m.seed.IDS.demoOrg, m.seed.IDS.agtAssistant);
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { rateLimitPerMinute: 100, maxWritesPerHour: null, maxRequestsPerDay: null });
    const now = new Date().toISOString();
    await m.repos.userIssuerRepo.insertIssuer({ id: 'uis_dlg', organizationId: m.seed.IDS.demoOrg, name: 'Acme login', issuer: ISSUER, audience: 'token-vault', publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(), keyFingerprint: 'test', groupsClaim: 'groups', maxTokenLifetimeSeconds: 3600, enabled: true, createdAt: now, updatedAt: now, lastUsedAt: null });
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('a delegation can only narrow the grant', async () => {
    expect(await failure(delegate({ operations: ['github.contents.read'] }))).toContain('not granted');
    expect(await failure(delegate({ operations: ['github.repositories.delete'] }))).toMatch(/not granted|destructive/);
    expect(await failure(delegate({ resources: ['demo-org/other-repo'] }))).toContain('outside what');
    // Expiry never exceeds the grant's.
    const long = await delegate({ expires_in_seconds: 86_400 });
    const grant = (await m.repos.grantRepo.getGrant(m.seed.IDS.demoOrg, m.seed.IDS.grtIssue))!;
    expect(Date.parse(long.body.expires_at)).toBeLessThanOrEqual(Date.parse(grant.expiresAt));
    expect(long.body.resources).toEqual(['demo-org/demo-repo']); // empty means "as the grant", frozen at creation
  });

  it('a sub-agent runs only its slice, records itself, and stops at its request cap', async () => {
    const { status, body } = await delegate({ max_requests: 2 });
    expect(status).toBe(201);
    expect(body.token).toMatch(/^tvdt_/);
    const first = await exec(body.token);
    expect(first.body).toMatchObject({ decision: 'ALLOW', delegation: { delegation_id: body.delegation_id, label: 'Triage helper', used: 1, max_requests: 2 } });
    const record = (await m.repos.auditRepo.getAccessRequest(m.seed.IDS.demoOrg, first.body.request_id))!;
    expect(record).toMatchObject({ agentId: m.seed.IDS.agtAssistant, delegation: { id: body.delegation_id, label: 'Triage helper', depth: 1 } });
    expect(record.checks[0]?.detail).toContain('sub-agent "Triage helper"');

    expect((await exec(body.token, 'github.issues.list')).body).toMatchObject({ decision_code: 'DELEGATION_DENIED' });
    expect((await exec(body.token)).body.decision).toBe('ALLOW');
    expect((await exec(body.token)).body.reason).toContain('all 2 requests');
    // The parent agent itself is unaffected.
    expect((await exec(apiKey, 'github.issues.list')).body.decision).toBe('ALLOW');

    const caps = await m.broker.getCapabilities(`Bearer ${body.token}`);
    expect(caps.status).toBe(200);
    if (caps.status === 200) {
      expect(caps.body.grants.map((g) => g.grant_id)).toEqual([m.seed.IDS.grtIssue]);
      expect(caps.body.grants[0]!.operations).toEqual(['github.issues.create']);
      expect(caps.body.delegation).toMatchObject({ delegation_id: body.delegation_id, used: 2, max_requests: 2 });
    }
  });

  it('sub-agents can delegate further, only narrower, and revoking up the chain stops everything below', async () => {
    const parent = await delegate({ operations: ['github.issues.create', 'github.issues.list'], label: 'Coordinator' });
    const resolved = await m.dlg.resolveDelegationToken(parent.body.token);
    if (!resolved.ok) throw new Error(resolved.reason);
    expect(await failure(delegate({ operations: ['github.repositories.read'] }, resolved.ctx))).toContain('not in this delegation');
    const child = await delegate({ operations: ['github.issues.list'], label: 'Reader' }, resolved.ctx);
    expect(child.status).toBe(201);
    expect((await exec(child.body.token, 'github.issues.list')).body.decision).toBe('ALLOW');

    // The coordinator sees what it delegated. Revoking the coordinator stops its child too.
    expect((await m.dlg.listForAgent(agent!, resolved.ctx)).map((d) => d.delegation_id)).toEqual([child.body.delegation_id]);
    await m.repos.delegationRepo.revoke(parent.body.delegation_id, { revokedAt: new Date().toISOString(), revokedBy: m.seed.IDS.securityAdmin, revocationReason: 'test' });
    const stopped = await exec(child.body.token, 'github.issues.list');
    expect(stopped.status).toBe(403);
    expect(stopped.body).toMatchObject({ decision_code: 'DELEGATION_REVOKED', reason: expect.stringContaining(parent.body.delegation_id) });
    expect((await m.repos.auditRepo.getAccessRequest(m.seed.IDS.demoOrg, stopped.body.request_id))?.delegation?.id).toBe(child.body.delegation_id);
  });

  it('a delegation made for a user acts only for that user, and never outlives the token', async () => {
    const forAda = await delegate({ on_behalf_of: userToken('u_ada', 300), expires_in_seconds: 3600 });
    expect(forAda.body.on_behalf_of).toMatchObject({ sub: 'u_ada' });
    expect(Date.parse(forAda.body.expires_at)).toBeLessThanOrEqual(Date.now() + 301_000);
    expect((await exec(forAda.body.token)).body).toMatchObject({ decision: 'ALLOW', acting_for: { sub: 'u_ada' } });
    expect((await exec(forAda.body.token, 'github.issues.create', { on_behalf_of: userToken('u_bob') })).body.decision_code).toBe('DELEGATION_DENIED');
  });

  it('revoking the parent grant stops every delegation made from it; records keep the chain valid', async () => {
    const d = await delegate({});
    expect((await exec(d.body.token)).body.decision).toBe('ALLOW');
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { storedStatus: 'REVOKED', revokedAt: new Date().toISOString() });
    expect((await exec(d.body.token)).body.decision_code).toBe('GRANT_REVOKED');
    const { rows, legacy } = await m.repos.auditRepo.chainRows('access_requests', m.seed.IDS.demoOrg);
    expect(rows.some((r) => r.delegation)).toBe(true);
    expect(m.chain.verify(m.config.config.auditSigningKey, 'access_requests', m.seed.IDS.demoOrg, rows, legacy)).toMatchObject({ ok: true });
  });
});
