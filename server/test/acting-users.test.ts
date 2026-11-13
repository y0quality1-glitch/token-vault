import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

/**
 * Acting on behalf of a user, against a real PostgreSQL database: user tokens verified
 * against a registered issuer, grants that require (or refuse) a user, approvals bound to
 * the user, and the user recorded in the tamper-evident access log. Skipped unless
 * TEST_DATABASE_URL is set. The database is wiped and reseeded. No webhook runs, so
 * authorized requests end in WEBHOOK_UNAVAILABLE (still decided ALLOW).
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

const ISSUER = 'https://login.acme.test';
const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });

function userToken(sub: string, extra: Record<string, unknown> = {}, key: KeyObject = keys.privateKey) {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const nowS = Math.floor(Date.now() / 1000);
  const h = b64({ alg: 'ES256', typ: 'JWT' });
  const p = b64({ iss: ISSUER, aud: 'token-vault-demo', sub, email: `${sub}@acme.test`, groups: ['engineering'], iat: nowS, exp: nowS + 300, ...extra });
  return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

suite('acting on behalf of a user', () => {
  let m: {
    client: typeof import('../src/databases/client');
    config: typeof import('../src/config');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    broker: typeof import('../src/services/brokerService/brokerService.service');
    crypto: typeof import('../src/lib/crypto');
    chain: typeof import('../src/services/auditService/chain');
  };
  let apiKey = '';

  const exec = (onBehalfOf?: string, extra: Record<string, unknown> = {}) =>
    m.broker.executeAgentRequest({
      authorization: `Bearer ${apiKey}`,
      orgHint: undefined,
      sourceIp: '127.0.0.1',
      source: 'agent-api',
      body: { integration_id: m.seed.IDS.intDemo, operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input: { title: 'For a user' }, ...(onBehalfOf ? { on_behalf_of: onBehalfOf } : {}), ...extra },
    });

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
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    m.broker.resetBrokerState();
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    apiKey = cred.apiKey;
    const now = new Date().toISOString();
    await m.repos.userIssuerRepo.insertIssuer({
      id: 'uis_test',
      organizationId: m.seed.IDS.demoOrg,
      name: 'Acme login',
      issuer: ISSUER,
      audience: 'token-vault-demo',
      publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      keyFingerprint: 'test',
      groupsClaim: 'groups',
      maxTokenLifetimeSeconds: 3600,
      enabled: true,
      createdAt: now,
      updatedAt: now,
      lastUsedAt: null,
    });
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { rateLimitPerMinute: 100, maxWritesPerHour: null, maxRequestsPerDay: null });
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('records the verified user on the decision and in the access log', async () => {
    const r = await exec(userToken('ada'));
    expect(r.body).toMatchObject({ decision: 'ALLOW', acting_for: { sub: 'ada', email: 'ada@acme.test', issuer: ISSUER } });
    const record = (await m.repos.auditRepo.getAccessRequest(m.seed.IDS.demoOrg, r.body.request_id))!;
    expect(record.onBehalfOf).toMatchObject({ sub: 'ada', groups: ['engineering'], issuerId: 'uis_test' });
    expect(record.checks.find((c) => c.name === 'Acting user')?.detail).toContain('ada@acme.test');
    expect((await m.repos.userIssuerRepo.getIssuer(m.seed.IDS.demoOrg, 'uis_test'))?.lastUsedAt).toBeTruthy();
    const { items } = await m.repos.auditRepo.listAccessRequests(m.seed.IDS.demoOrg, { user: 'ADA@acme' }, 50);
    expect(items.map((i) => i.id)).toContain(r.body.request_id);
  });

  it('denies (and records) a forged or foreign user token without running anything', async () => {
    const forged = await exec(userToken('ada', {}, generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey));
    expect(forged.status).toBe(403);
    expect(forged.body).toMatchObject({ decision: 'DENY', decision_code: 'USER_TOKEN_INVALID', execution: { status: 'NOT_EXECUTED' } });
    expect((await exec(userToken('ada', { iss: 'https://evil.test' }))).body.reason).toContain('not registered');
    expect((await m.repos.auditRepo.getAccessRequest(m.seed.IDS.demoOrg, forged.body.request_id))?.decisionCode).toBe('USER_TOKEN_INVALID');
  });

  it("a grant that requires a user denies the agent acting for itself; the user's groups and permissions narrow it", async () => {
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { onBehalfOf: 'REQUIRED', allowedUserGroups: ['engineering'] });
    expect((await exec()).body.decision_code).toBe('USER_REQUIRED');
    expect((await exec(userToken('ada'))).body.decision).toBe('ALLOW');
    expect((await exec(userToken('bob', { groups: ['sales'] }))).body.decision_code).toBe('USER_NOT_ALLOWED');
    expect((await exec(userToken('ada', { token_vault: { operations: ['risk:read'] } }))).body.decision_code).toBe('USER_PERMISSION_DENIED');
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { onBehalfOf: 'ALLOWED', allowedUserGroups: [] });
  });

  it('an approval given for one user cannot run for another', async () => {
    const now = new Date().toISOString();
    await m.repos.policyRepo.insertPolicy({
      id: 'pol_user_approval',
      organizationId: m.seed.IDS.demoOrg,
      name: 'Approve issues created for users',
      description: '',
      effect: 'REQUIRE_APPROVAL',
      priority: 50,
      enabled: true,
      conditions: { agentSelector: { type: 'agent', value: m.seed.IDS.agtAssistant }, integrationSelector: { type: 'any' }, operations: ['github.issues.create'], environment: 'any', arguments: [{ field: 'user.sub', op: 'not_equals', value: '' }] },
      createdAt: now,
      updatedAt: now,
    });
    const held = await exec(userToken('ada'));
    expect(held.status).toBe(202);
    const approvalId = held.body.approval!.approval_id;
    expect((await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, approvalId))?.onBehalfOf).toMatchObject({ sub: 'ada' });
    // The agent acting for itself is not held by this policy (no user).
    expect((await exec()).body.decision).toBe('ALLOW');
    await m.repos.approvalRepo.decideApproval(approvalId, { status: 'APPROVED', decidedBy: m.seed.IDS.securityAdmin, decidedAt: now, decisionNote: null, expiresAt: new Date(Date.now() + 15 * 60_000).toISOString() });

    const other = await exec(userToken('carol'), { approval_id: approvalId });
    expect(other.body).toMatchObject({ decision_code: 'APPROVAL_INVALID' });
    expect(other.body.reason).toContain('user or sub-agent differ');
    expect((await exec(userToken('ada'), { approval_id: approvalId })).body).toMatchObject({ decision: 'ALLOW', approval: { status: 'EXECUTED' }, acting_for: { sub: 'ada' } });
  });

  it('records with and without a user keep the audit chain valid', async () => {
    const { rows, legacy } = await m.repos.auditRepo.chainRows('access_requests', m.seed.IDS.demoOrg);
    expect(rows.some((r) => r.onBehalfOf)).toBe(true);
    expect(rows.some((r) => !r.onBehalfOf)).toBe(true);
    expect(m.chain.verify(m.config.config.auditSigningKey, 'access_requests', m.seed.IDS.demoOrg, rows, legacy)).toMatchObject({ ok: true });
  });
});
