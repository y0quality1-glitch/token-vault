import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';

/**
 * Just-in-time access requests against a real PostgreSQL database. Skipped unless
 * TEST_DATABASE_URL is set. The database is wiped and reseeded.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('just-in-time access requests', () => {
  let m: {
    client: typeof import('../src/db/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    jit: typeof import('../src/modules/grant-requests/grant-requests.service');
    broker: typeof import('../src/modules/broker/broker.service');
    crypto: typeof import('../src/lib/crypto');
  };
  let apiKey = '';

  // Admin context the way requireSession/requireOrg would build it.
  async function ctxFor(userId: string) {
    const user = (await m.repos.orgRepo.getUser(userId))!;
    const org = (await m.repos.orgRepo.getOrganization(m.seed.IDS.demoOrg))!;
    const member = (await m.repos.orgRepo.getMembership(userId, org.id))!;
    return { session: { tokenHash: 'x', userId, organizationId: org.id, createdAt: '', expiresAt: '' }, user, org, role: member.role };
  }
  const agent = () => m.repos.agentRepo.getAgent(m.seed.IDS.demoOrg, m.seed.IDS.agtAssistant).then((a) => a!);
  const execStaging = () =>
    m.broker.executeAgentRequest({
      authorization: `Bearer ${apiKey}`,
      orgHint: undefined,
      sourceIp: '127.0.0.1',
      source: 'agent-api',
      body: { integration_id: m.seed.IDS.intStaging, operation: 'github.repositories.read', resource: { repository: 'demo-org/demo-repo' } },
    });
  const request = (over: Record<string, unknown> = {}) =>
    agent().then((a) =>
      m.jit.createFromAgent(a, { integration_id: m.seed.IDS.intStaging, operations: ['github.repositories.read'], justification: 'Need repo metadata to draft release notes.', duration_minutes: 30, ...over }),
    );
  const error = (p: Promise<unknown>) => p.then(() => null, (e: { status?: number; message: string }) => e);

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    m = {
      client: await import('../src/db/client'),
      seed: await import('../src/store/seed'),
      repos: await import('../src/store/repos'),
      jit: await import('../src/modules/grant-requests/grant-requests.service'),
      broker: await import('../src/modules/broker/broker.service'),
      crypto: await import('../src/lib/crypto'),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    apiKey = cred.apiKey;
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('lets an agent request access, de-duplicates identical requests and refuses destructive operations', async () => {
    const first = await request();
    expect(first.status).toBe(201);
    expect(first.body).toMatchObject({ status: 'PENDING', operations: ['github.repositories.read'], requested_duration_minutes: 30 });
    const again = await request();
    expect(again).toMatchObject({ status: 200, body: { duplicate: true, access_request_id: first.body.access_request_id } });
    expect(await error(request({ operations: ['github.repositories.delete'] }))).toMatchObject({ status: 400, message: expect.stringMatching(/Destructive/) });
  });

  it('caps pending requests per agent', async () => {
    await request({ operations: ['github.issues.list'] });
    await request({ operations: ['github.contents.read'] });
    expect(await error(request({ operations: ['github.issues.create'] }))).toMatchObject({ status: 429 });
  });

  it('enforces separation of duties and never lets an approver widen a request', async () => {
    const pending = (await m.repos.grantRequestRepo.pendingForAgent(m.seed.IDS.agtAssistant)).find((r) => r.operations[0] === 'github.repositories.read')!;
    // The seeded agent is owned by the developer, so the developer may not approve it.
    expect(await error(m.jit.approve(await ctxFor(m.seed.IDS.developer), pending.id, { durationMinutes: 30 }))).toMatchObject({ status: 403 });
    expect(await error(m.jit.approve(await ctxFor(m.seed.IDS.securityAdmin), pending.id, { durationMinutes: 30, operations: ['github.repositories.read', 'github.issues.create'] }))).toMatchObject({ status: 400 });
  });

  it('approval creates a time-limited grant that authorizes the very next request', async () => {
    expect((await execStaging()).body.decision_code).toBe('GRANT_EXPIRED'); // seeded staging grant expired yesterday

    const pending = (await m.repos.grantRequestRepo.pendingForAgent(m.seed.IDS.agtAssistant)).find((r) => r.operations[0] === 'github.repositories.read')!;
    const before = Date.now();
    const decided = await m.jit.approve(await ctxFor(m.seed.IDS.securityAdmin), pending.id, { durationMinutes: 20, repositories: ['demo-org/demo-repo'], note: 'ok for today' });
    expect(decided).toMatchObject({ status: 'APPROVED', approvedDurationMinutes: 20, decidedBy: m.seed.IDS.securityAdmin });

    const grant = (await m.repos.grantRepo.getGrant(m.seed.IDS.demoOrg, decided.grantId!))!;
    expect(grant).toMatchObject({ storedStatus: 'ACTIVE', scopes: ['github.repositories.read'], resourceConstraints: { repositories: ['demo-org/demo-repo'] }, approvedBy: m.seed.IDS.securityAdmin });
    const ttl = new Date(grant.expiresAt).getTime() - before;
    expect(ttl).toBeGreaterThan(19 * 60_000);
    expect(ttl).toBeLessThanOrEqual(20 * 60_000 + 5_000);

    const after = await execStaging();
    expect(after.body.decision).toBe('ALLOW'); // execution may still fail here: no webhook runs in unit tests
    expect(after.body.grant_id).toBe(grant.id);

    // Decided requests cannot be decided again; the agent sees the outcome.
    expect(await error(m.jit.approve(await ctxFor(m.seed.IDS.securityAdmin), pending.id, { durationMinutes: 20 }))).toMatchObject({ status: 409 });
    expect(await m.jit.getForAgent(await agent(), pending.id)).toMatchObject({ status: 'APPROVED', grant_id: grant.id, grant_expires_at: grant.expiresAt });
  });

  it('rejects, and treats lapsed pending requests as expired', async () => {
    const pending = (await m.repos.grantRequestRepo.pendingForAgent(m.seed.IDS.agtAssistant)).find((r) => r.operations[0] === 'github.issues.list')!;
    expect(await m.jit.reject(await ctxFor(m.seed.IDS.owner), pending.id, { note: 'not needed' })).toMatchObject({ status: 'REJECTED', decisionNote: 'not needed' });

    const lapsed = (await m.repos.grantRequestRepo.pendingForAgent(m.seed.IDS.agtAssistant)).find((r) => r.operations[0] === 'github.contents.read')!;
    const { grantRequests } = await import('../src/db/schema');
    const { eq } = await import('drizzle-orm');
    await m.client.db.update(grantRequests).set({ expiresAt: new Date(Date.now() - 1000).toISOString() }).where(eq(grantRequests.id, lapsed.id));
    expect((await m.jit.toViews(m.seed.IDS.demoOrg, [(await m.repos.grantRequestRepo.getGrantRequest(m.seed.IDS.demoOrg, lapsed.id))!]))[0]!.status).toBe('EXPIRED');
    expect(await error(m.jit.approve(await ctxFor(m.seed.IDS.securityAdmin), lapsed.id, { durationMinutes: 30 }))).toMatchObject({ status: 409 });

    const events = await m.repos.auditRepo.listAuditEvents(m.seed.IDS.demoOrg, { eventType: 'grant_request.' }, 50);
    expect(events.items.map((e) => e.eventType)).toEqual(expect.arrayContaining(['grant_request.created', 'grant_request.approved', 'grant_request.rejected']));
  });
});
