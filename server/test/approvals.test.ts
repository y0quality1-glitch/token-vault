import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';

/**
 * Operation approvals (REQUIRE_APPROVAL policies) against a real PostgreSQL database.
 * Skipped unless TEST_DATABASE_URL is set. The database is wiped and reseeded.
 * No webhook runs here, so approved requests end in WEBHOOK_UNAVAILABLE after the
 * decision: what matters is the decision and the approval's state.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('operation approvals', () => {
  let m: {
    client: typeof import('../src/db/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    approvals: typeof import('../src/modules/approvals/approvals.service');
    broker: typeof import('../src/modules/broker/broker.service');
    crypto: typeof import('../src/lib/crypto');
  };
  let apiKey = '';

  async function ctxFor(userId: string) {
    const user = (await m.repos.orgRepo.getUser(userId))!;
    const org = (await m.repos.orgRepo.getOrganization(m.seed.IDS.demoOrg))!;
    const member = (await m.repos.orgRepo.getMembership(userId, org.id))!;
    return { session: { tokenHash: 'x', userId, organizationId: org.id, createdAt: '', expiresAt: '' }, user, org, role: member.role };
  }
  const createIssue = (title: string, extra: Record<string, unknown> = {}) =>
    m.broker.executeAgentRequest({
      authorization: `Bearer ${apiKey}`,
      orgHint: undefined,
      sourceIp: '127.0.0.1',
      source: 'agent-api',
      body: { integration_id: m.seed.IDS.intDemo, operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input: { title, body: '' }, ...extra },
    });
  const error = (p: Promise<unknown>) => p.then(() => null, (e: { status?: number; message: string }) => e);

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    m = {
      client: await import('../src/db/client'),
      seed: await import('../src/store/seed'),
      repos: await import('../src/store/repos'),
      approvals: await import('../src/modules/approvals/approvals.service'),
      broker: await import('../src/modules/broker/broker.service'),
      crypto: await import('../src/lib/crypto'),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    m.broker.resetBrokerState();
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    apiKey = cred.apiKey;
    const now = new Date().toISOString();
    await m.repos.policyRepo.insertPolicy({
      id: 'pol_approve_issues',
      organizationId: m.seed.IDS.demoOrg,
      name: 'Approve every new issue',
      description: '',
      effect: 'REQUIRE_APPROVAL',
      priority: 30,
      enabled: true,
      conditions: { agentSelector: { type: 'any' }, integrationSelector: { type: 'provider', value: 'github' }, operations: ['github.issues.create'], environment: 'any', timeWindow: null, sourceCidrs: [] },
      createdAt: now,
      updatedAt: now,
    });
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('holds the request, records one pending approval and does not duplicate it', async () => {
    const first = await createIssue('Release checklist');
    expect(first.status).toBe(202);
    expect(first.body).toMatchObject({ decision: 'DENY', decision_code: 'APPROVAL_REQUIRED', execution: { status: 'NOT_EXECUTED', webhook_status: 'NOT_CALLED' }, approval: { status: 'PENDING' } });
    const again = await createIssue('Release checklist');
    expect(again.body.approval?.approval_id).toBe(first.body.approval?.approval_id);

    const stored = (await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, first.body.approval!.approval_id))!;
    expect(stored).toMatchObject({ status: 'PENDING', operation: 'github.issues.create', input: { title: 'Release checklist', body: '' }, policyName: 'Approve every new issue', requestedByRequestId: first.body.request_id });
  });

  it('enforces separation of duties', async () => {
    const [pending] = await m.repos.approvalRepo.pendingForAgent(m.seed.IDS.agtAssistant);
    // The seeded agent is owned by the developer.
    expect(await error(m.approvals.approve(await ctxFor(m.seed.IDS.developer), pending!.id, {}))).toMatchObject({ status: 403 });
  });

  it('runs exactly the approved request, once', async () => {
    const [pending] = await m.repos.approvalRepo.pendingForAgent(m.seed.IDS.agtAssistant);
    const decided = await m.approvals.approve(await ctxFor(m.seed.IDS.securityAdmin), pending!.id, { note: 'fine' });
    expect(decided).toMatchObject({ status: 'APPROVED', decidedBy: m.seed.IDS.securityAdmin });

    // A different input is a different request: it needs its own approval.
    expect((await createIssue('Something else')).body.decision_code).toBe('APPROVAL_REQUIRED');
    // An approval_id for another request is refused.
    expect((await createIssue('Another title', { approval_id: pending!.id })).body.decision_code).toBe('APPROVAL_INVALID');

    // Re-sending the approved request runs it (the webhook is not running in this test).
    const run = await createIssue('Release checklist');
    expect(run.body).toMatchObject({ decision: 'ALLOW', approval: { approval_id: pending!.id, status: 'EXECUTED' } });
    expect(run.body.checks.find((c) => c.step === 11)).toMatchObject({ passed: true, detail: expect.stringContaining('Approved by') });
    expect(await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, pending!.id)).toMatchObject({ status: 'EXECUTED', executedRequestId: run.body.request_id });

    // Used once: the explicit approval_id is now refused, and a plain re-send asks again.
    expect((await createIssue('Release checklist', { approval_id: pending!.id })).body.decision_code).toBe('APPROVAL_INVALID');
    expect((await createIssue('Release checklist')).body).toMatchObject({ decision_code: 'APPROVAL_REQUIRED', approval: { status: 'PENDING' } });
  });

  it('answers a rejected request with APPROVAL_REJECTED instead of asking again', async () => {
    const held = await createIssue('Delete the old docs');
    await m.approvals.reject(await ctxFor(m.seed.IDS.securityAdmin), held.body.approval!.approval_id, { note: 'not now' });
    const again = await createIssue('Delete the old docs');
    expect(again.status).toBe(403);
    expect(again.body).toMatchObject({ decision_code: 'APPROVAL_REJECTED', reason: expect.stringContaining('not now') });
    expect(await error(m.approvals.approve(await ctxFor(m.seed.IDS.securityAdmin), held.body.approval!.approval_id, {}))).toMatchObject({ status: 409 });
  });

  it('revoking the grant beats an approval', async () => {
    const held = await createIssue('After revocation');
    await m.approvals.approve(await ctxFor(m.seed.IDS.securityAdmin), held.body.approval!.approval_id, {});
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { storedStatus: 'REVOKED', revokedAt: new Date().toISOString() });
    const run = await createIssue('After revocation');
    expect(run.body.decision_code).toBe('GRANT_REVOKED');
    // The approval was not used up by the denied request.
    expect(await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, held.body.approval!.approval_id)).toMatchObject({ status: 'APPROVED' });
  });
});
