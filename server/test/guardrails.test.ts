import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';

/**
 * Budgets and the emergency stop against a real PostgreSQL database. Skipped unless
 * TEST_DATABASE_URL is set. The database is wiped and reseeded. No webhook runs, so
 * authorized requests end in WEBHOOK_UNAVAILABLE: they are still authorized (ALLOW) and
 * count against budgets.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('budgets and emergency stop', () => {
  let m: {
    client: typeof import('../src/db/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    broker: typeof import('../src/modules/broker/broker.service');
    crypto: typeof import('../src/lib/crypto');
  };
  let apiKey = '';

  const exec = (operation: string, input: Record<string, unknown> = {}) =>
    m.broker.executeAgentRequest({
      authorization: `Bearer ${apiKey}`,
      orgHint: undefined,
      sourceIp: '127.0.0.1',
      source: 'agent-api',
      body: { integration_id: m.seed.IDS.intDemo, operation, resource: { repository: 'demo-org/demo-repo' }, input },
    });

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    m = {
      client: await import('../src/db/client'),
      seed: await import('../src/store/seed'),
      repos: await import('../src/store/repos'),
      broker: await import('../src/modules/broker/broker.service'),
      crypto: await import('../src/lib/crypto'),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    m.broker.resetBrokerState();
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    apiKey = cred.apiKey;
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  // The seeded demo history already has recent authorized requests on this grant; they count too.
  async function usageNow() {
    const g = (await m.repos.grantRepo.getGrant(m.seed.IDS.demoOrg, m.seed.IDS.grtIssue))!;
    const withBudgets = { ...g, maxRequestsPerDay: g.maxRequestsPerDay ?? 1, maxWritesPerHour: g.maxWritesPerHour ?? 1 };
    return (await m.broker.budgetUsageFor([withBudgets])).get(g.id)!;
  }

  it('counts writes per hour from the access log, and leaves reads alone', async () => {
    const before = await usageNow();
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { maxWritesPerHour: before.writesLastHour + 2, rateLimitPerMinute: 100 });
    expect((await exec('github.issues.create', { title: 'one' })).body.decision).toBe('ALLOW');
    expect((await exec('github.issues.create', { title: 'two' })).body.decision).toBe('ALLOW');
    const third = await exec('github.issues.create', { title: 'three' });
    expect(third.status).toBe(429);
    expect(third.body).toMatchObject({ decision: 'DENY', decision_code: 'BUDGET_EXCEEDED' });
    expect((await exec('github.repositories.read')).body.decision).toBe('ALLOW');
    // A restart forgets in-memory state, not the budget.
    m.broker.resetBrokerState();
    expect((await exec('github.issues.create', { title: 'four' })).body.decision_code).toBe('BUDGET_EXCEEDED');
  });

  it('counts every authorized request against the daily budget', async () => {
    const before = await usageNow();
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { maxWritesPerHour: null, maxRequestsPerDay: before.requestsLast24h + 1 });
    expect((await exec('github.repositories.read')).body.decision).toBe('ALLOW');
    expect((await exec('github.repositories.read')).body.decision_code).toBe('BUDGET_EXCEEDED');
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { maxRequestsPerDay: null });
  });

  it('the emergency stop denies every agent request until it is lifted, without touching grants', async () => {
    await m.repos.orgRepo.updateOrganization(m.seed.IDS.demoOrg, { emergencyStoppedAt: new Date().toISOString(), emergencyStoppedBy: m.seed.IDS.securityAdmin, emergencyStopReason: 'Suspicious activity' });
    const stopped = await exec('github.repositories.read');
    expect(stopped.status).toBe(403);
    expect(stopped.body).toMatchObject({ decision: 'DENY', decision_code: 'EMERGENCY_STOP', reason: expect.stringContaining('Suspicious activity') });
    expect((await m.repos.grantRepo.getGrant(m.seed.IDS.demoOrg, m.seed.IDS.grtIssue))?.storedStatus).toBe('ACTIVE');

    await m.repos.orgRepo.updateOrganization(m.seed.IDS.demoOrg, { emergencyStoppedAt: null, emergencyStoppedBy: null, emergencyStopReason: null });
    expect((await exec('github.repositories.read')).body.decision).toBe('ALLOW');
  });
});
