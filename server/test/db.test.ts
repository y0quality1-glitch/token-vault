import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';

/**
 * Integration tests against a real PostgreSQL database. Skipped unless TEST_DATABASE_URL
 * is set (CI provides one). The database is wiped and reseeded: never point this at
 * a database whose data you want to keep.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('PostgreSQL storage', () => {
  // Imported lazily so config validation sees the test environment.
  let m: {
    client: typeof import('../src/db/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    broker: typeof import('../src/modules/broker/broker.service');
  };

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
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('seeds both demo organizations idempotently', async () => {
    const { IDS } = m.seed;
    expect(await m.repos.orgRepo.getOrganization(IDS.demoOrg)).toMatchObject({ slug: 'demo-org' });
    expect(await m.repos.orgRepo.getOrganization(IDS.sandboxOrg)).toMatchObject({ slug: 'sandbox-org' });
    expect(await m.seed.seedIfEmpty()).toBe(false); // already seeded: no duplicate insert
    expect((await m.repos.agentRepo.listAgents(IDS.demoOrg)).length).toBe(3);
  });

  it('round-trips timestamps and JSONB columns', async () => {
    const g = (await m.repos.grantRepo.getGrant(m.seed.IDS.demoOrg, m.seed.IDS.grtIssue))!;
    expect(g.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(g.scopes).toEqual(['github.repositories.read', 'github.issues.list', 'github.issues.create']);
    expect(g.resourceConstraints).toEqual({ repositories: ['demo-org/demo-repo'] });
  });

  it('enforces organization isolation in repository lookups', async () => {
    const { IDS } = m.seed;
    expect(await m.repos.agentRepo.getAgent(IDS.sandboxOrg, IDS.agtAssistant)).toBeNull();
    expect(await m.repos.integrationRepo.getIntegration(IDS.sandboxOrg, IDS.intDemo)).toBeNull();
    expect(await m.repos.grantRepo.getGrant(IDS.sandboxOrg, IDS.grtIssue)).toBeNull();
  });

  it('rejects UPDATE and DELETE on audit tables (append-only trigger)', async () => {
    const { db } = m.client;
    const { sql } = await import('drizzle-orm');
    const cause = (p: Promise<unknown>) => p.then(() => 'no error', (e: Error & { cause?: Error }) => e.cause?.message ?? e.message);
    expect(await cause(db.execute(sql`update audit_events set actor_name = 'tampered'`))).toMatch(/append-only \(UPDATE rejected\)/);
    expect(await cause(db.execute(sql`delete from access_requests`))).toMatch(/append-only \(DELETE rejected\)/);
  });

  it('stores only a hash of session tokens', async () => {
    const { db } = m.client;
    const { sql } = await import('drizzle-orm');
    const token = randomBytes(32).toString('base64url');
    await m.repos.sessionRepo.createSession(token, m.seed.IDS.owner, null, 60_000);
    expect(await m.repos.sessionRepo.getSession(token)).toMatchObject({ userId: m.seed.IDS.owner });
    const { rows } = await db.execute(sql`select token_hash from sessions`);
    expect(rows.map((r) => r.token_hash)).not.toContain(token);
    await m.repos.sessionRepo.deleteSession(token);
    expect(await m.repos.sessionRepo.getSession(token)).toBeNull();
  });

  it('applies revocation on the very next agent request and audits both decisions', async () => {
    const { IDS } = m.seed;
    const { generateAgentCredential } = await import('../src/lib/crypto');
    const cred = generateAgentCredential();
    await m.repos.agentRepo.updateAgent(IDS.agtAssistant, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    const call = (operation: string) =>
      m.broker.executeAgentRequest({
        authorization: `Bearer ${cred.apiKey}`,
        orgHint: undefined,
        sourceIp: '127.0.0.1',
        source: 'agent-api',
        body: { integration_id: IDS.intDemo, operation, resource: { repository: 'demo-org/demo-repo' } },
      });

    // Scope check reads the grant from the database (no webhook needed for a denial).
    const scope = await call('github.contents.read');
    expect(scope.body.decision_code).toBe('SCOPE_DENIED');

    await m.repos.grantRepo.updateGrant(IDS.grtIssue, { storedStatus: 'REVOKED', revokedAt: new Date().toISOString() });
    const revoked = await call('github.repositories.read');
    expect(revoked.status).toBe(403);
    expect(revoked.body.decision_code).toBe('GRANT_REVOKED');

    const audited = await m.repos.auditRepo.getAccessRequest(IDS.demoOrg, revoked.body.request_id);
    expect(audited).toMatchObject({ decision: 'DENY', decisionCode: 'GRANT_REVOKED', grantId: IDS.grtIssue });
    const events = await m.repos.auditRepo.auditEventsByCorrelation(IDS.demoOrg, revoked.body.correlation_id);
    expect(events.map((e) => e.eventType)).toEqual(['access.denied']);
    // The plaintext credential never reaches storage.
    expect(JSON.stringify([audited, events])).not.toContain(cred.apiKey);
  });

  it('demo reset restores the seeded state', async () => {
    await m.seed.resetDatabase();
    const g = (await m.repos.grantRepo.getGrant(m.seed.IDS.demoOrg, m.seed.IDS.grtIssue))!;
    expect(g.storedStatus).toBe('ACTIVE');
  });

  it('persists the verified provider catalog, and a demo reset clears it', async () => {
    const { pgCatalogCache } = await import('../src/modules/providers/catalog-cache');
    const state = { envelopes: [], highWater: { notes: 4 }, savedAt: new Date().toISOString() };
    await pgCatalogCache.save(state);
    expect(await pgCatalogCache.load()).toMatchObject({ highWater: { notes: 4 } });
    await m.seed.resetDatabase();
    expect(await pgCatalogCache.load()).toBeNull();
  });
});

