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
    client: typeof import('../src/databases/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    broker: typeof import('../src/services/brokerService/brokerService.service');
  };

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    m = {
      client: await import('../src/databases/client'),
      seed: await import('../src/store/seed'),
      repos: await import('../src/store/repos'),
      broker: await import('../src/services/brokerService/brokerService.service'),
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
    const cause = (p: Promise<unknown>) => p.then(() => 'no error', (e: Error & { cause?: Error }) => e.cause?.message ?? e.message);
    expect(await cause(db.query(`update audit_events set actor_name = 'tampered'`))).toMatch(/append-only \(UPDATE rejected\)/);
    expect(await cause(db.query('delete from access_requests'))).toMatch(/append-only \(DELETE rejected\)/);
  });

  it('stores only a hash of session tokens', async () => {
    const { db } = m.client;
    const token = randomBytes(32).toString('base64url');
    await m.repos.sessionRepo.createSession(token, m.seed.IDS.owner, null, 60_000);
    expect(await m.repos.sessionRepo.getSession(token)).toMatchObject({ userId: m.seed.IDS.owner });
    const rows: { token_hash: string }[] = await db.query('select token_hash from sessions');
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
    const { pgCatalogCache } = await import('../src/services/providerService/catalogCache');
    const state = { envelopes: [], highWater: { notes: 4 }, savedAt: new Date().toISOString() };
    await pgCatalogCache.save(state);
    expect(await pgCatalogCache.load()).toMatchObject({ highWater: { notes: 4 } });
    await m.seed.resetDatabase();
    expect(await pgCatalogCache.load()).toBeNull();
  });

  it('accepts a rotated agent key only during its grace period, and says when it expires', async () => {
    const { IDS } = m.seed;
    const { generateAgentCredential } = await import('../src/lib/crypto');
    const oldCred = generateAgentCredential();
    const newCred = generateAgentCredential();
    const later = new Date(Date.now() + 15 * 60_000).toISOString();
    await m.repos.agentRepo.updateAgent(IDS.agtAssistant, {
      credentialKeyId: newCred.keyId,
      credentialHash: newCred.hash,
      previousCredentialKeyId: oldCred.keyId,
      previousCredentialHash: oldCred.hash,
      previousCredentialExpiresAt: later,
      previousCredentialLastUsedAt: null,
    });

    expect(await m.broker.verifyAgentKey(newCred.apiKey)).toMatchObject({ ok: true, previousKeyExpiresAt: null });
    expect(await m.broker.verifyAgentKey(oldCred.apiKey)).toMatchObject({ ok: true, previousKeyExpiresAt: later });
    expect((await m.repos.agentRepo.getAgent(IDS.demoOrg, IDS.agtAssistant))!.previousCredentialLastUsedAt).not.toBeNull();

    // The old key id with a wrong secret is still refused.
    const forged = oldCred.apiKey.slice(0, -4) + (oldCred.apiKey.endsWith('aaaa') ? 'bbbb' : 'aaaa');
    expect(await m.broker.verifyAgentKey(forged)).toMatchObject({ ok: false });

    // An agent request with the old key succeeds the authentication step and reports the expiry.
    let notice: string | null = null;
    const r = await m.broker.executeAgentRequest({
      authorization: `Bearer ${oldCred.apiKey}`,
      orgHint: undefined,
      sourceIp: '127.0.0.1',
      source: 'agent-api',
      body: { integration_id: IDS.intDemo, operation: 'github.contents.read', resource: { repository: 'demo-org/demo-repo' } },
      onPreviousKey: (at) => (notice = at),
    });
    expect(r.body.decision_code).not.toBe('AGENT_UNAUTHENTICATED');
    expect(notice).toBe(later);
    expect(r.body.checks[0]!.detail).toContain(`this key was rotated and stops working at ${later}`);

    // Once the grace period is over, the old key is refused with a reason that says so.
    await m.repos.agentRepo.updateAgent(IDS.agtAssistant, { previousCredentialExpiresAt: new Date(Date.now() - 1000).toISOString() });
    const expired = await m.broker.verifyAgentKey(oldCred.apiKey);
    expect(expired).toMatchObject({ ok: false });
    expect(expired.reason).toMatch(/was rotated and its grace period ended/);
    const denied = await m.broker.executeAgentRequest({ authorization: `Bearer ${oldCred.apiKey}`, orgHint: undefined, sourceIp: '127.0.0.1', source: 'agent-api', body: {} });
    expect(denied.body).toMatchObject({ decision_code: 'AGENT_UNAUTHENTICATED' });
    expect(denied.body.reason).toMatch(/grace period ended/);
    expect(await m.broker.verifyAgentKey(newCred.apiKey)).toMatchObject({ ok: true });

    // The console view never includes the hashes, and hides an expired previous key.
    const { toAgent, loadLookups } = await import('../src/store/views');
    const view = toAgent((await m.repos.agentRepo.getAgent(IDS.demoOrg, IDS.agtAssistant))!, await loadLookups(IDS.demoOrg));
    expect(JSON.stringify(view)).not.toContain(oldCred.hash);
    expect(view).toMatchObject({ previousCredentialKeyId: null, previousCredentialExpiresAt: null });
    expect(view).not.toHaveProperty('previousCredentialHash');
    expect(view).not.toHaveProperty('credentialHash');
  });
});
