import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { canonicalJson, type DecisionTokenClaims } from '@token-vault/shared';

/**
 * Access modes against a real PostgreSQL database, with the customer webhook replaced by a stub.
 * BROKERED: the webhook calls the application (unchanged). DECISION_ONLY: no webhook call; the
 * caller gets a decision token anyone can verify with the published public key.
 * SHORT_LIVED_CREDENTIAL: the webhook issues a token for this request, which reaches the caller
 * but never the audit. A Filter responses policy can't apply outside brokered mode, so such a
 * request is refused. Skipped unless TEST_DATABASE_URL is set. The database is wiped and reseeded.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

type Reply = { status: number; body: Record<string, unknown> };
const webhook = vi.hoisted(() => ({ calls: [] as { path: string; claims: Record<string, unknown> }[], reply: (_path: string, _claims: Record<string, unknown>): Reply => ({ status: 200, body: {} }) }));
vi.mock('../src/services/webhookService/webhook.client', async (orig) => {
  const real = await orig<typeof import('../src/services/webhookService/webhook.client')>();
  return {
    ...real,
    callWebhook: async (_wh: unknown, _method: string, path: string, claims: Record<string, unknown>) => {
      webhook.calls.push({ path, claims });
      return { latencyMs: 1, ...webhook.reply(path, claims) };
    },
  };
});

const ISSUE_TOKEN = 'ghs_issuedForThisRequestOnly0123456789';

suite('Access modes', () => {
  let m: {
    client: typeof import('../src/databases/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    broker: typeof import('../src/services/brokerService/brokerService.service');
    crypto: typeof import('../src/lib/crypto');
    tokens: typeof import('../src/lib/decision-token');
    integrations: typeof import('../src/services/integrationService/integrationService.service');
    db: typeof import('../src/entities');
  };
  let apiKey = '';
  const input = { title: 'Ship it', body: 'Release notes' };
  const createIssue = () =>
    m.broker.executeAgentRequest({ authorization: `Bearer ${apiKey}`, orgHint: undefined, sourceIp: '127.0.0.1', source: 'agent-api', body: { integration_id: m.seed.IDS.intDemo, operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input } });
  const setMode = (accessMode: 'BROKERED' | 'DECISION_ONLY' | 'SHORT_LIVED_CREDENTIAL') => m.repos.integrationRepo.updateIntegration(m.seed.IDS.intDemo, { accessMode });

  /** Verifies a decision token the way an application would: with the public key set alone. */
  const verifyToken = (token: string): DecisionTokenClaims => {
    const [h, p, s] = token.split('.');
    const header = JSON.parse(Buffer.from(h!, 'base64url').toString());
    const jwk = m.tokens.decisionJwks().keys.find((k) => k.kid === header.kid);
    expect(header).toMatchObject({ alg: 'EdDSA', typ: 'tv-decision+jwt' });
    expect(jwk).toBeTruthy();
    expect(verify(null, Buffer.from(`${h}.${p}`), createPublicKey({ key: jwk as never, format: 'jwk' }), Buffer.from(s!, 'base64url'))).toBe(true);
    return JSON.parse(Buffer.from(p!, 'base64url').toString());
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
      crypto: await import('../src/lib/crypto'),
      tokens: await import('../src/lib/decision-token'),
      integrations: await import('../src/services/integrationService/integrationService.service'),
      db: await import('../src/entities'),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    m.broker.resetBrokerState();
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    apiKey = cred.apiKey;
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { rateLimitPerMinute: 100, maxWritesPerHour: null, maxRequestsPerDay: null });
  }, 60_000);

  beforeEach(() => {
    webhook.calls.length = 0;
    webhook.reply = (path, claims) =>
      path === '/internal/v1/execute'
        ? { status: 200, body: { request_id: claims.request_id, upstream_status: 201, simulated: true, result: { number: 7 } } }
        : { status: 200, body: { request_id: claims.request_id, simulated: true, refreshed: false, credential: { type: 'github_app_installation_token', token: ISSUE_TOKEN, token_type: 'Bearer', expires_at: '2030-01-01T00:00:00.000Z', repositories: ['demo-repo'], permissions: { issues: 'write' } } } };
  });

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('brokered (the default): the webhook calls the application and returns its result', async () => {
    const r = await createIssue();
    expect(r.body).toMatchObject({ decision: 'ALLOW', execution: { status: 'SUCCEEDED' }, result: { number: 7 } });
    expect(r.body.authorization).toBeUndefined();
    expect(webhook.calls.map((c) => c.path)).toEqual(['/internal/v1/execute']);
  });

  it('decision only: no webhook call; a decision token any application can verify with the public key', async () => {
    await setMode('DECISION_ONLY');
    const r = await createIssue();
    expect(webhook.calls).toEqual([]);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ decision: 'ALLOW', decision_code: 'ALLOWED', execution: { status: 'HANDED_OFF', webhook_status: 'NOT_CALLED' }, result: null, authorization: { mode: 'DECISION_ONLY', expires_at: expect.any(String) } });
    expect(r.body.authorization!.credential).toBeUndefined();
    const claims = verifyToken(r.body.authorization!.decision_token);
    expect(claims).toMatchObject({ sub: m.seed.IDS.agtAssistant, jti: r.body.request_id, org_id: m.seed.IDS.demoOrg, integration_id: m.seed.IDS.intDemo, provider: 'github', operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, mode: 'DECISION_ONLY' });
    // The input hash pins the exact input that was decided on.
    expect(claims.input_sha256).toBe(createHash('sha256').update(canonicalJson(input)).digest('hex'));
    expect(claims.exp - claims.iat).toBe(120);

    // A token edited after signing does not verify.
    const [h, p, s] = r.body.authorization!.decision_token.split('.');
    const forged = Buffer.from(JSON.stringify({ ...claims, operation: 'github.repos.delete' })).toString('base64url');
    const jwk = m.tokens.decisionJwks().keys[0]!;
    expect(verify(null, Buffer.from(`${h}.${forged}`), createPublicKey({ key: jwk as never, format: 'jwk' }), Buffer.from(s!, 'base64url'))).toBe(false);
    expect(p).not.toBe(forged);

    const record = (await m.repos.auditRepo.getAccessRequest(m.seed.IDS.demoOrg, r.body.request_id))!;
    expect(record).toMatchObject({ decision: 'ALLOW', executionStatus: 'HANDED_OFF', webhookStatus: 'NOT_CALLED' });
  });

  it('short-lived credential: only for GitHub App and OAuth connections', () => {
    expect(m.integrations.canIssueCredential({ provider: 'github', authType: 'PAT' })).toBe(false);
    expect(m.integrations.canIssueCredential({ provider: 'github', authType: 'GITHUB_APP' })).toBe(true);
  });

  it('short-lived credential: the webhook issues a token for this request; the caller gets it, the audit never does', async () => {
    await setMode('SHORT_LIVED_CREDENTIAL');
    const r = await createIssue();
    expect(webhook.calls.map((c) => c.path)).toEqual(['/internal/v1/credentials/issue']);
    expect(webhook.calls[0]!.claims).toMatchObject({ operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, credential_ref: expect.any(String) });
    expect(webhook.calls[0]!.claims).not.toHaveProperty('input');
    expect(r.body).toMatchObject({
      decision: 'ALLOW',
      execution: { status: 'HANDED_OFF', webhook_status: 'OK', credential: { type: 'github_app_installation_token', repositories: ['demo-repo'], revoked: false } },
      authorization: { mode: 'SHORT_LIVED_CREDENTIAL', credential: { token: ISSUE_TOKEN, token_type: 'Bearer', repositories: ['demo-repo'] } },
    });
    expect(verifyToken(r.body.authorization!.decision_token).mode).toBe('SHORT_LIVED_CREDENTIAL');

    const record = await m.repos.auditRepo.getAccessRequest(m.seed.IDS.demoOrg, r.body.request_id);
    const events = await m.client.db.findBy(m.db.AuditEventEntity, { correlationId: r.body.correlation_id });
    expect(JSON.stringify(record)).not.toContain(ISSUE_TOKEN);
    expect(JSON.stringify(events)).not.toContain(ISSUE_TOKEN);
    expect(events[0]!.metadata).toMatchObject({ accessMode: 'SHORT_LIVED_CREDENTIAL' });
  });

  it("short-lived credential: says how to fix it when the customer's webhook does not hand out credentials", async () => {
    webhook.reply = () => ({ status: 403, body: { error: { code: 'CREDENTIAL_ISSUE_DISABLED', message: 'off' } } });
    const r = await createIssue();
    expect(r.status).toBe(502);
    expect(r.body).toMatchObject({ decision: 'ALLOW', execution: { status: 'FAILED', webhook_status: 'CREDENTIAL_ISSUE_DISABLED' } });
    expect(r.body.reason).toContain('WEBHOOK_ALLOW_CREDENTIAL_ISSUE=true');
    expect(r.body.authorization).toBeUndefined();
  });

  it('refuses a request a Filter responses policy must filter, unless the integration is brokered', async () => {
    const now = new Date().toISOString();
    await m.repos.policyRepo.insertPolicy({ id: 'pol_am_filter', organizationId: m.seed.IDS.demoOrg, name: 'Mask emails', description: '', effect: 'FILTER', priority: 50, enabled: true, responseFilter: { mask: ['email'], customPatterns: [], removeFields: [], promptInjection: 'off' }, conditions: { agentSelector: { type: 'agent', value: m.seed.IDS.agtAssistant }, integrationSelector: { type: 'any' }, operations: ['github.issues.create'], environment: 'any', arguments: [] }, createdAt: now, updatedAt: now });
    await setMode('DECISION_ONLY');
    const r = await createIssue();
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ decision: 'DENY', decision_code: 'FILTER_NEEDS_BROKERED', execution: { status: 'NOT_EXECUTED' } });
    expect(r.body.reason).toContain('"Mask emails"');
    expect(webhook.calls).toEqual([]);

    await setMode('BROKERED');
    expect((await createIssue()).body).toMatchObject({ decision: 'ALLOW', execution: { status: 'SUCCEEDED' } });
  });
});
