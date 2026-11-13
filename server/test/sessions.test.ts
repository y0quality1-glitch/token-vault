import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { formatTraceparent, parseTraceparent, sessionDisplayName } from '@token-vault/shared';

describe('W3C trace context', () => {
  it('parses valid traceparent headers and rejects invalid ones', () => {
    expect(parseTraceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01')).toEqual({ traceId: '4bf92f3577b34da6a3ce929d0e0e4736', parentSpanId: '00f067aa0ba902b7', sampled: true });
    expect(parseTraceparent('00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-00')?.sampled).toBe(false);
    for (const bad of [undefined, '', 'garbage', '00-00000000000000000000000000000000-00f067aa0ba902b7-01', '00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01', 'ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01', '00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01']) {
      expect(parseTraceparent(bad)).toBeNull();
    }
    expect(formatTraceparent('4bf92f3577b34da6a3ce929d0e0e4736', '00f067aa0ba902b7')).toBe('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    expect(sessionDisplayName({ sessionId: 's1', sessionLabel: 'Fix the login bug' })).toBe('Fix the login bug (s1)');
  });
});

/**
 * Sessions against a real PostgreSQL database: requests with a session id or a traceparent are
 * recorded with their trace (also when denied), grouped under Audit → Sessions, and approvals
 * show the session that led to them. Skipped unless TEST_DATABASE_URL is set; the database is
 * wiped and reseeded. No webhook runs, so authorized requests end in WEBHOOK_UNAVAILABLE.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

suite('agent sessions', () => {
  let m: {
    client: typeof import('../src/databases/client');
    config: typeof import('../src/config');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    broker: typeof import('../src/services/brokerService/brokerService.service');
    crypto: typeof import('../src/lib/crypto');
    chain: typeof import('../src/services/auditService/chain');
    approvals: typeof import('../src/services/approvalService/approvalService.service');
  };
  let apiKey = '';
  const TRACE = '4bf92f3577b34da6a3ce929d0e0e4736';
  const exec = (operation: string, extra: Record<string, unknown> = {}, traceparent?: string) =>
    m.broker.executeAgentRequest({
      authorization: `Bearer ${apiKey}`,
      orgHint: undefined,
      sourceIp: '127.0.0.1',
      source: 'agent-api',
      traceparent,
      body: { integration_id: m.seed.IDS.intDemo, operation, resource: { repository: 'demo-org/demo-repo' }, input: { title: 'x' }, ...extra },
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
      approvals: await import('../src/services/approvalService/approvalService.service'),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    m.broker.resetBrokerState();
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    apiKey = cred.apiKey;
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { rateLimitPerMinute: 100, maxWritesPerHour: null, maxRequestsPerDay: null });
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('records the session and trace on every request of a session, including denials', async () => {
    const tp = formatTraceparent(TRACE, '00f067aa0ba902b7');
    const a = await exec('github.issues.list', { session_id: 'task-42', session_label: 'Triage new bugs' }, tp);
    expect(a.body.trace).toMatchObject({ session_id: 'task-42', trace_id: TRACE, parent_span_id: '00f067aa0ba902b7', span_id: expect.stringMatching(/^[0-9a-f]{16}$/) });
    const denied = await exec('github.contents.read', { session_id: 'task-42' }, tp); // not granted
    expect(denied.body.decision).toBe('DENY');
    expect(denied.body.trace!.span_id).not.toBe(a.body.trace!.span_id);
    const record = (await m.repos.auditRepo.getAccessRequest(m.seed.IDS.demoOrg, denied.body.request_id))!;
    expect(record.trace).toMatchObject({ sessionId: 'task-42', traceId: TRACE });

    // Only a traceparent: grouped by trace id. Neither: nothing recorded (no one-request sessions).
    const traceOnly = await exec('github.issues.list', {}, formatTraceparent('aaaabbbbccccddddeeeeffff00001111', '1111222233334444'));
    expect(traceOnly.body.trace!.session_id).toBe('aaaabbbbccccddddeeeeffff00001111');
    expect((await exec('github.issues.list')).body.trace).toBeUndefined();
    // A malformed session id is a malformed request; a malformed traceparent is ignored (a new trace starts).
    expect((await exec('github.issues.list', { session_id: 'has spaces' })).body.decision_code).toBe('MALFORMED_REQUEST');
    expect((await exec('github.issues.list', { session_id: 'ok-1' }, 'nonsense')).body.trace).toMatchObject({ session_id: 'ok-1', parent_span_id: null });
  });

  it('groups requests into sessions with counts, and lists a session timeline', async () => {
    const sessions = await m.repos.auditRepo.listSessions(m.seed.IDS.demoOrg);
    const task = sessions.find((s) => s.sessionId === 'task-42')!;
    expect(task).toMatchObject({ sessionLabel: 'Triage new bugs', agentId: m.seed.IDS.agtAssistant, requests: 2, allowed: 1, denied: 1, held: 0, integrations: ['Demo GitHub'] });
    expect(sessions.map((s) => s.sessionId)).toContain('aaaabbbbccccddddeeeeffff00001111');
    expect((await m.repos.auditRepo.listSessions(m.seed.IDS.demoOrg, { search: 'triage' })).map((s) => s.sessionId)).toEqual(['task-42']);
    const timeline = await m.repos.auditRepo.sessionTimeline(m.seed.IDS.demoOrg, 'task-42', m.seed.IDS.agtAssistant);
    expect(timeline.map((r) => r.operation)).toEqual(['github.issues.list', 'github.contents.read']);
    const { items } = await new (await import('../src/services/accessRequestService/accessRequestService.service')).default().list(m.seed.IDS.demoOrg, { sessionId: 'task-42', limit: 50 });
    expect(items).toHaveLength(2);
  });

  it('shows the approver the session a held request came from', async () => {
    const now = new Date().toISOString();
    await m.repos.policyRepo.insertPolicy({ id: 'pol_session_approve', organizationId: m.seed.IDS.demoOrg, name: 'Approve issue creation', description: '', effect: 'REQUIRE_APPROVAL', priority: 50, enabled: true, conditions: { agentSelector: { type: 'agent', value: m.seed.IDS.agtAssistant }, integrationSelector: { type: 'any' }, operations: ['github.issues.create'], environment: 'any', arguments: [] }, createdAt: now, updatedAt: now });
    const held = await exec('github.issues.create', { session_id: 'task-42' });
    expect(held.status).toBe(202);
    const record = (await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, held.body.approval!.approval_id))!;
    const [view] = await m.approvals.toViews(m.seed.IDS.demoOrg, [record]);
    expect(view!.session).toEqual({ sessionId: 'task-42', sessionLabel: 'Triage new bugs', earlierRequests: 2 });
    expect((await m.repos.auditRepo.listSessions(m.seed.IDS.demoOrg, { sessionId: 'task-42' }))[0]).toMatchObject({ requests: 3, held: 1 });
  });

  it('keeps the audit chain valid with traced records', async () => {
    const { rows, legacy } = await m.repos.auditRepo.chainRows('access_requests', m.seed.IDS.demoOrg);
    expect(rows.some((r) => r.trace)).toBe(true);
    expect(m.chain.verify(m.config.config.auditSigningKey, 'access_requests', m.seed.IDS.demoOrg, rows, legacy)).toMatchObject({ ok: true });
  });
});
