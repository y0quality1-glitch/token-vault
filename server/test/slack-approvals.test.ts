import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHmac, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';

/**
 * Slack approvals against a real PostgreSQL database, with Slack replaced by a local stand-in
 * (SLACK_API_URL). Covers: settings checked with Slack and stored sealed; held requests posted
 * with buttons; clicks verified by signature and mapped to members by email; the console's
 * rules (permission, separation of duties) applied to Slack clicks; messages updated after a
 * decision in Slack or the console. Skipped unless TEST_DATABASE_URL is set.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

const SIGNING_SECRET = 'a'.repeat(32);
const BOT_TOKEN = 'xoxb-1111-2222-abcdefghijklmnop';
const SLACK_USERS: Record<string, string> = { U_SEC: 'security@demo.test', U_DEV: 'developer@demo.test', U_STRANGER: 'someone@elsewhere.test' };

suite('Slack approvals', () => {
  const calls: { method: string; body: Record<string, any> }[] = [];
  let slackServer: Server;
  let slackUrl = '';
  let m: {
    client: typeof import('../src/databases/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    broker: typeof import('../src/services/brokerService/brokerService.service');
    crypto: typeof import('../src/lib/crypto');
    slack: typeof import('../src/services/slackService/slackService.service');
    approvals: typeof import('../src/services/approvalService/approvalService.service');
    db: typeof import('../src/entities');
  };
  let apiKey = '';
  let n = 0;

  const until = async <T>(fn: () => T | undefined, ms = 3000): Promise<T> => {
    const end = Date.now() + ms;
    for (;;) {
      const v = fn();
      if (v) return v;
      if (Date.now() > end) throw new Error('timed out');
      await new Promise((r) => setTimeout(r, 25));
    }
  };
  const holdRequest = async () => {
    const r = await m.broker.executeAgentRequest({ authorization: `Bearer ${apiKey}`, orgHint: undefined, sourceIp: '127.0.0.1', source: 'agent-api', body: { integration_id: m.seed.IDS.intDemo, operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input: { title: `Release ${++n}`, body: '' }, session_id: 'release-train', session_label: 'Cut the release' } });
    expect(r.status).toBe(202);
    return r.body.approval!.approval_id;
  };
  const click = (approvalId: string, slackUser: string, action: 'tv_approve' | 'tv_reject', opts: { secret?: string; ts?: number } = {}) => {
    const payload = { type: 'block_actions', team: { id: 'T_DEMO' }, user: { id: slackUser }, actions: [{ action_id: action, value: approvalId }], response_url: `${slackUrl}/response/${approvalId}` };
    const raw = `payload=${encodeURIComponent(JSON.stringify(payload))}`;
    const ts = String(opts.ts ?? Math.floor(Date.now() / 1000));
    const signature = `v0=${createHmac('sha256', opts.secret ?? SIGNING_SECRET).update(`v0:${ts}:${raw}`).digest('hex')}`;
    return m.slack.handleInteraction(raw, { timestamp: ts, signature });
  };
  const replies = (approvalId: string) => calls.filter((c) => c.method === `response/${approvalId}`);

  beforeAll(async () => {
    slackServer = createServer((req, res) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => {
        const method = req.url!.slice(1);
        const body = data ? JSON.parse(data) : {};
        calls.push({ method, body });
        res.setHeader('content-type', 'application/json');
        if (method === 'auth.test') return res.end(JSON.stringify(req.headers.authorization === `Bearer ${BOT_TOKEN}` ? { ok: true, team_id: 'T_DEMO', team: 'Demo Workspace', user_id: 'U_BOT' } : { ok: false, error: 'invalid_auth' }));
        if (method === 'chat.postMessage') return res.end(JSON.stringify({ ok: true, channel: body.channel, ts: `1700000000.${String(calls.length).padStart(6, '0')}` }));
        if (method === 'chat.update') return res.end(JSON.stringify({ ok: true, ts: body.ts }));
        if (method === 'users.info') return res.end(JSON.stringify(SLACK_USERS[body.user] ? { ok: true, user: { profile: { email: SLACK_USERS[body.user] } } } : { ok: false, error: 'user_not_found' }));
        res.end(JSON.stringify({ ok: true }));
      });
    });
    await new Promise<void>((r) => slackServer.listen(0, '127.0.0.1', r));
    slackUrl = `http://127.0.0.1:${(slackServer.address() as { port: number }).port}`;
    process.env.SLACK_API_URL = slackUrl;
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
      slack: await import('../src/services/slackService/slackService.service'),
      approvals: await import('../src/services/approvalService/approvalService.service'),
      db: await import('../src/entities'),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    m.broker.resetBrokerState();
    m.slack.registerSlackApprovals();
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    apiKey = cred.apiKey;
    await m.repos.grantRepo.updateGrant(m.seed.IDS.grtIssue, { rateLimitPerMinute: 100, maxWritesPerHour: null, maxRequestsPerDay: null });
    const now = new Date().toISOString();
    await m.repos.policyRepo.insertPolicy({ id: 'pol_slack', organizationId: m.seed.IDS.demoOrg, name: 'Approve issue creation', description: '', effect: 'REQUIRE_APPROVAL', priority: 50, enabled: true, conditions: { agentSelector: { type: 'agent', value: m.seed.IDS.agtAssistant }, integrationSelector: { type: 'any' }, operations: ['github.issues.create'], environment: 'any', arguments: [] }, createdAt: now, updatedAt: now });
  }, 60_000);

  afterAll(async () => {
    await m?.client.closeDatabase();
    await new Promise((r) => slackServer?.close(r));
  });

  const owner = () => m.repos.orgRepo.findUserByEmail('owner@demo.test');

  it('checks the bot token with Slack and stores both secrets sealed', async () => {
    const ctx = { user: (await owner())!, org: { id: m.seed.IDS.demoOrg } } as never;
    await expect(m.slack.saveSettings(ctx, { botToken: 'xoxb-9999-9999-wrongtokenvalue', signingSecret: SIGNING_SECRET, channelId: 'C0APPROVALS' })).rejects.toMatchObject({ details: { fields: { botToken: expect.stringContaining('invalid_auth') } } });
    const view = await m.slack.saveSettings(ctx, { botToken: BOT_TOKEN, signingSecret: SIGNING_SECRET, channelId: 'C0APPROVALS' });
    expect(view).toMatchObject({ configured: true, enabled: true, teamId: 'T_DEMO', teamName: 'Demo Workspace', channelId: 'C0APPROVALS', botTokenHint: 'xoxb-…mnop', interactionsUrl: expect.stringMatching(/\/slack\/interactions$/) });
    expect(JSON.stringify(view)).not.toContain(BOT_TOKEN);
    const [row] = await m.client.db.find(m.db.SlackSettingsEntity);
    expect(row!.botTokenSealed).not.toContain('abcdefghijklmnop');
    expect(row!.signingSecretSealed).not.toContain(SIGNING_SECRET);
  });

  it('connects a Slack workspace to one organization only, also at the database level', async () => {
    const ctx = { user: (await owner())!, org: { id: m.seed.IDS.sandboxOrg } } as never;
    await expect(m.slack.saveSettings(ctx, { botToken: BOT_TOKEN, signingSecret: SIGNING_SECRET, channelId: 'C0SANDBOX' })).rejects.toMatchObject({ status: 409 });
    // Two saves racing past that check still can't both land: the unique index refuses the second.
    const [demo] = await m.client.db.find(m.db.SlackSettingsEntity);
    const codes: string[] = [];
    await m.client.db
      .insert(m.db.SlackSettingsEntity, { ...demo!, organizationId: m.seed.IDS.sandboxOrg })
      .catch((e: any) => {
        for (let x = e; x; x = x.cause) codes.push(x.code);
      });
    expect(codes).toContain('23505');
  });

  it('posts a held request to the channel with the exact input and Approve / Reject buttons', async () => {
    const id = await holdRequest();
    const post = await until(() => calls.find((c) => c.method === 'chat.postMessage' && JSON.stringify(c.body).includes(id)));
    expect(post.body.channel).toBe('C0APPROVALS');
    const text = JSON.stringify(post.body.blocks);
    expect(text).toContain(`Release ${n}`);
    expect(text).toContain('Cut the release');
    expect(text).toContain('tv_approve');
    const record = await (async () => {
      for (let i = 0; i < 40; i++) {
        const r = await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, id);
        if (r?.notifications?.slack) return r;
        await new Promise((res) => setTimeout(res, 25));
      }
      return null;
    })();
    expect(record?.notifications?.slack).toMatchObject({ channel: 'C0APPROVALS', ts: expect.any(String) });
  });

  it('refuses clicks that are unsigned, replayed, from strangers, or from members who may not approve', async () => {
    const id = await holdRequest();
    expect(await click(id, 'U_SEC', 'tv_approve', { secret: 'b'.repeat(32) })).toEqual({ status: 401 });
    expect(await click(id, 'U_SEC', 'tv_approve', { ts: Math.floor(Date.now() / 1000) - 600 })).toEqual({ status: 401 });
    expect(await click(id, 'U_STRANGER', 'tv_approve')).toEqual({ status: 200 });
    expect(await click(id, 'U_DEV', 'tv_approve')).toEqual({ status: 200 });
    const texts = replies(id).map((c) => c.body.text);
    expect(texts[0]).toContain('not a member');
    expect(texts[1]).toContain("can't decide approvals");
    expect((await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, id))!.status).toBe('PENDING');
  });

  it('answers 401, not an error, for a malformed signature header or a secret that cannot be decrypted', async () => {
    const ts = String(Math.floor(Date.now() / 1000));
    // As many characters as a real signature, but more bytes (non-ASCII): no exception.
    expect(m.slack.verifySlackSignature(SIGNING_SECRET, 'payload=x', ts, `v0=${'é'.repeat(64)}`)).toBe(false);
    expect(m.slack.verifySlackSignature(SIGNING_SECRET, 'payload=x', ts, 'v0=short')).toBe(false);

    const id = await holdRequest();
    const [row] = await m.client.db.find(m.db.SlackSettingsEntity);
    await m.client.db.query('UPDATE slack_settings SET signing_secret_sealed = $1', ['v1:damaged']);
    try {
      expect(await click(id, 'U_SEC', 'tv_approve')).toEqual({ status: 401 });
    } finally {
      await m.client.db.query('UPDATE slack_settings SET signing_secret_sealed = $1', [row!.signingSecretSealed]);
    }
    expect((await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, id))!.status).toBe('PENDING');
  });

  it('a Security Administrator approves in Slack; the message is replaced and the audit says so', async () => {
    const id = await holdRequest();
    expect(await click(id, 'U_SEC', 'tv_approve')).toEqual({ status: 200 });
    const approved = (await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, id))!;
    expect(approved).toMatchObject({ status: 'APPROVED', decidedBy: m.seed.IDS.securityAdmin, decisionNote: 'Approved in Slack' });
    const reply = replies(id).at(-1)!.body;
    expect(reply.replace_original).toBe(true);
    expect(JSON.stringify(reply.blocks)).toContain('Approved by Sam Okafor in Slack');
    expect(JSON.stringify(reply.blocks)).not.toContain('tv_approve');
    // A second click is refused like in the console.
    await click(id, 'U_SEC', 'tv_reject');
    expect(replies(id).at(-1)!.body.text).toContain('can no longer be rejected');
    const events = await m.client.db.findBy(m.db.AuditEventEntity, { eventType: 'approval.approved' });
    expect(events.find((e) => (e.metadata as { approvalId?: string }).approvalId === id)?.metadata).toMatchObject({ via: 'slack' });
  });

  it("applies separation of duties: the agent's owner cannot approve from Slack either", async () => {
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { ownerUserId: m.seed.IDS.securityAdmin });
    const id = await holdRequest();
    await click(id, 'U_SEC', 'tv_approve');
    expect(replies(id).at(-1)!.body.text).toContain('Separation of duties');
    expect((await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, id))!.status).toBe('PENDING');
    await m.repos.agentRepo.updateAgent(m.seed.IDS.agtAssistant, { ownerUserId: m.seed.IDS.developer });
  });

  it('updates the Slack message when someone decides in the console', async () => {
    const id = await holdRequest();
    const record = await (async () => {
      for (let i = 0; i < 40; i++) {
        const r = await m.repos.approvalRepo.getApproval(m.seed.IDS.demoOrg, id);
        if (r?.notifications?.slack) return r;
        await new Promise((res) => setTimeout(res, 25));
      }
      throw new Error('not posted');
    })();
    await m.approvals.reject({ user: (await owner())!, org: { id: m.seed.IDS.demoOrg } }, id, { note: 'not now' });
    const update = await until(() => calls.find((c) => c.method === 'chat.update' && c.body.ts === record.notifications!.slack!.ts));
    expect(JSON.stringify(update.body.blocks)).toContain('Rejected by Avery Chen in the Token Vault console');
  });
});
