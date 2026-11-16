import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { createHmac } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { DEMO_PASSWORD, login } from './helpers';

/**
 * Slack approvals, end to end, with a stand-in Slack on port 4900 (SLACK_API_URL in the
 * Playwright config): a Security Administrator connects Slack in the console, a held request is
 * posted with buttons, a signed click by a Slack user whose email is a Security Administrator
 * approves it, and the agent's request then runs. Slack is disconnected again at the end.
 */
const API = 'http://localhost:4000';
const SLACK_PORT = 4900;
const SIGNING_SECRET = 'c'.repeat(32);
const BOT_TOKEN = 'xoxb-4242-4242-e2etokenvalue123';
const SLACK_USERS: Record<string, string> = { U_SEC: 'security@demo.test' };

test.describe.serial('Slack approvals (Demo Organization)', () => {
  let admin: APIRequestContext;
  let agentApi: APIRequestContext;
  let page: Page;
  let slack: Server;
  const calls: { method: string; body: Record<string, any> }[] = [];
  const run = Date.now() % 100000;
  const agentName = `Slack Agent ${run}`;
  let approvalId = '';

  const createIssue = () =>
    agentApi.post('/agent/v1/execute', { data: { integration_id: 'int_github_001', operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input: { title: `Ship release ${run}`, body: '' } } }).then(async (r) => ({ status: r.status(), body: await r.json() }));

  test.beforeAll(async ({ playwright, browser }) => {
    slack = createServer((req, res) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => {
        const method = req.url!.slice(1);
        const body = data ? JSON.parse(data) : {};
        calls.push({ method, body });
        res.setHeader('content-type', 'application/json');
        if (method === 'auth.test') return res.end(JSON.stringify({ ok: true, team_id: `T_E2E${run}`, team: 'E2E Workspace', user_id: 'U_BOT' }));
        if (method === 'chat.postMessage') return res.end(JSON.stringify({ ok: true, channel: body.channel, ts: `1700000000.${calls.length}` }));
        if (method === 'users.info') return res.end(JSON.stringify(SLACK_USERS[body.user] ? { ok: true, user: { profile: { email: SLACK_USERS[body.user] } } } : { ok: false, error: 'user_not_found' }));
        res.end(JSON.stringify({ ok: true }));
      });
    });
    await new Promise<void>((r) => slack.listen(SLACK_PORT, '127.0.0.1', r));

    admin = await playwright.request.newContext({ baseURL: API });
    await admin.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } });
    await admin.post('/api/v1/auth/select-organization', { data: { organizationId: 'org_demo0000000001' } });
    const agent = await (await admin.post('/api/v1/agents', { data: { name: agentName, environment: 'development', ownerTeam: 'Release', agentType: 'AI_AGENT' } })).json();
    const grant = await admin.post('/api/v1/grants', {
      data: { name: `${agentName} issues`, agentId: agent.agent.id, integrationId: 'int_github_001', environment: 'development', scopes: ['github.issues.create'], repositories: ['demo-org/demo-repo'], validFrom: new Date(Date.now() - 60_000).toISOString(), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), rateLimitPerMinute: 60 },
    });
    expect(grant.ok(), await grant.text()).toBe(true);
    const policy = await admin.post('/api/v1/policies', {
      data: { name: `Approve issues of ${agentName}`, description: '', effect: 'REQUIRE_APPROVAL', priority: 40, enabled: true, conditions: { agentSelector: { type: 'agent', value: agent.agent.id }, integrationSelector: { type: 'any' }, operations: ['github.issues.create'], environment: 'any' } },
    });
    expect(policy.ok(), await policy.text()).toBe(true);
    agentApi = await playwright.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${agent.credential.apiKey}` } });
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await admin?.delete('/api/v1/slack-settings').catch(() => undefined);
    await admin?.dispose();
    await agentApi?.dispose();
    await page?.close();
    await new Promise((r) => slack?.close(r));
  });

  test('a Security Administrator connects Slack and sends a test message', async () => {
    await login(page, 'security@demo.test');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    await page.getByRole('link', { name: 'Slack approvals' }).click();
    await expect(page.getByText(/\/slack\/interactions$/).first()).toBeVisible();
    await page.getByLabel('Bot token').fill(BOT_TOKEN);
    await page.getByLabel('Signing secret').fill(SIGNING_SECRET);
    await page.getByLabel('Channel ID').fill('C0E2EAPPROVE');
    await page.getByRole('button', { name: 'Connect Slack' }).click();
    await expect(page.getByText('Slack connected')).toBeVisible();
    await expect(page.getByText(`E2E Workspace (T_E2E${run})`)).toBeVisible();
    expect(await page.content()).not.toContain(BOT_TOKEN);
    await page.getByRole('button', { name: 'Send test message' }).click();
    await expect(page.getByText('Test message sent')).toBeVisible();
    expect(calls.some((c) => c.method === 'chat.postMessage' && c.body.channel === 'C0E2EAPPROVE')).toBe(true);
  });

  test('a held request is posted to Slack with Approve and Reject buttons', async () => {
    const held = await createIssue();
    expect(held.status).toBe(202);
    approvalId = held.body.approval.approval_id;
    await expect.poll(() => calls.find((c) => c.method === 'chat.postMessage' && JSON.stringify(c.body).includes(approvalId))).toBeTruthy();
    const post = calls.find((c) => c.method === 'chat.postMessage' && JSON.stringify(c.body).includes(approvalId))!;
    const text = JSON.stringify(post.body.blocks);
    expect(text).toContain(`Ship release ${run}`);
    expect(text).toContain('tv_approve');
    expect(text).toContain('tv_reject');
  });

  test('a signed click in Slack approves it, and the agent runs the request', async () => {
    const payload = { type: 'block_actions', team: { id: `T_E2E${run}` }, user: { id: 'U_SEC' }, actions: [{ action_id: 'tv_approve', value: approvalId }], response_url: `http://127.0.0.1:${SLACK_PORT}/response/${approvalId}` };
    const raw = `payload=${encodeURIComponent(JSON.stringify(payload))}`;
    const ts = String(Math.floor(Date.now() / 1000));
    const sign = (secret: string) => `v0=${createHmac('sha256', secret).update(`v0:${ts}:${raw}`).digest('hex')}`;
    const send = (signature: string) => fetch(`${API}/slack/interactions`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-slack-request-timestamp': ts, 'x-slack-signature': signature }, body: raw });

    expect((await send(sign('d'.repeat(32)))).status).toBe(401); // forged
    expect((await send(sign(SIGNING_SECRET))).status).toBe(200);
    const reply = calls.filter((c) => c.method === `response/${approvalId}`).at(-1)!;
    expect(JSON.stringify(reply.body.blocks)).toContain('Approved by Sam Okafor in Slack');

    const ran = await createIssue();
    expect(ran.body).toMatchObject({ decision: 'ALLOW', execution: { status: 'SUCCEEDED' }, approval: { approval_id: approvalId, status: 'EXECUTED' } });
  });

  test('the console shows the decision came from Slack', async () => {
    await page.goto(`/access/approvals?approval=${approvalId}`);
    await expect(page.getByText('Approved in Slack')).toBeVisible();
  });
});
