import { createHmac, timingSafeEqual } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import { PERMISSIONS, ROLE_PERMISSIONS, actingUserLabel, type OperationApproval, type SlackSettingsView } from '@token-vault/shared';
import { config } from '../../config';
import { db } from '../../db/client';
import { operationApprovals, slackSettings } from '../../db/schema';
import { HttpError, badRequest, notFound } from '../../lib/errors';
import { open, seal } from '../../lib/secret-box';
import { parse } from '../../lib/validate';
import { approvalRepo, orgRepo } from '../../store/repos';
import type { OperationApprovalRecord } from '../../store/repos/operation-approvals';
import type { AdminContext } from '../../types/express';
import { recordEvent, SYSTEM_ACTOR, userActor } from '../audit/audit.service';
import { approvalHooks, approve, reject, toViews, type DecisionChannel } from '../approvals/approvals.service';
import { getOperation } from '../providers/registry';
import { SlackApiError, respond, slack } from './slack.client';

/**
 * Slack approvals. When a Require approval policy holds a request, Token Vault posts it to the
 * organization's Slack channel with Approve / Reject buttons. A click is accepted only when:
 *  - Slack's signature over the raw request verifies with the stored signing secret (and the
 *    timestamp is within five minutes, against replays);
 *  - the Slack user's email belongs to a Token Vault member of that organization with
 *    grant:approve;
 *  - every console rule passes too (it is the same decision code: separation of duties,
 *    pending only, agent active).
 * The message is updated when the request is decided, in Slack or in the console.
 */

type SettingsRow = typeof slackSettings.$inferSelect;

async function settingsFor(organizationId: string): Promise<SettingsRow | null> {
  const [row] = await db.select().from(slackSettings).where(eq(slackSettings.organizationId, organizationId));
  return row ?? null;
}

async function settingsForTeam(teamId: string): Promise<SettingsRow | null> {
  const [row] = await db.select().from(slackSettings).where(eq(slackSettings.teamId, teamId));
  return row ?? null;
}

/** Postgres unique_violation (23505), possibly wrapped by the driver or Drizzle. */
function isUniqueViolation(e: unknown): boolean {
  for (let x: any = e; x; x = x.cause) if (x.code === '23505') return true;
  return false;
}

const hint = (token: string) => `${token.slice(0, 5)}…${token.slice(-4)}`;

export async function getSettingsView(organizationId: string): Promise<SlackSettingsView> {
  const s = await settingsFor(organizationId);
  const updatedByName = s ? ((await orgRepo.userNames([s.updatedBy])).get(s.updatedBy) ?? null) : null;
  return {
    configured: !!s,
    enabled: s?.enabled ?? false,
    teamId: s?.teamId ?? null,
    teamName: s?.teamName ?? null,
    channelId: s?.channelId ?? null,
    botUserId: s?.botUserId ?? null,
    botTokenHint: s?.botTokenHint ?? null,
    interactionsUrl: `${config.apiPublicUrl}/slack/interactions`,
    updatedAt: s?.updatedAt ?? null,
    updatedByName,
  };
}

const settingsSchema = z.object({
  botToken: z.string().trim().regex(/^xoxb-[A-Za-z0-9-]{10,250}$/, 'A bot token starts with xoxb-').optional(),
  signingSecret: z.string().trim().regex(/^[a-f0-9]{32,64}$/i, 'The signing secret is the hexadecimal value from Basic Information').optional(),
  channelId: z.string().trim().regex(/^[CG][A-Z0-9]{6,20}$/, 'Use the channel ID (starts with C or G), not its name'),
  enabled: z.boolean().default(true),
});

/** Saves Slack settings; a new bot token is checked with Slack (auth.test) before it is stored. */
export async function saveSettings(ctx: AdminContext & { org: { id: string } }, raw: unknown): Promise<SlackSettingsView> {
  const body = parse(settingsSchema, raw);
  const existing = await settingsFor(ctx.org.id);
  if (!existing && (!body.botToken || !body.signingSecret)) throw badRequest('Request validation failed', { fields: { ...(!body.botToken ? { botToken: 'Paste the bot token' } : {}), ...(!body.signingSecret ? { signingSecret: 'Paste the signing secret' } : {}) } });
  let team = existing ? { teamId: existing.teamId, teamName: existing.teamName, botUserId: existing.botUserId } : null;
  if (body.botToken) {
    try {
      const who = await slack.authTest(body.botToken);
      team = { teamId: who.team_id, teamName: who.team, botUserId: who.user_id };
    } catch (e) {
      throw badRequest('Request validation failed', { fields: { botToken: e instanceof SlackApiError ? `Slack did not accept this token (${e.code})` : 'Slack could not be reached' } });
    }
  }
  const other = await settingsForTeam(team!.teamId);
  if (other && other.organizationId !== ctx.org.id) throw new HttpError(409, 'CONFLICT', 'This Slack workspace is already connected to another organization.');
  const now = new Date().toISOString();
  const row = {
    organizationId: ctx.org.id,
    ...team!,
    channelId: body.channelId,
    botTokenSealed: body.botToken ? seal(body.botToken, ctx.org.id) : existing!.botTokenSealed,
    botTokenHint: body.botToken ? hint(body.botToken) : existing!.botTokenHint,
    signingSecretSealed: body.signingSecret ? seal(body.signingSecret, ctx.org.id) : existing!.signingSecretSealed,
    enabled: body.enabled,
    updatedAt: now,
    updatedBy: ctx.user.id,
  };
  try {
    await db.insert(slackSettings).values(row).onConflictDoUpdate({ target: slackSettings.organizationId, set: row });
  } catch (e) {
    // Another organization connected the same workspace between the check above and this write.
    if (isUniqueViolation(e)) throw new HttpError(409, 'CONFLICT', 'This Slack workspace is already connected to another organization.');
    throw e;
  }
  await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: existing ? 'slack.updated' : 'slack.connected', target: { type: 'organization', id: ctx.org.id, name: team!.teamName }, severity: 'warning', metadata: { teamId: team!.teamId, channelId: body.channelId, enabled: body.enabled, tokenChanged: !!body.botToken, signingSecretChanged: !!body.signingSecret } });
  return getSettingsView(ctx.org.id);
}

export async function deleteSettings(ctx: AdminContext & { org: { id: string } }) {
  const existing = await settingsFor(ctx.org.id);
  if (!existing) throw notFound('Slack settings');
  await db.delete(slackSettings).where(eq(slackSettings.organizationId, ctx.org.id));
  await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'slack.disconnected', target: { type: 'organization', id: ctx.org.id, name: existing.teamName }, severity: 'warning', metadata: { teamId: existing.teamId } });
}

export async function sendTest(ctx: AdminContext & { org: { id: string } }) {
  const s = await settingsFor(ctx.org.id);
  if (!s) throw notFound('Slack settings');
  try {
    await slack.postMessage(open(s.botTokenSealed, s.organizationId), { channel: s.channelId, text: 'Token Vault is connected: requests that need approval will be posted here.', blocks: [{ type: 'section', text: { type: 'mrkdwn', text: `:white_check_mark: *Token Vault is connected.* Requests that need a human's approval will be posted in this channel, sent by ${ctx.user.fullName}'s test.` } }] });
  } catch (e) {
    throw badRequest(e instanceof SlackApiError ? `Slack refused the message (${e.code}). Is the bot invited to the channel?` : 'Slack could not be reached');
  }
  return { sent: true };
}

// ---------------------------------------------------------------- messages

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);

/** The approval as Slack blocks: what will run, who asks, and (while pending) the buttons. */
export function approvalBlocks(a: OperationApproval, decided?: { outcome: 'APPROVED' | 'REJECTED'; by: string; via: DecisionChannel }): { text: string; blocks: unknown[] } {
  const op = getOperation(a.operation);
  const destructive = op?.destructive ? ' :warning: *Destructive*' : '';
  const title = `${op?.label ?? a.operation} on ${a.integrationName}`;
  const facts = [
    `*Agent:* ${esc(a.agentName)}${a.delegation ? ` (via sub-agent ${esc(a.delegation.label)})` : ''}`,
    `*Operation:* ${esc(op?.label ?? a.operation)} \`${a.operation}\`${destructive}`,
    `*Resource:* ${esc(Object.entries(a.resource).map(([k, v]) => `${k}: ${v}`).join(', ') || 'none')}`,
    `*Required by:* ${esc(a.policyName)}`,
    ...(a.onBehalfOf ? [`*On behalf of:* ${esc(actingUserLabel(a.onBehalfOf))}`] : []),
    ...(a.session ? [`*Session:* ${esc(a.session.sessionLabel ?? a.session.sessionId)} (${a.session.earlierRequests} earlier request${a.session.earlierRequests === 1 ? '' : 's'})`] : []),
  ];
  const input = clip(JSON.stringify(a.input, null, 2), 2500).replace(/```/g, "'''");
  const link = `${config.consolePublicUrl}/access/approvals?approval=${a.id}`;
  const blocks: unknown[] = [
    { type: 'header', text: { type: 'plain_text', text: clip(`Approval needed: ${title}`, 150) } },
    { type: 'section', text: { type: 'mrkdwn', text: facts.join('\n') } },
    { type: 'section', text: { type: 'mrkdwn', text: `*Exactly what will run* (written by the agent, untrusted):\n\`\`\`${input}\`\`\`` } },
  ];
  if (decided) {
    const verb = decided.outcome === 'APPROVED' ? ':white_check_mark: Approved' : ':no_entry: Rejected';
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: `${verb} by ${esc(decided.by)} ${decided.via === 'slack' ? 'in Slack' : 'in the Token Vault console'}. <${link}|Open in Token Vault>` }] });
  } else {
    blocks.push(
      {
        type: 'actions',
        block_id: `tv_approval:${a.id}`,
        elements: [
          { type: 'button', action_id: 'tv_approve', style: 'primary', value: a.id, text: { type: 'plain_text', text: 'Approve' }, confirm: { title: { type: 'plain_text', text: 'Approve this request?' }, text: { type: 'mrkdwn', text: 'The agent may then run exactly this request once, within 15 minutes.' }, confirm: { type: 'plain_text', text: 'Approve' }, deny: { type: 'plain_text', text: 'Cancel' } } },
          { type: 'button', action_id: 'tv_reject', style: 'danger', value: a.id, text: { type: 'plain_text', text: 'Reject' } },
          { type: 'button', action_id: 'tv_open', url: link, text: { type: 'plain_text', text: 'Open in Token Vault' } },
        ],
      },
      { type: 'context', elements: [{ type: 'mrkdwn', text: `Lapses at ${a.expiresAt} if nobody decides. Approval ${a.id}.` }] },
    );
  }
  return { text: `Approval needed: ${title} (${a.agentName})`, blocks };
}

async function view(r: OperationApprovalRecord): Promise<OperationApproval> {
  return (await toViews(r.organizationId, [r]))[0]!;
}

/** Posts a new approval request to Slack (hook: approval requested). */
export async function notifyRequested(r: OperationApprovalRecord): Promise<void> {
  const s = await settingsFor(r.organizationId);
  if (!s?.enabled) return;
  const message = approvalBlocks(await view(r));
  try {
    const posted = await slack.postMessage(open(s.botTokenSealed, s.organizationId), { channel: s.channelId, ...message });
    await db.update(operationApprovals).set({ notifications: { slack: { channel: posted.channel, ts: posted.ts } } }).where(eq(operationApprovals.id, r.id));
  } catch (e) {
    await recordEvent({ orgId: r.organizationId, actor: SYSTEM_ACTOR, eventType: 'slack.notification_failed', target: { type: 'approval', id: r.id, name: r.operation }, outcome: 'FAILURE', severity: 'warning', metadata: { approvalId: r.id, code: e instanceof SlackApiError ? e.code : 'error' } });
  }
}

/** Updates the Slack message once a request is decided in the console (Slack decisions update it directly). */
export async function notifyDecided(r: OperationApprovalRecord, by: string, via: DecisionChannel): Promise<void> {
  if (via === 'slack') return;
  const s = await settingsFor(r.organizationId);
  const [fresh] = await db.select({ notifications: operationApprovals.notifications }).from(operationApprovals).where(eq(operationApprovals.id, r.id));
  const where = fresh?.notifications?.slack;
  if (!s || !where) return;
  await slack.update(open(s.botTokenSealed, s.organizationId), { ...where, ...approvalBlocks(await view(r), { outcome: r.status === 'APPROVED' ? 'APPROVED' : 'REJECTED', by, via }) }).catch(() => undefined);
}

export function registerSlackApprovals() {
  if (!approvalHooks.requested.includes(notifyRequested)) approvalHooks.requested.push(notifyRequested);
  if (!approvalHooks.decided.includes(notifyDecided)) approvalHooks.decided.push(notifyDecided);
}

// ---------------------------------------------------------------- button clicks

const REPLAY_WINDOW_S = 5 * 60;

/** Slack request signing (v0): HMAC-SHA256 of "v0:<timestamp>:<raw body>" with the app's signing secret. */
export function verifySlackSignature(signingSecret: string, rawBody: string, timestamp: string | undefined, signature: string | undefined, now = Date.now()): boolean {
  if (!timestamp || !signature || !/^\d+$/.test(timestamp)) return false;
  if (Math.abs(now / 1000 - Number(timestamp)) > REPLAY_WINDOW_S) return false;
  const expected = `v0=${createHmac('sha256', signingSecret).update(`v0:${timestamp}:${rawBody}`).digest('hex')}`;
  // Compare bytes, not characters: a non-ASCII header has more bytes than characters.
  const a = Buffer.from(expected);
  const b = Buffer.from(signature);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The stored signing secret, or null when it can't be decrypted (key changed, row damaged). */
function signingSecretOf(s: SettingsRow): string | null {
  try {
    return open(s.signingSecretSealed, s.organizationId);
  } catch {
    return null;
  }
}

interface BlockActionPayload {
  type: string;
  team?: { id?: string };
  user?: { id?: string; name?: string };
  actions?: { action_id?: string; value?: string }[];
  response_url?: string;
}

const ephemeral = (text: string) => ({ response_type: 'ephemeral', replace_original: false, text });

/**
 * Handles a Slack interaction (button click). Answers 401 for an unverifiable request and 200
 * otherwise (Slack shows nothing for 200); results and refusals go back via response_url.
 */
export async function handleInteraction(rawBody: string, headers: { timestamp?: string; signature?: string }): Promise<{ status: number }> {
  let payload: BlockActionPayload;
  try {
    payload = JSON.parse(new URLSearchParams(rawBody).get('payload') ?? '');
  } catch {
    return { status: 400 };
  }
  const settings = payload.team?.id ? await settingsForTeam(payload.team.id) : null;
  // The workspace is only a hint until the signature verifies with that workspace's secret.
  // A secret that can't be decrypted fails closed, like a wrong one.
  const secret = settings ? signingSecretOf(settings) : null;
  if (!settings || !secret || !verifySlackSignature(secret, rawBody, headers.timestamp, headers.signature)) return { status: 401 };
  const action = payload.actions?.[0];
  if (payload.type !== 'block_actions' || !action || (action.action_id !== 'tv_approve' && action.action_id !== 'tv_reject')) return { status: 200 };
  const reply = (body: Record<string, unknown>) => (payload.response_url ? respond(payload.response_url, body) : Promise.resolve());
  const orgId = settings.organizationId;
  const approval = action.value ? await approvalRepo.getApproval(orgId, action.value) : null;
  if (!approval) {
    await reply(ephemeral('This approval no longer exists in Token Vault.'));
    return { status: 200 };
  }

  // Who clicked: their Slack email must be a Token Vault member allowed to approve.
  const token = open(settings.botTokenSealed, orgId);
  const email = payload.user?.id ? await slack.userEmail(token, payload.user.id).catch(() => null) : null;
  const user = email ? await orgRepo.findUserByEmail(email.toLowerCase()) : null;
  const membership = user ? await orgRepo.getMembership(user.id, orgId) : null;
  if (!user || !membership || user.status !== 'ACTIVE') {
    await reply(ephemeral(`Your Slack account${email ? ` (${email})` : ''} is not a member of this Token Vault organization, so it can't decide approvals. Use the console instead.`));
    await recordEvent({ orgId, actor: SYSTEM_ACTOR, eventType: 'slack.decision_refused', target: { type: 'approval', id: approval.id, name: approval.operation }, outcome: 'DENIED', severity: 'warning', metadata: { approvalId: approval.id, slackUser: payload.user?.id ?? null, reason: 'not_a_member' } });
    return { status: 200 };
  }
  if (!ROLE_PERMISSIONS[membership.role].includes(PERMISSIONS.GRANT_APPROVE)) {
    await reply(ephemeral(`${user.fullName}, your role can't decide approvals (it needs grant:approve).`));
    await recordEvent({ orgId, actor: userActor({ user }), eventType: 'slack.decision_refused', target: { type: 'approval', id: approval.id, name: approval.operation }, outcome: 'DENIED', severity: 'warning', metadata: { approvalId: approval.id, reason: 'missing_permission' } });
    return { status: 200 };
  }

  const outcome = action.action_id === 'tv_approve' ? 'APPROVED' : 'REJECTED';
  try {
    const ctx = { user, org: { id: orgId } };
    const decided = outcome === 'APPROVED' ? await approve(ctx, approval.id, { note: 'Approved in Slack' }, 'slack') : await reject(ctx, approval.id, { note: 'Rejected in Slack' }, 'slack');
    await reply({ replace_original: true, ...approvalBlocks(await view(decided), { outcome, by: user.fullName, via: 'slack' }) });
  } catch (e) {
    // Same refusals as the console: separation of duties, already decided, agent disabled…
    await reply(ephemeral(e instanceof HttpError ? e.message : 'Token Vault could not record the decision. Try the console.'));
  }
  return { status: 200 };
}
