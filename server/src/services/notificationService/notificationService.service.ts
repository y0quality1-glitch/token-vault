import { createHmac, randomBytes } from 'node:crypto';
import { In } from 'typeorm';
import nodemailer from 'nodemailer';
import {
  SECRET_NOTIFICATION_EVENT_LABELS,
  type AuditEvent,
  type NotificationChannelView,
  type NotificationDeliveryStatus,
  type NotificationDeliveryView,
  type SecretNotificationEvent,
  type SecretNotificationPayload,
} from '@token-vault/shared';
import { config } from '../../config';
import { db, transaction, type Executor } from '../../databases/client';
import type { SaveNotificationChannelDto } from '../../databases/repository/secret/secretLifecycle.dto';
import { NotificationChannelEntity, NotificationDeliveryEntity, OrganizationEntity, SecretEntity } from '../../entities';
import { HttpError, badRequest, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { open, seal } from '../../lib/secret-box';
import type { OrgContext } from '../baseService';

/**
 * Notifications for secret lifecycle events (spec 4.9.18). Every secret event written to the
 * audit log is matched, in the same transaction, against the organization's enabled channels
 * (events and scope); a delivery row is queued per matching channel, and the delivery loop sends
 * it: by email (SMTP), as a signed HTTPS POST (outbound webhook) or to Slack. Failed deliveries
 * are retried with backoff, then marked FAILED. Payloads never carry a value: only what the
 * audit log already says (names, versions, reason codes).
 */

/** Audit event → notification event. */
const FROM_AUDIT: Record<string, SecretNotificationEvent> = {
  'secret.created': 'secret.created',
  'secret.updated': 'secret.updated',
  'secret.renewed': 'secret.updated',
  'secret.version_created': 'secret.updated',
  'secret.rolled_back': 'secret.updated',
  'secret.activated': 'secret.updated',
  'secret.expiring': 'secret.expiring',
  'secret.expired': 'secret.expired',
  'secret.rotation_scheduled': 'secret.rotation_scheduled',
  'secret.rotated': 'secret.rotation_succeeded',
  'secret.rotation_failed': 'secret.rotation_failed',
  'secret.access_denied': 'secret.access_denied',
  'secret.revoked': 'secret.revoked',
  'secret.provider_failure': 'secret.provider_failure',
};

/** Audit metadata keys that may appear in a notification (all describe the event, none a value). */
const DETAIL_KEYS = ['version', 'previousVersion', 'reasonCode', 'trigger', 'strategy', 'expiresAt', 'daysLeft', 'errorCode', 'attempts', 'from', 'to', 'reason', 'nextAttemptAt', 'fieldsRequested'];

/** Backoff after a failed attempt (index: attempts made - 1); after the last, the delivery is FAILED. */
const RETRY_AFTER_MS = [30_000, 120_000, 600_000, 3_600_000];
const MAX_ATTEMPTS = RETRY_AFTER_MS.length + 1;

const now = () => new Date().toISOString();

function details(e: AuditEvent): SecretNotificationPayload['details'] {
  const out: SecretNotificationPayload['details'] = { actor: e.actorName, actorType: e.actorType };
  for (const k of DETAIL_KEYS) {
    const v = (e.metadata as Record<string, unknown>)[k];
    if (v === null || ['string', 'number', 'boolean'].includes(typeof v)) out[k] = v as string | number | boolean | null;
    else if (Array.isArray(v)) out[k] = v.join(', ');
  }
  return out;
}

function inScope(ch: NotificationChannelEntity, s: Pick<SecretEntity, 'project' | 'environment'>): boolean {
  return (!ch.scope.project || ch.scope.project === s.project) && (!ch.scope.environment || ch.scope.environment === s.environment);
}

/** Called by recordEvent for every event whose target is a secret. */
export async function enqueueSecretNotifications(e: AuditEvent, ex: Executor = db): Promise<number> {
  const event = FROM_AUDIT[e.eventType];
  if (!event) return 0;
  const channels = (await ex.findBy(NotificationChannelEntity, { organizationId: e.organizationId, enabled: true })).filter((c) => c.events.includes(event));
  if (!channels.length) return 0;
  const s = await ex.findOneBy(SecretEntity, { id: e.targetId, organizationId: e.organizationId });
  if (!s) return 0;
  const matching = channels.filter((c) => inScope(c, s));
  if (!matching.length) return 0;
  const org = await ex.findOneBy(OrganizationEntity, { id: e.organizationId });
  const payload: Omit<SecretNotificationPayload, 'id'> = {
    event,
    occurredAt: e.createdAt,
    organization: { id: e.organizationId, name: org?.name ?? '' },
    secret: { id: s.id, name: s.name, typeKey: s.typeKey, project: s.project, workspace: s.workspace, environment: s.environment, status: s.status, activeVersion: s.activeVersion, expiresAt: s.expiresAt },
    details: details(e),
    consoleUrl: `${config.consolePublicUrl}/secrets/${s.id}`,
  };
  const t = now();
  await ex.insert(
    NotificationDeliveryEntity,
    matching.map((c) => {
      const id = newId('ndel');
      return { id, organizationId: e.organizationId, channelId: c.id, event, secretId: s.id, payload: { id, ...payload }, status: 'PENDING' as const, attempts: 0, lastError: null, nextAttemptAt: t, createdAt: t, deliveredAt: null };
    }),
  );
  return matching.length;
}

// ── sending ─────────────────────────────────────────────────────

export interface MailMessage {
  to: string[];
  subject: string;
  text: string;
}

/** The SMTP sender; tests replace `send`. Unconfigured: deliveries fail with a clear reason. */
export const mailer = {
  transport: null as ReturnType<typeof nodemailer.createTransport> | null,
  async send(msg: MailMessage): Promise<void> {
    if (!config.smtpUrl) throw new Error('Email is not configured on the control plane (SMTP_URL)');
    this.transport ??= nodemailer.createTransport(config.smtpUrl);
    await this.transport.sendMail({ from: config.smtpFrom, to: msg.to, subject: msg.subject, text: msg.text });
  },
};

/** Lazy, so the Slack module (which records audit events) is not loaded by the audit module. */
const slackPost = async (orgId: string, channelId: string | null, text: string) => (await import('../slackService/slackService.service')).postNotification(orgId, channelId, text);

function title(p: SecretNotificationPayload): string {
  const label = p.event === 'notification.test' ? 'Test notification' : SECRET_NOTIFICATION_EVENT_LABELS[p.event];
  return p.secret ? `${label}: ${p.secret.name}` : label;
}

function textOf(p: SecretNotificationPayload): string {
  const lines = [title(p), ''];
  if (p.secret) lines.push(`Secret: ${p.secret.name} (${p.secret.typeKey}) in ${p.secret.project}/${p.secret.workspace}, ${p.secret.environment}`, `Status: ${p.secret.status}${p.secret.activeVersion ? `, version ${p.secret.activeVersion}` : ''}${p.secret.expiresAt ? `, expires ${p.secret.expiresAt}` : ''}`);
  for (const [k, v] of Object.entries(p.details)) if (v !== null && v !== '') lines.push(`${k}: ${v}`);
  lines.push(`Organization: ${p.organization.name}`, `When: ${p.occurredAt}`);
  if (p.consoleUrl) lines.push('', p.consoleUrl);
  return lines.join('\n');
}

/** Token-Vault-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>"> (receivers should reject old timestamps). */
export function signatureHeader(secret: string, body: string, t = Math.floor(Date.now() / 1000)): string {
  return `t=${t},v1=${createHmac('sha256', secret).update(`${t}.${body}`).digest('hex')}`;
}

async function send(ch: NotificationChannelEntity, p: SecretNotificationPayload): Promise<void> {
  if (ch.kind === 'EMAIL') return mailer.send({ to: ch.recipients, subject: `[Token Vault] ${title(p)}`, text: textOf(p) });
  if (ch.kind === 'SLACK') {
    const link = p.consoleUrl ? ` <${p.consoleUrl}|Open in Token Vault>` : '';
    return slackPost(ch.organizationId, ch.slackChannelId, `*${title(p)}*${link}\n${textOf(p).split('\n').slice(2).filter(Boolean).slice(0, 8).join('\n')}`);
  }
  const body = JSON.stringify(p);
  const res = await fetch(ch.url!, {
    method: 'POST',
    redirect: 'manual',
    signal: AbortSignal.timeout(5_000),
    headers: {
      'content-type': 'application/json',
      'user-agent': 'TokenVault-Notifications/1',
      'token-vault-event': p.event,
      'token-vault-delivery': p.id,
      'token-vault-signature': signatureHeader(open(ch.signingSecretSealed!, ch.organizationId), body),
    },
    body,
  }).catch((e: Error) => {
    throw new Error(e.name === 'TimeoutError' ? 'The endpoint did not answer within 5 seconds' : 'The endpoint could not be reached');
  });
  await res.body?.cancel().catch(() => undefined);
  if (res.status < 200 || res.status > 299) throw new Error(`The endpoint answered HTTP ${res.status}`);
}

/** Sends one claimed delivery and records the outcome. */
async function attempt(d: NotificationDeliveryEntity, ch: NotificationChannelEntity | null): Promise<NotificationDeliveryEntity> {
  let error: string | null = null;
  try {
    if (!ch) throw new Error('The channel was removed');
    await send(ch, d.payload);
  } catch (e) {
    error = ((e as Error).message || 'Delivery failed').slice(0, 300);
  }
  const attempts = d.attempts;
  const changes: Partial<NotificationDeliveryEntity> = error
    ? attempts >= MAX_ATTEMPTS || !ch
      ? { status: 'FAILED', lastError: error, nextAttemptAt: null }
      : { status: 'PENDING', lastError: error, nextAttemptAt: new Date(Date.now() + RETRY_AFTER_MS[attempts - 1]!).toISOString() }
    : { status: 'DELIVERED', lastError: null, nextAttemptAt: null, deliveredAt: now() };
  await db.update(NotificationDeliveryEntity, { id: d.id }, changes);
  if (error) console.warn(`[notify] delivery ${d.id} (${d.event}) via ${ch?.kind ?? 'removed channel'} failed, attempt ${attempts}: ${error}`);
  return { ...d, ...changes } as NotificationDeliveryEntity;
}

/**
 * Sends due deliveries. Rows are claimed with SKIP LOCKED (and their next attempt pushed out),
 * so several control-plane instances never send the same delivery twice at once.
 */
export async function deliverDueNotifications(limit = 25): Promise<number> {
  const claimed: { id: string }[] = await db.query(
    `UPDATE notification_deliveries SET attempts = attempts + 1, next_attempt_at = now() + interval '2 minutes'
       WHERE id IN (SELECT id FROM notification_deliveries WHERE status = 'PENDING' AND next_attempt_at <= now() ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED)
       RETURNING id`,
    [limit],
  );
  const ids = (Array.isArray(claimed[0]) ? (claimed[0] as { id: string }[]) : claimed).map((r) => r.id);
  if (!ids.length) return 0;
  const rows = await db.findBy(NotificationDeliveryEntity, { id: In(ids) });
  const channels = new Map((await db.findBy(NotificationChannelEntity, { id: In([...new Set(rows.map((r) => r.channelId))]) })).map((c) => [c.id, c]));
  await Promise.all(rows.map((d) => attempt(d, channels.get(d.channelId) ?? null)));
  return rows.length;
}

let running = false;
export function startNotificationDelivery(): NodeJS.Timeout | null {
  if (!config.notificationIntervalMs) return null;
  return setInterval(() => {
    if (running) return;
    running = true;
    void deliverDueNotifications()
      .catch((e) => console.warn(`[notify] delivery loop failed: ${(e as Error).message}`))
      .finally(() => (running = false));
  }, config.notificationIntervalMs);
}

// ── channels (admin API) ─────────────────────────────────────────

const hintOf = (secret: string) => `${secret.slice(0, 6)}…${secret.slice(-4)}`;

function checkUrl(raw: string | undefined): string {
  let u: URL;
  try {
    u = new URL(raw ?? '');
  } catch {
    throw badRequest('Request validation failed', { fields: { url: 'Give the full URL of the endpoint' } });
  }
  if (u.username || u.password) throw badRequest('Request validation failed', { fields: { url: 'Put no credentials in the URL; verify requests with the signing secret' } });
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && !config.isProduction)) throw badRequest('Request validation failed', { fields: { url: config.isProduction ? 'Use an https:// URL' : 'Use an http:// or https:// URL' } });
  return u.toString();
}

export default class NotificationService {
  private async view(c: NotificationChannelEntity, last?: { status: NotificationDeliveryStatus; at: string; error: string | null }): Promise<NotificationChannelView> {
    return {
      id: c.id,
      name: c.name,
      kind: c.kind,
      enabled: c.enabled,
      events: c.events,
      scope: c.scope,
      recipients: c.recipients,
      url: c.url,
      signingSecretHint: c.signingSecretHint,
      slackChannelId: c.slackChannelId,
      createdBy: { id: c.createdBy, name: c.createdByName },
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
      lastDelivery: last ?? null,
    };
  }

  async list(orgId: string): Promise<{ items: NotificationChannelView[] }> {
    const rows = await db.find(NotificationChannelEntity, { where: { organizationId: orgId }, order: { createdAt: 'ASC' } });
    const last: { channel_id: string; status: NotificationDeliveryStatus; at: Date; last_error: string | null }[] = await db.query(
      `SELECT DISTINCT ON (channel_id) channel_id, status, coalesce(delivered_at, created_at) AS at, last_error FROM notification_deliveries WHERE organization_id = $1 ORDER BY channel_id, created_at DESC`,
      [orgId],
    );
    const byChannel = new Map(last.map((l) => [l.channel_id, { status: l.status, at: new Date(l.at).toISOString(), error: l.last_error }]));
    return { items: await Promise.all(rows.map((c) => this.view(c, byChannel.get(c.id)))) };
  }

  /** Create or update. A webhook channel's signing secret is returned in full only when created or replaced. */
  async save(ctx: OrgContext, dto: SaveNotificationChannelDto): Promise<NotificationChannelView & { signingSecret?: string }> {
    const existing = dto.id ? await db.findOneBy(NotificationChannelEntity, { id: dto.id, organizationId: ctx.org.id }) : null;
    if (dto.id && !existing) throw notFound('Notification channel');
    const kind = existing?.kind ?? dto.kind;
    if (!kind) throw badRequest('Request validation failed', { fields: { kind: 'Choose email, webhook or Slack' } });
    if (existing && dto.kind && dto.kind !== existing.kind) throw badRequest('Request validation failed', { fields: { kind: 'The kind of a channel cannot change; create another channel' } });

    const row: Partial<NotificationChannelEntity> = { name: dto.name, enabled: dto.enabled, events: [...new Set(dto.events)], scope: { ...(dto.scope?.project ? { project: dto.scope.project } : {}), ...(dto.scope?.environment ? { environment: dto.scope.environment } : {}) }, updatedAt: now() };
    let signingSecret: string | undefined;
    if (kind === 'EMAIL') {
      const recipients = [...new Set((dto.recipients ?? existing?.recipients ?? []).map((r) => r.trim().toLowerCase()))];
      if (!recipients.length) throw badRequest('Request validation failed', { fields: { recipients: 'Give at least one email address' } });
      row.recipients = recipients;
    } else if (kind === 'WEBHOOK') {
      row.url = dto.url !== undefined || !existing ? checkUrl(dto.url) : existing.url;
      if (!existing || dto.rotateSigningSecret) {
        signingSecret = `whsec_${randomBytes(32).toString('base64url')}`;
        row.signingSecretSealed = seal(signingSecret, ctx.org.id);
        row.signingSecretHint = hintOf(signingSecret);
      }
    } else {
      row.slackChannelId = dto.slackChannelId || null;
    }

    const id = existing?.id ?? newId('nch');
    await transaction(async (ex) => {
      if (existing) await ex.update(NotificationChannelEntity, { id }, row);
      else await ex.insert(NotificationChannelEntity, { id, organizationId: ctx.org.id, kind, recipients: [], url: null, signingSecretSealed: null, signingSecretHint: null, slackChannelId: null, ...row, createdBy: ctx.user.id, createdByName: ctx.user.fullName, createdAt: row.updatedAt! });
      const { recordEvent, userActor } = await import('../auditService/auditService.service');
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: existing ? 'notification_channel.updated' : 'notification_channel.created', target: { type: 'notification_channel', id, name: dto.name }, metadata: { kind, enabled: dto.enabled, events: row.events, scope: row.scope, signingSecretReplaced: !!signingSecret && !!existing } }, ex);
    });
    const view = await this.view((await db.findOneBy(NotificationChannelEntity, { id }))!);
    return signingSecret ? { ...view, signingSecret } : view;
  }

  async remove(ctx: OrgContext, id: string): Promise<{ id: string; removed: true }> {
    await transaction(async (ex) => {
      const c = await ex.findOneBy(NotificationChannelEntity, { id, organizationId: ctx.org.id });
      if (!c) throw notFound('Notification channel');
      await ex.delete(NotificationChannelEntity, { id });
      const { recordEvent, userActor } = await import('../auditService/auditService.service');
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'notification_channel.deleted', target: { type: 'notification_channel', id, name: c.name }, metadata: { kind: c.kind } }, ex);
    });
    return { id, removed: true };
  }

  /** Sends a test notification now (also when the channel is turned off) and returns the outcome. */
  async test(ctx: OrgContext, id: string): Promise<NotificationDeliveryView> {
    const c = await db.findOneBy(NotificationChannelEntity, { id, organizationId: ctx.org.id });
    if (!c) throw notFound('Notification channel');
    const deliveryId = newId('ndel');
    const t = now();
    const payload: SecretNotificationPayload = { id: deliveryId, event: 'notification.test', occurredAt: t, organization: { id: ctx.org.id, name: ctx.org.name }, secret: null, details: { actor: ctx.user.fullName, channel: c.name }, consoleUrl: `${config.consolePublicUrl}/settings/notifications` };
    const d = { id: deliveryId, organizationId: ctx.org.id, channelId: c.id, event: 'notification.test' as const, secretId: null, payload, status: 'PENDING' as const, attempts: 1, lastError: null, nextAttemptAt: null, createdAt: t, deliveredAt: null };
    await db.insert(NotificationDeliveryEntity, d);
    // A test is tried once: its result is what the person sees, no retries.
    const done = await attempt({ ...d, attempts: MAX_ATTEMPTS } as NotificationDeliveryEntity, c);
    return this.deliveryView(done, c);
  }

  private deliveryView(d: NotificationDeliveryEntity, c: Pick<NotificationChannelEntity, 'id' | 'name' | 'kind'> | undefined): NotificationDeliveryView {
    return {
      id: d.id,
      channel: c ? { id: c.id, name: c.name, kind: c.kind } : { id: d.channelId, name: '(removed)', kind: 'WEBHOOK' },
      event: d.event,
      secret: d.payload.secret ? { id: d.payload.secret.id, name: d.payload.secret.name } : null,
      status: d.status,
      attempts: Math.min(d.attempts, MAX_ATTEMPTS),
      lastError: d.lastError,
      createdAt: d.createdAt,
      deliveredAt: d.deliveredAt,
      nextAttemptAt: d.status === 'PENDING' ? d.nextAttemptAt : null,
    };
  }

  /** Recent deliveries (newest first), optionally of one channel or status. */
  async deliveries(orgId: string, body: { channelId?: unknown; status?: unknown } = {}): Promise<{ items: NotificationDeliveryView[] }> {
    const where: Record<string, unknown> = { organizationId: orgId };
    if (typeof body.channelId === 'string' && body.channelId) where.channelId = body.channelId;
    if (typeof body.status === 'string' && ['PENDING', 'DELIVERED', 'FAILED'].includes(body.status)) where.status = body.status;
    const rows = await db.find(NotificationDeliveryEntity, { where, order: { createdAt: 'DESC' }, take: 100 });
    const channels = new Map((await db.findBy(NotificationChannelEntity, { organizationId: orgId })).map((c) => [c.id, c]));
    return { items: rows.map((d) => this.deliveryView(d, channels.get(d.channelId))) };
  }

  /** Sends a failed delivery again (one more attempt now). */
  async retry(ctx: OrgContext, id: string): Promise<NotificationDeliveryView> {
    const d = await db.findOneBy(NotificationDeliveryEntity, { id, organizationId: ctx.org.id });
    if (!d) throw notFound('Delivery');
    if (d.status !== 'FAILED') throw new HttpError(409, 'DELIVERY_NOT_FAILED', 'Only failed deliveries can be sent again');
    const c = await db.findOneBy(NotificationChannelEntity, { id: d.channelId });
    await db.update(NotificationDeliveryEntity, { id: d.id }, { attempts: d.attempts + 1 });
    const done = await attempt({ ...d, attempts: MAX_ATTEMPTS } as NotificationDeliveryEntity, c);
    return this.deliveryView(done, c ?? undefined);
  }
}
