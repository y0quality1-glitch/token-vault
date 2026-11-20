import type { SelectQueryBuilder } from 'typeorm';
import { WebhookEntity } from '../../entities';
import { BaseServices } from '../baseService';
import { config } from '../../config';
import { transaction } from '../../databases/client';
import type { CreateWebhookDto, UpdateWebhookDto } from '../../databases/repository/webhook/webhook.dto';
import { hmacHex, randomToken, safeEqualHex } from '../../lib/crypto';
import { badRequest, conflict, describeError } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { sanitize } from '../../lib/sanitize';
import { integrationRepo, webhookRepo } from '../../store/repos';
import type { WebhookRecord } from '../../store/types';
import type { AdminContext } from '../../types/express';
import { SYSTEM_ACTOR, recordEvent, userActor } from '../auditService/auditService.service';
import { WebhookUnavailableError, callWebhook } from './webhook.client';

export interface HealthOutcome {
  ok: boolean;
  latencyMs: number | null;
  detail: string;
  instanceId?: string;
  version?: string;
  githubMode?: string;
}

/**
 * Signed health-check challenge. The webhook proves it holds the signing secret by
 * returning HMAC("health:<challenge>:<instance_id>"), and the response itself is signed.
 */
/** Transport of the link: mTLS with certificate details and an expiry warning, or plain HTTP. */
function transportNote(peer: { subject: string; issuer: string; validTo: string } | undefined, reported: { client_certificates?: string } | undefined): string {
  if (!peer) return '. Transport: plain HTTP (no TLS)';
  const days = Math.floor((Date.parse(peer.validTo) - Date.now()) / 86_400_000);
  const mutual = reported?.client_certificates === 'required' ? 'mutual TLS' : 'TLS (the webhook does not require a client certificate)';
  const expiry = days < 14 ? `; WEBHOOK CERTIFICATE EXPIRES IN ${Math.max(days, 0)} DAY${days === 1 ? '' : 'S'}` : `, valid ${days} more days`;
  return `. Transport: ${mutual}, webhook certificate ${peer.subject} issued by ${peer.issuer}${expiry}`;
}

/** Signing-secret rotation status: tells the admin which step of a rotation is next. */
function signingNote(s: { request_signed_with?: unknown; previous_secrets?: unknown } | undefined): string {
  if (!s) return '';
  if (s.request_signed_with === 'previous') return ". Signing-secret rotation in progress: the webhook has the new secret, Token Vault still signs with the old one (switch Token Vault next)";
  if (Number(s.previous_secrets) > 0) return '. Signing-secret rotation in progress: both sides use the new secret; the old one can be retired';
  return '';
}

/** Key status the webhook reports (key ids only): tells an admin whether a previous key is still needed. */
function encryptionNote(
  enc: { key_id?: unknown; records_by_key?: Record<string, number>; last_reencryption?: { unreadable?: number } | null; key_service?: { ok?: boolean; detail?: string } | null } | undefined,
): string {
  if (!enc || typeof enc.key_id !== 'string') return '';
  const byKey = enc.records_by_key ?? {};
  const onOld = Object.entries(byKey).reduce((n, [id, c]) => (id === enc.key_id ? n : n + (Number(c) || 0)), 0);
  const unreadable = Number(enc.last_reencryption?.unreadable) || 0;
  // A KMS outage: credentials are fine but cannot be opened until it is back (requests fail with KEY_SERVICE_UNAVAILABLE).
  const kms = enc.key_service && enc.key_service.ok === false ? `; KEY SERVICE UNAVAILABLE (${String(enc.key_service.detail ?? '').slice(0, 120)}): requests that need a credential fail until it is back` : '';
  return `. Credentials encrypted with key ${enc.key_id}${onOld ? `; ${onOld} still on an older key` : ''}${unreadable ? `; ${unreadable} unreadable with the configured keys` : ''}${kms}`;
}

export async function checkHealth(webhook: WebhookRecord): Promise<HealthOutcome> {
  const challenge = webhook.registrationChallenge ?? randomToken(16);
  try {
    const res = await callWebhook(webhook, 'GET', `/internal/v1/health?challenge=${encodeURIComponent(challenge)}`);
    if (res.status === 401 && res.body?.error?.code === 'CLIENT_CERTIFICATE_REJECTED') {
      return { ok: false, latencyMs: res.latencyMs, detail: `The webhook refused the control plane's client certificate (${res.body.error.message}). Check CONTROL_PLANE_TLS_CERT, and the webhook's WEBHOOK_TLS_CLIENT_CA and WEBHOOK_TLS_ALLOWED_CLIENTS.` };
    }
    if (res.status === 401) return { ok: false, latencyMs: res.latencyMs, detail: `Webhook rejected the signed challenge (${res.body?.error?.message ?? 'unauthorized'}). Check that WEBHOOK_SIGNING_SECRET matches on both sides.` };
    if (res.status !== 200) return { ok: false, latencyMs: res.latencyMs, detail: `Unexpected HTTP ${res.status} from webhook health endpoint` };
    const { instance_id, version, challenge_response, github_mode } = res.body ?? {};
    const proven = typeof challenge_response === 'string' && config.webhookAcceptedSecrets.some((secret) => safeEqualHex(hmacHex(secret, `health:${challenge}:${instance_id}`), challenge_response));
    if (!proven) {
      return { ok: false, latencyMs: res.latencyMs, detail: 'Challenge response signature is invalid; webhook identity could not be verified.' };
    }
    if (webhook.instanceId && webhook.instanceId !== instance_id) {
      return { ok: false, latencyMs: res.latencyMs, detail: `Webhook identity changed (expected ${webhook.instanceId}, got ${instance_id}).` };
    }
    return { ok: true, latencyMs: res.latencyMs, detail: `Signed health challenge verified${transportNote(res.tls, res.body?.tls)}${signingNote(res.body?.signing)}${encryptionNote(res.body?.encryption)}`, instanceId: instance_id, version, githubMode: github_mode };
  } catch (e) {
    const err = e as Error;
    const hint = err instanceof WebhookUnavailableError && err.reason === 'UNREACHABLE' ? ' Is the webhook runtime running (npm run dev -w webhook)?' : '';
    return { ok: false, latencyMs: null, detail: err.message + hint };
  }
}

/** Persists the outcome of a health check and audits status transitions. */
export async function applyHealth(webhook: WebhookRecord, outcome: HealthOutcome): Promise<WebhookRecord> {
  const now = new Date().toISOString();
  const previous = webhook.status;
  const healthHistory = [{ at: now, ok: outcome.ok, latencyMs: outcome.latencyMs, detail: outcome.detail }, ...webhook.healthHistory].slice(0, 30);
  const patch: Partial<WebhookRecord> = outcome.ok
    ? {
        healthHistory,
        status: 'CONNECTED',
        lastHeartbeatAt: now,
        lastError: null,
        instanceId: outcome.instanceId ?? webhook.instanceId,
        softwareVersion: outcome.version ?? webhook.softwareVersion,
        verifiedAt: webhook.verifiedAt ?? now,
        registrationChallenge: null, // one-time challenge consumed
      }
    : { healthHistory, status: webhook.verifiedAt ? 'UNHEALTHY' : 'PENDING', lastError: outcome.detail };
  const updated = await webhookRepo.updateWebhook(webhook.id, patch);
  if (previous !== updated.status && updated.verifiedAt && previous !== 'PENDING') {
    await recordEvent({
      orgId: updated.organizationId,
      actor: SYSTEM_ACTOR,
      eventType: outcome.ok ? 'webhook.recovered' : 'webhook.unhealthy',
      target: { type: 'webhook', id: updated.id, name: updated.name },
      outcome: outcome.ok ? 'SUCCESS' : 'FAILURE',
      severity: outcome.ok ? 'info' : 'critical',
      metadata: { detail: outcome.detail },
    });
  }
  return updated;
}

/** Periodic heartbeat over all verified webhooks. */
export function startHeartbeat() {
  const tick = async () => {
    try {
      for (const w of await webhookRepo.listVerifiedWebhooks()) {
        await applyHealth(w, w.simulateOutage ? { ok: false, latencyMs: null, detail: 'Simulated outage enabled' } : await checkHealth(w));
      }
    } catch (e) {
      console.error('[api] heartbeat failed:', sanitize(describeError(e)));
    }
  };
  setTimeout(() => void tick().then(syncSeedCredentialMetadata), 1500);
  return setInterval(() => void tick(), config.heartbeatIntervalMs);
}

/**
 * Seeded integrations start without a masked identifier because the webhook
 * generates the mock secret values. Ask the webhook for non-secret metadata.
 */
export async function syncSeedCredentialMetadata() {
  try {
    for (const i of await integrationRepo.listUnsyncedIntegrations()) {
      const w = await webhookRepo.getWebhook(i.organizationId, i.webhookId);
      if (!w || w.status !== 'CONNECTED') continue;
      try {
        const res = await callWebhook(w, 'POST', `/internal/v1/credentials/${i.credentialReference}/test`, { org_id: i.organizationId });
        if (res.status === 200) {
          await integrationRepo.updateIntegration(i.id, { maskedIdentifier: res.body.masked_identifier, credentialFingerprint: res.body.fingerprint, lastValidatedAt: new Date().toISOString() });
        }
      } catch {
        /* retried on next manual test */
      }
    }
  } catch (e) {
    console.error('[api] credential metadata sync failed:', sanitize(describeError(e)));
  }
}

type OrgContext = AdminContext & { org: { id: string } };

/** What the control plane can do on the webhook link (shown by the setup wizard). */
function transportInfo() {
  const t = config.webhookTls;
  return { mtlsAvailable: !!(t.cert && t.key), requireTls: t.requireTls, trustsCustomCa: !!t.ca };
}

/** Refuses a URL the transport settings do not allow. */
function checkUrl(url: string, environment: string) {
  if (url.startsWith('http://') && (environment === 'production' || config.webhookTls.requireTls)) {
    throw badRequest('Request validation failed', { fields: { endpointUrl: config.webhookTls.requireTls ? 'WEBHOOK_REQUIRE_TLS is on: webhooks must use https://' : 'Production webhooks must use https://' } });
  }
}

/** Webhook registrations (admin API): register, configure, verify, simulate an outage. */
export default class WebhookService extends BaseServices<WebhookEntity, WebhookRecord | (WebhookRecord & { integrations: { id: string; displayName: string }[] })> {
  constructor() {
    super(WebhookEntity);
  }
  getModuleName() {
    return 'Webhook';
  }
  getGlobalSearchColumns() {
    return ['main.name', 'main.endpoint_url', 'main.description'];
  }
  protected prepareFilter(qb: SelectQueryBuilder<WebhookEntity>, orgId: string) {
    return qb.where('main.organization_id = :orgId', { orgId }).orderBy('main.created_at', 'ASC');
  }
  /** The detail lists the integrations served by the webhook. */
  protected async postProcessAfterGetById(w: WebhookEntity, orgId: string) {
    const integrations = (await integrationRepo.listIntegrations(orgId)).filter((i) => i.webhookId === w.id).map((i) => ({ id: i.id, displayName: i.displayName }));
    return { ...w, integrations };
  }

  private async get(orgId: string, id: string): Promise<WebhookRecord> {
    return this.findEntity(orgId, id);
  }

  async list(orgId: string, body: unknown = {}) {
    const { records, totalRecords } = await this.getAll(orgId, body);
    return { items: records, total: totalRecords, defaultEndpointUrl: config.defaultWebhookUrl, transport: transportInfo() };
  }

  /** Step 1: register endpoint (PENDING) and issue a one-time registration challenge. */
  create(ctx: OrgContext, dto: CreateWebhookDto) {
    const body = { name: dto.name, endpointUrl: dto.endpointUrl, environment: dto.environment, description: dto.description };
    checkUrl(body.endpointUrl, body.environment);
    return transaction(async (tx) => {
      if ((await webhookRepo.listWebhooks(ctx.org.id, tx)).some((w) => w.name.toLowerCase() === body.name.toLowerCase())) throw conflict('A webhook with that name already exists');
      const created = await webhookRepo.insertWebhook(
        {
          id: newId('wh'),
          organizationId: ctx.org.id,
          ...body,
          authenticationType: 'SHARED_SECRET_HMAC',
          signingSecretRef: config.webhookSigningSecretRef,
          status: 'PENDING',
          instanceId: null,
          softwareVersion: null,
          lastHeartbeatAt: null,
          lastError: null,
          simulateOutage: false,
          registrationChallenge: `rc_${randomToken(12)}`,
          healthHistory: [],
          createdAt: new Date().toISOString(),
          verifiedAt: null,
        },
        tx,
      );
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'webhook.registered', target: { type: 'webhook', id: created.id, name: created.name }, metadata: { environment: created.environment, endpointUrl: created.endpointUrl } }, tx);
      return created;
    });
  }

  /**
   * Step 2: configure authentication (also name, description, or a move to a new URL; its pinned
   * instance identity must still match, so a URL change cannot swap in a different webhook).
   */
  async update(ctx: OrgContext, dto: UpdateWebhookDto) {
    const w = await this.get(ctx.org.id, dto.id);
    const body: Pick<UpdateWebhookDto, 'authenticationType' | 'name' | 'description' | 'endpointUrl'> = {};
    for (const k of ['authenticationType', 'name', 'description', 'endpointUrl'] as const) if (dto[k] !== undefined) Object.assign(body, { [k]: dto[k] });
    const url = body.endpointUrl ?? w.endpointUrl;
    if (body.endpointUrl) checkUrl(body.endpointUrl, w.environment);
    if ((body.authenticationType ?? w.authenticationType) === 'MTLS') {
      if (!transportInfo().mtlsAvailable) throw badRequest('Mutual TLS needs a control-plane client certificate (CONTROL_PLANE_TLS_CERT and CONTROL_PLANE_TLS_KEY). See docs/DEPLOYMENT.md.');
      if (!url.startsWith('https://')) throw badRequest('Request validation failed', { fields: { endpointUrl: 'Mutual TLS needs an https:// webhook URL' } });
    }
    return transaction(async (tx) => {
      const u = await webhookRepo.updateWebhook(w.id, body, tx);
      await recordEvent(
        {
          orgId: ctx.org.id,
          actor: userActor(ctx),
          eventType: body.endpointUrl && body.endpointUrl !== w.endpointUrl ? 'webhook.endpoint_changed' : 'webhook.updated',
          target: { type: 'webhook', id: u.id, name: u.name },
          severity: body.endpointUrl && body.endpointUrl !== w.endpointUrl ? 'warning' : 'info',
          metadata: { ...body, ...(body.endpointUrl ? { previousEndpointUrl: w.endpointUrl } : {}) },
        },
        tx,
      );
      return u;
    });
  }

  /** Step 3: verify connectivity (also used for manual health tests). */
  async test(ctx: OrgContext, id: string) {
    const w = await this.get(ctx.org.id, id);
    const firstVerification = !w.verifiedAt;
    const outcome: HealthOutcome = w.simulateOutage ? { ok: false, latencyMs: null, detail: 'Simulated outage enabled: webhook did not respond' } : await checkHealth(w);
    const updated = await applyHealth(w, outcome);
    await recordEvent({
      orgId: ctx.org.id,
      actor: userActor(ctx),
      eventType: outcome.ok ? (firstVerification ? 'webhook.verified' : 'webhook.health_check_passed') : 'webhook.health_check_failed',
      target: { type: 'webhook', id: w.id, name: w.name },
      outcome: outcome.ok ? 'SUCCESS' : 'FAILURE',
      severity: outcome.ok ? 'info' : 'warning',
      metadata: { latencyMs: outcome.latencyMs, detail: outcome.detail, instanceId: outcome.instanceId },
    });
    if (outcome.ok) void syncSeedCredentialMetadata();
    return { webhook: updated, result: outcome };
  }

  /** Demo control for Scenario F (webhook unavailable). */
  async simulateOutage(ctx: OrgContext, id: string, enabled: boolean) {
    const w = await this.get(ctx.org.id, id);
    const toggled = await webhookRepo.updateWebhook(w.id, { simulateOutage: enabled });
    const updated = await applyHealth(toggled, enabled ? { ok: false, latencyMs: null, detail: 'Simulated outage enabled' } : await checkHealth(toggled));
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: enabled ? 'webhook.outage_simulated' : 'webhook.outage_cleared', target: { type: 'webhook', id: w.id, name: w.name }, severity: 'warning', metadata: { simulated: true } });
    return updated;
  }
}
