import { config } from '../../config';
import { hmacHex, randomToken, safeEqualHex } from '../../lib/crypto';
import { db, type WebhookRecord } from '../../store/db';
import { SYSTEM_ACTOR, recordEvent } from '../audit/audit.service';
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
export async function checkHealth(webhook: WebhookRecord): Promise<HealthOutcome> {
  const challenge = webhook.registrationChallenge ?? randomToken(16);
  try {
    const res = await callWebhook(webhook, 'GET', `/internal/v1/health?challenge=${encodeURIComponent(challenge)}`);
    if (res.status === 401) return { ok: false, latencyMs: res.latencyMs, detail: `Webhook rejected the signed challenge (${res.body?.error?.message ?? 'unauthorized'}). Check that WEBHOOK_SIGNING_SECRET matches on both sides.` };
    if (res.status !== 200) return { ok: false, latencyMs: res.latencyMs, detail: `Unexpected HTTP ${res.status} from webhook health endpoint` };
    const { instance_id, version, challenge_response, github_mode } = res.body ?? {};
    const expected = hmacHex(config.webhookSigningSecret, `health:${challenge}:${instance_id}`);
    if (typeof challenge_response !== 'string' || !safeEqualHex(expected, challenge_response)) {
      return { ok: false, latencyMs: res.latencyMs, detail: 'Challenge response signature is invalid; webhook identity could not be verified.' };
    }
    if (webhook.instanceId && webhook.instanceId !== instance_id) {
      return { ok: false, latencyMs: res.latencyMs, detail: `Webhook identity changed (expected ${webhook.instanceId}, got ${instance_id}).` };
    }
    return { ok: true, latencyMs: res.latencyMs, detail: 'Signed health challenge verified', instanceId: instance_id, version, githubMode: github_mode };
  } catch (e) {
    const err = e as Error;
    const hint = err instanceof WebhookUnavailableError && err.reason === 'UNREACHABLE' ? ' Is the webhook runtime running (npm run dev -w webhook)?' : '';
    return { ok: false, latencyMs: null, detail: err.message + hint };
  }
}

export function applyHealth(webhook: WebhookRecord, outcome: HealthOutcome) {
  const now = new Date().toISOString();
  const previous = webhook.status;
  webhook.healthHistory = [{ at: now, ok: outcome.ok, latencyMs: outcome.latencyMs, detail: outcome.detail }, ...webhook.healthHistory].slice(0, 30);
  if (outcome.ok) {
    webhook.status = 'CONNECTED';
    webhook.lastHeartbeatAt = now;
    webhook.lastError = null;
    webhook.instanceId = outcome.instanceId ?? webhook.instanceId;
    webhook.softwareVersion = outcome.version ?? webhook.softwareVersion;
    if (!webhook.verifiedAt) webhook.verifiedAt = now;
    webhook.registrationChallenge = null; // one-time challenge consumed
  } else {
    webhook.status = webhook.verifiedAt ? 'UNHEALTHY' : 'PENDING';
    webhook.lastError = outcome.detail;
  }
  if (previous !== webhook.status && webhook.verifiedAt && previous !== 'PENDING') {
    recordEvent({
      orgId: webhook.organizationId,
      actor: SYSTEM_ACTOR,
      eventType: outcome.ok ? 'webhook.recovered' : 'webhook.unhealthy',
      target: { type: 'webhook', id: webhook.id, name: webhook.name },
      outcome: outcome.ok ? 'SUCCESS' : 'FAILURE',
      severity: outcome.ok ? 'info' : 'critical',
      metadata: { detail: outcome.detail },
    });
  }
}

/** Periodic heartbeat over all verified webhooks. */
export function startHeartbeat() {
  const tick = async () => {
    for (const w of db.webhooks.filter((x) => x.verifiedAt)) {
      applyHealth(w, w.simulateOutage ? { ok: false, latencyMs: null, detail: 'Simulated outage enabled' } : await checkHealth(w));
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
  for (const i of db.integrations.filter((x) => !x.maskedIdentifier)) {
    const w = db.webhooks.find((x) => x.id === i.webhookId);
    if (!w || w.status !== 'CONNECTED') continue;
    try {
      const res = await callWebhook(w, 'POST', `/internal/v1/credentials/${i.credentialReference}/test`, { org_id: i.organizationId });
      if (res.status === 200) {
        i.maskedIdentifier = res.body.masked_identifier;
        i.credentialFingerprint = res.body.fingerprint;
        i.lastValidatedAt = new Date().toISOString();
      }
    } catch {
      /* retried on next manual test */
    }
  }
}
