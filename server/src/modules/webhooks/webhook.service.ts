import { config } from '../../config';
import { hmacHex, randomToken, safeEqualHex } from '../../lib/crypto';
import { describeError } from '../../lib/errors';
import { sanitize } from '../../lib/sanitize';
import { integrationRepo, webhookRepo } from '../../store/repos';
import type { WebhookRecord } from '../../store/types';
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
