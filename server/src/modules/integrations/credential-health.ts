import { config } from '../../config';
import { describeError } from '../../lib/errors';
import { sanitize } from '../../lib/sanitize';
import { integrationRepo, webhookRepo } from '../../store/repos';
import type { IntegrationRecord } from '../../store/types';
import { SYSTEM_ACTOR, recordEvent } from '../audit/audit.service';
import { callWebhook } from '../webhooks/webhook.client';
import { isCredentialRejection, type HealthSignal } from './credential-signal';

export { isCredentialRejection };

/**
 * Credential health: whether the provider still accepts a stored credential.
 *
 * Two signals change it, both reported by the customer webhook (Token Vault never sees the
 * credential itself):
 * - an agent request the provider answers with HTTP 401, or a webhook error that means the
 *   credential is gone (App key or installation rejected, OAuth refresh refused);
 * - the scheduled re-test of every stored credential (CREDENTIAL_CHECK_INTERVAL_MS).
 *
 * A rejected credential marks the integration INVALID (agents are then denied with
 * INTEGRATION_UNAVAILABLE, and the dashboard raises an alert); a later successful test marks
 * it CONNECTED again. Provider outages (5xx, timeouts) never change the status.
 */

type Source = 'agent_request' | 'scheduled_check';

/** Marks the integration INVALID (once) and audits it. Returns the updated record, or null if it was already invalid or disabled. */
export async function reportCredentialRejected(i: IntegrationRecord, source: Source, details: HealthSignal & { requestId?: string }) {
  const updated = await integrationRepo.transitionCredentialStatus(i.id, ['CONNECTED', 'ROTATION_REQUIRED'], { credentialStatus: 'INVALID', updatedAt: new Date().toISOString(), ...(source === 'scheduled_check' ? { lastValidatedAt: new Date().toISOString() } : {}) });
  if (!updated) return null;
  console.warn(`[api] integration ${i.id} marked INVALID: the provider rejected its credential (${source}${details.errorCode ? `, ${details.errorCode}` : ''}${details.upstreamStatus ? `, HTTP ${details.upstreamStatus}` : ''})`);
  await recordEvent({
    orgId: i.organizationId,
    actor: SYSTEM_ACTOR,
    eventType: 'integration.credential_rejected',
    target: { type: 'integration', id: i.id, name: i.displayName },
    outcome: 'FAILURE',
    severity: 'critical',
    metadata: { source, upstreamStatus: details.upstreamStatus ?? details.errorUpstreamStatus ?? null, errorCode: details.errorCode ?? null, requestId: details.requestId ?? null, previousStatus: i.credentialStatus },
  });
  return updated;
}

/** Marks an INVALID integration CONNECTED again after a successful test, and audits it. */
async function reportCredentialRecovered(i: IntegrationRecord, upstreamStatus: number | null) {
  const updated = await integrationRepo.transitionCredentialStatus(i.id, ['INVALID'], { credentialStatus: 'CONNECTED', updatedAt: new Date().toISOString(), lastValidatedAt: new Date().toISOString() });
  if (!updated) return null;
  console.log(`[api] integration ${i.id} is CONNECTED again: its credential passed the scheduled check`);
  await recordEvent({
    orgId: i.organizationId,
    actor: SYSTEM_ACTOR,
    eventType: 'integration.credential_recovered',
    target: { type: 'integration', id: i.id, name: i.displayName },
    outcome: 'SUCCESS',
    severity: 'info',
    metadata: { source: 'scheduled_check', upstreamStatus },
  });
  return updated;
}

export type CheckOutcome = 'valid' | 'rejected' | 'unknown' | 'skipped';

/** Re-tests one stored credential through its webhook and applies the result. */
export async function checkCredential(i: IntegrationRecord): Promise<CheckOutcome> {
  if (i.credentialStatus === 'DISABLED') return 'skipped';
  const webhook = await webhookRepo.getWebhook(i.organizationId, i.webhookId);
  // An unhealthy webhook says nothing about the credential: try again next round.
  if (!webhook || webhook.status !== 'CONNECTED' || webhook.simulateOutage) return 'skipped';
  let res;
  try {
    res = await callWebhook(webhook, 'POST', `/internal/v1/credentials/${i.credentialReference}/test`, { org_id: i.organizationId });
  } catch {
    return 'unknown';
  }
  if (res.status !== 200) return 'unknown';
  const upstream = typeof res.body.upstream_status === 'number' ? res.body.upstream_status : null;
  if (res.body.valid === true) {
    if (i.credentialStatus === 'INVALID') await reportCredentialRecovered(i, upstream);
    else await integrationRepo.updateIntegration(i.id, { lastValidatedAt: new Date().toISOString() });
    return 'valid';
  }
  // A 401, or a credential-level webhook error, is a rejection. 403 (valid but lacking a scope), 5xx and timeouts are not.
  const signal = { upstreamStatus: upstream, errorCode: res.body.error_code ?? null, errorUpstreamStatus: upstream };
  if (isCredentialRejection(signal)) {
    await reportCredentialRejected(i, 'scheduled_check', signal);
    return 'rejected';
  }
  return 'unknown';
}

const running = new Set<string>();

/**
 * One round over the stored credentials of one organization, or of all of them (sequential,
 * so a large tenant cannot flood its webhook). A round already running for the same scope is not started twice.
 */
export async function checkAllCredentials(organizationId?: string): Promise<Record<CheckOutcome, number>> {
  const counts: Record<CheckOutcome, number> = { valid: 0, rejected: 0, unknown: 0, skipped: 0 };
  const scope = organizationId ?? '*';
  if (running.has(scope)) return counts;
  running.add(scope);
  try {
    for (const i of await integrationRepo.listCheckableIntegrations(organizationId)) counts[await checkCredential(i)]++;
    if (counts.rejected) console.warn(`[api] credential check: ${counts.rejected} rejected, ${counts.valid} valid, ${counts.unknown} unknown`);
  } catch (e) {
    console.error('[api] credential check failed:', sanitize(describeError(e)));
  } finally {
    running.delete(scope);
  }
  return counts;
}

/** Starts the scheduled credential check (CREDENTIAL_CHECK_INTERVAL_MS; 0 turns it off). */
export function startCredentialChecks(): NodeJS.Timeout | null {
  if (!config.credentialCheckIntervalMs) return null;
  return setInterval(() => void checkAllCredentials(), config.credentialCheckIntervalMs);
}
