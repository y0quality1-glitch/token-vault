import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, PROVIDER_CATALOG, type CatalogEntry, type IntegrationDetail } from '@token-vault/shared';
import { transaction } from '../../db/client';
import { HttpError, badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { grantRepo, integrationRepo, webhookRepo } from '../../store/repos';
import type { IntegrationRecord } from '../../store/types';
import { effectiveGrantStatus, loadLookups, toIntegration } from '../../store/views';
import { recordEvent, userActor } from '../audit/audit.service';
import { WebhookUnavailableError, callWebhook } from '../webhooks/webhook.client';

export const integrationsRouter = Router();

const repoPattern = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const secretSchema = z
  .string()
  .min(20, 'Token must be at least 20 characters')
  .max(512, 'Token is too long')
  .refine((s) => !/\s/.test(s), 'Token must not contain whitespace');

const createSchema = z.object({
  provider: z.literal('github', { errorMap: () => ({ message: 'Only GitHub is available in the POC' }) }),
  webhookId: z.string().min(1, 'Select a customer webhook'),
  displayName: z.string().trim().min(3, 'Name must be at least 3 characters').max(60),
  environment: z.enum(['development', 'staging', 'production']),
  accountLabel: z.string().trim().min(1, 'Account / organization label is required').max(80),
  authType: z.literal('PAT'),
  secret: secretSchema,
  allowedResources: z.array(z.string().trim().regex(repoPattern, 'Use owner/repository format')).max(20).default([]),
  description: z.string().trim().max(240).default(''),
});

async function getIntegration(orgId: string, id: string): Promise<IntegrationRecord> {
  const i = await integrationRepo.getIntegration(orgId, id);
  if (!i) throw notFound('Integration');
  return i;
}

async function webhookFor(i: Pick<IntegrationRecord, 'webhookId' | 'organizationId'>) {
  const w = await webhookRepo.getWebhook(i.organizationId, i.webhookId);
  if (!w) throw notFound('Webhook');
  return w;
}

function webhookError(e: unknown): never {
  if (e instanceof WebhookUnavailableError) throw new HttpError(503, 'WEBHOOK_UNAVAILABLE', `${e.message}. The credential was not stored.`);
  throw e;
}

async function detail(i: IntegrationRecord): Promise<IntegrationDetail> {
  const [lookups, grants] = await Promise.all([loadLookups(i.organizationId, [i.createdBy]), grantRepo.listGrants(i.organizationId, { integrationId: i.id })]);
  return {
    ...toIntegration(i, lookups),
    grantedAgents: grants
      .filter((g) => g.storedStatus !== 'SUPERSEDED')
      .map((g) => ({
        agentId: g.agentId,
        agentName: lookups.agents.get(g.agentId) ?? 'Deleted agent',
        grantId: g.id,
        grantName: g.name,
        status: effectiveGrantStatus(g),
        scopes: g.scopes,
      })),
  };
}

integrationsRouter.get('/integrations/catalog', async (req, res) => {
  const { org } = orgCtx(req);
  const list = await integrationRepo.listIntegrations(org.id);
  const items: CatalogEntry[] = PROVIDER_CATALOG.map((p) => ({
    ...p,
    connectedCount: list.filter((i) => i.provider === p.provider && i.credentialStatus !== 'DISABLED').length,
  }));
  res.json({ items });
});

integrationsRouter.get('/integrations', async (req, res) => {
  const { org } = orgCtx(req);
  const list = await integrationRepo.listIntegrations(org.id);
  const lookups = await loadLookups(org.id, list.map((i) => i.createdBy));
  res.json({ items: list.map((i) => toIntegration(i, lookups)) });
});

integrationsRouter.get('/integrations/:id', async (req, res) => {
  const { org } = orgCtx(req);
  res.json(await detail(await getIntegration(org.id, String(req.params.id))));
});

/**
 * Credential registration. The secret travels browser -> control plane (TLS) -> customer webhook (signed)
 * and is never written to the control-plane database, logs or audit. Only the returned reference is kept.
 */
integrationsRouter.post('/integrations', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(createSchema, req.body);
  const { secret, ...meta } = body;
  if (req.body && typeof req.body === 'object') delete (req.body as Record<string, unknown>).secret;

  const webhook = await webhookRepo.getWebhook(ctx.org.id, meta.webhookId);
  if (!webhook) throw badRequest('Request validation failed', { fields: { webhookId: 'Unknown webhook' } });
  if (webhook.status !== 'CONNECTED') throw new HttpError(409, 'WEBHOOK_NOT_CONNECTED', `Webhook "${webhook.name}" is ${webhook.status.toLowerCase()}. Verify connectivity before registering credentials.`);
  if ((await integrationRepo.listIntegrations(ctx.org.id)).some((i) => i.displayName.toLowerCase() === meta.displayName.toLowerCase())) throw conflict('An integration with that name already exists');

  let stored;
  try {
    stored = await callWebhook(webhook, 'POST', '/internal/v1/credentials', {
      org_id: ctx.org.id,
      provider: meta.provider,
      secret,
      metadata: { label: meta.displayName, account: meta.accountLabel, environment: meta.environment },
    });
  } catch (e) {
    webhookError(e);
  }
  if (stored.status !== 201) throw new HttpError(502, 'WEBHOOK_REJECTED', stored.body?.error?.message ?? 'The webhook rejected the credential');

  // Validate immediately through the webhook (it decrypts and calls the provider; we only see the outcome).
  let lastValidatedAt: string | null = null;
  let credentialStatus: IntegrationRecord['credentialStatus'] = 'CONNECTED';
  try {
    const test = await callWebhook(webhook, 'POST', `/internal/v1/credentials/${stored.body.credential_ref}/test`, { org_id: ctx.org.id });
    if (test.status === 200) {
      lastValidatedAt = new Date().toISOString();
      if (test.body.valid !== true) credentialStatus = 'INVALID';
    }
  } catch {
    /* validation is best-effort; status stays CONNECTED until the next test */
  }

  const now = new Date().toISOString();
  const integration = await transaction(async (tx) => {
    const created = await integrationRepo.insertIntegration(
      {
        id: newId('int'),
        organizationId: ctx.org.id,
        webhookId: webhook.id,
        provider: meta.provider,
        displayName: meta.displayName,
        environment: meta.environment,
        accountLabel: meta.accountLabel,
        authType: meta.authType,
        credentialReference: stored.body.credential_ref,
        credentialStatus,
        maskedIdentifier: stored.body.masked_identifier,
        credentialFingerprint: stored.body.fingerprint,
        allowedResources: meta.allowedResources,
        description: meta.description,
        createdBy: ctx.user.id,
        createdAt: now,
        updatedAt: now,
        lastValidatedAt,
        rotatedAt: null,
        deletedAt: null,
      },
      tx,
    );
    await recordEvent(
      {
        orgId: ctx.org.id,
        actor: userActor(ctx),
        eventType: 'integration.connected',
        target: { type: 'integration', id: created.id, name: created.displayName },
        metadata: { provider: created.provider, credentialReference: created.credentialReference, webhookId: webhook.id, environment: created.environment },
      },
      tx,
    );
    return created;
  });
  res.status(201).json(await detail(integration));
});

integrationsRouter.patch('/integrations/:id', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const i = await getIntegration(ctx.org.id, String(req.params.id));
  const body = parse(
    z.object({
      displayName: z.string().trim().min(3).max(60),
      accountLabel: z.string().trim().min(1).max(80),
      description: z.string().trim().max(240),
      allowedResources: z.array(z.string().trim().regex(repoPattern, 'Use owner/repository format')).max(20),
    }),
    req.body,
  );
  const updated = await transaction(async (tx) => {
    const u = await integrationRepo.updateIntegration(i.id, { ...body, updatedAt: new Date().toISOString() }, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'integration.metadata_updated', target: { type: 'integration', id: u.id, name: u.displayName }, metadata: body }, tx);
    return u;
  });
  res.json(await detail(updated));
});

integrationsRouter.post('/integrations/:id/test', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const i = await getIntegration(ctx.org.id, String(req.params.id));
  let result;
  try {
    result = await callWebhook(await webhookFor(i), 'POST', `/internal/v1/credentials/${i.credentialReference}/test`, { org_id: ctx.org.id });
  } catch (e) {
    if (e instanceof WebhookUnavailableError) throw new HttpError(503, 'WEBHOOK_UNAVAILABLE', e.message);
    throw e;
  }
  const valid = result.status === 200 && result.body.valid === true;
  const patch: Partial<IntegrationRecord> = { lastValidatedAt: new Date().toISOString() };
  if (result.status === 200) Object.assign(patch, { maskedIdentifier: result.body.masked_identifier, credentialFingerprint: result.body.fingerprint });
  if (i.credentialStatus !== 'DISABLED') patch.credentialStatus = valid ? 'CONNECTED' : 'INVALID';
  const updated = await integrationRepo.updateIntegration(i.id, patch);
  await recordEvent({
    orgId: ctx.org.id,
    actor: userActor(ctx),
    eventType: 'integration.tested',
    target: { type: 'integration', id: i.id, name: i.displayName },
    outcome: valid ? 'SUCCESS' : 'FAILURE',
    severity: valid ? 'info' : 'warning',
    metadata: { upstreamStatus: result.body.upstream_status ?? result.status, simulated: result.body.simulated },
  });
  res.json({ valid, upstreamStatus: result.body.upstream_status ?? null, simulated: result.body.simulated ?? true, integration: await detail(updated) });
});

integrationsRouter.post('/integrations/:id/rotate', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const i = await getIntegration(ctx.org.id, String(req.params.id));
  const { secret } = parse(z.object({ secret: secretSchema }), req.body);
  delete (req.body as Record<string, unknown>).secret;
  let result;
  try {
    result = await callWebhook(await webhookFor(i), 'POST', `/internal/v1/credentials/${i.credentialReference}/rotate`, { org_id: ctx.org.id, secret });
  } catch (e) {
    webhookError(e);
  }
  if (result.status !== 200) throw new HttpError(502, 'WEBHOOK_REJECTED', result.body?.error?.message ?? 'Rotation failed');
  const now = new Date().toISOString();
  const updated = await transaction(async (tx) => {
    const u = await integrationRepo.updateIntegration(
      i.id,
      { maskedIdentifier: result.body.masked_identifier, credentialFingerprint: result.body.fingerprint, rotatedAt: now, updatedAt: now, credentialStatus: i.credentialStatus === 'DISABLED' ? 'DISABLED' : 'CONNECTED' },
      tx,
    );
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'integration.credential_rotated', target: { type: 'integration', id: i.id, name: i.displayName }, severity: 'warning', metadata: { credentialReference: i.credentialReference } }, tx);
    return u;
  });
  res.json(await detail(updated));
});

async function setStatus(req: import('express').Request, status: 'DISABLED' | 'CONNECTED') {
  const ctx = orgCtx(req);
  const i = await getIntegration(ctx.org.id, String(req.params.id));
  return transaction(async (tx) => {
    const u = await integrationRepo.updateIntegration(i.id, { credentialStatus: status, updatedAt: new Date().toISOString() }, tx);
    await recordEvent(
      { orgId: ctx.org.id, actor: userActor(ctx), eventType: status === 'DISABLED' ? 'integration.disabled' : 'integration.enabled', target: { type: 'integration', id: i.id, name: i.displayName }, severity: status === 'DISABLED' ? 'warning' : 'info' },
      tx,
    );
    return u;
  });
}

integrationsRouter.post('/integrations/:id/disable', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  res.json(await detail(await setStatus(req, 'DISABLED')));
});

integrationsRouter.post('/integrations/:id/enable', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  res.json(await detail(await setStatus(req, 'CONNECTED')));
});

integrationsRouter.delete('/integrations/:id', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const i = await getIntegration(ctx.org.id, String(req.params.id));
  // Ask the customer webhook to crypto-shred the stored credential (best effort if unreachable).
  let shredded = false;
  try {
    const r = await callWebhook(await webhookFor(i), 'POST', `/internal/v1/credentials/${i.credentialReference}/delete`, { org_id: ctx.org.id });
    shredded = r.status === 200;
  } catch {
    shredded = false;
  }
  const revoked = await transaction(async (tx) => {
    const now = new Date().toISOString();
    const live = (await grantRepo.listGrants(ctx.org.id, { integrationId: i.id }, tx)).filter((g) => g.storedStatus === 'ACTIVE' || g.storedStatus === 'PENDING_APPROVAL');
    await grantRepo.revokeGrants(live.map((g) => g.id), ctx.user.id, 'Integration deleted', tx);
    // Soft delete: grants and audit records keep a valid reference.
    await integrationRepo.updateIntegration(i.id, { deletedAt: now, credentialStatus: 'DISABLED', updatedAt: now }, tx);
    await recordEvent(
      {
        orgId: ctx.org.id,
        actor: userActor(ctx),
        eventType: 'integration.deleted',
        target: { type: 'integration', id: i.id, name: i.displayName },
        severity: 'critical',
        metadata: { credentialReference: i.credentialReference, credentialShredded: shredded, grantsRevoked: live.map((g) => g.id) },
      },
      tx,
    );
    return live.length;
  });
  res.json({ ok: true, credentialShredded: shredded, grantsRevoked: revoked });
});
