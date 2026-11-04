import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, PROVIDER_CATALOG, type CatalogEntry, type IntegrationDetail } from '@token-vault/shared';
import { HttpError, badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { db, findInOrg, inOrg, type IntegrationRecord } from '../../store/db';
import { effectiveGrantStatus, toIntegration } from '../../store/views';
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

function getIntegration(orgId: string, id: string): IntegrationRecord {
  const i = findInOrg(db.integrations, orgId, id);
  if (!i) throw notFound('Integration');
  return i;
}

function webhookFor(i: Pick<IntegrationRecord, 'webhookId' | 'organizationId'>) {
  const w = findInOrg(db.webhooks, i.organizationId, i.webhookId);
  if (!w) throw notFound('Webhook');
  return w;
}

function webhookError(e: unknown): never {
  if (e instanceof WebhookUnavailableError) throw new HttpError(503, 'WEBHOOK_UNAVAILABLE', `${e.message}. The credential was not stored.`);
  throw e;
}

function detail(i: IntegrationRecord): IntegrationDetail {
  const grants = db.grants.filter((g) => g.integrationId === i.id && g.storedStatus !== 'SUPERSEDED');
  return {
    ...toIntegration(i),
    grantedAgents: grants.map((g) => ({
      agentId: g.agentId,
      agentName: db.agents.find((a) => a.id === g.agentId)?.name ?? 'Deleted agent',
      grantId: g.id,
      grantName: g.name,
      status: effectiveGrantStatus(g),
      scopes: g.scopes,
    })),
  };
}

integrationsRouter.get('/integrations/catalog', (req, res) => {
  const { org } = orgCtx(req);
  const items: CatalogEntry[] = PROVIDER_CATALOG.map((p) => ({
    ...p,
    connectedCount: inOrg(db.integrations, org.id).filter((i) => i.provider === p.provider && i.credentialStatus !== 'DISABLED').length,
  }));
  res.json({ items });
});

integrationsRouter.get('/integrations', (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: inOrg(db.integrations, org.id).map(toIntegration) });
});

integrationsRouter.get('/integrations/:id', (req, res) => {
  const { org } = orgCtx(req);
  res.json(detail(getIntegration(org.id, String(req.params.id))));
});

/**
 * Credential registration. The secret travels browser -> control plane (TLS) -> customer webhook (signed)
 * and is never written to the control-plane store, logs or audit. Only the returned reference is kept.
 */
integrationsRouter.post('/integrations', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(createSchema, req.body);
  const { secret, ...meta } = body;
  if (req.body && typeof req.body === 'object') delete (req.body as Record<string, unknown>).secret;

  const webhook = findInOrg(db.webhooks, ctx.org.id, meta.webhookId);
  if (!webhook) throw badRequest('Request validation failed', { fields: { webhookId: 'Unknown webhook' } });
  if (webhook.status !== 'CONNECTED') throw new HttpError(409, 'WEBHOOK_NOT_CONNECTED', `Webhook "${webhook.name}" is ${webhook.status.toLowerCase()}. Verify connectivity before registering credentials.`);
  if (inOrg(db.integrations, ctx.org.id).some((i) => i.displayName.toLowerCase() === meta.displayName.toLowerCase())) throw conflict('An integration with that name already exists');

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

  const now = new Date().toISOString();
  const integration: IntegrationRecord = {
    id: newId('int'),
    organizationId: ctx.org.id,
    webhookId: webhook.id,
    provider: meta.provider,
    displayName: meta.displayName,
    environment: meta.environment,
    accountLabel: meta.accountLabel,
    authType: meta.authType,
    credentialReference: stored.body.credential_ref,
    credentialStatus: 'CONNECTED',
    maskedIdentifier: stored.body.masked_identifier,
    credentialFingerprint: stored.body.fingerprint,
    allowedResources: meta.allowedResources,
    description: meta.description,
    createdBy: ctx.user.id,
    createdAt: now,
    updatedAt: now,
    lastValidatedAt: null,
    rotatedAt: null,
  };
  db.integrations.push(integration);

  // Validate immediately through the webhook (the webhook decrypts and calls the provider; we only see the outcome).
  try {
    const test = await callWebhook(webhook, 'POST', `/internal/v1/credentials/${integration.credentialReference}/test`, { org_id: ctx.org.id });
    if (test.status === 200) {
      integration.lastValidatedAt = new Date().toISOString();
      if (test.body.valid !== true) integration.credentialStatus = 'INVALID';
    }
  } catch {
    /* validation is best-effort; status stays CONNECTED until the next test */
  }

  recordEvent({
    orgId: ctx.org.id,
    actor: userActor(ctx),
    eventType: 'integration.connected',
    target: { type: 'integration', id: integration.id, name: integration.displayName },
    metadata: { provider: integration.provider, credentialReference: integration.credentialReference, webhookId: webhook.id, environment: integration.environment },
  });
  res.status(201).json(detail(integration));
});

integrationsRouter.patch('/integrations/:id', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const i = getIntegration(ctx.org.id, String(req.params.id));
  const body = parse(
    z.object({
      displayName: z.string().trim().min(3).max(60),
      accountLabel: z.string().trim().min(1).max(80),
      description: z.string().trim().max(240),
      allowedResources: z.array(z.string().trim().regex(repoPattern, 'Use owner/repository format')).max(20),
    }),
    req.body,
  );
  Object.assign(i, body, { updatedAt: new Date().toISOString() });
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'integration.metadata_updated', target: { type: 'integration', id: i.id, name: i.displayName }, metadata: body });
  res.json(detail(i));
});

integrationsRouter.post('/integrations/:id/test', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const i = getIntegration(ctx.org.id, String(req.params.id));
  let result;
  try {
    result = await callWebhook(webhookFor(i), 'POST', `/internal/v1/credentials/${i.credentialReference}/test`, { org_id: ctx.org.id });
  } catch (e) {
    if (e instanceof WebhookUnavailableError) throw new HttpError(503, 'WEBHOOK_UNAVAILABLE', e.message);
    throw e;
  }
  const valid = result.status === 200 && result.body.valid === true;
  if (result.status === 200) {
    i.maskedIdentifier = result.body.masked_identifier;
    i.credentialFingerprint = result.body.fingerprint;
  }
  if (i.credentialStatus !== 'DISABLED') i.credentialStatus = valid ? 'CONNECTED' : 'INVALID';
  i.lastValidatedAt = new Date().toISOString();
  recordEvent({
    orgId: ctx.org.id,
    actor: userActor(ctx),
    eventType: 'integration.tested',
    target: { type: 'integration', id: i.id, name: i.displayName },
    outcome: valid ? 'SUCCESS' : 'FAILURE',
    severity: valid ? 'info' : 'warning',
    metadata: { upstreamStatus: result.body.upstream_status ?? result.status, simulated: result.body.simulated },
  });
  res.json({ valid, upstreamStatus: result.body.upstream_status ?? null, simulated: result.body.simulated ?? true, integration: detail(i) });
});

integrationsRouter.post('/integrations/:id/rotate', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const i = getIntegration(ctx.org.id, String(req.params.id));
  const { secret } = parse(z.object({ secret: secretSchema }), req.body);
  delete (req.body as Record<string, unknown>).secret;
  let result;
  try {
    result = await callWebhook(webhookFor(i), 'POST', `/internal/v1/credentials/${i.credentialReference}/rotate`, { org_id: ctx.org.id, secret });
  } catch (e) {
    webhookError(e);
  }
  if (result.status !== 200) throw new HttpError(502, 'WEBHOOK_REJECTED', result.body?.error?.message ?? 'Rotation failed');
  const now = new Date().toISOString();
  Object.assign(i, { maskedIdentifier: result.body.masked_identifier, credentialFingerprint: result.body.fingerprint, rotatedAt: now, updatedAt: now, credentialStatus: i.credentialStatus === 'DISABLED' ? 'DISABLED' : 'CONNECTED' });
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'integration.credential_rotated', target: { type: 'integration', id: i.id, name: i.displayName }, severity: 'warning', metadata: { credentialReference: i.credentialReference } });
  res.json(detail(i));
});

integrationsRouter.post('/integrations/:id/disable', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const i = getIntegration(ctx.org.id, String(req.params.id));
  i.credentialStatus = 'DISABLED';
  i.updatedAt = new Date().toISOString();
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'integration.disabled', target: { type: 'integration', id: i.id, name: i.displayName }, severity: 'warning' });
  res.json(detail(i));
});

integrationsRouter.post('/integrations/:id/enable', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const i = getIntegration(ctx.org.id, String(req.params.id));
  i.credentialStatus = 'CONNECTED';
  i.updatedAt = new Date().toISOString();
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'integration.enabled', target: { type: 'integration', id: i.id, name: i.displayName } });
  res.json(detail(i));
});

integrationsRouter.delete('/integrations/:id', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const i = getIntegration(ctx.org.id, String(req.params.id));
  // Ask the customer webhook to crypto-shred the stored credential (best effort if unreachable).
  let shredded = false;
  try {
    const r = await callWebhook(webhookFor(i), 'POST', `/internal/v1/credentials/${i.credentialReference}/delete`, { org_id: ctx.org.id });
    shredded = r.status === 200;
  } catch {
    shredded = false;
  }
  const now = new Date().toISOString();
  const revoked = db.grants.filter((g) => g.integrationId === i.id && (g.storedStatus === 'ACTIVE' || g.storedStatus === 'PENDING_APPROVAL'));
  for (const g of revoked) Object.assign(g, { storedStatus: 'REVOKED', revokedAt: now, revokedBy: ctx.user.id, revocationReason: 'Integration deleted' });
  db.integrations = db.integrations.filter((x) => x !== i);
  recordEvent({
    orgId: ctx.org.id,
    actor: userActor(ctx),
    eventType: 'integration.deleted',
    target: { type: 'integration', id: i.id, name: i.displayName },
    severity: 'critical',
    metadata: { credentialReference: i.credentialReference, credentialShredded: shredded, grantsRevoked: revoked.map((g) => g.id) },
  });
  res.json({ ok: true, credentialShredded: shredded, grantsRevoked: revoked.length });
});
