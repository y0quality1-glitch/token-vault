import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS } from '@token-vault/shared';
import { config } from '../../config';
import { randomToken } from '../../lib/crypto';
import { badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { db, findInOrg, inOrg, type WebhookRecord } from '../../store/db';
import { recordEvent, userActor } from '../audit/audit.service';
import { applyHealth, checkHealth, syncSeedCredentialMetadata } from './webhook.service';

export const webhooksRouter = Router();

const createSchema = z.object({
  name: z.string().trim().min(3, 'Name must be at least 3 characters').max(60),
  endpointUrl: z
    .string()
    .trim()
    .url('Enter a valid URL, e.g. https://vault.internal.example.com')
    .refine((u) => /^https?:\/\//.test(u), 'URL must use http(s)')
    .refine((u) => !/[?#]/.test(u), 'Base URL must not contain a query string or fragment'),
  environment: z.enum(['development', 'staging', 'production']),
  description: z.string().trim().max(240).default(''),
});

function getWebhook(orgId: string, id: string): WebhookRecord {
  const w = findInOrg(db.webhooks, orgId, id);
  if (!w) throw notFound('Webhook');
  return w;
}

webhooksRouter.get('/webhooks', (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: inOrg(db.webhooks, org.id), defaultEndpointUrl: config.defaultWebhookUrl });
});

webhooksRouter.get('/webhooks/:id', (req, res) => {
  const { org } = orgCtx(req);
  const w = getWebhook(org.id, String(req.params.id));
  res.json({ ...w, integrations: inOrg(db.integrations, org.id).filter((i) => i.webhookId === w.id).map((i) => ({ id: i.id, displayName: i.displayName })) });
});

// Step 1: register endpoint (PENDING) and issue a one-time registration challenge.
webhooksRouter.post('/webhooks', requirePermission(PERMISSIONS.WEBHOOK_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(createSchema, req.body);
  if (body.environment === 'production' && body.endpointUrl.startsWith('http://')) {
    throw badRequest('Request validation failed', { fields: { endpointUrl: 'Production webhooks must use https://' } });
  }
  if (inOrg(db.webhooks, ctx.org.id).some((w) => w.name.toLowerCase() === body.name.toLowerCase())) throw conflict('A webhook with that name already exists');
  const webhook: WebhookRecord = {
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
  };
  db.webhooks.push(webhook);
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'webhook.registered', target: { type: 'webhook', id: webhook.id, name: webhook.name }, metadata: { environment: webhook.environment, endpointUrl: webhook.endpointUrl } });
  res.status(201).json(webhook);
});

// Step 2: configure authentication.
webhooksRouter.patch('/webhooks/:id', requirePermission(PERMISSIONS.WEBHOOK_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const w = getWebhook(ctx.org.id, String(req.params.id));
  const body = parse(
    z.object({
      authenticationType: z.enum(['SHARED_SECRET_HMAC', 'MTLS']).optional(),
      name: z.string().trim().min(3).max(60).optional(),
      description: z.string().trim().max(240).optional(),
    }),
    req.body,
  );
  if (body.authenticationType === 'MTLS') {
    throw badRequest('Mutual TLS is part of the production design and is not implemented in this POC. Use the shared signing secret.');
  }
  Object.assign(w, body);
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'webhook.updated', target: { type: 'webhook', id: w.id, name: w.name }, metadata: body });
  res.json(w);
});

// Step 3: verify connectivity (also used for manual health tests).
webhooksRouter.post('/webhooks/:id/test', requirePermission(PERMISSIONS.WEBHOOK_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const w = getWebhook(ctx.org.id, String(req.params.id));
  const firstVerification = !w.verifiedAt;
  const outcome = w.simulateOutage ? { ok: false, latencyMs: null, detail: 'Simulated outage enabled: webhook did not respond' } : await checkHealth(w);
  applyHealth(w, outcome);
  recordEvent({
    orgId: ctx.org.id,
    actor: userActor(ctx),
    eventType: outcome.ok ? (firstVerification ? 'webhook.verified' : 'webhook.health_check_passed') : 'webhook.health_check_failed',
    target: { type: 'webhook', id: w.id, name: w.name },
    outcome: outcome.ok ? 'SUCCESS' : 'FAILURE',
    severity: outcome.ok ? 'info' : 'warning',
    metadata: { latencyMs: outcome.latencyMs, detail: outcome.detail, instanceId: outcome.instanceId },
  });
  if (outcome.ok) void syncSeedCredentialMetadata();
  res.json({ webhook: w, result: outcome });
});

// Demo control for Scenario F (webhook unavailable).
webhooksRouter.post('/webhooks/:id/simulate-outage', requirePermission(PERMISSIONS.WEBHOOK_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const w = getWebhook(ctx.org.id, String(req.params.id));
  const { enabled } = parse(z.object({ enabled: z.boolean() }), req.body);
  w.simulateOutage = enabled;
  applyHealth(w, enabled ? { ok: false, latencyMs: null, detail: 'Simulated outage enabled' } : await checkHealth(w));
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: enabled ? 'webhook.outage_simulated' : 'webhook.outage_cleared', target: { type: 'webhook', id: w.id, name: w.name }, severity: 'warning', metadata: { simulated: true } });
  res.json(w);
});
