import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS } from '@token-vault/shared';
import { config } from '../../config';
import { transaction } from '../../db/client';
import { randomToken } from '../../lib/crypto';
import { badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { integrationRepo, webhookRepo } from '../../store/repos';
import type { WebhookRecord } from '../../store/types';
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

async function getWebhook(orgId: string, id: string): Promise<WebhookRecord> {
  const w = await webhookRepo.getWebhook(orgId, id);
  if (!w) throw notFound('Webhook');
  return w;
}

webhooksRouter.get('/webhooks', async (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: await webhookRepo.listWebhooks(org.id), defaultEndpointUrl: config.defaultWebhookUrl, transport: transportInfo() });
});

webhooksRouter.get('/webhooks/:id', async (req, res) => {
  const { org } = orgCtx(req);
  const w = await getWebhook(org.id, String(req.params.id));
  const integrations = (await integrationRepo.listIntegrations(org.id)).filter((i) => i.webhookId === w.id).map((i) => ({ id: i.id, displayName: i.displayName }));
  res.json({ ...w, integrations });
});

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

// Step 1: register endpoint (PENDING) and issue a one-time registration challenge.
webhooksRouter.post('/webhooks', requirePermission(PERMISSIONS.WEBHOOK_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(createSchema, req.body);
  checkUrl(body.endpointUrl, body.environment);
  const webhook = await transaction(async (tx) => {
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
  res.status(201).json(webhook);
});

// Step 2: configure authentication.
webhooksRouter.patch('/webhooks/:id', requirePermission(PERMISSIONS.WEBHOOK_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const w = await getWebhook(ctx.org.id, String(req.params.id));
  const body = parse(
    z.object({
      authenticationType: z.enum(['SHARED_SECRET_HMAC', 'MTLS']).optional(),
      name: z.string().trim().min(3).max(60).optional(),
      description: z.string().trim().max(240).optional(),
      // Moving the webhook (e.g. to https://). Its pinned instance identity must still match, so a
      // URL change cannot swap in a different webhook.
      endpointUrl: createSchema.shape.endpointUrl.optional(),
    }),
    req.body,
  );
  const url = body.endpointUrl ?? w.endpointUrl;
  if (body.endpointUrl) checkUrl(body.endpointUrl, w.environment);
  if ((body.authenticationType ?? w.authenticationType) === 'MTLS') {
    if (!transportInfo().mtlsAvailable) throw badRequest('Mutual TLS needs a control-plane client certificate (CONTROL_PLANE_TLS_CERT and CONTROL_PLANE_TLS_KEY). See docs/DEPLOYMENT.md.');
    if (!url.startsWith('https://')) throw badRequest('Request validation failed', { fields: { endpointUrl: 'Mutual TLS needs an https:// webhook URL' } });
  }
  const updated = await transaction(async (tx) => {
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
  res.json(updated);
});

// Step 3: verify connectivity (also used for manual health tests).
webhooksRouter.post('/webhooks/:id/test', requirePermission(PERMISSIONS.WEBHOOK_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const w = await getWebhook(ctx.org.id, String(req.params.id));
  const firstVerification = !w.verifiedAt;
  const outcome = w.simulateOutage ? { ok: false, latencyMs: null, detail: 'Simulated outage enabled: webhook did not respond' } : await checkHealth(w);
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
  res.json({ webhook: updated, result: outcome });
});

// Demo control for Scenario F (webhook unavailable).
webhooksRouter.post('/webhooks/:id/simulate-outage', requirePermission(PERMISSIONS.WEBHOOK_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const w = await getWebhook(ctx.org.id, String(req.params.id));
  const { enabled } = parse(z.object({ enabled: z.boolean() }), req.body);
  const toggled = await webhookRepo.updateWebhook(w.id, { simulateOutage: enabled });
  const updated = await applyHealth(toggled, enabled ? { ok: false, latencyMs: null, detail: 'Simulated outage enabled' } : await checkHealth(toggled));
  await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: enabled ? 'webhook.outage_simulated' : 'webhook.outage_cleared', target: { type: 'webhook', id: w.id, name: w.name }, severity: 'warning', metadata: { simulated: true } });
  res.json(updated);
});
