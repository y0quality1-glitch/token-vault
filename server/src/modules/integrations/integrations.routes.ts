import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, type AuthMethodDefinition, type CatalogEntry, type IntegrationDetail } from '@token-vault/shared';
import { and, eq, lt } from 'drizzle-orm';
import { createHash } from 'node:crypto';
import { config } from '../../config';
import { db, transaction } from '../../db/client';
import { oauthPending } from '../../db/schema';
import { HttpError, badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { grantRepo, integrationRepo, webhookRepo } from '../../store/repos';
import type { IntegrationRecord } from '../../store/types';
import { effectiveGrantStatus, loadLookups, toIntegration } from '../../store/views';
import { recordEvent, userActor } from '../audit/audit.service';
import { WebhookUnavailableError, callWebhook } from '../webhooks/webhook.client';
import { GENERIC_RESOURCE, providerCatalog, registry, resourceProblem } from '../providers/registry';

export const integrationsRouter = Router();

const secretSchema = z
  .string()
  .min(20, 'Token must be at least 20 characters')
  .max(512, 'Token is too long')
  .refine((s) => !/\s/.test(s), 'Token must not contain whitespace');

const baseSchema = z.object({
  provider: z.string().refine((p) => !!registry.get(p), 'This provider is not available'),
  webhookId: z.string().min(1, 'Select a customer webhook'),
  displayName: z.string().trim().min(3, 'Name must be at least 3 characters').max(60),
  environment: z.enum(['development', 'staging', 'production']),
  accountLabel: z.string().trim().max(80).default(''),
  allowedResources: z.array(z.string().trim().regex(GENERIC_RESOURCE, 'One resource per line, without spaces')).max(20).default([]),
  description: z.string().trim().max(240).default(''),
});

const privateKeySchema = z
  .string()
  .max(10_000, 'Private key is too long')
  .refine((k) => /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(k), 'Paste the PEM private key downloaded from the GitHub App settings');

const appSchema = baseSchema.extend({
  authType: z.string(),
  appId: z.string().trim().regex(/^\d{1,12}$/, 'Enter the numeric App ID from the GitHub App settings'),
  installationId: z.union([z.literal(''), z.string().trim().regex(/^\d{1,15}$/, 'Installation ID is numeric')]).default(''),
  keySource: z.enum(['stored', 'webhook_env']),
  privateKey: privateKeySchema.optional(),
});

/** The secret rules of a definition's auth method (GitHub PATs keep their historical rules). */
function secretSchemaFor(method: AuthMethodDefinition) {
  if (method.id === 'PAT') return secretSchema;
  const base = z.string().min(8, 'The secret is too short').max(4096, 'The secret is too long');
  return method.secretPattern ? base.refine((s) => new RegExp(method.secretPattern!).test(s), method.secretHint ?? 'The secret does not have the expected format') : base;
}

/**
 * Parses a create request against the provider definition: the auth method decides which
 * credential fields apply. Plugin methods (GitHub App) take App fields; the others a secret.
 */
function parseCreate(raw: unknown) {
  const head = parse(baseSchema.extend({ authType: z.string().min(1, 'Choose an authentication method') }), raw);
  const def = registry.get(head.provider)!;
  const method = def.auth.find((a) => a.id === head.authType);
  if (!method) throw badRequest('Request validation failed', { fields: { authType: `${def.name} does not support "${head.authType}"` } });
  if (method.kind === 'oauth2') throw badRequest('Request validation failed', { fields: { authType: `${method.label} connects through the provider's sign-in (POST /integrations/oauth/start)` } });
  const problem = resourceProblem(def.key, head.allowedResources);
  if (problem) throw badRequest('Request validation failed', { fields: { allowedResources: problem } });
  if (method.kind === 'plugin' && method.plugin === 'github_app') return { def, method, kind: 'github_app' as const, ...parse(appSchema, raw) };
  const accountLabel = method.id === 'PAT' ? z.string().trim().min(1, 'Account / organization label is required').max(80) : z.string().trim().max(80).default('');
  return { def, method, kind: 'secret' as const, ...parse(baseSchema.extend({ authType: z.string(), accountLabel, secret: secretSchemaFor(method) }), raw) };
}

type IntegrationDraft = { provider: string; displayName: string; environment: IntegrationRecord['environment']; accountLabel: string; authType: string; allowedResources: string[]; description: string };

/**
 * Shared tail of every connection (secret, GitHub App, OAuth): validate the stored
 * credential through the webhook, then record the integration and its audit event.
 */
async function finishIntegration(ctx: ReturnType<typeof orgCtx>, webhook: { id: string; name: string } & Parameters<typeof callWebhook>[0], meta: IntegrationDraft, stored: Record<string, any>) {
  // Validate immediately through the webhook (it decrypts and calls the provider; we only see the outcome).
  let lastValidatedAt: string | null = null;
  let credentialStatus: IntegrationRecord['credentialStatus'] = 'CONNECTED';
  try {
    const test = await callWebhook(webhook, 'POST', `/internal/v1/credentials/${stored.credential_ref}/test`, { org_id: ctx.org.id });
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
        accountLabel: meta.accountLabel || stored.account || '',
        authType: meta.authType,
        credentialReference: stored.credential_ref,
        credentialStatus,
        maskedIdentifier: stored.masked_identifier,
        credentialFingerprint: stored.fingerprint,
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
  return detail(integration);
}

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
  const items: CatalogEntry[] = providerCatalog().map((p) => ({
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
  const body = parseCreate(req.body);
  const meta = body;
  if (body.kind === 'github_app' && body.keySource === 'stored' && !body.privateKey) {
    throw badRequest('Request validation failed', { fields: { privateKey: 'Paste the App private key, or choose the key configured on the webhook' } });
  }
  // Credential material is forwarded to the customer webhook and never kept here.
  if (req.body && typeof req.body === 'object') for (const k of ['secret', 'privateKey']) delete (req.body as Record<string, unknown>)[k];

  const webhook = await webhookRepo.getWebhook(ctx.org.id, meta.webhookId);
  if (!webhook) throw badRequest('Request validation failed', { fields: { webhookId: 'Unknown webhook' } });
  if (webhook.status !== 'CONNECTED') throw new HttpError(409, 'WEBHOOK_NOT_CONNECTED', `Webhook "${webhook.name}" is ${webhook.status.toLowerCase()}. Verify connectivity before registering credentials.`);
  if ((await integrationRepo.listIntegrations(ctx.org.id)).some((i) => i.displayName.toLowerCase() === meta.displayName.toLowerCase())) throw conflict('An integration with that name already exists');

  let stored;
  try {
    const metadata = { label: meta.displayName, account: meta.accountLabel, environment: meta.environment };
    stored = await callWebhook(
      webhook,
      'POST',
      '/internal/v1/credentials',
      body.kind === 'github_app'
        ? { org_id: ctx.org.id, provider: meta.provider, type: 'github_app', app_id: body.appId, installation_id: body.installationId || undefined, key_source: body.keySource, private_key: body.privateKey, metadata }
        : { org_id: ctx.org.id, provider: meta.provider, auth_method: body.method.id, secret: body.secret, metadata },
    );
  } catch (e) {
    webhookError(e);
  }
  if (stored.status !== 201) {
    // 400 = the customer webhook judged the input invalid (bad key, unknown App or installation): show its reason.
    throw new HttpError(stored.status === 400 ? 400 : 502, stored.body?.error?.code ?? 'WEBHOOK_REJECTED', stored.body?.error?.message ?? 'The webhook rejected the credential');
  }

  res.status(201).json(await finishIntegration(ctx, webhook, meta, stored.body));
});

const OAUTH_PENDING_TTL_MS = 10 * 60_000;
const stateHash = (state: string) => createHash('sha256').update(state).digest('hex');

/**
 * OAuth connection, step 1. The client secret goes to the customer webhook (which also
 * generates the PKCE verifier) and is never stored here. The returned state is bound to
 * this admin and expires; the browser is then sent to the provider's consent screen.
 */
integrationsRouter.post('/integrations/oauth/start', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(
    baseSchema.extend({
      authType: z.string().min(1, 'Choose an authentication method'),
      clientId: z.string().trim().min(1, 'Enter the client ID').max(300).regex(/^\S+$/, 'The client ID has no spaces'),
      clientSecret: z.string().min(8, 'Enter the client secret').max(1000),
    }),
    req.body,
  );
  if (req.body && typeof req.body === 'object') delete (req.body as Record<string, unknown>).clientSecret;
  const def = registry.get(body.provider)!;
  const method = def.auth.find((a) => a.id === body.authType && a.kind === 'oauth2');
  if (!method) throw badRequest('Request validation failed', { fields: { authType: `${def.name} has no OAuth method "${body.authType}"` } });
  const problem = resourceProblem(def.key, body.allowedResources);
  if (problem) throw badRequest('Request validation failed', { fields: { allowedResources: problem } });
  const webhook = await webhookRepo.getWebhook(ctx.org.id, body.webhookId);
  if (!webhook) throw badRequest('Request validation failed', { fields: { webhookId: 'Unknown webhook' } });
  if (webhook.status !== 'CONNECTED') throw new HttpError(409, 'WEBHOOK_NOT_CONNECTED', `Webhook "${webhook.name}" is ${webhook.status.toLowerCase()}. Verify connectivity before registering credentials.`);
  if ((await integrationRepo.listIntegrations(ctx.org.id)).some((i) => i.displayName.toLowerCase() === body.displayName.toLowerCase())) throw conflict('An integration with that name already exists');

  let started;
  try {
    started = await callWebhook(webhook, 'POST', '/internal/v1/oauth/start', {
      org_id: ctx.org.id,
      provider: def.key,
      auth_method: method.id,
      client_id: body.clientId,
      client_secret: body.clientSecret,
      redirect_uri: `${config.consolePublicUrl}/oauth/callback`,
      metadata: { label: body.displayName, account: body.accountLabel, environment: body.environment },
    });
  } catch (e) {
    webhookError(e);
  }
  if (started.status !== 201) throw new HttpError(started.status === 400 ? 400 : 502, started.body?.error?.code ?? 'WEBHOOK_REJECTED', started.body?.error?.message ?? 'The webhook could not start the OAuth connection');
  const now = Date.now();
  const draft: IntegrationDraft = { provider: def.key, displayName: body.displayName, environment: body.environment, accountLabel: body.accountLabel, authType: method.id, allowedResources: body.allowedResources, description: body.description };
  await db.delete(oauthPending).where(lt(oauthPending.expiresAt, new Date(now).toISOString()));
  await db.insert(oauthPending).values({
    stateHash: stateHash(String(started.body.state)),
    organizationId: ctx.org.id,
    userId: ctx.user.id,
    webhookId: webhook.id,
    credentialReference: started.body.credential_ref,
    draft,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + OAUTH_PENDING_TTL_MS).toISOString(),
  });
  await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'integration.oauth_started', target: { type: 'integration', id: started.body.credential_ref, name: body.displayName }, metadata: { provider: def.key, authMethod: method.id } });
  res.status(201).json({ authorizeUrl: started.body.authorize_url });
});

/** Takes (and removes) the pending connection for a state, if it belongs to this admin and has not expired. */
async function takePending(ctx: ReturnType<typeof orgCtx>, state: string) {
  const [row] = await db
    .delete(oauthPending)
    .where(and(eq(oauthPending.stateHash, stateHash(state)), eq(oauthPending.organizationId, ctx.org.id), eq(oauthPending.userId, ctx.user.id)))
    .returning();
  if (!row || new Date(row.expiresAt).getTime() < Date.now()) throw new HttpError(400, 'OAUTH_STATE_INVALID', 'This sign-in does not match a connection you started, or it expired. Start again from the integration catalog.');
  const webhook = await webhookRepo.getWebhook(ctx.org.id, row.webhookId);
  if (!webhook) throw notFound('Webhook');
  return { row, webhook };
}

async function discardWebhookCredential(webhook: Parameters<typeof callWebhook>[0], orgId: string, ref: string) {
  await callWebhook(webhook, 'POST', `/internal/v1/credentials/${ref}/delete`, { org_id: orgId }).catch(() => undefined);
}

/**
 * OAuth connection, step 2, called by the console's /oauth/callback page (same origin, so
 * the SameSite=Strict session cookie is sent). The code is relayed to the webhook, which
 * checks the state against its own copy and redeems the code with the PKCE verifier.
 */
integrationsRouter.post('/integrations/oauth/complete', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(z.object({ code: z.string().min(1).max(2000), state: z.string().min(1).max(200) }), req.body);
  const { row, webhook } = await takePending(ctx, body.state);
  let done;
  try {
    done = await callWebhook(webhook, 'POST', '/internal/v1/oauth/complete', { org_id: ctx.org.id, credential_ref: row.credentialReference, code: body.code, state: body.state });
  } catch (e) {
    webhookError(e);
  }
  if (done.status !== 200) {
    await discardWebhookCredential(webhook, ctx.org.id, row.credentialReference);
    throw new HttpError(done.status === 400 ? 400 : 502, done.body?.error?.code ?? 'WEBHOOK_REJECTED', done.body?.error?.message ?? 'The webhook could not complete the OAuth connection');
  }
  res.status(201).json(await finishIntegration(ctx, webhook, row.draft as IntegrationDraft, done.body));
});

/** The provider reported an error (e.g. the admin denied consent): drop the pending connection. */
integrationsRouter.post('/integrations/oauth/cancel', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const { state } = parse(z.object({ state: z.string().min(1).max(200) }), req.body);
  const { row, webhook } = await takePending(ctx, state);
  await discardWebhookCredential(webhook, ctx.org.id, row.credentialReference);
  res.json({ ok: true });
});

integrationsRouter.patch('/integrations/:id', requirePermission(PERMISSIONS.INTEGRATION_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const i = await getIntegration(ctx.org.id, String(req.params.id));
  const body = parse(
    z.object({
      displayName: z.string().trim().min(3).max(60),
      accountLabel: z.string().trim().max(80),
      description: z.string().trim().max(240),
      allowedResources: z.array(z.string().trim().regex(GENERIC_RESOURCE, 'One resource per line, without spaces')).max(20),
    }),
    req.body,
  );
  const problem = resourceProblem(i.provider, body.allowedResources);
  if (problem) throw badRequest('Request validation failed', { fields: { allowedResources: problem } });
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
  const method = registry.get(i.provider)?.auth.find((a) => a.id === i.authType);
  if (method?.kind === 'oauth2') throw new HttpError(400, 'RECONNECT_REQUIRED', 'OAuth integrations are renewed by connecting again, not by entering a secret');
  const rotation =
    method?.kind === 'plugin'
      ? { private_key: parse(z.object({ privateKey: privateKeySchema }), req.body).privateKey }
      : { secret: parse(z.object({ secret: method ? secretSchemaFor(method) : secretSchema }), req.body).secret };
  for (const k of ['secret', 'privateKey']) delete (req.body as Record<string, unknown>)[k];
  let result;
  try {
    result = await callWebhook(await webhookFor(i), 'POST', `/internal/v1/credentials/${i.credentialReference}/rotate`, { org_id: ctx.org.id, ...rotation });
  } catch (e) {
    webhookError(e);
  }
  if (result.status !== 200) throw new HttpError(result.status === 400 ? 400 : 502, result.body?.error?.code ?? 'WEBHOOK_REJECTED', result.body?.error?.message ?? 'Rotation failed');
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
