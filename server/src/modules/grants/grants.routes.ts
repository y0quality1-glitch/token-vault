import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, type GrantDetail } from '@token-vault/shared';
import { transaction, type Executor } from '../../db/client';
import { HttpError, badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { isValidCidr } from '../../lib/net';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { agentRepo, auditRepo, grantRepo, integrationRepo, policyRepo } from '../../store/repos';
import type { GrantRecord, IntegrationRecord } from '../../store/types';
import { effectiveGrantStatus, loadLookups, toGrant } from '../../store/views';
import { recordEvent, userActor } from '../audit/audit.service';
import { GENERIC_RESOURCE, foreignOperations, grantableOperationIds, resourceProblem } from '../providers/registry';
import { policyMatches } from '../policy-engine/engine';

export const grantsRouter = Router();


const restrictionsSchema = z.object({
  scopes: z
    .array(z.string())
    .min(1, 'Select at least one permission')
    .refine((s) => s.every((x) => grantableOperationIds().includes(x)), 'Destructive or unknown operations cannot be granted in the POC'),
  repositories: z.array(z.string().trim().regex(GENERIC_RESOURCE, 'Enter one resource per line, without spaces')).max(20).default([]),
  validFrom: z.string().datetime({ offset: true, message: 'Enter a valid start date/time' }),
  expiresAt: z.string().datetime({ offset: true, message: 'Enter a valid expiry date/time' }),
  rateLimitPerMinute: z.number().int().min(1, 'Must be at least 1').max(600, 'Maximum 600 per minute'),
  allowedCidrs: z.array(z.string().trim().refine(isValidCidr, 'Use IPv4 CIDR notation')).max(20).default([]),
});

const createSchema = restrictionsSchema.extend({
  name: z.string().trim().min(3, 'Grant name must be at least 3 characters').max(80),
  agentId: z.string().min(1, 'Select an agent'),
  integrationId: z.string().min(1, 'Select an integration'),
  environment: z.enum(['development', 'staging', 'production']),
  approvalRequired: z.boolean().default(false),
});

async function getGrant(orgId: string, id: string, ex?: Executor): Promise<GrantRecord> {
  const g = await grantRepo.getGrant(orgId, id, ex);
  if (!g) throw notFound('Grant');
  return g;
}

function validateWindow(validFrom: string, expiresAt: string) {
  const from = new Date(validFrom).getTime();
  const to = new Date(expiresAt).getTime();
  if (to <= from) throw badRequest('Request validation failed', { fields: { expiresAt: 'Expiry must be after the start time' } });
  if (to <= Date.now()) throw badRequest('Request validation failed', { fields: { expiresAt: 'Expiry must be in the future' } });
  if (to - from > 366 * 86400e3) throw badRequest('Request validation failed', { fields: { expiresAt: 'Grants may be valid for at most one year' } });
}

function validateRepos(integration: IntegrationRecord, repos: string[], scopes?: string[]) {
  const problem = resourceProblem(integration.provider, repos);
  if (problem) throw badRequest('Request validation failed', { fields: { repositories: problem } });
  const foreign = scopes ? foreignOperations(integration.provider, scopes) : [];
  if (foreign.length) throw badRequest('Request validation failed', { fields: { scopes: `Not operations of this integration's provider: ${foreign.join(', ')}` } });
  if (integration.allowedResources.length > 0) {
    const bad = repos.filter((r) => !integration.allowedResources.some((a) => a.toLowerCase() === r.toLowerCase()));
    if (bad.length) throw badRequest('Request validation failed', { fields: { repositories: `Not allowed by the integration: ${bad.join(', ')}` } });
  }
}

async function toDetail(g: GrantRecord): Promise<GrantDetail> {
  const [requests, chain, lookups, agent, integration, policies] = await Promise.all([
    auditRepo.accessRequestsForGrant(g.id),
    grantRepo.versionChain(g.organizationId, g),
    loadLookups(g.organizationId, [g.createdBy]),
    agentRepo.getAgent(g.organizationId, g.agentId),
    integrationRepo.getIntegration(g.organizationId, g.integrationId),
    policyRepo.listPolicies(g.organizationId),
  ]);
  const since = Date.now() - 86400e3;
  const matchingPolicies =
    agent && integration
      ? policies
          .filter((p) => p.enabled)
          .filter((p) => g.scopes.some((op) => policyMatches(p, { agent, integration, operationId: op })))
          .map((p) => ({ id: p.id, name: p.name, effect: p.effect }))
      : [];
  return {
    ...toGrant(g, lookups),
    usage: {
      allowed: requests.filter((r) => r.decision === 'ALLOW').length,
      denied: requests.filter((r) => r.decision === 'DENY').length,
      last24h: requests.filter((r) => new Date(r.createdAt).getTime() > since).length,
    },
    recentRequests: requests.slice(0, 20),
    versions: chain.map((v) => ({ id: v.id, version: v.version, status: effectiveGrantStatus(v), createdAt: v.createdAt })),
    matchingPolicies,
  };
}

grantsRouter.get('/grants', async (req, res) => {
  const { org } = orgCtx(req);
  const { status, agentId, integrationId } = req.query;
  const [list, lookups] = await Promise.all([
    grantRepo.listGrants(org.id, { agentId: typeof agentId === 'string' && agentId ? agentId : undefined, integrationId: typeof integrationId === 'string' && integrationId ? integrationId : undefined }),
    loadLookups(org.id),
  ]);
  let items = list.map((g) => toGrant(g, lookups));
  if (typeof status === 'string' && status) items = items.filter((g) => g.status === status);
  res.json({ items });
});

grantsRouter.get('/grants/:id', async (req, res) => {
  const { org } = orgCtx(req);
  res.json(await toDetail(await getGrant(org.id, String(req.params.id))));
});

grantsRouter.post('/grants', requirePermission(PERMISSIONS.GRANT_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(createSchema, req.body);
  const grant = await transaction(async (tx) => {
    const agent = await agentRepo.getAgent(ctx.org.id, body.agentId, tx);
    if (!agent) throw badRequest('Request validation failed', { fields: { agentId: 'Unknown agent' } });
    if (agent.status !== 'ACTIVE') throw badRequest('Request validation failed', { fields: { agentId: 'Agent is disabled; enable it before granting access' } });
    const integration = await integrationRepo.getIntegration(ctx.org.id, body.integrationId, tx);
    if (!integration) throw badRequest('Request validation failed', { fields: { integrationId: 'Unknown integration' } });
    if (integration.credentialStatus !== 'CONNECTED') throw badRequest('Request validation failed', { fields: { integrationId: 'Integration is not connected' } });
    if (body.environment !== integration.environment) throw badRequest('Request validation failed', { fields: { environment: `Must match the integration environment (${integration.environment})` } });
    validateWindow(body.validFrom, body.expiresAt);
    validateRepos(integration, body.repositories, body.scopes);
    if (await grantRepo.grantNameExists(ctx.org.id, body.name, tx)) throw conflict('A grant with that name already exists');

    const created = await grantRepo.insertGrant(
      {
        id: newId('grt'),
        organizationId: ctx.org.id,
        agentId: agent.id,
        integrationId: integration.id,
        name: body.name,
        environment: body.environment,
        scopes: body.scopes,
        resourceConstraints: { repositories: body.repositories },
        rateLimitPerMinute: body.rateLimitPerMinute,
        allowedCidrs: body.allowedCidrs,
        validFrom: new Date(body.validFrom).toISOString(),
        expiresAt: new Date(body.expiresAt).toISOString(),
        approvalRequired: body.approvalRequired,
        storedStatus: body.approvalRequired ? 'PENDING_APPROVAL' : 'ACTIVE',
        version: 1,
        previousVersionId: null,
        createdBy: ctx.user.id,
        createdAt: new Date().toISOString(),
        approvedBy: null,
        approvedAt: null,
        revokedAt: null,
        revokedBy: null,
        revocationReason: null,
        lastUsedAt: null,
        usageCount: 0,
      },
      tx,
    );
    await recordEvent(
      {
        orgId: ctx.org.id,
        actor: userActor(ctx),
        eventType: 'grant.created',
        target: { type: 'grant', id: created.id, name: created.name },
        metadata: { agentId: agent.id, integrationId: integration.id, scopes: created.scopes, repositories: body.repositories, expiresAt: created.expiresAt, status: created.storedStatus },
      },
      tx,
    );
    return created;
  });
  res.status(201).json(await toDetail(grant));
});

function assertMutable(g: GrantRecord) {
  const s = effectiveGrantStatus(g);
  if (s === 'REVOKED' || s === 'SUPERSEDED') throw new HttpError(409, 'GRANT_NOT_MUTABLE', `Grant is ${s.toLowerCase()} and cannot be changed`);
}

/** Revocation takes effect on the very next authorization check (state is read from the database per request). */
grantsRouter.post('/grants/:id/revoke', requirePermission(PERMISSIONS.GRANT_REVOKE), async (req, res) => {
  const ctx = orgCtx(req);
  const { reason } = parse(z.object({ reason: z.string().trim().max(240).default('') }), req.body ?? {});
  const updated = await transaction(async (tx) => {
    const g = await getGrant(ctx.org.id, String(req.params.id), tx);
    assertMutable(g);
    const u = await grantRepo.updateGrant(g.id, { storedStatus: 'REVOKED', revokedAt: new Date().toISOString(), revokedBy: ctx.user.id, revocationReason: reason || 'Revoked by administrator' }, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.revoked', target: { type: 'grant', id: g.id, name: g.name }, severity: 'warning', metadata: { reason: u.revocationReason, agentId: g.agentId, integrationId: g.integrationId } }, tx);
    return u;
  });
  res.json(await toDetail(updated));
});

grantsRouter.post('/grants/:id/approve', requirePermission(PERMISSIONS.GRANT_APPROVE), async (req, res) => {
  const ctx = orgCtx(req);
  const updated = await transaction(async (tx) => {
    const g = await getGrant(ctx.org.id, String(req.params.id), tx);
    if (g.storedStatus !== 'PENDING_APPROVAL') throw conflict('Only grants pending approval can be approved');
    const u = await grantRepo.updateGrant(g.id, { storedStatus: 'ACTIVE', approvedBy: ctx.user.id, approvedAt: new Date().toISOString() }, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.approved', target: { type: 'grant', id: g.id, name: g.name }, metadata: { simulatedApproval: true } }, tx);
    return u;
  });
  res.json(await toDetail(updated));
});

grantsRouter.post('/grants/:id/extend', requirePermission(PERMISSIONS.GRANT_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const { expiresAt } = parse(z.object({ expiresAt: z.string().datetime({ offset: true, message: 'Enter a valid date/time' }) }), req.body);
  const updated = await transaction(async (tx) => {
    const g = await getGrant(ctx.org.id, String(req.params.id), tx);
    assertMutable(g);
    validateWindow(g.validFrom, expiresAt);
    const u = await grantRepo.updateGrant(g.id, { expiresAt: new Date(expiresAt).toISOString() }, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.expiry_extended', target: { type: 'grant', id: g.id, name: g.name }, metadata: { from: g.expiresAt, to: u.expiresAt } }, tx);
    return u;
  });
  res.json(await toDetail(updated));
});

/** Editing restrictions creates a new grant version for auditability; the old version is superseded atomically. */
grantsRouter.post('/grants/:id/versions', requirePermission(PERMISSIONS.GRANT_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(restrictionsSchema, req.body);
  const next = await transaction(async (tx) => {
    const g = await getGrant(ctx.org.id, String(req.params.id), tx);
    assertMutable(g);
    validateWindow(body.validFrom, body.expiresAt);
    const integration = await integrationRepo.getIntegration(ctx.org.id, g.integrationId, tx);
    if (!integration) throw badRequest('The integration for this grant no longer exists');
    validateRepos(integration, body.repositories, body.scopes);
    await grantRepo.updateGrant(g.id, { storedStatus: 'SUPERSEDED' }, tx);
    const created = await grantRepo.insertGrant(
      {
        ...g,
        id: newId('grt'),
        scopes: body.scopes,
        resourceConstraints: { repositories: body.repositories },
        rateLimitPerMinute: body.rateLimitPerMinute,
        allowedCidrs: body.allowedCidrs,
        validFrom: new Date(body.validFrom).toISOString(),
        expiresAt: new Date(body.expiresAt).toISOString(),
        version: g.version + 1,
        previousVersionId: g.id,
        createdBy: ctx.user.id,
        createdAt: new Date().toISOString(),
        lastUsedAt: null,
        usageCount: 0,
      },
      tx,
    );
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.version_created', target: { type: 'grant', id: created.id, name: created.name }, metadata: { previousVersionId: g.id, version: created.version, scopes: created.scopes, repositories: body.repositories } }, tx);
    return created;
  });
  res.status(201).json(await toDetail(next));
});

/** Demo control for Scenario E: immediately expire a grant. */
grantsRouter.post('/grants/:id/expire-now', requirePermission(PERMISSIONS.GRANT_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const updated = await transaction(async (tx) => {
    const g = await getGrant(ctx.org.id, String(req.params.id), tx);
    assertMutable(g);
    const now = Date.now();
    const patch: Partial<GrantRecord> = { expiresAt: new Date(now - 1000).toISOString() };
    if (new Date(g.validFrom).getTime() > now) patch.validFrom = new Date(now - 60_000).toISOString();
    const u = await grantRepo.updateGrant(g.id, patch, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.expired_manually', target: { type: 'grant', id: g.id, name: g.name }, severity: 'warning', metadata: { simulated: true } }, tx);
    return u;
  });
  res.json(await toDetail(updated));
});
