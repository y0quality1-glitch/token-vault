import { Router } from 'express';
import { z } from 'zod';
import { GRANTABLE_OPERATIONS, PERMISSIONS, type GrantDetail } from '@token-vault/shared';
import { HttpError, badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { isValidCidr } from '../../lib/net';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { db, findInOrg, inOrg, type GrantRecord } from '../../store/db';
import { effectiveGrantStatus, toGrant } from '../../store/views';
import { recordEvent, userActor } from '../audit/audit.service';
import { policyMatches } from '../policy-engine/engine';

export const grantsRouter = Router();

const grantable = GRANTABLE_OPERATIONS.map((o) => o.id);
const repoPattern = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

const restrictionsSchema = z.object({
  scopes: z
    .array(z.string())
    .min(1, 'Select at least one permission')
    .refine((s) => s.every((x) => grantable.includes(x)), 'Destructive or unknown operations cannot be granted in the POC'),
  repositories: z.array(z.string().trim().regex(repoPattern, 'Use owner/repository format')).max(20).default([]),
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

function getGrant(orgId: string, id: string): GrantRecord {
  const g = findInOrg(db.grants, orgId, id);
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

function validateRepos(orgId: string, integrationId: string, repos: string[]) {
  const integration = findInOrg(db.integrations, orgId, integrationId)!;
  if (integration.allowedResources.length > 0) {
    const bad = repos.filter((r) => !integration.allowedResources.some((a) => a.toLowerCase() === r.toLowerCase()));
    if (bad.length) throw badRequest('Request validation failed', { fields: { repositories: `Not allowed by the integration: ${bad.join(', ')}` } });
  }
}

function toDetail(g: GrantRecord): GrantDetail {
  const requests = db.accessRequests.filter((r) => r.grantId === g.id);
  const since = Date.now() - 86400e3;
  // Walk the version chain in both directions.
  const chain: GrantRecord[] = [];
  let cursor: GrantRecord | undefined = g;
  while (cursor?.previousVersionId) cursor = db.grants.find((x) => x.id === cursor!.previousVersionId);
  while (cursor) {
    chain.push(cursor);
    const current: GrantRecord = cursor;
    cursor = db.grants.find((x) => x.previousVersionId === current.id);
  }
  const agent = db.agents.find((a) => a.id === g.agentId);
  const integration = db.integrations.find((i) => i.id === g.integrationId);
  const matchingPolicies =
    agent && integration
      ? db.policies
          .filter((p) => p.organizationId === g.organizationId && p.enabled)
          .filter((p) => g.scopes.some((op) => policyMatches(p, { agent, integration, operationId: op })))
          .map((p) => ({ id: p.id, name: p.name, effect: p.effect }))
      : [];
  return {
    ...toGrant(g),
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

grantsRouter.get('/grants', (req, res) => {
  const { org } = orgCtx(req);
  let items = inOrg(db.grants, org.id).map(toGrant);
  const { status, agentId, integrationId } = req.query;
  if (typeof status === 'string' && status) items = items.filter((g) => g.status === status);
  if (typeof agentId === 'string' && agentId) items = items.filter((g) => g.agentId === agentId);
  if (typeof integrationId === 'string' && integrationId) items = items.filter((g) => g.integrationId === integrationId);
  items.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json({ items });
});

grantsRouter.get('/grants/:id', (req, res) => {
  const { org } = orgCtx(req);
  res.json(toDetail(getGrant(org.id, String(req.params.id))));
});

grantsRouter.post('/grants', requirePermission(PERMISSIONS.GRANT_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(createSchema, req.body);
  const agent = findInOrg(db.agents, ctx.org.id, body.agentId);
  if (!agent) throw badRequest('Request validation failed', { fields: { agentId: 'Unknown agent' } });
  if (agent.status !== 'ACTIVE') throw badRequest('Request validation failed', { fields: { agentId: 'Agent is disabled; enable it before granting access' } });
  const integration = findInOrg(db.integrations, ctx.org.id, body.integrationId);
  if (!integration) throw badRequest('Request validation failed', { fields: { integrationId: 'Unknown integration' } });
  if (integration.credentialStatus !== 'CONNECTED') throw badRequest('Request validation failed', { fields: { integrationId: 'Integration is not connected' } });
  if (body.environment !== integration.environment) throw badRequest('Request validation failed', { fields: { environment: `Must match the integration environment (${integration.environment})` } });
  validateWindow(body.validFrom, body.expiresAt);
  validateRepos(ctx.org.id, integration.id, body.repositories);
  if (inOrg(db.grants, ctx.org.id).some((g) => g.name.toLowerCase() === body.name.toLowerCase() && g.storedStatus !== 'SUPERSEDED')) throw conflict('A grant with that name already exists');

  const grant: GrantRecord = {
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
  };
  db.grants.push(grant);
  recordEvent({
    orgId: ctx.org.id,
    actor: userActor(ctx),
    eventType: 'grant.created',
    target: { type: 'grant', id: grant.id, name: grant.name },
    metadata: { agentId: agent.id, integrationId: integration.id, scopes: grant.scopes, repositories: body.repositories, expiresAt: grant.expiresAt, status: grant.storedStatus },
  });
  res.status(201).json(toDetail(grant));
});

function assertMutable(g: GrantRecord) {
  const s = effectiveGrantStatus(g);
  if (s === 'REVOKED' || s === 'SUPERSEDED') throw new HttpError(409, 'GRANT_NOT_MUTABLE', `Grant is ${s.toLowerCase()} and cannot be changed`);
}

/** Revocation takes effect on the very next authorization check (state is evaluated per request). */
grantsRouter.post('/grants/:id/revoke', requirePermission(PERMISSIONS.GRANT_REVOKE), (req, res) => {
  const ctx = orgCtx(req);
  const g = getGrant(ctx.org.id, String(req.params.id));
  assertMutable(g);
  const { reason } = parse(z.object({ reason: z.string().trim().max(240).default('') }), req.body ?? {});
  Object.assign(g, { storedStatus: 'REVOKED', revokedAt: new Date().toISOString(), revokedBy: ctx.user.id, revocationReason: reason || 'Revoked by administrator' });
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.revoked', target: { type: 'grant', id: g.id, name: g.name }, severity: 'warning', metadata: { reason: g.revocationReason, agentId: g.agentId, integrationId: g.integrationId } });
  res.json(toDetail(g));
});

grantsRouter.post('/grants/:id/approve', requirePermission(PERMISSIONS.GRANT_APPROVE), (req, res) => {
  const ctx = orgCtx(req);
  const g = getGrant(ctx.org.id, String(req.params.id));
  if (g.storedStatus !== 'PENDING_APPROVAL') throw conflict('Only grants pending approval can be approved');
  Object.assign(g, { storedStatus: 'ACTIVE', approvedBy: ctx.user.id, approvedAt: new Date().toISOString() });
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.approved', target: { type: 'grant', id: g.id, name: g.name }, metadata: { simulatedApproval: true } });
  res.json(toDetail(g));
});

grantsRouter.post('/grants/:id/extend', requirePermission(PERMISSIONS.GRANT_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const g = getGrant(ctx.org.id, String(req.params.id));
  assertMutable(g);
  const { expiresAt } = parse(z.object({ expiresAt: z.string().datetime({ offset: true, message: 'Enter a valid date/time' }) }), req.body);
  validateWindow(g.validFrom, expiresAt);
  const previous = g.expiresAt;
  g.expiresAt = new Date(expiresAt).toISOString();
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.expiry_extended', target: { type: 'grant', id: g.id, name: g.name }, metadata: { from: previous, to: g.expiresAt } });
  res.json(toDetail(g));
});

/** Editing restrictions creates a new grant version for auditability; the old version is superseded. */
grantsRouter.post('/grants/:id/versions', requirePermission(PERMISSIONS.GRANT_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const g = getGrant(ctx.org.id, String(req.params.id));
  assertMutable(g);
  const body = parse(restrictionsSchema, req.body);
  validateWindow(body.validFrom, body.expiresAt);
  validateRepos(ctx.org.id, g.integrationId, body.repositories);
  const next: GrantRecord = {
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
  };
  g.storedStatus = 'SUPERSEDED';
  db.grants.push(next);
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.version_created', target: { type: 'grant', id: next.id, name: next.name }, metadata: { previousVersionId: g.id, version: next.version, scopes: next.scopes, repositories: body.repositories } });
  res.status(201).json(toDetail(next));
});

/** Demo control for Scenario E: immediately expire a grant. */
grantsRouter.post('/grants/:id/expire-now', requirePermission(PERMISSIONS.GRANT_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const g = getGrant(ctx.org.id, String(req.params.id));
  assertMutable(g);
  const now = Date.now();
  g.expiresAt = new Date(now - 1000).toISOString();
  if (new Date(g.validFrom).getTime() > now) g.validFrom = new Date(now - 60_000).toISOString();
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.expired_manually', target: { type: 'grant', id: g.id, name: g.name }, severity: 'warning', metadata: { simulated: true } });
  res.json(toDetail(g));
});
