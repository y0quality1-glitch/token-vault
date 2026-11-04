import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, roleHas, type ApiClient, type IssuedCredential } from '@token-vault/shared';
import { generateAgentCredential, maskAgentKey } from '../../lib/crypto';
import { conflict, forbidden, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { isValidCidr } from '../../lib/net';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { db, findInOrg, inOrg, type AgentRecord } from '../../store/db';
import { effectiveGrantStatus, toAgent, toGrant } from '../../store/views';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../audit/audit.service';

export const agentsRouter = Router();

const cidrList = z.array(z.string().trim().refine(isValidCidr, 'Use IPv4 CIDR notation, e.g. 10.0.0.0/16')).max(20).default([]);

const agentSchema = z.object({
  name: z.string().trim().min(3, 'Name must be at least 3 characters').max(60),
  description: z.string().trim().max(240).default(''),
  environment: z.enum(['development', 'staging', 'production']),
  ownerTeam: z.string().trim().min(1, 'Owner / team is required').max(60),
  agentType: z.enum(['AI_AGENT', 'APPLICATION', 'SERVICE']),
  callbackUrl: z.union([z.literal(''), z.string().trim().url('Enter a valid URL')]).default(''),
  allowedCidrs: cidrList,
});

function getAgent(orgId: string, id: string): AgentRecord {
  const a = findInOrg(db.agents, orgId, id);
  if (!a) throw notFound('Agent');
  return a;
}

/** Developers may manage only agents they own; Owner may manage any agent. */
function assertCanManage(ctx: AdminContext, agent: AgentRecord) {
  if (roleHas(ctx.role, PERMISSIONS.AGENT_MANAGE_ANY)) return;
  if (agent.ownerUserId !== ctx.user.id) throw forbidden('Developers can only manage agents they own');
}

function issue(agent: AgentRecord): IssuedCredential {
  const cred = generateAgentCredential();
  agent.credentialKeyId = cred.keyId;
  agent.credentialHash = cred.hash; // only the scrypt hash is stored
  agent.credentialIssuedAt = new Date().toISOString();
  return { apiKey: cred.apiKey, keyId: cred.keyId, issuedAt: agent.credentialIssuedAt };
}

agentsRouter.get('/agents', (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: inOrg(db.agents, org.id).map(toAgent) });
});

agentsRouter.get('/agents/:id', (req, res) => {
  const { org } = orgCtx(req);
  const a = getAgent(org.id, String(req.params.id));
  const grants = db.grants.filter((g) => g.agentId === a.id).map(toGrant);
  const activity = db.accessRequests.filter((r) => r.agentId === a.id).slice(0, 25);
  res.json({ ...toAgent(a), grants, activity, maskedKey: maskAgentKey(a.credentialKeyId) });
});

agentsRouter.post('/agents', requirePermission(PERMISSIONS.AGENT_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(agentSchema, req.body);
  if (inOrg(db.agents, ctx.org.id).some((a) => a.name.toLowerCase() === body.name.toLowerCase())) throw conflict('An agent with that name already exists');
  const now = new Date().toISOString();
  const agent: AgentRecord = {
    id: newId('agt'),
    organizationId: ctx.org.id,
    ...body,
    ownerUserId: ctx.user.id,
    credentialKeyId: '',
    credentialHash: '',
    credentialIssuedAt: now,
    status: 'ACTIVE',
    lastAccessAt: null,
    createdAt: now,
  };
  const credential = issue(agent);
  db.agents.push(agent);
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.registered', target: { type: 'agent', id: agent.id, name: agent.name }, metadata: { agentType: agent.agentType, environment: agent.environment, keyId: credential.keyId } });
  res.status(201).json({ agent: toAgent(agent), credential });
});

agentsRouter.patch('/agents/:id', requirePermission(PERMISSIONS.AGENT_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const a = getAgent(ctx.org.id, String(req.params.id));
  assertCanManage(ctx, a);
  const body = parse(agentSchema.omit({ agentType: true }), req.body);
  Object.assign(a, body);
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.updated', target: { type: 'agent', id: a.id, name: a.name }, metadata: body });
  res.json(toAgent(a));
});

agentsRouter.post('/agents/:id/rotate-credential', requirePermission(PERMISSIONS.AGENT_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const a = getAgent(ctx.org.id, String(req.params.id));
  assertCanManage(ctx, a);
  const previousKeyId = a.credentialKeyId;
  const credential = issue(a);
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.credential_rotated', target: { type: 'agent', id: a.id, name: a.name }, severity: 'warning', metadata: { previousKeyId, keyId: credential.keyId } });
  res.json({ agent: toAgent(a), credential });
});

agentsRouter.post('/agents/:id/disable', requirePermission(PERMISSIONS.AGENT_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const a = getAgent(ctx.org.id, String(req.params.id));
  assertCanManage(ctx, a);
  a.status = 'DISABLED';
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.disabled', target: { type: 'agent', id: a.id, name: a.name }, severity: 'warning' });
  res.json(toAgent(a));
});

agentsRouter.post('/agents/:id/enable', requirePermission(PERMISSIONS.AGENT_MANAGE), (req, res) => {
  const ctx = orgCtx(req);
  const a = getAgent(ctx.org.id, String(req.params.id));
  assertCanManage(ctx, a);
  a.status = 'ACTIVE';
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.enabled', target: { type: 'agent', id: a.id, name: a.name } });
  res.json(toAgent(a));
});

agentsRouter.post('/agents/:id/revoke-grants', requirePermission(PERMISSIONS.GRANT_REVOKE), (req, res) => {
  const ctx = orgCtx(req);
  const a = getAgent(ctx.org.id, String(req.params.id));
  const now = new Date().toISOString();
  const affected = db.grants.filter((g) => g.agentId === a.id && ['ACTIVE', 'PENDING_APPROVAL', 'SCHEDULED'].includes(effectiveGrantStatus(g)));
  for (const g of affected) Object.assign(g, { storedStatus: 'REVOKED', revokedAt: now, revokedBy: ctx.user.id, revocationReason: 'All grants revoked for agent' });
  recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.grants_revoked', target: { type: 'agent', id: a.id, name: a.name }, severity: 'critical', metadata: { grantIds: affected.map((g) => g.id) } });
  res.json({ revoked: affected.length, agent: toAgent(a) });
});

/** API Clients: metadata about issued agent credentials (never the secret). */
agentsRouter.get('/api-clients', (req, res) => {
  const { org } = orgCtx(req);
  const items: ApiClient[] = inOrg(db.agents, org.id).map((a) => ({
    keyId: a.credentialKeyId,
    maskedKey: maskAgentKey(a.credentialKeyId),
    agentId: a.id,
    agentName: a.name,
    agentStatus: a.status,
    issuedAt: a.credentialIssuedAt,
    lastUsedAt: a.lastAccessAt,
  }));
  res.json({ items });
});
