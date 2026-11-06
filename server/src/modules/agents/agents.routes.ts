import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, roleHas, type ApiClient, type IssuedCredential } from '@token-vault/shared';
import { transaction } from '../../db/client';
import { generateAgentCredential, maskAgentKey } from '../../lib/crypto';
import { conflict, forbidden, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { isValidCidr } from '../../lib/net';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { agentRepo, auditRepo, grantRepo } from '../../store/repos';
import type { AgentRecord } from '../../store/types';
import { agentView, effectiveGrantStatus, loadLookups, toAgent, toGrant } from '../../store/views';
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

async function getAgent(orgId: string, id: string): Promise<AgentRecord> {
  const a = await agentRepo.getAgent(orgId, id);
  if (!a) throw notFound('Agent');
  return a;
}

/** Developers may manage only agents they own; Owner may manage any agent. */
function assertCanManage(ctx: AdminContext, agent: AgentRecord) {
  if (roleHas(ctx.role, PERMISSIONS.AGENT_MANAGE_ANY)) return;
  if (agent.ownerUserId !== ctx.user.id) throw forbidden('Developers can only manage agents they own');
}

/** New API credential: the plaintext is returned once; only the scrypt hash is persisted. */
/**
 * A new API key. With `previous` and a grace period, the replaced key keeps working until
 * then, so the agent can switch without failed requests; otherwise it stops at once.
 */
function issueCredential(previous?: { keyId: string; hash: string; graceMinutes: number }) {
  const cred = generateAgentCredential();
  const issuedAt = new Date().toISOString();
  const grace = previous && previous.graceMinutes > 0;
  return {
    patch: {
      credentialKeyId: cred.keyId,
      credentialHash: cred.hash,
      credentialIssuedAt: issuedAt,
      previousCredentialKeyId: grace ? previous.keyId : null,
      previousCredentialHash: grace ? previous.hash : null,
      previousCredentialExpiresAt: grace ? new Date(Date.parse(issuedAt) + previous.graceMinutes * 60_000).toISOString() : null,
      previousCredentialLastUsedAt: null,
    },
    credential: { apiKey: cred.apiKey, keyId: cred.keyId, issuedAt } satisfies IssuedCredential,
  };
}

agentsRouter.get('/agents', async (req, res) => {
  const { org } = orgCtx(req);
  const [list, lookups] = await Promise.all([agentRepo.listAgents(org.id), loadLookups(org.id)]);
  res.json({ items: list.map((a) => toAgent(a, lookups)) });
});

agentsRouter.get('/agents/:id', async (req, res) => {
  const { org } = orgCtx(req);
  const a = await getAgent(org.id, String(req.params.id));
  const [grants, activity, lookups] = await Promise.all([grantRepo.listGrants(org.id, { agentId: a.id }), auditRepo.accessRequestsForAgent(a.id, 25), loadLookups(org.id)]);
  res.json({ ...toAgent(a, lookups), grants: grants.map((g) => toGrant(g, lookups)), activity, maskedKey: maskAgentKey(a.credentialKeyId) });
});

agentsRouter.post('/agents', requirePermission(PERMISSIONS.AGENT_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(agentSchema, req.body);
  const { patch, credential } = issueCredential();
  const agent = await transaction(async (tx) => {
    if ((await agentRepo.listAgents(ctx.org.id, tx)).some((a) => a.name.toLowerCase() === body.name.toLowerCase())) throw conflict('An agent with that name already exists');
    const now = new Date().toISOString();
    const created = await agentRepo.insertAgent({ id: newId('agt'), organizationId: ctx.org.id, ...body, ownerUserId: ctx.user.id, ...patch, status: 'ACTIVE', lastAccessAt: null, createdAt: now }, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.registered', target: { type: 'agent', id: created.id, name: created.name }, metadata: { agentType: created.agentType, environment: created.environment, keyId: credential.keyId } }, tx);
    return created;
  });
  res.status(201).json({ agent: await agentView(agent), credential });
});

agentsRouter.patch('/agents/:id', requirePermission(PERMISSIONS.AGENT_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const a = await getAgent(ctx.org.id, String(req.params.id));
  assertCanManage(ctx, a);
  const body = parse(agentSchema.omit({ agentType: true }), req.body);
  const updated = await transaction(async (tx) => {
    const u = await agentRepo.updateAgent(a.id, body, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.updated', target: { type: 'agent', id: a.id, name: u.name }, metadata: body }, tx);
    return u;
  });
  res.json(await agentView(updated));
});

agentsRouter.post('/agents/:id/rotate-credential', requirePermission(PERMISSIONS.AGENT_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const a = await getAgent(ctx.org.id, String(req.params.id));
  assertCanManage(ctx, a);
  // graceMinutes: how long the replaced key keeps working (0 = stops at once; at most 24 h).
  // A key still in an earlier grace period stops now: only the key being replaced gets one.
  const { graceMinutes } = parse(z.object({ graceMinutes: z.number().int().min(0).max(1440).default(0) }), req.body ?? {});
  const { patch, credential } = issueCredential({ keyId: a.credentialKeyId, hash: a.credentialHash, graceMinutes });
  const updated = await transaction(async (tx) => {
    const u = await agentRepo.updateAgent(a.id, patch, tx);
    await recordEvent(
      {
        orgId: ctx.org.id,
        actor: userActor(ctx),
        eventType: 'agent.credential_rotated',
        target: { type: 'agent', id: a.id, name: a.name },
        severity: 'warning',
        metadata: { previousKeyId: a.credentialKeyId, keyId: credential.keyId, graceMinutes, previousKeyValidUntil: patch.previousCredentialExpiresAt },
      },
      tx,
    );
    return u;
  });
  res.json({ agent: await agentView(updated), credential });
});

/** Ends a rotation's grace period now: the previous key stops working at once. */
agentsRouter.post('/agents/:id/revoke-previous-credential', requirePermission(PERMISSIONS.AGENT_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const a = await getAgent(ctx.org.id, String(req.params.id));
  assertCanManage(ctx, a);
  if (!a.previousCredentialKeyId || !a.previousCredentialExpiresAt || Date.parse(a.previousCredentialExpiresAt) <= Date.now()) throw conflict('This agent has no previous key in a grace period');
  const updated = await transaction(async (tx) => {
    const u = await agentRepo.updateAgent(a.id, { previousCredentialKeyId: null, previousCredentialHash: null, previousCredentialExpiresAt: null, previousCredentialLastUsedAt: null }, tx);
    await recordEvent(
      {
        orgId: ctx.org.id,
        actor: userActor(ctx),
        eventType: 'agent.previous_credential_revoked',
        target: { type: 'agent', id: a.id, name: a.name },
        severity: 'warning',
        metadata: { previousKeyId: a.previousCredentialKeyId, wasValidUntil: a.previousCredentialExpiresAt, lastUsedAt: a.previousCredentialLastUsedAt },
      },
      tx,
    );
    return u;
  });
  res.json({ agent: await agentView(updated) });
});

async function setAgentStatus(req: import('express').Request, status: 'ACTIVE' | 'DISABLED') {
  const ctx = orgCtx(req);
  const a = await getAgent(ctx.org.id, String(req.params.id));
  assertCanManage(ctx, a);
  return transaction(async (tx) => {
    const u = await agentRepo.updateAgent(a.id, { status }, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: status === 'DISABLED' ? 'agent.disabled' : 'agent.enabled', target: { type: 'agent', id: a.id, name: a.name }, severity: status === 'DISABLED' ? 'warning' : 'info' }, tx);
    return u;
  });
}

agentsRouter.post('/agents/:id/disable', requirePermission(PERMISSIONS.AGENT_MANAGE), async (req, res) => {
  res.json(await agentView(await setAgentStatus(req, 'DISABLED')));
});

agentsRouter.post('/agents/:id/enable', requirePermission(PERMISSIONS.AGENT_MANAGE), async (req, res) => {
  res.json(await agentView(await setAgentStatus(req, 'ACTIVE')));
});

agentsRouter.post('/agents/:id/revoke-grants', requirePermission(PERMISSIONS.GRANT_REVOKE), async (req, res) => {
  const ctx = orgCtx(req);
  const a = await getAgent(ctx.org.id, String(req.params.id));
  const revoked = await transaction(async (tx) => {
    const affected = (await grantRepo.listGrants(ctx.org.id, { agentId: a.id }, tx)).filter((g) => ['ACTIVE', 'PENDING_APPROVAL', 'SCHEDULED'].includes(effectiveGrantStatus(g)));
    await grantRepo.revokeGrants(affected.map((g) => g.id), ctx.user.id, 'All grants revoked for agent', tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.grants_revoked', target: { type: 'agent', id: a.id, name: a.name }, severity: 'critical', metadata: { grantIds: affected.map((g) => g.id) } }, tx);
    return affected.length;
  });
  res.json({ revoked, agent: await agentView(a) });
});

/** API Clients: metadata about issued agent credentials (never the secret). */
agentsRouter.get('/api-clients', async (req, res) => {
  const { org } = orgCtx(req);
  const items: ApiClient[] = (await agentRepo.listAgents(org.id)).map((a) => ({
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
