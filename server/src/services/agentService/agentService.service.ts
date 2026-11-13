import { PERMISSIONS, roleHas, type ApiClient, type IssuedCredential } from '@token-vault/shared';
import { transaction } from '../../databases/client';
import type { AgentDto } from '../../databases/repository/agent/agent.dto';
import { generateAgentCredential, maskAgentKey } from '../../lib/crypto';
import { conflict, forbidden, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { agentRepo, auditRepo, grantRepo } from '../../store/repos';
import type { AgentRecord } from '../../store/types';
import { agentView, effectiveGrantStatus, loadLookups, toAgent, toGrant } from '../../store/views';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';

type OrgContext = AdminContext & { org: { id: string } };

/**
 * A new API key. With `previous` and a grace period, the replaced key keeps working until
 * then, so the agent can switch without failed requests; otherwise it stops at once.
 * The plaintext is returned once; only the scrypt hash is persisted.
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

/** Developers may manage only agents they own; Owner may manage any agent. */
function assertCanManage(ctx: AdminContext, agent: AgentRecord) {
  if (roleHas(ctx.role, PERMISSIONS.AGENT_MANAGE_ANY)) return;
  if (agent.ownerUserId !== ctx.user.id) throw forbidden('Developers can only manage agents they own');
}

/** Agents (machine identities) and their API credentials. */
export default class AgentService {
  private async get(orgId: string, id: string): Promise<AgentRecord> {
    const a = await agentRepo.getAgent(orgId, id);
    if (!a) throw notFound('Agent');
    return a;
  }

  /** The agent, checked against the caller's right to manage it. */
  private async manageable(ctx: OrgContext, id: string): Promise<AgentRecord> {
    const a = await this.get(ctx.org.id, id);
    assertCanManage(ctx, a);
    return a;
  }

  async list(orgId: string) {
    const [list, lookups] = await Promise.all([agentRepo.listAgents(orgId), loadLookups(orgId)]);
    return { items: list.map((a) => toAgent(a, lookups)) };
  }

  async detail(orgId: string, id: string) {
    const a = await this.get(orgId, id);
    const [grants, activity, lookups] = await Promise.all([grantRepo.listGrants(orgId, { agentId: a.id }), auditRepo.accessRequestsForAgent(a.id, 25), loadLookups(orgId)]);
    return { ...toAgent(a, lookups), grants: grants.map((g) => toGrant(g, lookups)), activity, maskedKey: maskAgentKey(a.credentialKeyId) };
  }

  /** Registers an agent (no `id`, returns `{ agent, credential }`) or updates one (returns the agent). */
  async save(ctx: OrgContext, body: AgentDto): Promise<{ result: unknown; created: boolean }> {
    const fields = { name: body.name, description: body.description, environment: body.environment, ownerTeam: body.ownerTeam, callbackUrl: body.callbackUrl, allowedCidrs: [...body.allowedCidrs] };
    if (!body.id) {
      const { patch, credential } = issueCredential();
      const agent = await transaction(async (tx) => {
        if ((await agentRepo.listAgents(ctx.org.id, tx)).some((a) => a.name.toLowerCase() === fields.name.toLowerCase())) throw conflict('An agent with that name already exists');
        const now = new Date().toISOString();
        const created = await agentRepo.insertAgent({ id: newId('agt'), organizationId: ctx.org.id, ...fields, agentType: body.agentType!, ownerUserId: ctx.user.id, ...patch, status: 'ACTIVE', lastAccessAt: null, createdAt: now }, tx);
        await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.registered', target: { type: 'agent', id: created.id, name: created.name }, metadata: { agentType: created.agentType, environment: created.environment, keyId: credential.keyId } }, tx);
        return created;
      });
      return { result: { agent: await agentView(agent), credential }, created: true };
    }
    const a = await this.manageable(ctx, body.id);
    const updated = await transaction(async (tx) => {
      const u = await agentRepo.updateAgent(a.id, fields, tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.updated', target: { type: 'agent', id: a.id, name: u.name }, metadata: fields }, tx);
      return u;
    });
    return { result: await agentView(updated), created: false };
  }

  /** A new key; the replaced one keeps working for `graceMinutes` (a key still in an earlier grace period stops now). */
  async rotateCredential(ctx: OrgContext, id: string, graceMinutes: number) {
    const a = await this.manageable(ctx, id);
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
    return { agent: await agentView(updated), credential };
  }

  /** Ends a rotation's grace period now: the previous key stops working at once. */
  async revokePreviousCredential(ctx: OrgContext, id: string) {
    const a = await this.manageable(ctx, id);
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
    return { agent: await agentView(updated) };
  }

  async setStatus(ctx: OrgContext, id: string, status: 'ACTIVE' | 'DISABLED') {
    const a = await this.manageable(ctx, id);
    const updated = await transaction(async (tx) => {
      const u = await agentRepo.updateAgent(a.id, { status }, tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: status === 'DISABLED' ? 'agent.disabled' : 'agent.enabled', target: { type: 'agent', id: a.id, name: a.name }, severity: status === 'DISABLED' ? 'warning' : 'info' }, tx);
      return u;
    });
    return agentView(updated);
  }

  /** Revokes every active, pending or scheduled grant of the agent. */
  async revokeGrants(ctx: OrgContext, id: string) {
    const a = await this.get(ctx.org.id, id);
    const revoked = await transaction(async (tx) => {
      const affected = (await grantRepo.listGrants(ctx.org.id, { agentId: a.id }, tx)).filter((g) => ['ACTIVE', 'PENDING_APPROVAL', 'SCHEDULED'].includes(effectiveGrantStatus(g)));
      await grantRepo.revokeGrants(affected.map((g) => g.id), ctx.user.id, 'All grants revoked for agent', tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'agent.grants_revoked', target: { type: 'agent', id: a.id, name: a.name }, severity: 'critical', metadata: { grantIds: affected.map((g) => g.id) } }, tx);
      return affected.length;
    });
    return { revoked, agent: await agentView(a) };
  }

  /** API Clients: metadata about issued agent credentials (never the secret). */
  async listApiClients(orgId: string) {
    const items: ApiClient[] = (await agentRepo.listAgents(orgId)).map((a) => ({
      keyId: a.credentialKeyId,
      maskedKey: maskAgentKey(a.credentialKeyId),
      agentId: a.id,
      agentName: a.name,
      agentStatus: a.status,
      issuedAt: a.credentialIssuedAt,
      lastUsedAt: a.lastAccessAt,
    }));
    return { items };
  }
}
