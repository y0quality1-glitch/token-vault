import type { Agent, Grant, GrantStatus, Integration } from '@token-vault/shared';
import { db, type Executor } from '../databases/client';
import { agentRepo, grantRepo, integrationRepo, orgRepo, webhookRepo } from './repos';
import type { AgentRecord, GrantRecord, IntegrationRecord } from './types';

/**
 * Converts storage records to API DTOs: adds display names and computed state, and strips
 * internal fields (credential hashes, soft-delete markers). Names are batch-loaded per
 * organization so list endpoints issue a fixed number of queries.
 */

export function effectiveGrantStatus(g: Pick<GrantRecord, 'storedStatus' | 'validFrom' | 'expiresAt'>, now = Date.now()): GrantStatus {
  if (g.storedStatus === 'REVOKED' || g.storedStatus === 'SUPERSEDED') return g.storedStatus;
  if (new Date(g.expiresAt).getTime() <= now) return 'EXPIRED';
  if (g.storedStatus === 'PENDING_APPROVAL') return 'PENDING_APPROVAL';
  if (new Date(g.validFrom).getTime() > now) return 'SCHEDULED';
  return 'ACTIVE';
}

export interface Lookups {
  agents: Map<string, string>;
  integrations: Map<string, string>;
  webhooks: Map<string, string>;
  users: Map<string, string>;
  activeGrantsByAgent: Map<string, number>;
}

/** Loads every display name an org-scoped view may need. */
export async function loadLookups(organizationId: string, extraUserIds: string[] = [], ex: Executor = db): Promise<Lookups> {
  const [agents, integrations, webhooks, grants] = await Promise.all([
    agentRepo.listAgents(organizationId, ex),
    integrationRepo.integrationNames(organizationId, ex),
    webhookRepo.listWebhooks(organizationId, ex),
    grantRepo.listGrants(organizationId, {}, ex),
  ]);
  const userIds = [...agents.map((a) => a.ownerUserId), ...grants.map((g) => g.createdBy), ...extraUserIds];
  const activeGrantsByAgent = new Map<string, number>();
  for (const g of grants) if (effectiveGrantStatus(g) === 'ACTIVE') activeGrantsByAgent.set(g.agentId, (activeGrantsByAgent.get(g.agentId) ?? 0) + 1);
  return {
    agents: new Map(agents.map((a) => [a.id, a.name])),
    integrations,
    webhooks: new Map(webhooks.map((w) => [w.id, w.name])),
    users: await orgRepo.userNames(userIds, ex),
    activeGrantsByAgent,
  };
}

const userName = (l: Lookups, id: string) => l.users.get(id) ?? 'Unknown user';

export function toGrant(g: GrantRecord, l: Lookups): Grant {
  return {
    ...g,
    agentName: l.agents.get(g.agentId) ?? 'Deleted agent',
    integrationName: l.integrations.get(g.integrationId) ?? 'Deleted integration',
    createdByName: userName(l, g.createdBy),
    status: effectiveGrantStatus(g),
  };
}

export function toAgent(a: AgentRecord, l: Lookups): Agent {
  const { credentialHash: _hash, previousCredentialHash: _previousHash, ...rest } = a;
  // A previous key whose grace period is over is no longer shown.
  const graceOver = !rest.previousCredentialExpiresAt || Date.parse(rest.previousCredentialExpiresAt) <= Date.now();
  if (graceOver) Object.assign(rest, { previousCredentialKeyId: null, previousCredentialExpiresAt: null, previousCredentialLastUsedAt: null });
  return { ...rest, ownerName: userName(l, a.ownerUserId), activeGrants: l.activeGrantsByAgent.get(a.id) ?? 0 };
}

export function toIntegration(i: IntegrationRecord, l: Lookups): Integration {
  const { deletedAt: _deleted, ...rest } = i;
  return { ...rest, webhookName: l.webhooks.get(i.webhookId) ?? 'Unknown webhook', createdByName: userName(l, i.createdBy) };
}

// Convenience wrappers for single-record responses.
export async function grantView(g: GrantRecord, ex: Executor = db) {
  return toGrant(g, await loadLookups(g.organizationId, [g.createdBy], ex));
}
export async function agentView(a: AgentRecord, ex: Executor = db) {
  return toAgent(a, await loadLookups(a.organizationId, [a.ownerUserId], ex));
}
export async function integrationView(i: IntegrationRecord, ex: Executor = db) {
  return toIntegration(i, await loadLookups(i.organizationId, [i.createdBy], ex));
}
