import type { Agent, Grant, GrantStatus, Integration } from '@token-vault/shared';
import { db, type AgentRecord, type GrantRecord, type IntegrationRecord } from './db';

/** Converts storage records to API DTOs (adds display names and computed state; strips hashes). */

export function userName(userId: string): string {
  return db.users.find((u) => u.id === userId)?.fullName ?? 'Unknown user';
}

export function effectiveGrantStatus(g: Pick<GrantRecord, 'storedStatus' | 'validFrom' | 'expiresAt'>, now = Date.now()): GrantStatus {
  if (g.storedStatus === 'REVOKED' || g.storedStatus === 'SUPERSEDED') return g.storedStatus;
  if (new Date(g.expiresAt).getTime() <= now) return 'EXPIRED';
  if (g.storedStatus === 'PENDING_APPROVAL') return 'PENDING_APPROVAL';
  if (new Date(g.validFrom).getTime() > now) return 'SCHEDULED';
  return 'ACTIVE';
}

export function toGrant(g: GrantRecord): Grant {
  return {
    ...g,
    agentName: db.agents.find((a) => a.id === g.agentId)?.name ?? 'Deleted agent',
    integrationName: db.integrations.find((i) => i.id === g.integrationId)?.displayName ?? 'Deleted integration',
    createdByName: userName(g.createdBy),
    status: effectiveGrantStatus(g),
  };
}

export function toAgent(a: AgentRecord): Agent {
  const { credentialHash: _hash, ...rest } = a;
  return {
    ...rest,
    ownerName: userName(a.ownerUserId),
    activeGrants: db.grants.filter((g) => g.agentId === a.id && effectiveGrantStatus(g) === 'ACTIVE').length,
  };
}

export function toIntegration(i: IntegrationRecord): Integration {
  return {
    ...i,
    webhookName: db.webhooks.find((w) => w.id === i.webhookId)?.name ?? 'Unknown webhook',
    createdByName: userName(i.createdBy),
  };
}
