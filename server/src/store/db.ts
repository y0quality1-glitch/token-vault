import type {
  AccessRequest,
  Agent,
  AuditEvent,
  Grant,
  Integration,
  Organization,
  Policy,
  Role,
  User,
  Webhook,
} from '@token-vault/shared';

/**
 * In-memory repository for the POC control plane.
 *
 * The record shapes mirror the PostgreSQL data model in the specification
 * (section 9). Swapping this module for Prisma/Drizzle repositories only
 * requires re-implementing the accessors below; services never touch storage
 * directly except through these collections.
 *
 * Note what is NOT here: no provider secret, no encryption key, no plaintext
 * agent API key. Agents carry only a scrypt hash of their credential.
 */
export interface UserRecord extends User {
  passwordHash: string;
}

export interface MemberRecord {
  id: string;
  organizationId: string;
  userId: string;
  role: Role;
  createdAt: string;
}

export interface SessionRecord {
  id: string;
  userId: string;
  organizationId: string | null;
  createdAt: number;
  expiresAt: number;
}

export type WebhookRecord = Webhook;
export type IntegrationRecord = Omit<Integration, 'webhookName' | 'createdByName'>;
export type AgentRecord = Omit<Agent, 'ownerName' | 'activeGrants'> & { credentialHash: string };
export type GrantRecord = Omit<Grant, 'agentName' | 'integrationName' | 'status' | 'createdByName'>;

export interface Db {
  organizations: Organization[];
  users: UserRecord[];
  members: MemberRecord[];
  sessions: Map<string, SessionRecord>;
  webhooks: WebhookRecord[];
  integrations: IntegrationRecord[];
  agents: AgentRecord[];
  grants: GrantRecord[];
  policies: Policy[];
  accessRequests: AccessRequest[];
  auditEvents: AuditEvent[];
}

export const db: Db = {
  organizations: [],
  users: [],
  members: [],
  sessions: new Map(),
  webhooks: [],
  integrations: [],
  agents: [],
  grants: [],
  policies: [],
  accessRequests: [],
  auditEvents: [],
};

/** Organization isolation helper: every org-scoped query goes through this. */
export function inOrg<T extends { organizationId: string }>(list: T[], orgId: string): T[] {
  return list.filter((x) => x.organizationId === orgId);
}

export function findInOrg<T extends { id: string; organizationId: string }>(list: T[], orgId: string, id: string): T | undefined {
  return list.find((x) => x.id === id && x.organizationId === orgId);
}
