import type { Agent, Grant, Integration, Role, User, Webhook } from '@token-vault/shared';

/**
 * Storage record shapes. Each matches a row of the PostgreSQL schema in src/db/schema.ts
 * (camelCase in TypeScript, snake_case in SQL). API DTOs are built from these in views.ts.
 *
 * Not present anywhere: provider secrets, encryption keys, plaintext agent keys or session tokens.
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
  tokenHash: string;
  userId: string;
  organizationId: string | null;
  createdAt: string;
  expiresAt: string;
}

export type WebhookRecord = Webhook;
export type IntegrationRecord = Omit<Integration, 'webhookName' | 'createdByName'> & { deletedAt: string | null };
export type AgentRecord = Omit<Agent, 'ownerName' | 'activeGrants'> & { credentialHash: string; previousCredentialHash: string | null };
export type GrantRecord = Omit<Grant, 'agentName' | 'integrationName' | 'status' | 'createdByName'>;
