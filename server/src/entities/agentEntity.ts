import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { AgentStatus, AgentType, Environment } from '@token-vault/shared';
import { tsColumn } from './columns';

/** Table `agents` (see the baseline migration for constraints, indexes and triggers). */
@Entity('agents')
export class AgentEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'name', type: 'text' })
  name!: string;

  @Column({ name: 'description', type: 'text', default: '' })
  description!: string;

  @Column({ name: 'agent_type', type: 'text' })
  agentType!: AgentType;

  @Column({ name: 'environment', type: 'text' })
  environment!: Environment;

  @Column({ name: 'owner_user_id', type: 'text' })
  ownerUserId!: string;

  @Column({ name: 'owner_team', type: 'text' })
  ownerTeam!: string;

  @Column({ name: 'callback_url', type: 'text', default: '' })
  callbackUrl!: string;

  @Column({ name: 'allowed_cidrs', type: 'jsonb', default: () => "'[]'::jsonb" })
  allowedCidrs!: string[];

  @Column({ name: 'credential_key_id', type: 'text', unique: true })
  credentialKeyId!: string;

  /** scrypt hash of the agent API key; the key itself is never stored. */
  @Column({ name: 'credential_hash', type: 'text' })
  credentialHash!: string;

  @tsColumn('credential_issued_at')
  credentialIssuedAt!: string;

  /**
  * The key replaced by the last rotation, still accepted until previous_credential_expires_at
  * (grace period, so the agent can switch without failed requests). Hash only, like the current key.
  */
  @Column({ name: 'previous_credential_key_id', type: 'text', nullable: true, unique: true })
  previousCredentialKeyId!: string | null;

  @Column({ name: 'previous_credential_hash', type: 'text', nullable: true })
  previousCredentialHash!: string | null;

  @tsColumn('previous_credential_expires_at', true)
  previousCredentialExpiresAt!: string | null;

  @tsColumn('previous_credential_last_used_at', true)
  previousCredentialLastUsedAt!: string | null;

  @Column({ name: 'status', type: 'text' })
  status!: AgentStatus;

  @tsColumn('last_access_at', true)
  lastAccessAt!: string | null;

  @tsColumn('created_at')
  createdAt!: string;
}
