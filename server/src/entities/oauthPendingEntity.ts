import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './columns';

/** Table `oauth_pending` (see the baseline migration for constraints, indexes and triggers). */
@Entity('oauth_pending')
export class OauthPendingEntity extends BaseEntity {
  @PrimaryColumn({ name: 'state_hash', type: 'text' })
  stateHash!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'user_id', type: 'text' })
  userId!: string;

  @Column({ name: 'webhook_id', type: 'text' })
  webhookId!: string;

  @Column({ name: 'credential_reference', type: 'text' })
  credentialReference!: string;

  @Column({ name: 'draft', type: 'jsonb' })
  draft!: Record<string, unknown>;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('expires_at')
  expiresAt!: string;
}
