import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './columns';

/** Table `slack_settings` (see the baseline migration for constraints, indexes and triggers). */
@Entity('slack_settings')
export class SlackSettingsEntity extends BaseEntity {
  @PrimaryColumn({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'team_id', type: 'text' })
  teamId!: string;

  @Column({ name: 'team_name', type: 'text' })
  teamName!: string;

  @Column({ name: 'bot_user_id', type: 'text' })
  botUserId!: string;

  @Column({ name: 'channel_id', type: 'text' })
  channelId!: string;

  @Column({ name: 'bot_token_sealed', type: 'text' })
  botTokenSealed!: string;

  @Column({ name: 'bot_token_hint', type: 'text' })
  botTokenHint!: string;

  @Column({ name: 'signing_secret_sealed', type: 'text' })
  signingSecretSealed!: string;

  @Column({ name: 'enabled', type: 'boolean', default: true })
  enabled!: boolean;

  @tsColumn('updated_at')
  updatedAt!: string;

  @Column({ name: 'updated_by', type: 'text' })
  updatedBy!: string;
}
