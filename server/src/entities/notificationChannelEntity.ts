import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { NotificationChannelKind, NotificationDeliveryStatus, NotificationScope, SecretNotificationEvent, SecretNotificationPayload } from '@token-vault/shared';
import { tsColumn } from './columns';

/**
 * Table `notification_channels` (spec 4.9.18): where an organization hears about secret
 * lifecycle events: email recipients, an outbound webhook (signed; its signing secret sealed
 * with the settings key) or the organization's Slack connection.
 */
@Entity('notification_channels')
export class NotificationChannelEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'name', type: 'text' })
  name!: string;

  @Column({ name: 'kind', type: 'text' })
  kind!: NotificationChannelKind;

  @Column({ name: 'enabled', type: 'boolean', default: true })
  enabled!: boolean;

  @Column({ name: 'events', type: 'jsonb', default: () => "'[]'::jsonb" })
  events!: SecretNotificationEvent[];

  @Column({ name: 'scope', type: 'jsonb', default: () => "'{}'::jsonb" })
  scope!: NotificationScope;

  @Column({ name: 'recipients', type: 'jsonb', default: () => "'[]'::jsonb" })
  recipients!: string[];

  @Column({ name: 'url', type: 'text', nullable: true })
  url!: string | null;

  @Column({ name: 'signing_secret_sealed', type: 'text', nullable: true })
  signingSecretSealed!: string | null;

  @Column({ name: 'signing_secret_hint', type: 'text', nullable: true })
  signingSecretHint!: string | null;

  @Column({ name: 'slack_channel_id', type: 'text', nullable: true })
  slackChannelId!: string | null;

  @Column({ name: 'created_by', type: 'text' })
  createdBy!: string;

  @Column({ name: 'created_by_name', type: 'text' })
  createdByName!: string;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('updated_at')
  updatedAt!: string;
}

/** Table `notification_deliveries`: one event for one channel, retried with backoff until delivered or given up. */
@Entity('notification_deliveries')
export class NotificationDeliveryEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'channel_id', type: 'text' })
  channelId!: string;

  @Column({ name: 'event', type: 'text' })
  event!: SecretNotificationPayload['event'];

  @Column({ name: 'secret_id', type: 'text', nullable: true })
  secretId!: string | null;

  @Column({ name: 'payload', type: 'jsonb' })
  payload!: SecretNotificationPayload;

  @Column({ name: 'status', type: 'text' })
  status!: NotificationDeliveryStatus;

  @Column({ name: 'attempts', type: 'integer', default: 0 })
  attempts!: number;

  @Column({ name: 'last_error', type: 'text', nullable: true })
  lastError!: string | null;

  @tsColumn('next_attempt_at', true)
  nextAttemptAt!: string | null;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('delivered_at', true)
  deliveredAt!: string | null;
}
