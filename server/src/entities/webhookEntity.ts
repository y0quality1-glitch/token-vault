import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { Environment, HealthCheckResult, WebhookAuthType, WebhookStatus } from '@token-vault/shared';
import { tsColumn } from './columns';

/** Table `webhooks` (see the baseline migration for constraints, indexes and triggers). */
@Entity('webhooks')
export class WebhookEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'name', type: 'text' })
  name!: string;

  @Column({ name: 'endpoint_url', type: 'text' })
  endpointUrl!: string;

  @Column({ name: 'environment', type: 'text' })
  environment!: Environment;

  @Column({ name: 'description', type: 'text', default: '' })
  description!: string;

  @Column({ name: 'authentication_type', type: 'text' })
  authenticationType!: WebhookAuthType;

  /** Name of the env var holding the signing secret. Never the value. */
  @Column({ name: 'signing_secret_ref', type: 'text' })
  signingSecretRef!: string;

  @Column({ name: 'status', type: 'text' })
  status!: WebhookStatus;

  @Column({ name: 'instance_id', type: 'text', nullable: true })
  instanceId!: string | null;

  @Column({ name: 'software_version', type: 'text', nullable: true })
  softwareVersion!: string | null;

  @tsColumn('last_heartbeat_at', true)
  lastHeartbeatAt!: string | null;

  @Column({ name: 'last_error', type: 'text', nullable: true })
  lastError!: string | null;

  @Column({ name: 'simulate_outage', type: 'boolean', default: false })
  simulateOutage!: boolean;

  @Column({ name: 'registration_challenge', type: 'text', nullable: true })
  registrationChallenge!: string | null;

  @Column({ name: 'health_history', type: 'jsonb', default: () => "'[]'::jsonb" })
  healthHistory!: HealthCheckResult[];

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('verified_at', true)
  verifiedAt!: string | null;
}
