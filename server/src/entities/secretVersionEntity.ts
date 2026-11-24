import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { CertificateInfo, SecretVersionState } from '@token-vault/shared';
import { tsColumn } from './columns';

/**
 * Table `secret_versions` (spec 4.9.8): one row per value a secret has had. `value_ref` points
 * at the encrypted value on the customer webhook (null once destroyed); `summary` is the masked
 * view the webhook returned (sensitive fields fully masked). Never a value.
 */
@Entity('secret_versions')
export class SecretVersionEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'secret_id', type: 'text' })
  secretId!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'version', type: 'integer' })
  version!: number;

  @Column({ name: 'value_ref', type: 'text', nullable: true })
  valueRef!: string | null;

  @Column({ name: 'fingerprint', type: 'text' })
  fingerprint!: string;

  @Column({ name: 'summary', type: 'jsonb', default: () => "'{}'::jsonb" })
  summary!: Record<string, string>;

  @Column({ name: 'type_version', type: 'integer' })
  typeVersion!: number;

  @Column({ name: 'state', type: 'text' })
  state!: SecretVersionState;

  @Column({ name: 'reason', type: 'text', default: '' })
  reason!: string;

  @Column({ name: 'copied_from', type: 'integer', nullable: true })
  copiedFrom!: number | null;

  @Column({ name: 'created_by', type: 'text' })
  createdBy!: string;

  @Column({ name: 'created_by_name', type: 'text' })
  createdByName!: string;

  @tsColumn('created_at')
  createdAt!: string;

  /** When a newer version became active (retention and the rotation grace period count from here). */
  @tsColumn('superseded_at', true)
  supersededAt!: string | null;

  @tsColumn('destroyed_at', true)
  destroyedAt!: string | null;

  /** Key types: false once this version is deactivated (no operations); null for other types. */
  @Column({ name: 'key_enabled', type: 'boolean', nullable: true })
  keyEnabled!: boolean | null;

  /** Certificate types: what the certificate says (public; read by the webhook when stored). */
  @Column({ name: 'certificate', type: 'jsonb', nullable: true })
  certificate!: CertificateInfo | null;
}
