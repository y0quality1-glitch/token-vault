import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import type { CertificateKeyAlgorithm, CertificateRequestStatus } from '@token-vault/shared';
import { tsColumn } from './columns';

/**
 * Table `certificate_requests` (spec 4.9.3 F): a certificate renewal. The customer webhook made a
 * new key pair and keeps the private key encrypted under this request's id (`request_ref`); this
 * table holds only the CSR (public) and the outcome.
 */
@Entity('certificate_requests')
export class CertificateRequestEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'text' })
  id!: string;

  @Column({ name: 'organization_id', type: 'text' })
  organizationId!: string;

  @Column({ name: 'secret_id', type: 'text' })
  secretId!: string;

  @Column({ name: 'status', type: 'text' })
  status!: CertificateRequestStatus;

  @Column({ name: 'key_algorithm', type: 'text' })
  keyAlgorithm!: CertificateKeyAlgorithm;

  @Column({ name: 'subject', type: 'text' })
  subject!: string;

  @Column({ name: 'subject_alt_names', type: 'jsonb', default: () => "'[]'::jsonb" })
  subjectAltNames!: string[];

  @Column({ name: 'csr', type: 'text' })
  csr!: string;

  /** The pending key's value on the webhook (null once used or destroyed). */
  @Column({ name: 'request_ref', type: 'text', nullable: true })
  requestRef!: string | null;

  @Column({ name: 'created_by', type: 'text' })
  createdBy!: string;

  @Column({ name: 'created_by_name', type: 'text' })
  createdByName!: string;

  @tsColumn('created_at')
  createdAt!: string;

  @tsColumn('expires_at')
  expiresAt!: string;

  @tsColumn('completed_at', true)
  completedAt!: string | null;

  @Column({ name: 'completed_version', type: 'integer', nullable: true })
  completedVersion!: number | null;

  @Column({ name: 'issuer_secret_id', type: 'text', nullable: true })
  issuerSecretId!: string | null;

  @Column({ name: 'issuer_name', type: 'text', nullable: true })
  issuerName!: string | null;

  @Column({ name: 'cancelled_reason', type: 'text', nullable: true })
  cancelledReason!: string | null;
}
