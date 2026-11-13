import { Column, Entity } from 'typeorm';
import type { VersionStatus } from '@token-vault/shared';
import { Y0Entity, tsColumn } from './y0Entity';

/**
 * A version of an application's definition. At most one open (DRAFT or IN_REVIEW) and one
 * PUBLISHED version per application (partial unique indexes); published versions are
 * immutable and never deleted (database trigger). See the baseline migration.
 */
@Entity('application_versions')
export class VersionEntity extends Y0Entity {
  @Column({ name: 'application_id', type: 'text' })
  application_id!: string;

  @Column({ type: 'integer' })
  version!: number;

  @Column({ type: 'text' })
  status!: VersionStatus;

  /** The definition as edited (may be invalid while DRAFT). Frozen once published. */
  @Column({ type: 'jsonb' })
  definition!: unknown;

  /** Set on publication: sha256 of the canonical definition, and its Ed25519 signature. */
  @Column({ type: 'text', nullable: true })
  digest!: string | null;

  @Column({ type: 'text', nullable: true })
  signature!: string | null;

  @Column({ name: 'key_id', type: 'text', nullable: true })
  key_id!: string | null;

  @Column({ name: 'created_by', type: 'text' })
  created_by!: string;

  @tsColumn('updated_at')
  updated_at!: string;

  /** Everyone who created or edited this version; none of them may approve it. */
  @Column({ type: 'text', array: true, default: () => "'{}'::text[]" })
  authors!: string[];

  @Column({ name: 'submitted_by', type: 'text', nullable: true })
  submitted_by!: string | null;

  @tsColumn('submitted_at', true)
  submitted_at!: string | null;

  @Column({ name: 'reviewed_by', type: 'text', nullable: true })
  reviewed_by!: string | null;

  @tsColumn('reviewed_at', true)
  reviewed_at!: string | null;

  @Column({ name: 'review_note', type: 'text', nullable: true })
  review_note!: string | null;

  @tsColumn('published_at', true)
  published_at!: string | null;

  @Column({ name: 'host_change_acknowledged', type: 'boolean', default: false })
  host_change_acknowledged!: boolean;
}
