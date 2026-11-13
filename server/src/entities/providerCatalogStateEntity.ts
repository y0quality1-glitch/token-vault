import { BaseEntity, Column, Entity, PrimaryColumn } from 'typeorm';
import { tsColumn } from './columns';

/** Table `provider_catalog_state` (see the baseline migration for constraints, indexes and triggers). */
@Entity('provider_catalog_state')
export class ProviderCatalogStateEntity extends BaseEntity {
  @PrimaryColumn({ name: 'id', type: 'integer' })
  id!: number;

  @Column({ name: 'envelopes', type: 'jsonb' })
  envelopes!: unknown;

  @Column({ name: 'high_water', type: 'jsonb' })
  highWater!: Record<string, number>;

  @tsColumn('saved_at')
  savedAt!: string;
}
