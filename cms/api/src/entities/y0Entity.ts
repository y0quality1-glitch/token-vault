import { BaseEntity, Column, PrimaryColumn, type ValueTransformer } from 'typeorm';

/**
 * timestamp(3) with time zone, exposed as ISO-8601 strings (what the API returns).
 * Column types are always written out: tsx/esbuild do not emit decorator type metadata.
 */
export const isoTimestamp: ValueTransformer = {
  to: (v: string | Date | null | undefined) => v,
  from: (v: Date | string | null) => (v == null ? null : new Date(v).toISOString()),
};

export const tsColumn = (name: string, nullable = false) => Column({ name, type: 'timestamptz', precision: 3, nullable, transformer: isoTimestamp });

/**
 * Base entity (template: entities/y0Entity.ts). Ids are prefixed text (`app_…`, `ver_…`),
 * as everywhere in Token Vault, rather than integers.
 */
export abstract class Y0Entity extends BaseEntity {
  @PrimaryColumn({ type: 'text' })
  id!: string;

  @tsColumn('created_at')
  created_at!: string;
}
