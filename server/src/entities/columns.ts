import { Column, type ValueTransformer } from 'typeorm';

/**
 * Column helpers. Types are always written out (tsx/esbuild do not emit decorator metadata).
 * Timestamps are `timestamp(3) with time zone` in the database and ISO-8601 strings in
 * TypeScript, matching the domain types shared with the console.
 */
export const isoTimestamp: ValueTransformer = {
  to: (v: string | Date | null | undefined) => v,
  from: (v: Date | string | null) => (v == null ? null : (v instanceof Date ? v : new Date(v)).toISOString()),
};

export const tsColumn = (name: string, nullable = false) => Column({ name, type: 'timestamptz', precision: 3, nullable, transformer: isoTimestamp });

/** bigint columns hold sequence numbers well inside Number's range; the driver returns strings. */
export const bigintNumber: ValueTransformer = {
  to: (v: number | null | undefined) => v,
  from: (v: string | number | null) => (v == null ? null : Number(v)),
};
