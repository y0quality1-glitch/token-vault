import { resolve } from 'node:path';
import pg from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { config } from '../config';
import * as schema from './schema';

export const pool = new pg.Pool({ connectionString: config.databaseUrl, max: config.dbPoolMax });
pool.on('error', (err) => console.error('[vault] idle database client error:', describeError(err)));

export const db = drizzle(pool, { schema });

export async function runMigrations() {
  await migrate(db, { migrationsFolder: resolve(import.meta.dirname, '../../drizzle') });
}

export async function closeDatabase() {
  await pool.end();
}

/**
 * Log-safe error text. ORM errors embed SQL parameter values (which here include
 * ciphertext) in `message`; the driver's own message lives in `cause`, so prefer it.
 */
export function describeError(err: unknown): string {
  const e = err as Error & { cause?: Error & { code?: string } };
  if (e?.cause?.message) return `${e.cause.code ?? ''} ${e.cause.message}`.trim();
  return e?.message ?? String(err);
}
