import type { DataSource, EntityManager } from 'typeorm';
import { databaseError } from '@token-vault/shared';
import { DB_URL } from '../config';
import { getPostgresConnection } from './dataSource';

/**
 * Database singleton (template: databases/database.ts): connect once, run migrations, raw
 * queries and transactions. Connecting is awaited before the server listens (template fix B-06).
 */
class AppDatabase {
  private static instance: AppDatabase;
  private postgresConnection: DataSource | null = null;

  static getInstance(): AppDatabase {
    if (!AppDatabase.instance) AppDatabase.instance = new AppDatabase();
    return AppDatabase.instance;
  }

  async connectToDB(): Promise<void> {
    if (this.postgresConnection?.isInitialized) return;
    this.postgresConnection = getPostgresConnection();
    try {
      await this.postgresConnection.initialize();
    } catch (e) {
      this.postgresConnection = null;
      throw databaseError(e, DB_URL);
    }
  }

  /** Applies pending migrations, each in its own transaction. */
  async runMigrations(): Promise<string[]> {
    const ran = await this.dataSource.runMigrations({ transaction: 'each' });
    return ran.map((m) => m.name);
  }

  get dataSource(): DataSource {
    if (!this.postgresConnection?.isInitialized) throw new Error('Database connection not established');
    return this.postgresConnection;
  }

  get manager(): EntityManager {
    return this.dataSource.manager;
  }

  async executeExternalQuery<T = unknown>(query: string, params: unknown[] = []): Promise<T> {
    return this.manager.query(query, params);
  }

  async executeInTransaction<T>(callback: (manager: EntityManager) => Promise<T>): Promise<T> {
    return this.dataSource.transaction(callback);
  }

  async close(): Promise<void> {
    if (this.postgresConnection?.isInitialized) await this.postgresConnection.destroy();
    this.postgresConnection = null;
  }
}

export default AppDatabase;

/** Log-safe error text: ORM errors embed SQL parameters in `message`; prefer the driver's. */
export function describeError(err: unknown): string {
  const e = err as Error & { driverError?: Error & { code?: string }; cause?: Error & { code?: string } };
  const inner = e?.driverError ?? e?.cause;
  if (inner?.message) return `${inner.code ?? ''} ${inner.message}`.trim();
  return e?.message ?? String(err);
}
