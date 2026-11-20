import type { DataSource, EntityManager } from 'typeorm';
import { databaseError } from '@token-vault/shared';
import { config } from '../config';
import { getPostgresConnection } from './dataSource';

/**
 * Database singleton (template: databases/database.ts): connect once, run migrations, raw
 * queries and transactions. Connecting and migrating are awaited before the server listens
 * (template fix B-06).
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
    const ds = getPostgresConnection();
    try {
      await ds.initialize();
    } catch (e) {
      throw databaseError(e, config.databaseUrl);
    }
    this.postgresConnection = ds;
  }

  /** Applies pending migrations, each in its own transaction. Returns their names. */
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
