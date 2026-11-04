import { lt, sql } from 'drizzle-orm';
import { db } from '../db/client';
import { usedNonces } from '../db/schema';
import type { NonceStore } from './signature';

/**
 * PostgreSQL-backed replay cache shared by all webhook instances. A nonce is accepted
 * once until it expires. An expired row may be reused (the ON CONFLICT … WHERE clause),
 * so the table never needs to be cleaned for correctness; cleanup only bounds its size.
 */
export class PgNonceStore implements NonceStore {
  private lastPurge = 0;

  constructor(private ttlMs: number) {}

  async use(nonce: string, now = Date.now()): Promise<boolean> {
    const expiresAt = new Date(now + this.ttlMs).toISOString();
    const rows = await db
      .insert(usedNonces)
      .values({ nonce, expiresAt })
      .onConflictDoUpdate({
        target: usedNonces.nonce,
        set: { expiresAt },
        setWhere: sql`${usedNonces.expiresAt} < ${new Date(now).toISOString()}`,
      })
      .returning({ nonce: usedNonces.nonce });
    if (now - this.lastPurge > 60_000) {
      this.lastPurge = now;
      void db
        .delete(usedNonces)
        .where(lt(usedNonces.expiresAt, new Date(now).toISOString()))
        .catch(() => undefined);
    }
    return rows.length === 1;
  }
}
