import { eq, lt } from 'drizzle-orm';
import { db, type Executor } from '../../db/client';
import { sessions } from '../../db/schema';
import { sha256Hex } from '../../lib/crypto';
import type { SessionRecord } from '../types';

/**
 * Admin sessions persisted in Postgres so they survive restarts. Only the SHA-256
 * of the cookie token is stored: a database dump does not contain usable sessions.
 */
const hash = (token: string) => sha256Hex(token);

export async function createSession(token: string, userId: string, organizationId: string | null, ttlMs: number, ex: Executor = db): Promise<SessionRecord> {
  const now = Date.now();
  const [row] = await ex
    .insert(sessions)
    .values({ tokenHash: hash(token), userId, organizationId, createdAt: new Date(now).toISOString(), expiresAt: new Date(now + ttlMs).toISOString() })
    .returning();
  return row!;
}

export async function getSession(token: string, ex: Executor = db): Promise<SessionRecord | null> {
  const [row] = await ex.select().from(sessions).where(eq(sessions.tokenHash, hash(token)));
  return row ?? null;
}

export async function setSessionOrganization(tokenHash: string, organizationId: string, ex: Executor = db) {
  await ex.update(sessions).set({ organizationId }).where(eq(sessions.tokenHash, tokenHash));
}

export async function deleteSession(token: string, ex: Executor = db) {
  await ex.delete(sessions).where(eq(sessions.tokenHash, hash(token)));
}

export async function purgeExpiredSessions(ex: Executor = db) {
  await ex.delete(sessions).where(lt(sessions.expiresAt, new Date().toISOString()));
}
