import { LessThan } from 'typeorm';
import { db, type Executor } from '../../databases/client';
import { UserLoginsEntity } from '../../entities';
import { sha256Hex } from '../../lib/crypto';
import type { SessionRecord } from '../types';
import { deleteBy, insertRow, oneBy, updateBy } from './orm';

/**
 * Admin sessions (template: user_logins) persisted in Postgres so they survive restarts. The
 * token is a JWT; only its SHA-256 is stored, so a database dump does not contain usable sessions.
 */
const hash = (token: string) => sha256Hex(token);

export async function createSession(token: string, userId: string, organizationId: string | null, ttlMs: number, ex: Executor = db): Promise<SessionRecord> {
  const now = Date.now();
  const tokenHash = hash(token);
  return insertRow(ex, UserLoginsEntity, { tokenHash, userId, organizationId, createdAt: new Date(now).toISOString(), expiresAt: new Date(now + ttlMs).toISOString() }, { tokenHash });
}

export async function getSession(token: string, ex: Executor = db): Promise<SessionRecord | null> {
  return oneBy(ex, UserLoginsEntity, { tokenHash: hash(token) });
}

export async function setSessionOrganization(tokenHash: string, organizationId: string, ex: Executor = db) {
  await updateBy(ex, UserLoginsEntity, { tokenHash }, { organizationId });
}

export async function deleteSession(token: string, ex: Executor = db) {
  await deleteBy(ex, UserLoginsEntity, { tokenHash: hash(token) });
}

export async function purgeExpiredSessions(ex: Executor = db) {
  await ex.delete(UserLoginsEntity, { expiresAt: LessThan(new Date().toISOString()) });
}
