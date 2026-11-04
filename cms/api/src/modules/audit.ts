import { desc, eq } from 'drizzle-orm';
import { Router } from 'express';
import type { CmsAuditEvent, CmsUser } from '@token-vault/shared';
import { db, type Executor } from '../db/client';
import { auditEvents } from '../db/schema';

export type Actor = Pick<CmsUser, 'id' | 'fullName'>;
export const SYSTEM_ACTOR: Actor = { id: 'system', fullName: 'System' };

/** Appends one audit event (the table rejects UPDATE and DELETE). */
export async function audit(ex: Executor, actor: Actor, action: string, target: { key?: string; version?: number } = {}, details: Record<string, unknown> = {}) {
  await ex.insert(auditEvents).values({
    at: new Date().toISOString(),
    actorId: actor.id,
    actorName: actor.fullName,
    action,
    applicationKey: target.key ?? null,
    version: target.version ?? null,
    details,
  });
}

export const auditRouter = Router();

auditRouter.get('/audit', async (req, res) => {
  const key = typeof req.query.application === 'string' ? req.query.application : undefined;
  const rows = await db
    .select()
    .from(auditEvents)
    .where(key ? eq(auditEvents.applicationKey, key) : undefined)
    .orderBy(desc(auditEvents.id))
    .limit(200);
  const items: CmsAuditEvent[] = rows.map((r) => ({ id: r.id, at: r.at, actorName: r.actorName, action: r.action, applicationKey: r.applicationKey, version: r.version, details: r.details }));
  res.json({ items });
});
