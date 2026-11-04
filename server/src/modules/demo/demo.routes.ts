import { Router } from 'express';
import { and, desc, eq, isNotNull, sql } from 'drizzle-orm';
import { transaction } from '../../db/client';
import { auditEvents } from '../../db/schema';
import { HttpError } from '../../lib/errors';
import { PERMISSIONS } from '@token-vault/shared';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { resetDatabase } from '../../store/seed';
import { recordEvent, userActor } from '../audit/audit.service';
import { resetBrokerState } from '../broker/broker.service';
import { syncSeedCredentialMetadata } from '../webhooks/webhook.service';

export const demoRouter = Router();

/** Restores the seeded demonstration state atomically. Sessions are preserved (seed IDs are stable). */
demoRouter.post('/demo/reset', requirePermission(PERMISSIONS.DEMO_RESET), async (req, res) => {
  const ctx = orgCtx(req);
  await resetDatabase();
  resetBrokerState();
  await syncSeedCredentialMetadata();
  await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'demo.reset', target: { type: 'organization', id: ctx.org.id, name: ctx.org.name }, severity: 'warning' });
  res.json({ ok: true });
});

/**
 * Demo only: simulates an attacker with database write access editing the newest chained
 * audit event. It bypasses the append-only trigger (as a table owner could) to show that the
 * hash chain still detects the change. Owner only, and itself audited.
 */
demoRouter.post('/demo/tamper-audit', requirePermission(PERMISSIONS.DEMO_RESET), async (req, res) => {
  const ctx = orgCtx(req);
  const target = await transaction(async (tx) => {
    const [row] = await tx
      .select({ id: auditEvents.id, seq: auditEvents.seq, actorName: auditEvents.actorName })
      .from(auditEvents)
      .where(and(eq(auditEvents.organizationId, ctx.org.id), isNotNull(auditEvents.seq)))
      .orderBy(desc(auditEvents.seq))
      .limit(1);
    if (!row) throw new HttpError(409, 'NOTHING_TO_TAMPER', 'This organization has no chained audit events yet');
    await tx.execute(sql`ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only`);
    await tx.execute(sql`UPDATE audit_events SET actor_name = ${row.actorName + ' [edited in database]'} WHERE id = ${row.id}`);
    await tx.execute(sql`ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only`);
    return row;
  });
  await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'demo.audit_tampered', target: { type: 'audit_event', id: target.id, name: `audit record #${target.seq}` }, severity: 'critical', metadata: { simulated: true, seq: target.seq } });
  res.json({ ok: true, tamperedEventId: target.id, seq: target.seq });
});
