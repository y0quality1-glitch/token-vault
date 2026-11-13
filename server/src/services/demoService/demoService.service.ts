import { transaction } from '../../databases/client';
import { HttpError } from '../../lib/errors';
import { resetDatabase } from '../../store/seed';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';
import { resetBrokerState } from '../brokerService/brokerService.service';
import { syncSeedCredentialMetadata } from '../webhookService/webhookService.service';

type OrgContext = AdminContext & { org: { id: string; name: string } };

/** Demonstration controls. */
export default class DemoService {
  /** Restores the seeded demonstration state atomically. Sessions are preserved (seed IDs are stable). */
  async reset(ctx: OrgContext) {
    await resetDatabase();
    resetBrokerState();
    await syncSeedCredentialMetadata();
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'demo.reset', target: { type: 'organization', id: ctx.org.id, name: ctx.org.name }, severity: 'warning' });
    return { ok: true };
  }

  /**
   * Demo only: simulates an attacker with database write access editing the newest chained
   * audit event. It bypasses the append-only trigger (as a table owner could) to show that the
   * hash chain still detects the change. Owner only, and itself audited.
   */
  async tamperAudit(ctx: OrgContext) {
    const target = await transaction(async (tx) => {
      const [raw]: { id: string; seq: string; actor_name: string }[] = await tx.query(
        'SELECT id, seq, actor_name FROM audit_events WHERE organization_id = $1 AND seq IS NOT NULL ORDER BY seq DESC LIMIT 1',
        [ctx.org.id],
      );
      if (!raw) throw new HttpError(409, 'NOTHING_TO_TAMPER', 'This organization has no chained audit events yet');
      const row = { id: raw.id, seq: Number(raw.seq), actorName: raw.actor_name };
      await tx.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only');
      await tx.query('UPDATE audit_events SET actor_name = $1 WHERE id = $2', [row.actorName + ' [edited in database]', row.id]);
      await tx.query('ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only');
      return row;
    });
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'demo.audit_tampered', target: { type: 'audit_event', id: target.id, name: `audit record #${target.seq}` }, severity: 'critical', metadata: { simulated: true, seq: target.seq } });
    return { ok: true, tamperedEventId: target.id, seq: target.seq };
  }
}
