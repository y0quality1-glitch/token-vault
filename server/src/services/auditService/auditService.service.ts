import type { AccessRequest, AuditEvent, AuditActorType, AuditOutcome } from '@token-vault/shared';
import { db, type Executor } from '../../databases/client';
import { correlationId as newCorrelationId, newId } from '../../lib/ids';
import { sanitize } from '../../lib/sanitize';
import { auditRepo } from '../../store/repos';
import type { AdminContext } from '../../types/express';

export interface Actor {
  type: AuditActorType;
  id: string;
  name: string;
}

export function userActor(ctx: Pick<AdminContext, 'user'>): Actor {
  return { type: 'USER', id: ctx.user.id, name: ctx.user.fullName };
}

export const SYSTEM_ACTOR: Actor = { type: 'SYSTEM', id: 'system', name: 'Token Vault' };

/**
 * Append-only audit log. Metadata is sanitized so secrets cannot be persisted even by
 * mistake. Pass the transaction executor to write the event atomically with the change
 * it describes.
 */
export async function recordEvent(
  input: {
    orgId: string;
    actor: Actor;
    eventType: string;
    target: { type: string; id: string; name: string };
    outcome?: AuditOutcome;
    severity?: AuditEvent['severity'];
    metadata?: Record<string, unknown>;
    correlationId?: string;
  },
  ex: Executor = db,
): Promise<AuditEvent> {
  return auditRepo.insertAuditEvent(
    {
      id: newId('evt'),
      organizationId: input.orgId,
      actorType: input.actor.type,
      actorId: input.actor.id,
      actorName: input.actor.name,
      eventType: input.eventType,
      targetType: input.target.type,
      targetId: input.target.id,
      targetName: input.target.name,
      outcome: input.outcome ?? 'SUCCESS',
      severity: input.severity ?? 'info',
      metadata: sanitize(input.metadata ?? {}),
      correlationId: input.correlationId ?? newCorrelationId(),
      createdAt: new Date().toISOString(),
    },
    ex,
  );
}

export async function recordAccessRequest(req: AccessRequest, ex: Executor = db): Promise<AccessRequest> {
  return auditRepo.insertAccessRequest(sanitize(req), ex);
}
