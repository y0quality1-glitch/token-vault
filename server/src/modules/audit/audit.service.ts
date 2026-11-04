import type { AccessRequest, AuditEvent, AuditActorType, AuditOutcome } from '@token-vault/shared';
import { correlationId as newCorrelationId, newId } from '../../lib/ids';
import { sanitize } from '../../lib/sanitize';
import { db } from '../../store/db';
import type { AdminContext } from '../../types/express';

export interface Actor {
  type: AuditActorType;
  id: string;
  name: string;
}

export function userActor(ctx: AdminContext): Actor {
  return { type: 'USER', id: ctx.user.id, name: ctx.user.fullName };
}

export const SYSTEM_ACTOR: Actor = { type: 'SYSTEM', id: 'system', name: 'Token Vault' };

/**
 * Append-only audit log. Records are never updated or deleted through the API;
 * metadata is sanitized so secrets cannot be persisted even by mistake.
 */
export function recordEvent(input: {
  orgId: string;
  actor: Actor;
  eventType: string;
  target: { type: string; id: string; name: string };
  outcome?: AuditOutcome;
  severity?: AuditEvent['severity'];
  metadata?: Record<string, unknown>;
  correlationId?: string;
}): AuditEvent {
  const event: AuditEvent = Object.freeze({
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
  });
  db.auditEvents.unshift(event);
  return event;
}

export function recordAccessRequest(req: AccessRequest): AccessRequest {
  const frozen = Object.freeze(sanitize(req));
  db.accessRequests.unshift(frozen);
  return frozen;
}
