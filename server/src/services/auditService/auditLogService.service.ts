import { type IntegrityReport } from '@token-vault/shared';
import { config } from '../../config';
import { notFound } from '../../lib/errors';
import { auditRepo } from '../../store/repos';
import { verify, type ChainTable } from './chain';

type Filters = Record<string, unknown>;

/** A non-empty string filter value, otherwise undefined (non-strings are ignored, as before). */
const q = (v: unknown) => (typeof v === 'string' && v.length > 0 ? v : undefined);
/** A parseable date as ISO 8601, otherwise undefined. */
const isoOrUndefined = (v: unknown) => {
  const s = q(v);
  if (!s) return undefined;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
};
/** Page size: default 200, at most 500. */
const limitOf = (v: unknown) => Math.min(Number(v ?? 200) || 200, 500);

/** Audit log: access requests (every agent request and its decision), audit events, and the integrity of both hash chains. */
export default class AuditLogService {
  listAccessRequests(orgId: string, f: Filters = {}) {
    return auditRepo.listAccessRequests(
      orgId,
      { agentId: q(f.agentId), integrationId: q(f.integrationId), grantId: q(f.grantId), decision: q(f.decision), operation: q(f.operation), from: isoOrUndefined(f.from), to: isoOrUndefined(f.to), search: q(f.search), user: q(f.user), sessionId: q(f.sessionId) },
      limitOf(f.limit),
    );
  }

  /** An access request with the audit events of the same correlation id. */
  async getAccessRequest(orgId: string, id: string) {
    const item = await auditRepo.getAccessRequest(orgId, id);
    if (!item) throw notFound('Access request');
    const auditEvents = await auditRepo.auditEventsByCorrelation(orgId, item.correlationId);
    return { ...item, auditEvents };
  }

  listAuditEvents(orgId: string, f: Filters = {}) {
    return auditRepo.listAuditEvents(
      orgId,
      { securityOnly: f.category === 'security', actorType: q(f.actorType), eventType: q(f.eventType), outcome: q(f.outcome), targetId: q(f.targetId), from: isoOrUndefined(f.from), to: isoOrUndefined(f.to), search: q(f.search) },
      limitOf(f.limit),
    );
  }

  async getAuditEvent(orgId: string, id: string) {
    const item = await auditRepo.getAuditEvent(orgId, id);
    if (!item) throw notFound('Audit event');
    return item;
  }

  /** Verifies both audit hash chains for the organization (signatures checked with a key outside the database). */
  async verifyIntegrity(orgId: string): Promise<IntegrityReport> {
    const tables: ChainTable[] = ['audit_events', 'access_requests'];
    const chains = await Promise.all(
      tables.map(async (table) => {
        const { rows, legacy } = await auditRepo.chainRows(table, orgId);
        return verify(config.auditSigningKey, table, orgId, rows, legacy);
      }),
    );
    return { ok: chains.every((c) => c.ok), verifiedAt: new Date().toISOString(), chains };
  }
}
