import type { SelectQueryBuilder } from 'typeorm';
import type { AuditEvent } from '@token-vault/shared';
import type { Pagination } from '../../core/Y0Params';
import { AuditEventEntity } from '../../entities';
import { BaseServices } from '../baseService';
import { isoOrUndefined, pageBody } from '../auditService/filters';

/**
 * Audit events (Audit → Security events), newest first. Filters: category ("security": all but
 * routine allowed requests), actorType, eventType (prefix), outcome, targetId, from, to, plus
 * `search`; the old `limit` (default 200, at most 500) still sets the page size.
 */
export default class AuditEventService extends BaseServices<AuditEventEntity, AuditEvent> {
  constructor() {
    super(AuditEventEntity);
  }
  getModuleName() {
    return 'Audit event';
  }
  getGlobalSearchColumns() {
    return ['main.id', 'main.correlation_id', 'main.actor_name', 'main.target_name', 'main.event_type'];
  }

  protected applyFilters(qb: SelectQueryBuilder<AuditEventEntity>, { filters: f }: Pagination) {
    if (f.category === 'security') qb.andWhere(`main.event_type <> 'access.allowed'`);
    if (f.actorType) qb.andWhere('main.actor_type = :actorType', { actorType: f.actorType });
    if (f.eventType) qb.andWhere('main.event_type LIKE :eventType', { eventType: `${f.eventType.replace(/[\\%_]/g, (c) => `\\${c}`)}%` });
    if (f.outcome) qb.andWhere('main.outcome = :outcome', { outcome: f.outcome });
    if (f.targetId) qb.andWhere('main.target_id = :targetId', { targetId: f.targetId });
    const from = isoOrUndefined(f.from);
    const to = isoOrUndefined(f.to);
    if (from) qb.andWhere('main.created_at >= :from', { from });
    if (to) qb.andWhere('main.created_at <= :to', { to });
    return qb;
  }

  async list(orgId: string, body: unknown = {}) {
    const { records, totalRecords } = await this.getAll(orgId, pageBody(body));
    return { items: records, total: totalRecords };
  }
}
