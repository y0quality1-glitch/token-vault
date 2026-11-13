import type { SelectQueryBuilder } from 'typeorm';
import type { AccessRequest } from '@token-vault/shared';
import { AccessRequestEntity } from '../../entities';
import { auditRepo } from '../../store/repos';
import type { Pagination } from '../../core/Y0Params';
import { BaseServices } from '../baseService';
import { isoOrUndefined, pageBody } from '../auditService/filters';

/**
 * The access log (Audit → Access logs): every agent request and its decision, newest first.
 * Filters: agentId, integrationId, grantId, decision, operation, from, to, user, sessionId, plus
 * `search`; the old `limit` (default 200, at most 500) still sets the page size.
 */
export default class AccessRequestService extends BaseServices<AccessRequestEntity, AccessRequest> {
  constructor() {
    super(AccessRequestEntity);
  }
  getModuleName() {
    return 'Access request';
  }
  getGlobalSearchColumns() {
    return ['main.id', 'main.correlation_id', 'main.agent_name', 'main.integration_name', 'main.decision_code', "main.on_behalf_of->>'sub'", "main.on_behalf_of->>'email'"];
  }

  protected applyFilters(qb: SelectQueryBuilder<AccessRequestEntity>, { filters: f }: Pagination) {
    if (f.agentId) qb.andWhere('main.agent_id = :agentId', { agentId: f.agentId });
    if (f.integrationId) qb.andWhere('main.integration_id = :integrationId', { integrationId: f.integrationId });
    if (f.grantId) qb.andWhere('main.grant_id = :grantId', { grantId: f.grantId });
    if (f.decision === 'ALLOW' || f.decision === 'DENY') qb.andWhere('main.decision = :decision', { decision: f.decision });
    if (f.operation) qb.andWhere('main.operation = :operation', { operation: f.operation });
    const from = isoOrUndefined(f.from);
    const to = isoOrUndefined(f.to);
    if (from) qb.andWhere('main.created_at >= :from', { from });
    if (to) qb.andWhere('main.created_at <= :to', { to });
    if (f.sessionId) qb.andWhere(`main.trace->>'sessionId' = :sessionId`, { sessionId: f.sessionId });
    if (f.user) qb.andWhere(`(main.on_behalf_of->>'sub' ILIKE :user OR main.on_behalf_of->>'email' ILIKE :user)`, { user: `%${f.user.replace(/[\\%_]/g, (c) => `\\${c}`)}%` });
    return qb;
  }

  async list(orgId: string, body: unknown = {}) {
    const { records, totalRecords } = await this.getAll(orgId, pageBody(body));
    return { items: records, total: totalRecords };
  }

  /** An access request with the audit events of the same correlation id. */
  protected async postProcessAfterGetById(item: AccessRequestEntity, orgId: string) {
    const auditEvents = await auditRepo.auditEventsByCorrelation(orgId, item.correlationId);
    return { ...item, auditEvents } as AccessRequest;
  }
}
