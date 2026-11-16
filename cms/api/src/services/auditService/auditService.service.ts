import type { EntityManager, SelectQueryBuilder } from 'typeorm';
import type { CmsAuditEvent, CmsUser } from '@token-vault/shared';
import type { Pagination } from '../../core/Y0Params';
import { Y0Model } from '../../databases/repository/y0Model/y0Model.model';
import { AuditEventEntity } from '../../entities/auditEventEntity';
import { BaseServices } from '../baseService';

export type Actor = Pick<CmsUser, 'id' | 'fullName'>;
export const SYSTEM_ACTOR: Actor = { id: 'system', fullName: 'System' };

/** Appends one audit event (the table rejects UPDATE and DELETE). */
export async function audit(m: EntityManager, actor: Actor, action: string, target: { key?: string; version?: number } = {}, details: Record<string, unknown> = {}) {
  await m.insert(AuditEventEntity, {
    at: new Date().toISOString(),
    actor_id: actor.id,
    actor_name: actor.fullName,
    action,
    application_key: target.key ?? null,
    version: target.version ?? null,
    details: details as never,
  });
}

class AuditFilterDto {}

/** The audit log, newest first, optionally for one application. */
export default class AuditService extends BaseServices<AuditEventEntity, CmsAuditEvent> {
  constructor() {
    super(AuditEventEntity);
  }
  getModel() {
    return new Y0Model();
  }
  getDTO() {
    return AuditFilterDto;
  }
  getModuleName() {
    return 'Audit events';
  }
  getGlobalSearchColumns() {
    return ['main.action', 'main.actor_name', 'main.application_key'];
  }

  protected prepareFilter(qb: SelectQueryBuilder<AuditEventEntity>, param: Pagination) {
    if (param.filter.application) qb.where('main.application_key = :key', { key: param.filter.application });
    return qb.orderBy('main.id', 'DESC').skip((param.pageNumber - 1) * param.pageSize).take(param.pageSize);
  }

  protected async postProcessAfterGetData(rows: AuditEventEntity[]): Promise<CmsAuditEvent[]> {
    return rows.map((r) => ({ id: Number(r.id), at: r.at, actorName: r.actor_name, action: r.action, applicationKey: r.application_key, version: r.version, details: r.details }));
  }
}
