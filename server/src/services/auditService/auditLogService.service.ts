import { type IntegrityReport } from '@token-vault/shared';
import { config } from '../../config';
import { auditRepo } from '../../store/repos';
import { verify, type ChainTable } from './chain';

/** The integrity of both audit hash chains (lists: AccessRequestService and AuditEventService). */
export default class AuditLogService {
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
