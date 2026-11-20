import { In, type SelectQueryBuilder } from 'typeorm';
import type { Member } from '@token-vault/shared';
import { db, transaction } from '../../databases/client';
import { OrganizationMemberEntity, UserEntity } from '../../entities';
import { BaseServices } from '../baseService';
import type { MemberDto } from '../../databases/repository/member/member.dto';
import { conflict, notFound } from '../../lib/errors';
import { orgRepo } from '../../store/repos';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';

type OrgContext = AdminContext & { org: { id: string } };

/** Members of the current organization and their roles. */
export default class MemberService extends BaseServices<OrganizationMemberEntity, Member> {
  constructor() {
    super(OrganizationMemberEntity);
  }
  getModuleName() {
    return 'Member';
  }
  /** Matches the member's name or email. */
  getGlobalSearchColumns() {
    return ['u.full_name', 'u.email'];
  }
  /** Members with their user (for name, email and search), in joining order then by name. */
  protected prepareFilter(qb: SelectQueryBuilder<OrganizationMemberEntity>, orgId: string) {
    return qb.innerJoin(UserEntity, 'u', 'u.id = main.user_id').where('main.organization_id = :orgId', { orgId }).orderBy('main.created_at', 'ASC').addOrderBy('u.full_name', 'ASC');
  }
  protected async postProcessAfterGetData(rows: OrganizationMemberEntity[]): Promise<Member[]> {
    const users = new Map((await db.findBy(UserEntity, { id: In(rows.map((m) => m.userId)) })).map((u) => [u.id, u]));
    return rows.map((m) => ({ id: m.id, organizationId: m.organizationId, userId: m.userId, email: users.get(m.userId)?.email ?? '', fullName: users.get(m.userId)?.fullName ?? '', role: m.role, createdAt: m.createdAt }));
  }

  async list(orgId: string, body: unknown = {}) {
    const { records, totalRecords } = await this.getAll(orgId, body);
    return { items: records, total: totalRecords };
  }

  /** Changes a member's role; an organization always keeps at least one owner. */
  setRole(ctx: OrgContext, { id, role }: MemberDto) {
    return transaction(async (tx) => {
      const member = await orgRepo.getMember(ctx.org.id, id, tx);
      if (!member) throw notFound('Member');
      if (member.role === 'OWNER' && role !== 'OWNER' && (await orgRepo.countOwners(ctx.org.id, tx)) === 1) throw conflict('An organization must keep at least one owner');
      await orgRepo.updateMemberRole(member.id, role, tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'member.role_changed', target: { type: 'user', id: member.userId, name: member.fullName }, severity: 'warning', metadata: { from: member.role, to: role } }, tx);
      return { ...member, role };
    });
  }
}
