import { transaction } from '../../databases/client';
import type { MemberDto } from '../../databases/repository/member/member.dto';
import { conflict, notFound } from '../../lib/errors';
import { orgRepo } from '../../store/repos';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';

type OrgContext = AdminContext & { org: { id: string } };

/** Members of the current organization and their roles. */
export default class MemberService {
  async list(orgId: string) {
    return { items: await orgRepo.listMembers(orgId) };
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
