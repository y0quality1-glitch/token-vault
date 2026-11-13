import { Transform } from 'class-transformer';
import { Check, trim } from '../common/validators';
import { zEnum, zString } from '../common/zodCompat';

export const MEMBER_ROLES = ['OWNER', 'VAULT_ADMIN', 'SECURITY_ADMIN', 'DEVELOPER', 'AUDITOR'] as const;

/** POST /member/save `{ id: memberId, role }`: changes a member's role (members are never created here). */
export class MemberDto {
  @Transform(trim)
  @Check(zString({ min: 1, minMessage: 'Required' }))
  id!: string;

  @Check(zEnum(MEMBER_ROLES))
  role!: (typeof MEMBER_ROLES)[number];
}
