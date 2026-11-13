import { In } from 'typeorm';
import type { Member, Organization, OrganizationMembership, Role } from '@token-vault/shared';
import { db, type Executor } from '../../databases/client';
import { OrganizationEntity, OrganizationMemberEntity, UserEntity } from '../../entities';
import type { MemberRecord, UserRecord } from '../types';
import { oneBy, updateBy, updateRow } from './orm';

// ---------------------------------------------------------------- organizations
export async function getOrganization(id: string, ex: Executor = db): Promise<Organization | null> {
  return oneBy(ex, OrganizationEntity, { id });
}

export async function findOrganizationBySlug(slug: string, ex: Executor = db): Promise<Organization | null> {
  return oneBy(ex, OrganizationEntity, { slug });
}

export async function updateOrganization(id: string, patch: Partial<Pick<Organization, 'name' | 'environment' | 'updatedAt' | 'emergencyStoppedAt' | 'emergencyStoppedBy' | 'emergencyStopReason'>>, ex: Executor = db) {
  return updateRow(ex, OrganizationEntity, { id }, patch);
}

// ---------------------------------------------------------------- users
export async function findUserByEmail(email: string, ex: Executor = db): Promise<UserRecord | null> {
  return oneBy(ex, UserEntity, { email });
}

export async function getUser(id: string, ex: Executor = db): Promise<UserRecord | null> {
  return oneBy(ex, UserEntity, { id });
}

/** Display names for a set of user IDs (creators, owners, revokers). */
export async function userNames(ids: string[], ex: Executor = db): Promise<Map<string, string>> {
  const unique = [...new Set(ids.filter(Boolean))];
  if (unique.length === 0) return new Map();
  const rows = await ex.find(UserEntity, { where: { id: In(unique) }, select: { id: true, fullName: true } });
  return new Map(rows.map((r) => [r.id, r.fullName]));
}

// ---------------------------------------------------------------- memberships
export async function membershipsForUser(userId: string, ex: Executor = db): Promise<OrganizationMembership[]> {
  const rows: { id: string; organization_id: string; organization_name: string; organization_slug: string; role: Role }[] = await ex.query(
    `SELECT m.id, o.id AS organization_id, o.name AS organization_name, o.slug AS organization_slug, m.role
       FROM organization_members m JOIN organizations o ON o.id = m.organization_id
      WHERE m.user_id = $1 ORDER BY o.name`,
    [userId],
  );
  return rows.map((r) => ({ id: r.id, organizationId: r.organization_id, organizationName: r.organization_name, organizationSlug: r.organization_slug, role: r.role }));
}

export async function getMembership(userId: string, organizationId: string, ex: Executor = db): Promise<MemberRecord | null> {
  return oneBy(ex, OrganizationMemberEntity, { userId, organizationId });
}

type MemberRow = { id: string; organization_id: string; user_id: string; email: string; full_name: string; role: Role; created_at: Date | string };
const toMember = (r: MemberRow): Member => ({ id: r.id, organizationId: r.organization_id, userId: r.user_id, email: r.email, fullName: r.full_name, role: r.role, createdAt: new Date(r.created_at).toISOString() });
const MEMBER_SQL = `SELECT m.id, m.organization_id, u.id AS user_id, u.email, u.full_name, m.role, m.created_at
  FROM organization_members m JOIN users u ON u.id = m.user_id`;

export async function getMember(organizationId: string, memberId: string, ex: Executor = db): Promise<Member | null> {
  const [row]: MemberRow[] = await ex.query(`${MEMBER_SQL} WHERE m.organization_id = $1 AND m.id = $2`, [organizationId, memberId]);
  return row ? toMember(row) : null;
}

export async function countOwners(organizationId: string, ex: Executor = db): Promise<number> {
  return ex.countBy(OrganizationMemberEntity, { organizationId, role: 'OWNER' });
}

export async function updateMemberRole(memberId: string, role: Role, ex: Executor = db) {
  await updateBy(ex, OrganizationMemberEntity, { id: memberId }, { role });
}
