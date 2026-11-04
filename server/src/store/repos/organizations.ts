import { and, eq, inArray } from 'drizzle-orm';
import type { Member, Organization, OrganizationMembership, Role } from '@token-vault/shared';
import { db, type Executor } from '../../db/client';
import { organizationMembers, organizations, users } from '../../db/schema';
import type { MemberRecord, UserRecord } from '../types';

// ---------------------------------------------------------------- organizations
export async function getOrganization(id: string, ex: Executor = db): Promise<Organization | null> {
  const [row] = await ex.select().from(organizations).where(eq(organizations.id, id));
  return row ?? null;
}

export async function findOrganizationBySlug(slug: string, ex: Executor = db): Promise<Organization | null> {
  const [row] = await ex.select().from(organizations).where(eq(organizations.slug, slug));
  return row ?? null;
}

export async function updateOrganization(id: string, patch: Partial<Pick<Organization, 'name' | 'environment' | 'updatedAt'>>, ex: Executor = db) {
  const [row] = await ex.update(organizations).set(patch).where(eq(organizations.id, id)).returning();
  return row!;
}

// ---------------------------------------------------------------- users
export async function findUserByEmail(email: string, ex: Executor = db): Promise<UserRecord | null> {
  const [row] = await ex.select().from(users).where(eq(users.email, email));
  return row ?? null;
}

export async function getUser(id: string, ex: Executor = db): Promise<UserRecord | null> {
  const [row] = await ex.select().from(users).where(eq(users.id, id));
  return row ?? null;
}

/** Display names for a set of user IDs (creators, owners, revokers). */
export async function userNames(ids: string[], ex: Executor = db): Promise<Map<string, string>> {
  const unique = [...new Set(ids.filter(Boolean))];
  if (unique.length === 0) return new Map();
  const rows = await ex.select({ id: users.id, fullName: users.fullName }).from(users).where(inArray(users.id, unique));
  return new Map(rows.map((r) => [r.id, r.fullName]));
}

// ---------------------------------------------------------------- memberships
export async function membershipsForUser(userId: string, ex: Executor = db): Promise<OrganizationMembership[]> {
  const rows = await ex
    .select({ id: organizationMembers.id, organizationId: organizations.id, organizationName: organizations.name, organizationSlug: organizations.slug, role: organizationMembers.role })
    .from(organizationMembers)
    .innerJoin(organizations, eq(organizations.id, organizationMembers.organizationId))
    .where(eq(organizationMembers.userId, userId))
    .orderBy(organizations.name);
  return rows;
}

export async function getMembership(userId: string, organizationId: string, ex: Executor = db): Promise<MemberRecord | null> {
  const [row] = await ex
    .select()
    .from(organizationMembers)
    .where(and(eq(organizationMembers.userId, userId), eq(organizationMembers.organizationId, organizationId)));
  return row ?? null;
}

const memberColumns = {
  id: organizationMembers.id,
  organizationId: organizationMembers.organizationId,
  userId: users.id,
  email: users.email,
  fullName: users.fullName,
  role: organizationMembers.role,
  createdAt: organizationMembers.createdAt,
};

export async function listMembers(organizationId: string, ex: Executor = db): Promise<Member[]> {
  return ex.select(memberColumns).from(organizationMembers).innerJoin(users, eq(users.id, organizationMembers.userId)).where(eq(organizationMembers.organizationId, organizationId)).orderBy(organizationMembers.createdAt, users.fullName);
}

export async function getMember(organizationId: string, memberId: string, ex: Executor = db): Promise<Member | null> {
  const [row] = await ex
    .select(memberColumns)
    .from(organizationMembers)
    .innerJoin(users, eq(users.id, organizationMembers.userId))
    .where(and(eq(organizationMembers.organizationId, organizationId), eq(organizationMembers.id, memberId)));
  return row ?? null;
}

export async function countOwners(organizationId: string, ex: Executor = db): Promise<number> {
  const rows = await ex.select({ id: organizationMembers.id }).from(organizationMembers).where(and(eq(organizationMembers.organizationId, organizationId), eq(organizationMembers.role, 'OWNER')));
  return rows.length;
}

export async function updateMemberRole(memberId: string, role: Role, ex: Executor = db) {
  await ex.update(organizationMembers).set({ role }).where(eq(organizationMembers.id, memberId));
}
