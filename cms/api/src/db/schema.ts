import { sql } from 'drizzle-orm';
import { bigserial, boolean, customType, index, integer, jsonb, pgTable, text, uniqueIndex } from 'drizzle-orm/pg-core';
import type { CmsRole, VersionStatus } from '@token-vault/shared';

/** timestamptz(3) exposed as ISO-8601 strings. */
const ts = customType<{ data: string; driverData: string | Date }>({
  dataType: () => 'timestamp(3) with time zone',
  toDriver: (v) => v,
  fromDriver: (v) => new Date(v).toISOString(),
});

export const users = pgTable('cms_users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  fullName: text('full_name').notNull(),
  role: text('role').$type<CmsRole>().notNull(),
  passwordHash: text('password_hash').notNull(),
  createdAt: ts('created_at').notNull(),
});

/** Admin sessions: only the SHA-256 of the cookie token is stored. */
export const sessions = pgTable('cms_sessions', {
  tokenHash: text('token_hash').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  expiresAt: ts('expires_at').notNull(),
  createdAt: ts('created_at').notNull(),
});

export const applications = pgTable('applications', {
  id: text('id').primaryKey(),
  key: text('key').notNull().unique(),
  name: text('name').notNull(),
  description: text('description').notNull().default(''),
  createdBy: text('created_by').notNull(),
  createdAt: ts('created_at').notNull(),
  updatedAt: ts('updated_at').notNull(),
  archivedAt: ts('archived_at'),
});

export const versions = pgTable(
  'application_versions',
  {
    id: text('id').primaryKey(),
    applicationId: text('application_id')
      .notNull()
      .references(() => applications.id),
    version: integer('version').notNull(),
    status: text('status').$type<VersionStatus>().notNull(),
    /** The definition as edited (may be invalid while DRAFT). Frozen once published. */
    definition: jsonb('definition').notNull(),
    /** Set on publication: sha256 of the canonical definition, and its Ed25519 signature. */
    digest: text('digest'),
    signature: text('signature'),
    keyId: text('key_id'),
    createdBy: text('created_by').notNull(),
    createdAt: ts('created_at').notNull(),
    updatedAt: ts('updated_at').notNull(),
    /** Everyone who created or edited this version; none of them may approve it. */
    authors: text('authors').array().notNull().default(sql`'{}'::text[]`),
    submittedBy: text('submitted_by'),
    submittedAt: ts('submitted_at'),
    reviewedBy: text('reviewed_by'),
    reviewedAt: ts('reviewed_at'),
    reviewNote: text('review_note'),
    publishedAt: ts('published_at'),
    hostChangeAcknowledged: boolean('host_change_acknowledged').notNull().default(false),
  },
  (t) => [
    uniqueIndex('application_versions_app_version').on(t.applicationId, t.version),
    // At most one open (DRAFT or IN_REVIEW) and one PUBLISHED version per application.
    uniqueIndex('application_versions_one_open').on(t.applicationId).where(sql`status in ('DRAFT', 'IN_REVIEW')`),
    uniqueIndex('application_versions_one_published').on(t.applicationId).where(sql`status = 'PUBLISHED'`),
  ],
);

/** Append-only (enforced by trigger in migration 0001). */
export const auditEvents = pgTable(
  'cms_audit_events',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    at: ts('at').notNull(),
    actorId: text('actor_id').notNull(),
    actorName: text('actor_name').notNull(),
    action: text('action').notNull(),
    applicationKey: text('application_key'),
    version: integer('version'),
    details: jsonb('details').$type<Record<string, unknown>>().notNull(),
  },
  (t) => [index('cms_audit_events_app').on(t.applicationKey, t.at)],
);
