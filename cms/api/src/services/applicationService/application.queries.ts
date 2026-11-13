import { In, LessThan, type EntityManager } from 'typeorm';
import type { CmsApplicationSummary, CmsUser, CmsVersionDetail, CmsVersionSummary } from '@token-vault/shared';
import { SETTINGS, SIGNING } from '../../config';
import { notFound } from '../../core/ApiError';
import { ApplicationEntity } from '../../entities/applicationEntity';
import { VersionEntity } from '../../entities/versionEntity';
import { VersionSignatureEntity } from '../../entities/versionSignatureEntity';
import { check, diffDefinitions } from '../definitionService/definitionService.service';

/** Reads and views shared by the application and version services. */

export const now = () => new Date().toISOString();
export const OPEN: VersionEntity['status'][] = ['DRAFT', 'IN_REVIEW'];

export async function getApp(m: EntityManager, key: string): Promise<ApplicationEntity> {
  const app = await m.findOneBy(ApplicationEntity, { key });
  if (!app) throw notFound(`Application "${key}"`);
  return app;
}

/** One version; `lock` takes a row lock (FOR UPDATE) for the rest of the transaction. */
export async function getVersion(m: EntityManager, app: ApplicationEntity, version: number, lock = false): Promise<VersionEntity> {
  const q = m.createQueryBuilder(VersionEntity, 'v').where('v.application_id = :id AND v.version = :version', { id: app.id, version });
  const row = await (lock ? q.setLock('pessimistic_write') : q).getOne();
  if (!row) throw notFound(`Version ${version} of "${app.key}"`);
  return row;
}

export async function publishedOf(m: EntityManager, appId: string): Promise<VersionEntity | null> {
  return m.findOneBy(VersionEntity, { application_id: appId, status: 'PUBLISHED' });
}

export async function versionsOf(m: EntityManager, appId: string, lock = false): Promise<VersionEntity[]> {
  const q = m.createQueryBuilder(VersionEntity, 'v').where('v.application_id = :id', { id: appId }).orderBy('v.version', 'DESC');
  return (lock ? q.setLock('pessimistic_write') : q).getMany();
}

export const toVersionSummary = (v: VersionEntity): CmsVersionSummary => ({
  version: v.version,
  status: v.status,
  digest: v.digest,
  createdBy: v.created_by,
  createdAt: v.created_at,
  authors: v.authors,
  submittedBy: v.submitted_by,
  submittedAt: v.submitted_at,
  reviewedBy: v.reviewed_by,
  reviewedAt: v.reviewed_at,
  reviewNote: v.review_note,
  publishedAt: v.published_at,
});

type Listing = { catalog?: { icon?: string; category?: string; availability?: string } } | undefined;
const availabilityOf = (v: VersionEntity) => ((v.definition as Listing)?.catalog?.availability === 'coming_soon' ? ('coming_soon' as const) : ('available' as const));

export function summarize(app: ApplicationEntity, rows: VersionEntity[]): CmsApplicationSummary {
  const published = rows.find((v) => v.status === 'PUBLISHED');
  const open = rows.find((v) => OPEN.includes(v.status));
  const ops = (published?.definition as { operations?: unknown[] } | undefined)?.operations;
  const shown = (published ?? open ?? rows[0])?.definition as Listing;
  return {
    key: app.key,
    name: app.name,
    description: app.description,
    archived: !!app.archived_at,
    publishedVersion: published?.version ?? null,
    publishedAt: published?.published_at ?? null,
    openVersion: open ? { version: open.version, status: open.status as 'DRAFT' | 'IN_REVIEW', availability: availabilityOf(open) } : null,
    operationCount: Array.isArray(ops) ? ops.length : 0,
    icon: shown?.catalog?.icon ?? 'plug',
    category: shown?.catalog?.category ?? 'Other',
    availability: published ? availabilityOf(published) : null,
    updatedAt: app.updated_at,
  };
}

/** Why the user may not review this version (separation of duties), or null if they may. */
export function reviewBlock(user: CmsUser, v: VersionEntity): string | null {
  if (v.status !== 'IN_REVIEW') return 'Only versions in review can be approved or rejected.';
  if (user.role !== 'PUBLISHER' && user.role !== 'ADMIN') return 'Only publishers can approve or reject.';
  if (v.authors.includes(user.id) || v.submitted_by === user.id) return 'You authored or submitted this version; another publisher must review it (separation of duties).';
  return null;
}

/** Why the user may not publish this version directly, or null if they may. */
export function directPublishBlock(user: CmsUser, app: ApplicationEntity, v: VersionEntity, issues: string[]): string | null {
  if (user.role !== 'ADMIN') return 'Only administrators can publish directly.';
  if (!SETTINGS.adminDirectPublish) return 'Direct publishing is turned off (CMS_ADMIN_DIRECT_PUBLISH=false): submit the version for review.';
  if (app.archived_at) return 'This application is archived.';
  if (!OPEN.includes(v.status)) return 'Only drafts and versions in review can be published.';
  if (issues.length) return 'Fix the validation problems first.';
  return null;
}

/**
 * What a version is compared with: the current publication for open versions, and the
 * publication it replaced for published or superseded ones.
 */
async function baselineFor(m: EntityManager, app: ApplicationEntity, v: VersionEntity): Promise<VersionEntity | null> {
  if (OPEN.includes(v.status)) return publishedOf(m, app.id);
  return m.findOne(VersionEntity, { where: { application_id: app.id, status: In(['PUBLISHED', 'SUPERSEDED']), version: LessThan(v.version) }, order: { version: 'DESC' } });
}

/** The full view of a version for this user: diff, signatures, and what the user may do with it. */
export async function versionDetail(m: EntityManager, user: CmsUser, app: ApplicationEntity, v: VersionEntity): Promise<CmsVersionDetail> {
  const baseline = await baselineFor(m, app, v);
  const { issues } = check(v.definition);
  const sigs = await m.find(VersionSignatureEntity, { where: { version_id: v.id }, order: { signed_at: 'ASC' } });
  const isEditor = user.role === 'EDITOR' || user.role === 'ADMIN';
  const block = reviewBlock(user, v);
  const open = await m.findOne(VersionEntity, { where: { application_id: app.id, status: In(OPEN) }, select: { version: true } });
  return {
    ...toVersionSummary(v),
    key: app.key,
    definition: v.definition,
    issues,
    signatures: sigs.map((x) => ({ keyId: x.key_id, signedAt: x.signed_at, active: x.key_id === SIGNING.keyId })),
    diff: diffDefinitions(v.definition, baseline?.definition ?? null, baseline?.version ?? null),
    can: {
      edit: isEditor && v.status === 'DRAFT' && !app.archived_at,
      submit: isEditor && v.status === 'DRAFT' && issues.length === 0 && !app.archived_at,
      withdraw: isEditor && v.status === 'IN_REVIEW',
      review: block === null,
      reviewBlockedReason: block,
      publishDirectly: directPublishBlock(user, app, v, issues) === null,
      editAsNewVersion: isEditor && (v.status === 'PUBLISHED' || v.status === 'SUPERSEDED') && !app.archived_at,
    },
    openVersion: open?.version ?? null,
  };
}
