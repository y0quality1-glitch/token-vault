import { and, asc, desc, eq, inArray, lt } from 'drizzle-orm';
import { Router } from 'express';
import { z } from 'zod';
import type { CmsApplicationDetail, CmsApplicationSummary, CmsUser, CmsVersionDetail, CmsVersionSummary } from '@token-vault/shared';
import { db, transaction, type Executor } from '../db/client';
import { applications, versionSignatures, versions } from '../db/schema';
import { config } from '../config';
import { newId, signDefinition } from '../lib/crypto';
import { HttpError, conflict, forbidden, notFound, parse } from '../lib/http';
import { audit } from './audit';
import { requireRole } from './auth';
import { addSignature, registerActiveKey } from './signing';
import { check, diffDefinitions, preview, starterDefinition } from './definitions';

type AppRow = typeof applications.$inferSelect;
type VersionRow = typeof versions.$inferSelect;

const now = () => new Date().toISOString();
const editors = requireRole('EDITOR', 'ADMIN');
const reviewers = requireRole('PUBLISHER', 'ADMIN');

// ---------------------------------------------------------------- reads

async function getApp(ex: Executor, key: string): Promise<AppRow> {
  const [app] = await ex.select().from(applications).where(eq(applications.key, key));
  if (!app) throw notFound(`Application "${key}"`);
  return app;
}

async function getVersion(ex: Executor, app: AppRow, version: number, lock = false): Promise<VersionRow> {
  const q = ex.select().from(versions).where(and(eq(versions.applicationId, app.id), eq(versions.version, version)));
  const [row] = lock ? await q.for('update') : await q;
  if (!row) throw notFound(`Version ${version} of "${app.key}"`);
  return row;
}

async function publishedOf(ex: Executor, appId: string): Promise<VersionRow | null> {
  const [row] = await ex.select().from(versions).where(and(eq(versions.applicationId, appId), eq(versions.status, 'PUBLISHED')));
  return row ?? null;
}

const toVersionSummary = (v: VersionRow): CmsVersionSummary => ({
  version: v.version,
  status: v.status,
  digest: v.digest,
  createdBy: v.createdBy,
  createdAt: v.createdAt,
  authors: v.authors,
  submittedBy: v.submittedBy,
  submittedAt: v.submittedAt,
  reviewedBy: v.reviewedBy,
  reviewedAt: v.reviewedAt,
  reviewNote: v.reviewNote,
  publishedAt: v.publishedAt,
});

function summarize(app: AppRow, rows: VersionRow[]): CmsApplicationSummary {
  const published = rows.find((v) => v.status === 'PUBLISHED');
  const open = rows.find((v) => v.status === 'DRAFT' || v.status === 'IN_REVIEW');
  const ops = (published?.definition as { operations?: unknown[] } | undefined)?.operations;
  type Listing = { catalog?: { icon?: string; category?: string; availability?: string } } | undefined;
  const shown = (published ?? open ?? rows[0])?.definition as Listing;
  const availabilityOf = (v: VersionRow) => ((v.definition as Listing)?.catalog?.availability === 'coming_soon' ? ('coming_soon' as const) : ('available' as const));
  return {
    key: app.key,
    name: app.name,
    description: app.description,
    archived: !!app.archivedAt,
    publishedVersion: published?.version ?? null,
    publishedAt: published?.publishedAt ?? null,
    openVersion: open ? { version: open.version, status: open.status as 'DRAFT' | 'IN_REVIEW', availability: availabilityOf(open) } : null,
    operationCount: Array.isArray(ops) ? ops.length : 0,
    icon: shown?.catalog?.icon ?? 'plug',
    category: shown?.catalog?.category ?? 'Other',
    availability: published ? availabilityOf(published) : null,
    updatedAt: app.updatedAt,
  };
}

/** Why the user may not review this version (separation of duties), or null if they may. */
function reviewBlock(user: CmsUser, v: VersionRow): string | null {
  if (v.status !== 'IN_REVIEW') return 'Only versions in review can be approved or rejected.';
  if (user.role !== 'PUBLISHER' && user.role !== 'ADMIN') return 'Only publishers can approve or reject.';
  if (v.authors.includes(user.id) || v.submittedBy === user.id) return 'You authored or submitted this version; another publisher must review it (separation of duties).';
  return null;
}

/**
 * What a version is compared with: the current publication for open versions, and the
 * publication it replaced for published or superseded ones.
 */
async function baselineFor(ex: Executor, app: AppRow, v: VersionRow): Promise<VersionRow | null> {
  if (v.status === 'DRAFT' || v.status === 'IN_REVIEW') return publishedOf(ex, app.id);
  const [prev] = await ex
    .select()
    .from(versions)
    .where(and(eq(versions.applicationId, app.id), inArray(versions.status, ['PUBLISHED', 'SUPERSEDED']), lt(versions.version, v.version)))
    .orderBy(desc(versions.version))
    .limit(1);
  return prev ?? null;
}

async function detail(ex: Executor, user: CmsUser, app: AppRow, v: VersionRow): Promise<CmsVersionDetail> {
  const baseline = await baselineFor(ex, app, v);
  const { issues } = check(v.definition);
  const sigs = await ex.select().from(versionSignatures).where(eq(versionSignatures.versionId, v.id)).orderBy(asc(versionSignatures.signedAt));
  const isEditor = user.role === 'EDITOR' || user.role === 'ADMIN';
  const block = reviewBlock(user, v);
  return {
    ...toVersionSummary(v),
    key: app.key,
    definition: v.definition,
    issues,
    signatures: sigs.map((x) => ({ keyId: x.keyId, signedAt: x.signedAt, active: x.keyId === config.keyId })),
    diff: diffDefinitions(v.definition, baseline?.definition ?? null, baseline?.version ?? null),
    can: {
      edit: isEditor && v.status === 'DRAFT' && !app.archivedAt,
      submit: isEditor && v.status === 'DRAFT' && issues.length === 0 && !app.archivedAt,
      withdraw: isEditor && v.status === 'IN_REVIEW',
      review: block === null,
      reviewBlockedReason: block,
    },
  };
}

// ---------------------------------------------------------------- routes

export const applicationsRouter = Router();

applicationsRouter.get('/applications', async (_req, res) => {
  const apps = await db.select().from(applications).orderBy(asc(applications.key));
  const rows = apps.length ? await db.select().from(versions).where(inArray(versions.applicationId, apps.map((a) => a.id))) : [];
  res.json({ items: apps.map((a) => summarize(a, rows.filter((v) => v.applicationId === a.id))) });
});

applicationsRouter.post('/applications', editors, async (req, res) => {
  const body = parse(
    z.object({
      key: z.string().regex(/^[a-z][a-z0-9-]{1,30}$/, 'Lower-case letters, digits and dashes; starts with a letter (2-31 characters)'),
      name: z.string().trim().min(1, 'Name is required').max(60),
      description: z.string().trim().max(500).default(''),
    }),
    req.body,
  );
  const user = req.user!;
  const created = await transaction(async (tx) => {
    const [exists] = await tx.select({ id: applications.id }).from(applications).where(eq(applications.key, body.key));
    if (exists) throw new HttpError(409, 'KEY_TAKEN', `An application with key "${body.key}" already exists`, { fields: { key: 'This key is already in use' } });
    const t = now();
    const app = { id: newId('app'), key: body.key, name: body.name, description: body.description, createdBy: user.fullName, createdAt: t, updatedAt: t, archivedAt: null };
    await tx.insert(applications).values(app);
    await tx.insert(versions).values({ id: newId('ver'), applicationId: app.id, version: 1, status: 'DRAFT', definition: starterDefinition(body.key, body.name, body.description), createdBy: user.fullName, createdAt: t, updatedAt: t, authors: [user.id] });
    await audit(tx, user, 'application.created', { key: body.key, version: 1 }, { name: body.name });
    return app;
  });
  res.status(201).json({ key: created.key, version: 1 });
});

applicationsRouter.get('/applications/:key', async (req, res) => {
  const app = await getApp(db, String(req.params.key));
  const rows = await db.select().from(versions).where(eq(versions.applicationId, app.id)).orderBy(desc(versions.version));
  const body: CmsApplicationDetail = { ...summarize(app, rows), createdBy: app.createdBy, createdAt: app.createdAt, versions: rows.map(toVersionSummary) };
  res.json(body);
});

/** Starts a new draft from the latest version (or a chosen one). Only one open version at a time. */
applicationsRouter.post('/applications/:key/versions', editors, async (req, res) => {
  const { from } = parse(z.object({ from: z.number().int().positive().optional() }), req.body ?? {});
  const user = req.user!;
  const out = await transaction(async (tx) => {
    const app = await getApp(tx, String(req.params.key));
    if (app.archivedAt) throw conflict('This application is archived', 'ARCHIVED');
    const rows = await tx.select().from(versions).where(eq(versions.applicationId, app.id)).orderBy(desc(versions.version));
    const open = rows.find((v) => v.status === 'DRAFT' || v.status === 'IN_REVIEW');
    if (open) throw conflict(`Version ${open.version} is still ${open.status === 'DRAFT' ? 'a draft' : 'in review'}; finish it first`, 'OPEN_VERSION_EXISTS');
    const base = from ? rows.find((v) => v.version === from) : rows[0];
    if (!base) throw notFound(`Version ${from}`);
    const version = (rows[0]?.version ?? 0) + 1;
    const t = now();
    await tx.insert(versions).values({ id: newId('ver'), applicationId: app.id, version, status: 'DRAFT', definition: { ...(base.definition as object), version }, createdBy: user.fullName, createdAt: t, updatedAt: t, authors: [user.id] });
    await tx.update(applications).set({ updatedAt: t }).where(eq(applications.id, app.id));
    await audit(tx, user, 'version.created', { key: app.key, version }, { from: base.version });
    return { key: app.key, version };
  });
  res.status(201).json(out);
});

applicationsRouter.get('/applications/:key/versions/:version', async (req, res) => {
  const app = await getApp(db, String(req.params.key));
  const v = await getVersion(db, app, Number(req.params.version));
  res.json(await detail(db, req.user!, app, v));
});

applicationsRouter.put('/applications/:key/versions/:version', editors, async (req, res) => {
  const { definition } = parse(z.object({ definition: z.record(z.unknown()) }), req.body);
  const user = req.user!;
  const out = await transaction(async (tx) => {
    const app = await getApp(tx, String(req.params.key));
    const v = await getVersion(tx, app, Number(req.params.version), true);
    if (v.status !== 'DRAFT') throw conflict(`Version ${v.version} is ${v.status.toLowerCase().replace('_', ' ')} and cannot be edited`, 'NOT_EDITABLE');
    if (app.archivedAt) throw conflict('This application is archived', 'ARCHIVED');
    // The key and version are owned by the CMS, not the editor.
    const next = { ...definition, key: app.key, version: v.version };
    await tx
      .update(versions)
      .set({ definition: next, updatedAt: now(), authors: v.authors.includes(user.id) ? v.authors : [...v.authors, user.id] })
      .where(eq(versions.id, v.id));
    await audit(tx, user, 'version.edited', { key: app.key, version: v.version }, { valid: check(next).issues.length === 0 });
    return detail(tx, user, app, { ...v, definition: next, authors: v.authors.includes(user.id) ? v.authors : [...v.authors, user.id] });
  });
  res.json(out);
});

/** DRAFT -> IN_REVIEW. The definition is normalized here, so reviewers see exactly what will be signed. */
applicationsRouter.post('/applications/:key/versions/:version/submit', editors, async (req, res) => {
  const user = req.user!;
  const out = await transaction(async (tx) => {
    const app = await getApp(tx, String(req.params.key));
    const v = await getVersion(tx, app, Number(req.params.version), true);
    if (v.status !== 'DRAFT') throw conflict('Only drafts can be submitted for review', 'INVALID_STATE');
    const { normalized, issues } = check(v.definition);
    if (!normalized) throw new HttpError(400, 'DEFINITION_INVALID', 'Fix the validation problems before submitting', { issues });
    const t = now();
    await tx.update(versions).set({ status: 'IN_REVIEW', definition: normalized, submittedBy: user.id, submittedAt: t, updatedAt: t, reviewNote: null }).where(eq(versions.id, v.id));
    await audit(tx, user, 'version.submitted', { key: app.key, version: v.version });
    return detail(tx, user, app, { ...v, status: 'IN_REVIEW', definition: normalized, submittedBy: user.id, submittedAt: t, reviewNote: null });
  });
  res.json(out);
});

applicationsRouter.post('/applications/:key/versions/:version/withdraw', editors, async (req, res) => {
  const user = req.user!;
  const out = await transaction(async (tx) => {
    const app = await getApp(tx, String(req.params.key));
    const v = await getVersion(tx, app, Number(req.params.version), true);
    if (v.status !== 'IN_REVIEW') throw conflict('Only versions in review can be withdrawn', 'INVALID_STATE');
    await tx.update(versions).set({ status: 'DRAFT', submittedBy: null, submittedAt: null, updatedAt: now() }).where(eq(versions.id, v.id));
    await audit(tx, user, 'version.withdrawn', { key: app.key, version: v.version });
    return detail(tx, user, app, { ...v, status: 'DRAFT', submittedBy: null, submittedAt: null });
  });
  res.json(out);
});

/**
 * IN_REVIEW -> PUBLISHED: a publisher who neither authored nor submitted the version
 * approves it; it is signed and replaces the previously published version. A change of
 * API host (or a first publication) must be acknowledged explicitly, because it decides
 * where customer credentials are sent.
 */
applicationsRouter.post('/applications/:key/versions/:version/approve', reviewers, async (req, res) => {
  const body = parse(z.object({ note: z.string().trim().max(1000).default(''), acknowledgeHostChange: z.boolean().default(false) }), req.body ?? {});
  const user = req.user!;
  const out = await transaction(async (tx) => {
    const app = await getApp(tx, String(req.params.key));
    const v = await getVersion(tx, app, Number(req.params.version), true);
    const block = reviewBlock(user, v);
    if (block) throw v.status !== 'IN_REVIEW' ? conflict(block, 'INVALID_STATE') : forbidden(block, 'SEPARATION_OF_DUTIES');
    const { normalized, issues } = check(v.definition);
    if (!normalized) throw new HttpError(400, 'DEFINITION_INVALID', 'The definition no longer passes validation', { issues });
    const published = await publishedOf(tx, app.id);
    const diff = diffDefinitions(normalized, published?.definition ?? null, published?.version ?? null);
    if (diff.hostChange && !body.acknowledgeHostChange) {
      throw new HttpError(409, 'HOST_CHANGE_UNACKNOWLEDGED', published ? 'This version changes where credentials are sent (api.baseUrl or allowedHosts). Confirm the new hosts to publish.' : 'First publication: confirm the hosts credentials will be sent to.', {
        baseUrl: normalized.api.baseUrl,
        allowedHosts: normalized.api.allowedHosts,
      });
    }
    const t = now();
    if (published) await tx.update(versions).set({ status: 'SUPERSEDED', updatedAt: t }).where(eq(versions.id, published.id));
    const signed = signDefinition(normalized);
    await tx
      .update(versions)
      .set({ status: 'PUBLISHED', definition: normalized, ...signed, reviewedBy: user.id, reviewedAt: t, reviewNote: body.note || null, publishedAt: t, updatedAt: t, hostChangeAcknowledged: diff.hostChange })
      .where(eq(versions.id, v.id));
    await registerActiveKey(tx);
    await addSignature(tx, v.id, signed.digest, signed.signature);
    await tx.update(applications).set({ name: normalized.name, description: normalized.description, updatedAt: t }).where(eq(applications.id, app.id));
    await audit(tx, user, 'version.published', { key: app.key, version: v.version }, { digest: signed.digest, keyId: signed.keyId, supersedes: published?.version ?? null, hostChange: diff.hostChange, hosts: normalized.api.allowedHosts });
    return detail(tx, user, app, { ...v, status: 'PUBLISHED', definition: normalized, ...signed, reviewedBy: user.id, reviewedAt: t, reviewNote: body.note || null, publishedAt: t });
  });
  res.json(out);
});

applicationsRouter.post('/applications/:key/versions/:version/reject', reviewers, async (req, res) => {
  const { note } = parse(z.object({ note: z.string().trim().min(3, 'Explain what needs to change').max(1000) }), req.body ?? {});
  const user = req.user!;
  const out = await transaction(async (tx) => {
    const app = await getApp(tx, String(req.params.key));
    const v = await getVersion(tx, app, Number(req.params.version), true);
    const block = reviewBlock(user, v);
    if (block) throw v.status !== 'IN_REVIEW' ? conflict(block, 'INVALID_STATE') : forbidden(block, 'SEPARATION_OF_DUTIES');
    const t = now();
    await tx.update(versions).set({ status: 'DRAFT', reviewedBy: user.id, reviewedAt: t, reviewNote: note, submittedBy: null, submittedAt: null, updatedAt: t }).where(eq(versions.id, v.id));
    await audit(tx, user, 'version.rejected', { key: app.key, version: v.version }, { note });
    return detail(tx, user, app, { ...v, status: 'DRAFT', reviewedBy: user.id, reviewedAt: t, reviewNote: note, submittedBy: null, submittedAt: null });
  });
  res.json(out);
});

applicationsRouter.post('/applications/:key/versions/:version/preview', async (req, res) => {
  const body = parse(
    z.object({ operation: z.string().min(1).max(100), resource: z.record(z.string().max(500)).default({}), input: z.record(z.unknown()).default({}) }),
    req.body ?? {},
  );
  const app = await getApp(db, String(req.params.key));
  const v = await getVersion(db, app, Number(req.params.version));
  const { normalized, issues } = check(v.definition);
  if (!normalized) throw new HttpError(400, 'DEFINITION_INVALID', 'Fix the validation problems to preview requests', { issues });
  res.json(preview(normalized, body.operation, body.resource, body.input));
});

/** Archived applications disappear from the catalog; their versions stay for the record. */
applicationsRouter.post('/applications/:key/archive', requireRole('ADMIN'), async (req, res) => {
  const { reason } = parse(z.object({ reason: z.string().trim().min(3, 'Give a reason').max(500) }), req.body ?? {});
  const user = req.user!;
  await transaction(async (tx) => {
    const app = await getApp(tx, String(req.params.key));
    if (app.archivedAt) throw conflict('Already archived', 'ARCHIVED');
    await tx.update(applications).set({ archivedAt: now(), updatedAt: now() }).where(eq(applications.id, app.id));
    await audit(tx, user, 'application.archived', { key: app.key }, { reason });
  });
  res.json({ ok: true });
});
