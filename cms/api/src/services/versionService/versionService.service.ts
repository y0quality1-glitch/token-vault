import type { EntityManager } from 'typeorm';
import type { CmsPreviewResult, CmsUser, CmsVersionDetail } from '@token-vault/shared';
import { ServiceError } from '../../core/ApiError';
import { signDefinition } from '../../core/Crypto';
import { SaveVersionDto, type PreviewDto, type RejectDto, type ReviewDto, type VersionRefDto } from '../../databases/repository/version/version.dto';
import { VersionModel } from '../../databases/repository/version/version.model';
import { ApplicationEntity } from '../../entities/applicationEntity';
import { VersionEntity } from '../../entities/versionEntity';
import { directPublishBlock, getApp, getVersion, now, publishedOf, reviewBlock, versionDetail } from '../applicationService/application.queries';
import { audit } from '../auditService/auditService.service';
import { BaseServices } from '../baseService';
import { check, diffDefinitions, preview } from '../definitionService/definitionService.service';
import { addSignature, registerActiveKey } from '../signingService/signingService.service';
import { SETTINGS } from '../../config';

/**
 * Versions of a definition and their review workflow:
 * DRAFT → (submit) IN_REVIEW → (approve by another publisher) PUBLISHED → SUPERSEDED,
 * with withdraw and reject back to DRAFT, and direct publication by administrators.
 */
export default class VersionService extends BaseServices<VersionEntity, CmsVersionDetail> {
  constructor() {
    super(VersionEntity);
  }
  getModel() {
    return new VersionModel();
  }
  getDTO() {
    return SaveVersionDto;
  }
  getModuleName() {
    return 'Version';
  }

  /** POST /version/getdatabyid: one version, with diff, signatures and what this user may do. */
  protected async prepareQueryById(ref: VersionRefDto, user: CmsUser): Promise<CmsVersionDetail> {
    const m = this.db.manager;
    const app = await getApp(m, ref.key);
    return versionDetail(m, user, app, await getVersion(m, app, ref.version));
  }

  // ── save: replace a draft's definition ─────────────────────────
  async updateDraft(model: VersionModel, user: CmsUser): Promise<CmsVersionDetail> {
    return this.db.executeInTransaction(async (m) => {
      const app = await getApp(m, model.key);
      const v = await getVersion(m, app, model.version, true);
      if (v.status !== 'DRAFT') throw new ServiceError('E30013', `Version ${v.version} is ${v.status.toLowerCase().replace('_', ' ')} and cannot be edited`);
      if (app.archived_at) throw new ServiceError('E30011');
      // The key and version are owned by the CMS, not the editor.
      const definition = { ...model.definition, key: app.key, version: v.version };
      const authors = v.authors.includes(user.id) ? v.authors : [...v.authors, user.id];
      await m.update(VersionEntity, { id: v.id }, { definition, updated_at: now(), authors });
      await audit(m, user, 'version.edited', { key: app.key, version: v.version }, { valid: check(definition).issues.length === 0 });
      return versionDetail(m, user, app, Object.assign(v, { definition, authors }));
    });
  }

  /** Locks the version for the rest of the transaction and runs `fn` on it. */
  private inTransaction<T>(ref: VersionRefDto, fn: (m: EntityManager, app: ApplicationEntity, v: VersionEntity) => Promise<T>): Promise<T> {
    return this.db.executeInTransaction(async (m) => {
      const app = await getApp(m, ref.key);
      return fn(m, app, await getVersion(m, app, ref.version, true));
    });
  }

  /** DRAFT → IN_REVIEW. The definition is normalized here, so reviewers see exactly what will be signed. */
  submit(ref: VersionRefDto, user: CmsUser) {
    return this.inTransaction(ref, async (m, app, v) => {
      if (v.status !== 'DRAFT') throw new ServiceError('E30014', 'Only drafts can be submitted for review');
      const { normalized, issues } = check(v.definition);
      if (!normalized) throw new ServiceError('E30015', 'Fix the validation problems before submitting', { issues });
      const t = now();
      const changes = { status: 'IN_REVIEW' as const, definition: normalized, submitted_by: user.id, submitted_at: t, updated_at: t, review_note: null };
      await m.update(VersionEntity, { id: v.id }, changes);
      await audit(m, user, 'version.submitted', { key: app.key, version: v.version });
      return versionDetail(m, user, app, Object.assign(v, changes));
    });
  }

  withdraw(ref: VersionRefDto, user: CmsUser) {
    return this.inTransaction(ref, async (m, app, v) => {
      if (v.status !== 'IN_REVIEW') throw new ServiceError('E30014', 'Only versions in review can be withdrawn');
      const changes = { status: 'DRAFT' as const, submitted_by: null, submitted_at: null, updated_at: now() };
      await m.update(VersionEntity, { id: v.id }, changes);
      await audit(m, user, 'version.withdrawn', { key: app.key, version: v.version });
      return versionDetail(m, user, app, Object.assign(v, changes));
    });
  }

  /**
   * IN_REVIEW → PUBLISHED: a publisher who neither authored nor submitted the version approves
   * it; it is signed and replaces the previously published version. A change of API host (or a
   * first publication) must be acknowledged, because it decides where customer credentials go.
   */
  approve(body: ReviewDto, user: CmsUser) {
    return this.inTransaction(body, async (m, app, v) => {
      const block = reviewBlock(user, v);
      if (block) throw new ServiceError(v.status !== 'IN_REVIEW' ? 'E30014' : 'E30016', block);
      return this.publishVersion(m, user, app, v, { note: body.note, acknowledgeHostChange: body.acknowledgeHostChange, direct: false });
    });
  }

  /**
   * DRAFT or IN_REVIEW → PUBLISHED in one step, by an administrator, without a second reviewer
   * (unless CMS_ADMIN_DIRECT_PUBLISH=false). Validation, host-change confirmation and signing are
   * the same as for an approval; the audit log records it as direct.
   */
  publish(body: ReviewDto, user: CmsUser) {
    return this.inTransaction(body, async (m, app, v) => {
      const issues = check(v.definition).issues;
      const block = directPublishBlock(user, app, v, issues);
      if (block) {
        if (!SETTINGS.adminDirectPublish) throw new ServiceError('E30017', block);
        if (app.archived_at) throw new ServiceError('E30011', block);
        if (v.status !== 'DRAFT' && v.status !== 'IN_REVIEW') throw new ServiceError('E30014', block);
        throw new ServiceError('E30015', block, { issues });
      }
      return this.publishVersion(m, user, app, v, { note: body.note, acknowledgeHostChange: body.acknowledgeHostChange, direct: true });
    });
  }

  /** Signs a version and makes it the published one (superseding the previous). */
  private async publishVersion(m: EntityManager, user: CmsUser, app: ApplicationEntity, v: VersionEntity, opts: { note: string; acknowledgeHostChange: boolean; direct: boolean }) {
    const { normalized, issues } = check(v.definition);
    if (!normalized) throw new ServiceError('E30015', 'The definition no longer passes validation', { issues });
    const published = await publishedOf(m, app.id);
    const diff = diffDefinitions(normalized, published?.definition ?? null, published?.version ?? null);
    if (diff.hostChange && !opts.acknowledgeHostChange) {
      throw new ServiceError('E30018', published ? 'This version changes where credentials are sent (api.baseUrl or allowedHosts). Confirm the new hosts to publish.' : 'First publication: confirm the hosts credentials will be sent to.', {
        baseUrl: normalized.api.baseUrl,
        allowedHosts: normalized.api.allowedHosts,
      });
    }
    const t = now();
    const reviewNote = opts.direct ? `Published directly by an administrator (no separate review)${opts.note ? `: ${opts.note}` : ''}` : opts.note || null;
    const submitted = v.submitted_by ? {} : { submitted_by: user.id, submitted_at: t };
    if (published) await m.update(VersionEntity, { id: published.id }, { status: 'SUPERSEDED', updated_at: t });
    const signed = signDefinition(normalized);
    const changes = {
      status: 'PUBLISHED' as const,
      definition: normalized,
      digest: signed.digest,
      signature: signed.signature,
      key_id: signed.keyId,
      ...submitted,
      reviewed_by: user.id,
      reviewed_at: t,
      review_note: reviewNote,
      published_at: t,
      updated_at: t,
      host_change_acknowledged: diff.hostChange,
    };
    await m.update(VersionEntity, { id: v.id }, changes);
    await registerActiveKey(m);
    await addSignature(m, v.id, signed.digest, signed.signature);
    await m.update(ApplicationEntity, { id: app.id }, { name: normalized.name, description: normalized.description, updated_at: t });
    await audit(m, user, 'version.published', { key: app.key, version: v.version }, { digest: signed.digest, keyId: signed.keyId, supersedes: published?.version ?? null, hostChange: diff.hostChange, hosts: normalized.api.allowedHosts, ...(opts.direct ? { direct: true } : {}) });
    return versionDetail(m, user, app, Object.assign(v, changes));
  }

  reject(body: RejectDto, user: CmsUser) {
    return this.inTransaction(body, async (m, app, v) => {
      const block = reviewBlock(user, v);
      if (block) throw new ServiceError(v.status !== 'IN_REVIEW' ? 'E30014' : 'E30016', block);
      const t = now();
      const changes = { status: 'DRAFT' as const, reviewed_by: user.id, reviewed_at: t, review_note: body.note, submitted_by: null, submitted_at: null, updated_at: t };
      await m.update(VersionEntity, { id: v.id }, changes);
      await audit(m, user, 'version.rejected', { key: app.key, version: v.version }, { note: body.note });
      return versionDetail(m, user, app, Object.assign(v, changes));
    });
  }

  /** What the webhook would send for an operation, without any credential. */
  async preview(body: PreviewDto): Promise<CmsPreviewResult> {
    const m = this.db.manager;
    const app = await getApp(m, body.key);
    const v = await getVersion(m, app, body.version);
    const { normalized, issues } = check(v.definition);
    if (!normalized) throw new ServiceError('E30015', 'Fix the validation problems to preview requests', { issues });
    return preview(normalized, body.operation, body.resource, body.input);
  }
}
