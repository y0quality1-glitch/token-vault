import { In, type EntityManager, type SelectQueryBuilder } from 'typeorm';
import type { CmsApplicationDetail, CmsApplicationSummary, CmsUser } from '@token-vault/shared';
import { ServiceError, notFound } from '../../core/ApiError';
import { newId, signDefinition } from '../../core/Crypto';
import type { Pagination } from '../../core/Y0Params';
import { CreateApplicationDto, type ArchiveDto, type AvailabilityDto, type NewVersionDto } from '../../databases/repository/application/application.dto';
import { ApplicationModel } from '../../databases/repository/application/application.model';
import { ApplicationEntity } from '../../entities/applicationEntity';
import { VersionEntity } from '../../entities/versionEntity';
import { audit } from '../auditService/auditService.service';
import { BaseServices } from '../baseService';
import { check, starterDefinition } from '../definitionService/definitionService.service';
import { addSignature, registerActiveKey } from '../signingService/signingService.service';
import { OPEN, getApp, now, summarize, toVersionSummary, versionsOf } from './application.queries';

/** Applications in the provider catalog: list, detail, create, new versions, availability, archive. */
export default class ApplicationService extends BaseServices<ApplicationEntity, CmsApplicationSummary> {
  constructor() {
    super(ApplicationEntity);
  }
  getModel() {
    return new ApplicationModel();
  }
  getDTO() {
    return CreateApplicationDto;
  }
  getModuleName() {
    return 'Application';
  }
  getGlobalSearchColumns() {
    return ['main.key', 'main.name', 'main.description'];
  }
  protected idColumn() {
    return 'key';
  }

  protected prepareFilter(qb: SelectQueryBuilder<ApplicationEntity>, param: Pagination) {
    return qb.orderBy('main.key', param.sortType ?? 'ASC').skip((param.pageNumber - 1) * param.pageSize).take(param.pageSize);
  }

  /** One query for the versions of every application on the page. */
  protected async postProcessAfterGetData(apps: ApplicationEntity[]): Promise<CmsApplicationSummary[]> {
    const rows = await this.db.manager.findBy(VersionEntity, { application_id: In(apps.map((a) => a.id)) });
    return apps.map((a) => summarize(a, rows.filter((v) => v.application_id === a.id)));
  }

  protected async postProcessAfterGetById(app: ApplicationEntity): Promise<CmsApplicationDetail> {
    const rows = await versionsOf(this.db.manager, app.id);
    return { ...summarize(app, rows), createdBy: app.created_by, createdAt: app.created_at, versions: rows.map(toVersionSummary) } as CmsApplicationDetail;
  }

  // ── create: a new application with a starter draft as version 1 ──
  protected async createPreProcess(m: EntityManager, model: ApplicationModel) {
    if (await m.existsBy(ApplicationEntity, { key: model.key })) {
      throw new ServiceError('E30010', `An application with key "${model.key}" already exists`, { fields: { key: 'This key is already in use' } });
    }
    return model;
  }

  protected async saveData(m: EntityManager, model: ApplicationModel, user: CmsUser) {
    const t = now();
    const app = m.create(ApplicationEntity, { id: newId('app'), key: model.key, name: model.name, description: model.description, created_by: user.fullName, created_at: t, updated_at: t, archived_at: null });
    await m.insert(ApplicationEntity, app);
    await m.insert(VersionEntity, { id: newId('ver'), application_id: app.id, version: 1, status: 'DRAFT', definition: starterDefinition(model.key, model.name, model.description), created_by: user.fullName, created_at: t, updated_at: t, authors: [user.id] });
    return app;
  }

  protected async createPostProcess(m: EntityManager, app: ApplicationEntity, _model: ApplicationModel, user: CmsUser) {
    await audit(m, user, 'application.created', { key: app.key, version: 1 }, { name: app.name });
    return { key: app.key, version: 1 };
  }

  // ── domain actions ─────────────────────────────────────────────

  /** Starts a new draft from the latest version (or a chosen one). Only one open version at a time. */
  async newVersion(body: NewVersionDto, user: CmsUser): Promise<{ key: string; version: number }> {
    return this.db.executeInTransaction(async (m) => {
      const app = await getApp(m, body.key);
      if (app.archived_at) throw new ServiceError('E30011');
      const rows = await versionsOf(m, app.id);
      const open = rows.find((v) => OPEN.includes(v.status));
      if (open) throw new ServiceError('E30012', `Version ${open.version} is still ${open.status === 'DRAFT' ? 'a draft' : 'in review'}; finish it first`);
      const base = body.from ? rows.find((v) => v.version === body.from) : rows[0];
      if (!base) throw notFound(`Version ${body.from}`);
      const version = (rows[0]?.version ?? 0) + 1;
      const t = now();
      await m.insert(VersionEntity, { id: newId('ver'), application_id: app.id, version, status: 'DRAFT', definition: { ...(base.definition as object), version }, created_by: user.fullName, created_at: t, updated_at: t, authors: [user.id] });
      await m.update(ApplicationEntity, { id: app.id }, { updated_at: t });
      await audit(m, user, 'version.created', { key: app.key, version }, { from: base.version });
      return { key: app.key, version };
    });
  }

  /**
   * One-click availability (administrators). Publishes the next version with only
   * catalog.availability changed: signed, audited, and picked up by Token Vault on its next
   * sync. Because nothing else can change (no hosts, auth or operations), this skips the
   * editor/publisher review. It is refused while a version is open: publishing past it would
   * leave the open version with a lower number, which consumers refuse as a rollback.
   */
  async setAvailability(body: AvailabilityDto, user: CmsUser): Promise<{ key: string; version: number; availability: string }> {
    return this.db.executeInTransaction(async (m) => {
      const app = await getApp(m, body.key);
      if (app.archived_at) throw new ServiceError('E30011');
      const rows = await versionsOf(m, app.id, true);
      const open = rows.find((v) => OPEN.includes(v.status));
      if (open) throw new ServiceError('E30012', `Version ${open.version} is ${open.status === 'DRAFT' ? 'a draft' : 'in review'}. Set the availability in that version, or withdraw it first.`);
      const published = rows.find((v) => v.status === 'PUBLISHED');
      if (!published) throw new ServiceError('E30019', 'Nothing is published yet: publish a first version through review');
      const current = published.definition as { catalog?: { availability?: string } };
      if ((current.catalog?.availability ?? 'available') === body.availability) throw new ServiceError('E30020', `It is already ${body.availability === 'available' ? 'available' : 'coming soon'}`);

      const version = rows[0]!.version + 1;
      const { normalized, issues } = check({ ...(published.definition as object), version, catalog: { ...(current.catalog ?? {}), availability: body.availability } });
      if (!normalized) throw new ServiceError('E30015', 'The published definition no longer passes validation; publish a corrected version through review', { issues });
      const t = now();
      const signed = signDefinition(normalized);
      await m.update(VersionEntity, { id: published.id }, { status: 'SUPERSEDED', updated_at: t });
      const id = newId('ver');
      const label = body.availability === 'available' ? 'available' : 'coming soon';
      await m.insert(VersionEntity, {
        id,
        application_id: app.id,
        version,
        status: 'PUBLISHED',
        definition: normalized,
        digest: signed.digest,
        signature: signed.signature,
        key_id: signed.keyId,
        created_by: user.fullName,
        created_at: t,
        updated_at: t,
        authors: [],
        reviewed_by: user.id,
        reviewed_at: t,
        review_note: `Availability changed to ${label} by an administrator; nothing else changed${body.note ? `. ${body.note}` : ''}`,
        published_at: t,
        host_change_acknowledged: false,
      });
      await registerActiveKey(m);
      await addSignature(m, id, signed.digest, signed.signature);
      await m.update(ApplicationEntity, { id: app.id }, { updated_at: t });
      await audit(m, user, 'version.published', { key: app.key, version }, { digest: signed.digest, keyId: signed.keyId, supersedes: published.version, availability: body.availability, oneClick: true, note: body.note || null });
      return { key: app.key, version, availability: body.availability };
    });
  }

  /** Archived applications disappear from the catalog; their versions stay for the record. */
  async archive(body: ArchiveDto, user: CmsUser): Promise<{ ok: true }> {
    await this.db.executeInTransaction(async (m) => {
      const app = await getApp(m, body.key);
      if (app.archived_at) throw new ServiceError('E30011', 'Already archived');
      const t = now();
      await m.update(ApplicationEntity, { id: app.id }, { archived_at: t, updated_at: t });
      await audit(m, user, 'application.archived', { key: app.key }, { reason: body.reason });
    });
    return { ok: true };
  }
}
