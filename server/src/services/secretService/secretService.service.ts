import type { EntityManager, SelectQueryBuilder } from 'typeorm';
import { In } from 'typeorm';
import {
  PERMISSIONS,
  RETRIEVABLE_SECRET_STATUSES,
  ROLE_PERMISSIONS,
  SECRET_STATUSES,
  SECRET_TRANSITIONS,
  validateSecretMetadata,
  validateSecretPayload,
  type Permission,
  type SecretDetail,
  type SecretPayload,
  type SecretRetrieval,
  type SecretStatus,
  type SecretTypeDefinition,
  type SecretVersionView,
  type SecretView,
} from '@token-vault/shared';
import { Pagination } from '../../core/Y0Params';
import { db, transaction } from '../../databases/client';
import type { RetrieveSecretDto, SaveSecretDto, SecretLifecycleDto, SecretVersionDto, UpdateSecretValueDto } from '../../databases/repository/secret/secret.dto';
import { SecretEntity, SecretVersionEntity } from '../../entities';
import { HttpError, badRequest, conflict, forbidden, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { webhookRepo } from '../../store/repos';
import type { WebhookRecord } from '../../store/types';
import { recordEvent, userActor } from '../auditService/auditService.service';
import { BaseServices, type OrgContext } from '../baseService';
import { getSecretType } from '../secretTypeService/registry';
import { WebhookUnavailableError, callWebhook } from '../webhookService/webhook.client';

/**
 * Secrets (Secret Management, spec 4.9.4–4.9.10, 4.9.13). The control plane keeps metadata and
 * version metadata; every value is stored, read, copied and destroyed by the customer webhook.
 * A value passes through here only in memory (create, new version, retrieval) and is never
 * written to this database, the logs or the audit log. Audit metadata deliberately avoids key
 * names that look secret-related (they would be redacted): the secret is the event's target.
 */

const DAY = 86_400_000;
const now = () => new Date().toISOString();
const addDays = (days: number) => new Date(Date.now() + days * DAY).toISOString();
const has = (ctx: OrgContext, p: Permission) => ROLE_PERMISSIONS[ctx.role!]?.includes(p) ?? false;
const expired = (s: Pick<SecretEntity, 'expiresAt'>) => !!s.expiresAt && Date.parse(s.expiresAt) <= Date.now();

/**
 * The status a secret is in now: a retrievable secret whose expiry has passed is EXPIRED even
 * before the background job records it (retrieval is refused either way, spec 4.9.12).
 */
export function effectiveStatus(s: Pick<SecretEntity, 'status' | 'expiresAt'>): SecretStatus {
  return RETRIEVABLE_SECRET_STATUSES.includes(s.status) && expired(s) ? 'EXPIRED' : s.status;
}

type Stored = { value_ref: string; version: number; fingerprint: string; summary: Record<string, string>; type_version: number; copied_from?: number };

/** Maps a webhook failure to a response that says what happened without revealing anything. */
function webhookFailure(e: unknown, what: string): never {
  if (e instanceof WebhookUnavailableError) throw new HttpError(503, 'WEBHOOK_UNAVAILABLE', `${e.message}. ${what}`);
  throw e;
}

function rejected(res: { status: number; body: any }, fieldsPrefix = 'payload'): never {
  const err = res.body?.error ?? {};
  if (res.status === 400 && err.code === 'SECRET_INVALID') {
    const fields = Object.fromEntries(Object.entries((err.details?.fields ?? {}) as Record<string, string>).map(([k, v]) => [`${fieldsPrefix}.${k}`, v]));
    throw badRequest('The value does not match its secret type', { fields });
  }
  if (res.status === 409 && err.code === 'SECRET_INVALID') throw new HttpError(409, 'SECRET_INVALID', err.message ?? 'That version no longer matches its secret type', { fields: err.details?.fields });
  if (res.status === 409) throw conflict(err.message ?? 'The secret changed meanwhile; reload and try again');
  if (res.status === 503) throw new HttpError(503, 'KEY_SERVICE_UNAVAILABLE', err.message ?? 'The customer key service is unavailable; retry shortly');
  if (res.status === 404) throw new HttpError(410, 'SECRET_VALUE_GONE', 'The customer webhook no longer holds this value');
  throw new HttpError(502, err.code ?? 'WEBHOOK_REJECTED', err.message ?? 'The customer webhook rejected the request');
}

export default class SecretService extends BaseServices<SecretEntity, SecretView> {
  constructor() {
    super(SecretEntity);
  }
  getModuleName() {
    return 'Secret';
  }
  getGlobalSearchColumns() {
    return ['main.name', 'main.description', 'main.type_key'];
  }

  // ── list (spec 4.9.13): metadata only, never a value ───────────

  /**
   * Filters (top-level string fields of the body): typeKey, category, project, workspace,
   * environment, status, tag, integrationId, createdFrom/To, updatedFrom/To, expiresBefore/After;
   * sortBy (name, createdAt, updatedAt, expiresAt) and sortOrder (asc, desc). Deleted secrets are
   * listed only when asked for (status=DELETED).
   */
  protected applyFilters(qb: SelectQueryBuilder<SecretEntity>, param: Pagination) {
    const f = param.filters;
    for (const [key, col] of [
      ['typeKey', 'type_key'],
      ['category', 'category'],
      ['project', 'project'],
      ['workspace', 'workspace'],
      ['environment', 'environment'],
      ['integrationId', 'integration_id'],
    ] as const) {
      if (f[key]) qb.andWhere(`main.${col} = :${key}`, { [key]: f[key] });
    }
    const status = f.status && (SECRET_STATUSES as readonly string[]).includes(f.status) ? f.status : null;
    if (status === 'EXPIRED') qb.andWhere(`(main.status = 'EXPIRED' OR (main.status IN (:...retrievable) AND main.expires_at <= now()))`, { retrievable: RETRIEVABLE_SECRET_STATUSES });
    else if (status && RETRIEVABLE_SECRET_STATUSES.includes(status as SecretStatus)) qb.andWhere(`main.status = :status AND (main.expires_at IS NULL OR main.expires_at > now())`, { status });
    else if (status) qb.andWhere('main.status = :status', { status });
    else qb.andWhere(`main.status <> 'DELETED'`);
    if (f.tag) qb.andWhere('main.tags @> :tag::jsonb', { tag: JSON.stringify([f.tag]) });
    const range = (key: string, col: string, op: '>=' | '<=') => {
      if (f[key] && !Number.isNaN(Date.parse(f[key]!))) qb.andWhere(`main.${col} ${op} :${key}`, { [key]: new Date(f[key]!).toISOString() });
    };
    range('createdFrom', 'created_at', '>=');
    range('createdTo', 'created_at', '<=');
    range('updatedFrom', 'updated_at', '>=');
    range('updatedTo', 'updated_at', '<=');
    range('expiresAfter', 'expires_at', '>=');
    range('expiresBefore', 'expires_at', '<=');
    const sortCol = ({ name: 'main.name', createdAt: 'main.created_at', updatedAt: 'main.updated_at', expiresAt: 'main.expires_at' } as Record<string, string>)[f.sortBy ?? ''] ?? 'main.created_at';
    const order = f.sortOrder === 'asc' ? 'ASC' : f.sortOrder === 'desc' ? 'DESC' : sortCol === 'main.name' ? 'ASC' : 'DESC';
    return qb.orderBy(sortCol, order, 'NULLS LAST').addOrderBy('main.id', 'ASC');
  }

  protected async postProcessAfterGetData(rows: SecretEntity[]): Promise<SecretView[]> {
    const active = await db.findBy(SecretVersionEntity, { secretId: In(rows.map((r) => r.id)), state: 'ACTIVE' });
    return rows.map((r) => this.view(r, active.find((v) => v.secretId === r.id) ?? null));
  }

  async list(orgId: string, body: unknown = {}) {
    const { records, totalRecords } = await this.getAll(orgId, body);
    return { items: records, total: totalRecords };
  }

  // ── views ──────────────────────────────────────────────────────

  private view(s: SecretEntity, active: SecretVersionEntity | null): SecretView {
    const type = getSecretType(s.typeKey);
    return {
      id: s.id,
      organizationId: s.organizationId,
      name: s.name,
      description: s.description,
      typeKey: s.typeKey,
      typeName: type?.name ?? s.typeKey,
      category: s.category,
      project: s.project,
      workspace: s.workspace,
      environment: s.environment,
      tags: s.tags,
      metadata: s.metadata,
      status: effectiveStatus(s),
      activeVersion: s.activeVersion,
      summary: active?.summary ?? {},
      fingerprint: active?.fingerprint ?? null,
      webhookId: s.webhookId,
      integrationId: s.integrationId,
      expiresAt: s.expiresAt,
      rotation: { enabled: s.rotationEnabled, intervalDays: s.rotationIntervalDays, nextRotationAt: s.nextRotationAt },
      lastRetrievedAt: s.lastRetrievedAt,
      createdBy: { id: s.createdBy, name: s.createdByName },
      createdAt: s.createdAt,
      updatedBy: { id: s.updatedBy, name: s.updatedByName },
      updatedAt: s.updatedAt,
    };
  }

  private versionView(v: SecretVersionEntity): SecretVersionView {
    return {
      id: v.id,
      version: v.version,
      state: v.state,
      fingerprint: v.fingerprint,
      summary: v.summary,
      typeVersion: v.typeVersion,
      reason: v.reason,
      copiedFrom: v.copiedFrom,
      createdBy: { id: v.createdBy, name: v.createdByName },
      createdAt: v.createdAt,
      destroyedAt: v.destroyedAt,
    };
  }

  async detail(ctx: OrgContext, id: string): Promise<SecretDetail> {
    const s = await this.secret(ctx.org.id, id);
    const versions = await db.find(SecretVersionEntity, { where: { secretId: s.id }, order: { version: 'DESC' } });
    const status = effectiveStatus(s);
    const live = status !== 'DELETED';
    return {
      ...this.view(s, versions.find((v) => v.state === 'ACTIVE') ?? null),
      versions: versions.map((v) => this.versionView(v)),
      can: {
        retrieve: has(ctx, PERMISSIONS.SECRET_RETRIEVE) && RETRIEVABLE_SECRET_STATUSES.includes(status),
        updateValue: has(ctx, PERMISSIONS.SECRET_UPDATE_VALUE) && !['REVOKED', 'ARCHIVED', 'DELETED'].includes(status),
        updateMetadata: has(ctx, PERMISSIONS.SECRET_UPDATE_METADATA) && live,
        manageVersions: has(ctx, PERMISSIONS.SECRET_MANAGE_VERSIONS) && live,
        activate: has(ctx, PERMISSIONS.SECRET_UPDATE_METADATA) && SECRET_TRANSITIONS.activate.includes(status),
        revoke: has(ctx, PERMISSIONS.SECRET_DELETE) && SECRET_TRANSITIONS.revoke.includes(status),
        archive: has(ctx, PERMISSIONS.SECRET_DELETE) && SECRET_TRANSITIONS.archive.includes(status),
        delete: has(ctx, PERMISSIONS.SECRET_DELETE) && SECRET_TRANSITIONS.delete.includes(status),
      },
    };
  }

  // ── lookups ────────────────────────────────────────────────────

  /** Org-scoped: a secret of another organization is not found. */
  private async secret(orgId: string, id: string, ex: EntityManager = db, lock = false): Promise<SecretEntity> {
    if (!id || !orgId) throw notFound('Secret');
    const q = ex.createQueryBuilder(SecretEntity, 's').where('s.id = :id AND s.organization_id = :orgId', { id, orgId });
    const s = await (lock ? q.setLock('pessimistic_write') : q).getOne();
    if (!s) throw notFound('Secret');
    return s;
  }

  private async webhookOf(orgId: string, s: Pick<SecretEntity, 'webhookId'>): Promise<WebhookRecord> {
    const w = await webhookRepo.getWebhook(orgId, s.webhookId);
    if (!w) throw new HttpError(409, 'WEBHOOK_NOT_FOUND', 'The webhook holding this secret no longer exists');
    return w;
  }

  /** The webhook a new secret goes to: the one asked for, else the organization's first connected one. */
  private async targetWebhook(orgId: string, webhookId?: string): Promise<WebhookRecord> {
    if (webhookId) {
      const w = await webhookRepo.getWebhook(orgId, webhookId);
      if (!w) throw badRequest('Request validation failed', { fields: { webhookId: 'Unknown webhook' } });
      if (w.status !== 'CONNECTED') throw new HttpError(409, 'WEBHOOK_NOT_CONNECTED', `Webhook "${w.name}" is ${w.status.toLowerCase()}. Verify connectivity before storing secrets.`);
      return w;
    }
    const w = (await webhookRepo.listWebhooks(orgId)).filter((x) => x.status === 'CONNECTED').sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0];
    if (!w) throw new HttpError(409, 'WEBHOOK_NOT_CONNECTED', 'Connect a customer webhook first: secret values are stored only there');
    return w;
  }

  private typeOf(key: string | undefined): SecretTypeDefinition {
    const type = key ? getSecretType(key) : undefined;
    if (!type) throw badRequest('Request validation failed', { fields: { typeKey: key ? 'Unknown secret type' : 'Choose a secret type' } });
    return type;
  }

  /** Checks a payload here first (the webhook checks it again): problems by field, never the value. */
  private checkPayload(type: SecretTypeDefinition, payload: unknown) {
    const { issues } = validateSecretPayload(type, payload);
    if (Object.keys(issues).length) throw badRequest('The value does not match its secret type', { fields: Object.fromEntries(Object.entries(issues).map(([k, v]) => [`payload.${k}`, v])) });
  }

  private checkMetadata(type: SecretTypeDefinition, metadata: unknown): SecretPayload {
    const { value, issues } = validateSecretMetadata(type, metadata);
    if (Object.keys(issues).length) throw badRequest('Request validation failed', { fields: Object.fromEntries(Object.entries(issues).map(([k, v]) => [`metadata.${k}`, v])) });
    return value;
  }

  private lifecycleSettings(type: SecretTypeDefinition, dto: Pick<SaveSecretDto, 'expiresAt' | 'rotationEnabled' | 'rotationIntervalDays'>, current?: SecretEntity) {
    const fields: Record<string, string> = {};
    let expiresAt = dto.expiresAt !== undefined ? dto.expiresAt : current ? current.expiresAt : type.defaults.expiresInDays ? addDays(type.defaults.expiresInDays) : null;
    if (expiresAt && !type.lifecycle.expiration) fields.expiresAt = `${type.name} secrets do not expire`;
    if (expiresAt) expiresAt = new Date(expiresAt).toISOString();
    const interval = dto.rotationIntervalDays !== undefined ? dto.rotationIntervalDays : current ? current.rotationIntervalDays : (type.defaults.rotationIntervalDays ?? null);
    const enabled = dto.rotationEnabled ?? current?.rotationEnabled ?? !!type.defaults.rotationIntervalDays;
    if (enabled && !type.lifecycle.rotation) fields.rotationEnabled = `${type.name} secrets are not rotated`;
    if (enabled && !interval) fields.rotationIntervalDays = 'Give a rotation interval in days';
    if (Object.keys(fields).length) throw badRequest('Request validation failed', { fields });
    const keepSchedule = current && current.rotationEnabled && current.rotationIntervalDays === interval && current.nextRotationAt;
    return { expiresAt, rotationEnabled: enabled, rotationIntervalDays: interval ?? null, nextRotationAt: enabled ? (keepSchedule ? current!.nextRotationAt : addDays(interval!)) : null };
  }

  private async nameTaken(ex: EntityManager, orgId: string, s: Pick<SecretEntity, 'project' | 'workspace' | 'environment' | 'name'>, exceptId?: string) {
    const q = ex
      .createQueryBuilder(SecretEntity, 's')
      .where(`s.organization_id = :orgId AND s.project = :project AND s.workspace = :workspace AND s.environment = :environment AND lower(s.name) = lower(:name) AND s.status <> 'DELETED'`, { orgId, ...s });
    if (exceptId) q.andWhere('s.id <> :exceptId', { exceptId });
    return (await q.getCount()) > 0;
  }

  // ── create (spec 4.9.4) ────────────────────────────────────────

  /** Validates, stores the value on the webhook, then records metadata and version 1 with the audit, atomically. */
  async create(ctx: OrgContext, dto: SaveSecretDto): Promise<SecretDetail> {
    const type = this.typeOf(dto.typeKey);
    const fields: Record<string, string> = {};
    if (!dto.environment) fields.environment = 'Choose development, staging or production';
    if (!dto.payload) fields.payload = 'Give the secret’s value';
    if (Object.keys(fields).length) throw badRequest('Request validation failed', { fields });
    this.checkPayload(type, dto.payload);
    const metadata = this.checkMetadata(type, dto.metadata);
    const lifecycle = this.lifecycleSettings(type, dto);
    const scope = { project: dto.project ?? 'default', workspace: dto.workspace ?? 'default', environment: dto.environment!, name: dto.name };
    if (await this.nameTaken(db, ctx.org.id, scope)) throw conflict(`A secret named "${dto.name}" already exists in ${scope.project}/${scope.workspace} (${scope.environment})`);
    const webhook = await this.targetWebhook(ctx.org.id, dto.webhookId);

    const id = newId('sec');
    const stored = await this.storeOnWebhook(webhook, ctx.org.id, id, 1, type, dto.payload!);
    const t = now();
    const actor = userActor(ctx);
    try {
      await transaction(async (ex) => {
        await ex.insert(SecretEntity, {
          id,
          organizationId: ctx.org.id,
          description: dto.description ?? '',
          typeKey: type.key,
          category: type.category,
          ...scope,
          tags: [...new Set(dto.tags ?? [])],
          metadata,
          status: dto.activate === false ? 'PENDING' : 'ACTIVE',
          activeVersion: 1,
          webhookId: webhook.id,
          integrationId: dto.integrationId ?? null,
          ...lifecycle,
          lastRetrievedAt: null,
          createdBy: ctx.user.id,
          createdByName: ctx.user.fullName,
          createdAt: t,
          updatedBy: ctx.user.id,
          updatedByName: ctx.user.fullName,
          updatedAt: t,
          deletedAt: null,
        });
        await ex.insert(SecretVersionEntity, this.versionRow(ctx, id, stored, 'Initial value', t));
        await recordEvent({ orgId: ctx.org.id, actor, eventType: 'secret.created', target: { type: 'secret', id, name: dto.name }, metadata: { typeKey: type.key, project: scope.project, workspace: scope.workspace, environment: scope.environment, version: 1, fingerprint: stored.fingerprint, status: dto.activate === false ? 'PENDING' : 'ACTIVE' } }, ex);
      });
    } catch (e) {
      // Nothing recorded here: remove the value the webhook just stored.
      await this.destroyOnWebhook(webhook, ctx.org.id, id, [stored.value_ref]).catch(() => undefined);
      if ((e as { code?: string; driverError?: { code?: string } }).driverError?.code === '23505') throw conflict(`A secret named "${dto.name}" already exists in ${scope.project}/${scope.workspace} (${scope.environment})`);
      throw e;
    }
    return this.detail(ctx, id);
  }

  private versionRow(ctx: OrgContext, secretId: string, stored: Stored, reason: string, t: string): Partial<SecretVersionEntity> {
    return {
      id: newId('secv'),
      secretId,
      organizationId: ctx.org.id,
      version: stored.version,
      valueRef: stored.value_ref,
      fingerprint: stored.fingerprint,
      summary: stored.summary,
      typeVersion: stored.type_version,
      state: 'ACTIVE',
      reason,
      copiedFrom: stored.copied_from ?? null,
      createdBy: ctx.user.id,
      createdByName: ctx.user.fullName,
      createdAt: t,
      destroyedAt: null,
    };
  }

  private async storeOnWebhook(webhook: WebhookRecord, orgId: string, secretId: string, version: number, type: SecretTypeDefinition, payload: Record<string, unknown>): Promise<Stored> {
    let res;
    try {
      res = await callWebhook<Stored & { error?: unknown }>(webhook, 'POST', '/internal/v1/secrets/store', { org_id: orgId, secret_id: secretId, version, type_key: type.key, payload });
    } catch (e) {
      webhookFailure(e, 'The value was not stored.');
    }
    if (res.status !== 201) rejected(res);
    return res.body;
  }

  private async destroyOnWebhook(webhook: WebhookRecord, orgId: string, secretId: string, refs: string[]): Promise<string[]> {
    if (!refs.length) return [];
    let res;
    try {
      res = await callWebhook<{ destroyed: string[] }>(webhook, 'POST', '/internal/v1/secrets/destroy', { org_id: orgId, secret_id: secretId, value_refs: refs });
    } catch (e) {
      webhookFailure(e, 'Nothing was destroyed.');
    }
    if (res.status !== 200) rejected(res);
    return res.body.destroyed ?? [];
  }

  // ── metadata (spec 4.9.7) ──────────────────────────────────────

  async updateMetadata(ctx: OrgContext, dto: SaveSecretDto): Promise<SecretDetail> {
    const ignored = (['typeKey', 'project', 'workspace', 'environment', 'payload', 'webhookId'] as const).filter((k) => dto[k] !== undefined);
    if (ignored.length) throw badRequest('Request validation failed', { fields: Object.fromEntries(ignored.map((k) => [k, k === 'payload' ? 'Use /secret/updateValue to change the value' : 'Cannot be changed on an existing secret'])) });
    await transaction(async (ex) => {
      const s = await this.secret(ctx.org.id, dto.id!, ex, true);
      if (s.status === 'DELETED') throw new HttpError(409, 'SECRET_DELETED', 'This secret is deleted');
      const type = this.typeOf(s.typeKey);
      const metadata = dto.metadata === undefined ? s.metadata : this.checkMetadata(type, dto.metadata);
      const lifecycle = this.lifecycleSettings(type, dto, s);
      if (dto.name !== s.name && (await this.nameTaken(ex, ctx.org.id, { ...s, name: dto.name }, s.id))) throw conflict(`A secret named "${dto.name}" already exists in ${s.project}/${s.workspace} (${s.environment})`);
      // Renewal (spec 4.9.12): an expired secret given a future expiry is active again.
      const renewed = effectiveStatus(s) === 'EXPIRED' && !!lifecycle.expiresAt && Date.parse(lifecycle.expiresAt) > Date.now();
      const changes = {
        name: dto.name,
        description: dto.description ?? s.description,
        tags: dto.tags ? [...new Set(dto.tags)] : s.tags,
        metadata,
        ...lifecycle,
        integrationId: dto.integrationId !== undefined ? dto.integrationId : s.integrationId,
        ...(renewed ? { status: 'ACTIVE' as const } : s.status !== effectiveStatus(s) ? { status: effectiveStatus(s) } : {}),
        updatedBy: ctx.user.id,
        updatedByName: ctx.user.fullName,
        updatedAt: now(),
      };
      await ex.update(SecretEntity, { id: s.id }, changes);
      const changed = Object.keys(changes).filter((k) => !['updatedBy', 'updatedByName', 'updatedAt'].includes(k) && JSON.stringify((changes as Record<string, unknown>)[k]) !== JSON.stringify((s as unknown as Record<string, unknown>)[k]));
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: renewed ? 'secret.renewed' : 'secret.updated', target: { type: 'secret', id: s.id, name: dto.name }, metadata: { changed, expiresAt: lifecycle.expiresAt, rotationEnabled: lifecycle.rotationEnabled, rotationIntervalDays: lifecycle.rotationIntervalDays } }, ex);
    });
    return this.detail(ctx, dto.id!);
  }

  // ── values and versions (spec 4.9.7, 4.9.8, 4.9.11) ─────────────

  /**
   * Stores a new version on the webhook and makes it active (the previous one stays, as
   * PREVIOUS, until destroyed). `copyFrom`: a rollback, whose value the webhook copies.
   */
  private async newVersion(ctx: OrgContext, id: string, opts: { payload?: Record<string, unknown>; copyFrom?: number; reason: string; eventType: string }): Promise<SecretDetail> {
    const s = await this.secret(ctx.org.id, id);
    const status = effectiveStatus(s);
    if (['REVOKED', 'ARCHIVED', 'DELETED'].includes(status)) throw new HttpError(409, 'SECRET_NOT_WRITABLE', `This secret is ${status.toLowerCase()}; its value cannot change`);
    const type = this.typeOf(s.typeKey);
    if (!type.lifecycle.versioning && opts.copyFrom) throw new HttpError(409, 'SECRET_VERSIONING_OFF', `${type.name} secrets keep no versions to roll back to`);
    const webhook = await this.webhookOf(ctx.org.id, s);
    const next = (s.activeVersion ?? 0) + 1;

    let stored: Stored;
    if (opts.copyFrom !== undefined) {
      const from = await db.findOneBy(SecretVersionEntity, { secretId: s.id, version: opts.copyFrom });
      if (!from) throw notFound(`Version ${opts.copyFrom}`);
      if (from.state === 'DESTROYED' || !from.valueRef) throw new HttpError(409, 'SECRET_VERSION_DESTROYED', `Version ${from.version} was destroyed`);
      if (from.state === 'ACTIVE') throw new HttpError(409, 'SECRET_VERSION_ACTIVE', `Version ${from.version} is already the active version`);
      let res;
      try {
        res = await callWebhook<Stored>(webhook, 'POST', '/internal/v1/secrets/copy', { org_id: ctx.org.id, secret_id: s.id, from_ref: from.valueRef, version: next });
      } catch (e) {
        webhookFailure(e, 'Nothing changed.');
      }
      if (res.status !== 201) rejected(res);
      stored = res.body;
    } else {
      this.checkPayload(type, opts.payload);
      stored = await this.storeOnWebhook(webhook, ctx.org.id, s.id, next, type, opts.payload!);
    }

    try {
      await transaction(async (ex) => {
        const locked = await this.secret(ctx.org.id, s.id, ex, true);
        if (locked.activeVersion !== s.activeVersion) throw conflict('Another version was stored meanwhile; reload and try again');
        const t = now();
        await ex.update(SecretVersionEntity, { secretId: s.id, state: 'ACTIVE' }, { state: 'PREVIOUS' });
        await ex.insert(SecretVersionEntity, this.versionRow(ctx, s.id, stored, opts.reason, t));
        const st = effectiveStatus(locked);
        await ex.update(
          SecretEntity,
          { id: s.id },
          {
            activeVersion: next,
            status: st === 'PENDING' || st === 'EXPIRED' ? st : 'ACTIVE',
            ...(locked.rotationEnabled && locked.rotationIntervalDays ? { nextRotationAt: addDays(locked.rotationIntervalDays) } : {}),
            updatedBy: ctx.user.id,
            updatedByName: ctx.user.fullName,
            updatedAt: t,
          },
        );
        await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: opts.eventType, target: { type: 'secret', id: s.id, name: s.name }, metadata: { version: next, previousVersion: s.activeVersion, fingerprint: stored.fingerprint, ...(opts.copyFrom ? { copiedFrom: opts.copyFrom } : {}), reason: opts.reason } }, ex);
      });
    } catch (e) {
      await this.destroyOnWebhook(webhook, ctx.org.id, s.id, [stored.value_ref]).catch(() => undefined);
      throw e;
    }
    return this.detail(ctx, s.id);
  }

  updateValue(ctx: OrgContext, dto: UpdateSecretValueDto) {
    return this.newVersion(ctx, dto.id, { payload: dto.payload, reason: dto.reason, eventType: 'secret.version_created' });
  }

  /** Manual rotation (spec 4.9.11): a new value, recorded as a rotation; the schedule restarts. */
  rotate(ctx: OrgContext, dto: UpdateSecretValueDto) {
    return this.newVersion(ctx, dto.id, { payload: dto.payload, reason: dto.reason || 'Manual rotation', eventType: 'secret.rotated' });
  }

  /** Rollback (spec 4.9.8): a new active version with an older version's value; history is not rewritten. */
  rollback(ctx: OrgContext, dto: SecretVersionDto) {
    return this.newVersion(ctx, dto.id, { copyFrom: dto.version, reason: dto.reason || `Rollback to version ${dto.version}`, eventType: 'secret.rolled_back' });
  }

  /** Destroys an inactive version on the webhook (crypto-shredding); its metadata stays. */
  async destroyVersion(ctx: OrgContext, dto: SecretVersionDto): Promise<SecretDetail> {
    const s = await this.secret(ctx.org.id, dto.id);
    const v = await db.findOneBy(SecretVersionEntity, { secretId: s.id, version: dto.version });
    if (!v) throw notFound(`Version ${dto.version}`);
    if (v.state === 'ACTIVE') throw new HttpError(409, 'SECRET_VERSION_ACTIVE', 'The active version cannot be destroyed; store a new value or roll back first');
    if (v.state === 'DESTROYED') throw new HttpError(409, 'SECRET_VERSION_DESTROYED', `Version ${v.version} was already destroyed`);
    await this.destroyOnWebhook(await this.webhookOf(ctx.org.id, s), ctx.org.id, s.id, [v.valueRef!]);
    await transaction(async (ex) => {
      await ex.update(SecretVersionEntity, { id: v.id }, { state: 'DESTROYED', valueRef: null, destroyedAt: now() });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret.version_destroyed', target: { type: 'secret', id: s.id, name: s.name }, metadata: { version: v.version, fingerprint: v.fingerprint, reason: dto.reason } }, ex);
    });
    return this.detail(ctx, s.id);
  }

  // ── retrieval (spec 4.9.6) ─────────────────────────────────────

  /**
   * Reveals a value to a member with secret:retrieve (checked here, so refusals are audited). Default deny: the secret must be in a
   * retrievable state and not expired; an older version needs secret:manage_versions. Every
   * refusal and every retrieval is audited (never the value).
   */
  async retrieve(ctx: OrgContext, dto: RetrieveSecretDto): Promise<SecretRetrieval> {
    const s = await this.secret(ctx.org.id, dto.id);
    const actor = userActor(ctx);
    const deny = async (code: string, status: number, message: string): Promise<never> => {
      await recordEvent({ orgId: ctx.org.id, actor, eventType: 'secret.access_denied', target: { type: 'secret', id: s.id, name: s.name }, outcome: 'DENIED', severity: 'warning', metadata: { reasonCode: code, version: dto.version ?? s.activeVersion } });
      throw new HttpError(status, code, message);
    };
    // Checked here rather than in the route, so a refused reveal is audited (spec 4.9.17).
    if (!has(ctx, PERMISSIONS.SECRET_RETRIEVE)) await deny('PERMISSION_DENIED', 403, `Your role (${ctx.role}) does not allow this action. Required: ${PERMISSIONS.SECRET_RETRIEVE}`);
    const status = effectiveStatus(s);
    if (status === 'EXPIRED') await deny('SECRET_EXPIRED', 409, 'This secret has expired; renew it or store a new value');
    if (!RETRIEVABLE_SECRET_STATUSES.includes(status)) await deny('SECRET_NOT_ACTIVE', 409, `This secret is ${status.toLowerCase().replace('_', ' ')} and cannot be retrieved`);
    const versionNo = dto.version ?? s.activeVersion;
    const v = versionNo ? await db.findOneBy(SecretVersionEntity, { secretId: s.id, version: versionNo }) : null;
    if (!v) throw notFound(`Version ${versionNo}`);
    if (v.state === 'DESTROYED' || !v.valueRef) await deny('SECRET_VERSION_DESTROYED', 410, `Version ${v.version} was destroyed`);
    if (v.state !== 'ACTIVE' && !has(ctx, PERMISSIONS.SECRET_MANAGE_VERSIONS)) await deny('SECRET_VERSION_NOT_PERMITTED', 403, 'Only the active version can be retrieved with your role');
    const type = getSecretType(s.typeKey);
    const unknown = type && dto.fields ? dto.fields.filter((f) => !type.fields[f]) : [];
    if (unknown.length) throw badRequest('Request validation failed', { fields: { fields: `Not a field of ${type!.name}: ${unknown.join(', ')}` } });

    let res;
    try {
      res = await callWebhook<{ version: number; payload: SecretPayload }>(await this.webhookOf(ctx.org.id, s), 'POST', '/internal/v1/secrets/read', { org_id: ctx.org.id, secret_id: s.id, value_ref: v.valueRef, ...(dto.fields?.length ? { fields: dto.fields } : {}) });
    } catch (e) {
      webhookFailure(e, 'Nothing was retrieved.');
    }
    if (res.status !== 200) rejected(res);
    const t = now();
    await transaction(async (ex) => {
      await ex.update(SecretEntity, { id: s.id }, { lastRetrievedAt: t });
      await recordEvent(
        {
          orgId: ctx.org.id,
          actor,
          eventType: v.state === 'ACTIVE' ? 'secret.retrieved' : 'secret.version_retrieved',
          target: { type: 'secret', id: s.id, name: s.name },
          severity: 'warning',
          metadata: { version: v.version, fingerprint: v.fingerprint, fieldsRequested: dto.fields ?? 'all', reason: dto.reason },
        },
        ex,
      );
    });
    return { id: s.id, name: s.name, typeKey: s.typeKey, version: v.version, payload: res.body.payload, expiresAt: s.expiresAt, retrievedAt: t };
  }

  // ── lifecycle (spec 4.9.10) ────────────────────────────────────

  private async transition(ctx: OrgContext, dto: SecretLifecycleDto, action: 'activate' | 'revoke' | 'archive', to: SecretStatus): Promise<SecretDetail> {
    await transaction(async (ex) => {
      const s = await this.secret(ctx.org.id, dto.id, ex, true);
      const from = effectiveStatus(s);
      if (!SECRET_TRANSITIONS[action].includes(from)) throw new HttpError(409, 'SECRET_INVALID_STATE', `A ${from.toLowerCase().replace('_', ' ')} secret cannot be ${action === 'activate' ? 'activated' : `${action}d`}`);
      if (action === 'activate' && expired(s)) throw new HttpError(409, 'SECRET_EXPIRED', 'Its expiry has passed; set a new expiry first');
      await ex.update(SecretEntity, { id: s.id }, { status: to, updatedBy: ctx.user.id, updatedByName: ctx.user.fullName, updatedAt: now() });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: `secret.${action === 'activate' ? 'activated' : `${action}d`}`, target: { type: 'secret', id: s.id, name: s.name }, severity: action === 'revoke' ? 'warning' : 'info', metadata: { from, to, reason: dto.reason } }, ex);
    });
    return this.detail(ctx, dto.id);
  }

  activate(ctx: OrgContext, dto: SecretLifecycleDto) {
    return this.transition(ctx, dto, 'activate', 'ACTIVE');
  }
  /** Revoked secrets are never returned by retrieval again (spec 4.9.10). */
  revoke(ctx: OrgContext, dto: SecretLifecycleDto) {
    return this.transition(ctx, dto, 'revoke', 'REVOKED');
  }
  archive(ctx: OrgContext, dto: SecretLifecycleDto) {
    return this.transition(ctx, dto, 'archive', 'ARCHIVED');
  }

  /**
   * Deletion: every stored version is destroyed on the webhook first (if the webhook cannot be
   * reached nothing changes); the metadata stays as a DELETED tombstone for the audit trail, and
   * the name becomes free again.
   */
  async remove(ctx: OrgContext, id: string): Promise<{ id: string; status: 'DELETED'; destroyedVersions: number }> {
    const s = await this.secret(ctx.org.id, id);
    const from = effectiveStatus(s);
    if (!SECRET_TRANSITIONS.delete.includes(from)) throw new HttpError(409, 'SECRET_INVALID_STATE', from === 'DELETED' ? 'Already deleted' : `Revoke the secret before deleting it (it is ${from.toLowerCase().replace('_', ' ')})`);
    const versions = await db.findBy(SecretVersionEntity, { secretId: s.id });
    const refs = versions.filter((v) => v.valueRef).map((v) => v.valueRef!);
    await this.destroyOnWebhook(await this.webhookOf(ctx.org.id, s), ctx.org.id, s.id, refs);
    await transaction(async (ex) => {
      const t = now();
      await ex.update(SecretVersionEntity, { secretId: s.id, state: In(['ACTIVE', 'PREVIOUS']) }, { state: 'DESTROYED', valueRef: null, destroyedAt: t });
      await ex.update(SecretEntity, { id: s.id }, { status: 'DELETED', activeVersion: null, deletedAt: t, updatedBy: ctx.user.id, updatedByName: ctx.user.fullName, updatedAt: t });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret.deleted', target: { type: 'secret', id: s.id, name: s.name }, severity: 'warning', metadata: { from, destroyedVersions: refs.length } }, ex);
    });
    return { id: s.id, status: 'DELETED', destroyedVersions: refs.length };
  }

  /** A permission the route cannot express on its own (save: create vs update). */
  static require(ctx: OrgContext, p: Permission) {
    if (!has(ctx, p)) throw forbidden(`Your role (${ctx.role}) does not allow this action. Required: ${p}`);
  }
}
