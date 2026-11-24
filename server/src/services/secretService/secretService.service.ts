import type { EntityManager, SelectQueryBuilder } from 'typeorm';
import { In } from 'typeorm';
import {
  PERMISSIONS,
  RETRIEVABLE_SECRET_STATUSES,
  ROLE_PERMISSIONS,
  SECRET_STATUSES,
  SECRET_PROVIDER_CAPABILITIES,
  SECRET_TRANSITIONS,
  generatableSecretFields,
  validateSecretMetadata,
  validateSecretPayload,
  type Permission,
  type SecretDetail,
  type SecretPayload,
  type SecretRetrieval,
  type SecretRotationJobView,
  type SecretRotationTrigger,
  type SecretStatus,
  type SecretTypeDefinition,
  type SecretVersionView,
  type SecretView,
} from '@token-vault/shared';
import { Pagination } from '../../core/Y0Params';
import { db, transaction } from '../../databases/client';
import type { RetrieveSecretDto, SaveSecretDto, SecretLifecycleDto, SecretVersionDto, UpdateSecretValueDto } from '../../databases/repository/secret/secret.dto';
import type { RotateSecretDto } from '../../databases/repository/secret/secretLifecycle.dto';
import { RotationJobEntity, SecretAccessGrantEntity, SecretEntity, SecretLeaseEntity, SecretVersionEntity } from '../../entities';
import { HttpError, badRequest, conflict, forbidden, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { webhookRepo } from '../../store/repos';
import type { WebhookRecord } from '../../store/types';
import { SYSTEM_ACTOR, recordEvent, userActor, type Actor } from '../auditService/auditService.service';
import { policiesOf, resolvePolicy } from '../secretPolicyService/secretPolicyService.service';
import { BaseServices, type OrgContext } from '../baseService';
import { customTypeRow, getSecretType, isCustomTypeKey, loadCustomTypes } from '../secretTypeService/registry';
import SecretLeaseService, { leaseView } from '../secretLeaseService/secretLeaseService.service';
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

/**
 * The status a live, retrievable secret should have for its expiry: EXPIRED once it has passed,
 * EXPIRING inside the warning window, otherwise ACTIVE (spec 4.9.12).
 */
export function expiryStatus(expiresAt: string | null, warningDays: number): 'ACTIVE' | 'EXPIRING' | 'EXPIRED' {
  if (!expiresAt) return 'ACTIVE';
  const left = Date.parse(expiresAt) - Date.now();
  return left <= 0 ? 'EXPIRED' : left <= warningDays * DAY ? 'EXPIRING' : 'ACTIVE';
}

/** Who writes: a member (from the request) or Token Vault itself (scheduled rotation, retention). */
export interface Writer {
  orgId: string;
  userId: string;
  userName: string;
  actor: Actor;
}
const writerOf = (ctx: OrgContext): Writer => ({ orgId: ctx.org.id, userId: ctx.user.id, userName: ctx.user.fullName, actor: userActor(ctx) });
export const systemWriter = (orgId: string): Writer => ({ orgId, userId: SYSTEM_ACTOR.id, userName: SYSTEM_ACTOR.name, actor: SYSTEM_ACTOR });

/** Rotation failures worth retrying (the webhook or its key service was unavailable). */
export const PROVIDER_FAILURE_CODES = ['WEBHOOK_UNAVAILABLE', 'KEY_SERVICE_UNAVAILABLE', 'PROVIDER_UNAVAILABLE'];

const leases = new SecretLeaseService();

/** Connection details kept as metadata (static database types): the webhook still checks them against its allow-list. */
const connectionOf = (s: Pick<SecretEntity, 'metadata'>) => {
  const m = s.metadata;
  return { ...(typeof m.host === 'string' ? { host: m.host } : {}), ...(typeof m.port === 'number' ? { port: m.port } : {}), ...(typeof m.database === 'string' ? { database: m.database } : {}) };
};
/** Custom types travel with each webhook request (they are not in the signed catalog). */
const typeDefinitionFor = (type: SecretTypeDefinition) => (isCustomTypeKey(type.key) ? { type_definition: type } : {});

export function rotationJobView(j: RotationJobEntity, secretName: string): SecretRotationJobView {
  return {
    id: j.id,
    secret: { id: j.secretId, name: secretName },
    trigger: j.trigger,
    strategy: j.strategy,
    status: j.status,
    attempts: j.attempts,
    fromVersion: j.fromVersion,
    toVersion: j.toVersion,
    errorCode: j.errorCode,
    errorMessage: j.errorMessage,
    requestedBy: j.requestedBy ? { id: j.requestedBy, name: j.requestedByName ?? '' } : null,
    scheduledFor: j.scheduledFor,
    startedAt: j.startedAt,
    finishedAt: j.finishedAt,
    nextAttemptAt: j.nextAttemptAt,
    createdAt: j.createdAt,
  };
}

const OPEN_JOB = In(['PENDING', 'RUNNING', 'WAITING_FOR_VALUE']);

type Stored = { value_ref: string; version: number; fingerprint: string; summary: Record<string, string>; type_version: number; copied_from?: number };

/** Maps a webhook failure to a response that says what happened without revealing anything. */
function webhookFailure(e: unknown, what: string): never {
  if (e instanceof WebhookUnavailableError) throw new HttpError(503, 'WEBHOOK_UNAVAILABLE', `${e.message}. ${what}`);
  throw e;
}

function rejected(res: { status: number; body: any }, fieldsPrefix = 'payload'): never {
  const err = res.body?.error ?? {};
  // Provider errors keep their code (PROVIDER_UNAVAILABLE is retried, the others are not).
  if (typeof err.code === 'string' && /^(PROVIDER_|LEASE_|SECRET_NOT_GENERATABLE)/.test(err.code)) throw new HttpError(res.status === 503 ? 503 : 409, err.code, err.message ?? 'The provider refused the request');
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
    if (rows.length) await loadCustomTypes(rows[0]!.organizationId);
    const active = await db.findBy(SecretVersionEntity, { secretId: In(rows.map((r) => r.id)), state: 'ACTIVE' });
    return rows.map((r) => this.view(r, active.find((v) => v.secretId === r.id) ?? null));
  }

  async list(orgId: string, body: unknown = {}) {
    const { records, totalRecords } = await this.getAll(orgId, body);
    return { items: records, total: totalRecords };
  }

  // ── views ──────────────────────────────────────────────────────

  private view(s: SecretEntity, active: SecretVersionEntity | null): SecretView {
    const type = getSecretType(s.typeKey, s.organizationId);
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
      rotation: {
        enabled: s.rotationEnabled,
        intervalDays: s.rotationIntervalDays,
        strategy: s.rotationStrategy,
        graceHours: s.rotationGraceHours,
        nextRotationAt: s.nextRotationAt,
        lastRotatedAt: s.lastRotatedAt,
        generatable: !!type && generatableSecretFields(type).length > 0,
        providerRotation: !!SECRET_PROVIDER_CAPABILITIES[s.typeKey]?.rotate,
      },
      provider: SECRET_PROVIDER_CAPABILITIES[s.typeKey] ? { capabilities: SECRET_PROVIDER_CAPABILITIES[s.typeKey]!, status: s.providerStatus, checkedAt: s.providerCheckedAt, error: s.providerError } : null,
      customType: isCustomTypeKey(s.typeKey),
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
      supersededAt: v.supersededAt,
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
    const jobs = await db.find(RotationJobEntity, { where: { secretId: s.id }, order: { createdAt: 'DESC' }, take: 10 });
    return {
      ...this.view(s, versions.find((v) => v.state === 'ACTIVE') ?? null),
      versions: versions.map((v) => this.versionView(v)),
      rotationJobs: jobs.map((j) => rotationJobView(j, s.name)),
      leases: SECRET_PROVIDER_CAPABILITIES[s.typeKey]?.lease ? (await db.find(SecretLeaseEntity, { where: { secretId: s.id }, order: { createdAt: 'DESC' }, take: 50 })).map((l) => leaseView(l, s)) : [],
      policy: resolvePolicy(await policiesOf(ctx.org.id), s, getSecretType(s.typeKey, s.organizationId)),
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

  /** Rotation history across the organization (newest first), optionally of one secret or status. */
  async rotations(orgId: string, body: { secretId?: unknown; status?: unknown } = {}): Promise<{ items: SecretRotationJobView[] }> {
    const q = db.createQueryBuilder(RotationJobEntity, 'j').where('j.organization_id = :orgId', { orgId }).orderBy('j.created_at', 'DESC').take(200);
    if (typeof body.secretId === 'string' && body.secretId) q.andWhere('j.secret_id = :secretId', { secretId: body.secretId });
    if (typeof body.status === 'string' && body.status) q.andWhere('j.status = :status', { status: body.status });
    const jobs = await q.getMany();
    const names = new Map((jobs.length ? await db.findBy(SecretEntity, { id: In([...new Set(jobs.map((j) => j.secretId))]) }) : []).map((s) => [s.id, s.name]));
    return { items: jobs.map((j) => rotationJobView(j, names.get(j.secretId) ?? j.secretId)) };
  }

  /**
   * Checks that the stored credential works at its provider (spec 4.9.16, provider health). A
   * change to FAILING is audited and notified (secret.provider_failure); recovery is audited.
   */
  async checkProvider(w: Writer, id: string): Promise<{ ok: boolean; detail: string; code: string | null; checkedAt: string }> {
    const s = await this.secret(w.orgId, id);
    if (!SECRET_PROVIDER_CAPABILITIES[s.typeKey]?.check) throw new HttpError(409, 'PROVIDER_NOT_SUPPORTED', 'The webhook cannot reach the provider of this secret type');
    const v = s.activeVersion ? await db.findOneBy(SecretVersionEntity, { secretId: s.id, version: s.activeVersion }) : null;
    if (!v?.valueRef) throw new HttpError(409, 'SECRET_VERSION_DESTROYED', 'This secret has no active value');
    let r: { ok: boolean; detail: string; code?: string };
    try {
      const res = await callWebhook<{ ok: boolean; detail: string; code?: string }>(await this.webhookOf(w.orgId, s), 'POST', '/internal/v1/secrets/provider-check', { org_id: w.orgId, secret_id: s.id, value_ref: v.valueRef, connection: connectionOf(s) });
      if (res.status !== 200) rejected(res);
      r = res.body;
    } catch (e) {
      const err = e instanceof WebhookUnavailableError ? new HttpError(503, 'WEBHOOK_UNAVAILABLE', e.message) : (e as HttpError);
      r = { ok: false, code: err.code ?? 'ERROR', detail: err.message };
    }
    const t = now();
    // A webhook not allowed to reach this host does not monitor it: no status, no failure notice.
    const status = r.ok ? 'OK' : r.code === 'PROVIDER_HOST_NOT_ALLOWED' ? null : 'FAILING';
    await transaction(async (ex) => {
      await ex.update(SecretEntity, { id: s.id }, { providerStatus: status, providerCheckedAt: t, providerError: r.ok ? null : `${r.code ?? 'ERROR'}: ${r.detail}`.slice(0, 300) });
      if (status === null) return;
      const target = { type: 'secret', id: s.id, name: s.name };
      if (!r.ok && s.providerStatus !== 'FAILING') await recordEvent({ orgId: w.orgId, actor: w.actor, eventType: 'secret.provider_failure', target, outcome: 'FAILURE', severity: 'warning', metadata: { errorCode: r.code ?? 'ERROR', reason: 'Connection check' } }, ex);
      else if (r.ok && s.providerStatus === 'FAILING') await recordEvent({ orgId: w.orgId, actor: w.actor, eventType: 'secret.provider_recovered', target, metadata: { reason: 'Connection check' } }, ex);
    });
    return { ok: r.ok, detail: r.detail, code: r.ok ? null : (r.code ?? 'ERROR'), checkedAt: t };
  }

  /** Writer for a member (controllers that call checkProvider and similar). */
  static writer(ctx: OrgContext): Writer {
    return writerOf(ctx);
  }

  // ── lookups ────────────────────────────────────────────────────

  /** Org-scoped: a secret of another organization is not found. */
  private async secret(orgId: string, id: string, ex: EntityManager = db, lock = false): Promise<SecretEntity> {
    if (!id || !orgId) throw notFound('Secret');
    await loadCustomTypes(orgId);
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

  private typeOf(key: string | undefined, orgId: string): SecretTypeDefinition {
    const type = key ? getSecretType(key, orgId) : undefined;
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

  private lifecycleSettings(type: SecretTypeDefinition, dto: Pick<SaveSecretDto, 'expiresAt' | 'rotationEnabled' | 'rotationIntervalDays' | 'rotationStrategy' | 'rotationGraceHours'>, current?: SecretEntity, defaultExpiresInDays?: number | null) {
    const fields: Record<string, string> = {};
    // A new secret without an expiry gets the policy's default (or the type's), spec 4.9.12.
    let expiresAt = dto.expiresAt !== undefined ? dto.expiresAt : current ? current.expiresAt : defaultExpiresInDays ? addDays(defaultExpiresInDays) : null;
    if (expiresAt && !type.lifecycle.expiration) fields.expiresAt = `${type.name} secrets do not expire`;
    if (expiresAt) expiresAt = new Date(expiresAt).toISOString();
    const interval = dto.rotationIntervalDays !== undefined ? dto.rotationIntervalDays : current ? current.rotationIntervalDays : (type.defaults.rotationIntervalDays ?? null);
    const enabled = dto.rotationEnabled ?? current?.rotationEnabled ?? !!type.defaults.rotationIntervalDays;
    if (enabled && !type.lifecycle.rotation) fields.rotationEnabled = `${type.name} secrets are not rotated`;
    if (enabled && !interval) fields.rotationIntervalDays = 'Give a rotation interval in days';
    const strategy = dto.rotationStrategy ?? current?.rotationStrategy ?? 'manual';
    if (strategy === 'generated' && !generatableSecretFields(type).length) fields.rotationStrategy = `${type.name} values cannot be generated by the webhook; use manual rotation`;
    if (strategy === 'provider' && !SECRET_PROVIDER_CAPABILITIES[type.key]?.rotate) fields.rotationStrategy = `The webhook cannot rotate ${type.name} secrets at their provider; use manual rotation`;
    if (Object.keys(fields).length) throw badRequest('Request validation failed', { fields });
    const keepSchedule = current && current.rotationEnabled && current.rotationIntervalDays === interval && current.nextRotationAt;
    return {
      expiresAt,
      rotationEnabled: enabled,
      rotationIntervalDays: interval ?? null,
      nextRotationAt: enabled ? (keepSchedule ? current!.nextRotationAt : addDays(interval!)) : null,
      rotationStrategy: strategy,
      rotationGraceHours: dto.rotationGraceHours ?? current?.rotationGraceHours ?? 24,
    };
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
  async create(ctx: OrgContext, dto: SaveSecretDto, opts: { source?: 'import' } = {}): Promise<SecretDetail> {
    await loadCustomTypes(ctx.org.id);
    const type = this.typeOf(dto.typeKey, ctx.org.id);
    if (customTypeRow(ctx.org.id, type.key)?.archivedAt) throw badRequest('Request validation failed', { fields: { typeKey: 'This custom type is archived' } });
    const fields: Record<string, string> = {};
    if (!dto.environment) fields.environment = 'Choose development, staging or production';
    if (!dto.payload) fields.payload = 'Give the secret’s value';
    if (Object.keys(fields).length) throw badRequest('Request validation failed', { fields });
    this.checkPayload(type, dto.payload);
    const metadata = this.checkMetadata(type, dto.metadata);
    const scope = { project: dto.project ?? 'default', workspace: dto.workspace ?? 'default', environment: dto.environment!, name: dto.name };
    const policy = resolvePolicy(await policiesOf(ctx.org.id), scope, type);
    const lifecycle = this.lifecycleSettings(type, dto, undefined, policy.defaultExpiresInDays.value);
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
          lastRotatedAt: null,
          lastRetrievedAt: null,
          createdBy: ctx.user.id,
          createdByName: ctx.user.fullName,
          createdAt: t,
          updatedBy: ctx.user.id,
          updatedByName: ctx.user.fullName,
          updatedAt: t,
          deletedAt: null,
        });
        await ex.insert(SecretVersionEntity, this.versionRow(writerOf(ctx), id, stored, 'Initial value', t));
        await recordEvent({ orgId: ctx.org.id, actor, eventType: 'secret.created', target: { type: 'secret', id, name: dto.name }, metadata: { typeKey: type.key, project: scope.project, workspace: scope.workspace, environment: scope.environment, version: 1, fingerprint: stored.fingerprint, status: dto.activate === false ? 'PENDING' : 'ACTIVE', ...(opts.source ? { source: opts.source } : {}) } }, ex);
      });
    } catch (e) {
      // Nothing recorded here: remove the value the webhook just stored.
      await this.destroyOnWebhook(webhook, ctx.org.id, id, [stored.value_ref]).catch(() => undefined);
      if ((e as { code?: string; driverError?: { code?: string } }).driverError?.code === '23505') throw conflict(`A secret named "${dto.name}" already exists in ${scope.project}/${scope.workspace} (${scope.environment})`);
      throw e;
    }
    return this.detail(ctx, id);
  }

  private versionRow(w: Writer, secretId: string, stored: Stored, reason: string, t: string): Partial<SecretVersionEntity> {
    return {
      id: newId('secv'),
      secretId,
      organizationId: w.orgId,
      version: stored.version,
      valueRef: stored.value_ref,
      fingerprint: stored.fingerprint,
      summary: stored.summary,
      typeVersion: stored.type_version,
      state: 'ACTIVE',
      reason,
      copiedFrom: stored.copied_from ?? null,
      createdBy: w.userId,
      createdByName: w.userName,
      createdAt: t,
      supersededAt: null,
      destroyedAt: null,
    };
  }

  private async storeOnWebhook(webhook: WebhookRecord, orgId: string, secretId: string, version: number, type: SecretTypeDefinition, payload: Record<string, unknown>): Promise<Stored> {
    let res;
    try {
      res = await callWebhook<Stored & { error?: unknown }>(webhook, 'POST', '/internal/v1/secrets/store', { org_id: orgId, secret_id: secretId, version, type_key: type.key, payload, ...typeDefinitionFor(type) });
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
      const type = this.typeOf(s.typeKey, s.organizationId);
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
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: renewed ? 'secret.renewed' : 'secret.updated', target: { type: 'secret', id: s.id, name: dto.name }, metadata: { changed, expiresAt: lifecycle.expiresAt, rotationEnabled: lifecycle.rotationEnabled, rotationIntervalDays: lifecycle.rotationIntervalDays, strategy: lifecycle.rotationStrategy } }, ex);
      // Rotation turned off: a rotation waiting for its value no longer applies.
      if (!lifecycle.rotationEnabled) await this.cancelOpenRotation(ex, s, 'Rotation turned off');
    });
    return this.detail(ctx, dto.id!);
  }

  // ── values and versions (spec 4.9.7, 4.9.8, 4.9.11) ─────────────

  /**
   * Stores a new version on the webhook and makes it active (the previous one stays, as
   * PREVIOUS, until destroyed). `copyFrom`: a rollback, whose value the webhook copies;
   * `generate`: the webhook creates fresh values for the type's generatable fields (rotation).
   * A new value completes a rotation in progress (its job is closed); a rotation also renews
   * the expiry when a policy or the type gives secrets a lifetime.
   */
  private async newVersion(w: Writer, id: string, opts: { payload?: Record<string, unknown>; copyFrom?: number; generate?: boolean; provider?: boolean; reason: string; eventType: string; trigger?: SecretRotationTrigger }): Promise<SecretEntity> {
    const s = await this.secret(w.orgId, id);
    const status = effectiveStatus(s);
    if (['REVOKED', 'ARCHIVED', 'DELETED'].includes(status)) throw new HttpError(409, 'SECRET_NOT_WRITABLE', `This secret is ${status.toLowerCase()}; its value cannot change`);
    const type = this.typeOf(s.typeKey, s.organizationId);
    if (!type.lifecycle.versioning && opts.copyFrom) throw new HttpError(409, 'SECRET_VERSIONING_OFF', `${type.name} secrets keep no versions to roll back to`);
    const webhook = await this.webhookOf(w.orgId, s);
    const next = (s.activeVersion ?? 0) + 1;
    const policy = resolvePolicy(await policiesOf(w.orgId), s, type);

    let stored: Stored;
    const fromRef = async (version: number, activeAllowed: boolean) => {
      const from = await db.findOneBy(SecretVersionEntity, { secretId: s.id, version });
      if (!from) throw notFound(`Version ${version}`);
      if (from.state === 'DESTROYED' || !from.valueRef) throw new HttpError(409, 'SECRET_VERSION_DESTROYED', `Version ${from.version} was destroyed`);
      if (from.state === 'ACTIVE' && !activeAllowed) throw new HttpError(409, 'SECRET_VERSION_ACTIVE', `Version ${from.version} is already the active version`);
      return from.valueRef;
    };
    const copyOrGenerate = async (path: string, ref: string) => {
      let res;
      try {
        res = await callWebhook<Stored>(webhook, 'POST', path, { org_id: w.orgId, secret_id: s.id, from_ref: ref, version: next, ...typeDefinitionFor(type), ...(path.endsWith('provider-rotate') ? { connection: connectionOf(s) } : {}) });
      } catch (e) {
        webhookFailure(e, 'Nothing changed.');
      }
      if (res.status !== 201) rejected(res);
      return res.body;
    };
    if (opts.copyFrom !== undefined) stored = await copyOrGenerate('/internal/v1/secrets/copy', await fromRef(opts.copyFrom, false));
    else if (opts.provider) {
      if (!SECRET_PROVIDER_CAPABILITIES[type.key]?.rotate) throw new HttpError(409, 'PROVIDER_NOT_SUPPORTED', `The webhook cannot rotate ${type.name} secrets at their provider`);
      if (!s.activeVersion) throw new HttpError(409, 'SECRET_VERSION_DESTROYED', 'This secret has no active version to rotate from');
      stored = await copyOrGenerate('/internal/v1/secrets/provider-rotate', await fromRef(s.activeVersion, true));
    } else if (opts.generate) {
      if (!generatableSecretFields(type).length) throw new HttpError(409, 'SECRET_NOT_GENERATABLE', `${type.name} values cannot be generated; give the new value`);
      if (!s.activeVersion) throw new HttpError(409, 'SECRET_VERSION_DESTROYED', 'This secret has no active version to rotate from');
      stored = await copyOrGenerate('/internal/v1/secrets/generate', await fromRef(s.activeVersion, true));
    } else {
      this.checkPayload(type, opts.payload);
      stored = await this.storeOnWebhook(webhook, w.orgId, s.id, next, type, opts.payload!);
    }

    const rotation = opts.eventType === 'secret.rotated';
    try {
      await transaction(async (ex) => {
        const locked = await this.secret(w.orgId, s.id, ex, true);
        if (locked.activeVersion !== s.activeVersion) throw conflict('Another version was stored meanwhile; reload and try again');
        const t = now();
        await ex.update(SecretVersionEntity, { secretId: s.id, state: 'ACTIVE' }, { state: 'PREVIOUS', supersededAt: t });
        await ex.insert(SecretVersionEntity, this.versionRow(w, s.id, stored, opts.reason, t));

        // A new value (not a rollback) completes the rotation in progress, if any.
        const job = opts.copyFrom === undefined ? await ex.findOne(RotationJobEntity, { where: { secretId: s.id, status: OPEN_JOB }, lock: { mode: 'pessimistic_write' } }) : null;
        const rotated = rotation || !!job;
        if (job) await ex.update(RotationJobEntity, { id: job.id }, { status: 'SUCCEEDED', fromVersion: s.activeVersion, toVersion: next, startedAt: job.startedAt ?? t, finishedAt: t, nextAttemptAt: null, errorCode: null, errorMessage: null });
        else if (rotation) await ex.insert(RotationJobEntity, { id: newId('rot'), organizationId: w.orgId, secretId: s.id, trigger: opts.trigger ?? 'MANUAL', strategy: opts.provider ? 'provider' : opts.generate ? 'generated' : 'manual', status: 'SUCCEEDED', attempts: 1, fromVersion: s.activeVersion, toVersion: next, errorCode: null, errorMessage: null, requestedBy: w.userId, requestedByName: w.userName, scheduledFor: t, startedAt: t, finishedAt: t, nextAttemptAt: null, createdAt: t });

        // Rotation renews the lifetime (expiration-based rotation, spec 4.9.12).
        const lifetime = policy.defaultExpiresInDays.value;
        const expiresAt = rotated && lifetime && locked.expiresAt ? addDays(lifetime) : locked.expiresAt;
        const st = effectiveStatus(locked);
        const nextStatus: SecretStatus =
          st === 'PENDING' ? 'PENDING' : opts.copyFrom !== undefined && st === 'ROTATION_PENDING' ? 'ROTATION_PENDING' : st === 'EXPIRED' && expiresAt === locked.expiresAt ? 'EXPIRED' : expiryStatus(expiresAt, policy.expiryWarningDays.value);
        await ex.update(
          SecretEntity,
          { id: s.id },
          {
            activeVersion: next,
            status: nextStatus,
            expiresAt,
            ...(locked.rotationEnabled && locked.rotationIntervalDays ? { nextRotationAt: addDays(locked.rotationIntervalDays) } : {}),
            ...(rotated ? { lastRotatedAt: t } : {}),
            updatedBy: w.userId,
            updatedByName: w.userName,
            updatedAt: t,
          },
        );
        const eventType = job && !rotation ? 'secret.rotated' : opts.eventType;
        await recordEvent(
          {
            orgId: w.orgId,
            actor: w.actor,
            eventType,
            target: { type: 'secret', id: s.id, name: s.name },
            metadata: {
              version: next,
              previousVersion: s.activeVersion,
              fingerprint: stored.fingerprint,
              ...(opts.copyFrom ? { copiedFrom: opts.copyFrom } : {}),
              ...(rotated ? { trigger: job?.trigger ?? opts.trigger ?? 'MANUAL', strategy: opts.provider ? 'provider' : opts.generate ? 'generated' : 'manual', ...(expiresAt !== locked.expiresAt ? { expiresAt } : {}) } : {}),
              reason: opts.reason,
            },
          },
          ex,
        );
      });
    } catch (e) {
      await this.destroyOnWebhook(webhook, w.orgId, s.id, [stored.value_ref]).catch(() => undefined);
      throw e;
    }
    return (await db.findOneBy(SecretEntity, { id: s.id }))!;
  }

  /** Closes a rotation that will not happen (rotation turned off, secret revoked). */
  private async cancelOpenRotation(ex: EntityManager, s: SecretEntity, why: string) {
    const job = await ex.findOneBy(RotationJobEntity, { secretId: s.id, status: OPEN_JOB });
    if (!job) return;
    await ex.update(RotationJobEntity, { id: job.id }, { status: 'CANCELLED', errorMessage: why, finishedAt: now(), nextAttemptAt: null });
    if (s.status === 'ROTATION_PENDING' || s.status === 'ROTATING') await ex.update(SecretEntity, { id: s.id }, { status: 'ACTIVE' });
  }

  async updateValue(ctx: OrgContext, dto: UpdateSecretValueDto) {
    await this.newVersion(writerOf(ctx), dto.id, { payload: dto.payload, reason: dto.reason || '', eventType: 'secret.version_created' });
    return this.detail(ctx, dto.id);
  }

  /**
   * Rotate now (spec 4.9.11): with a payload, the given value; without, the webhook generates it
   * (types with generatable fields). Recorded as a rotation, with a rotation job; the schedule
   * restarts. A failed generated rotation is recorded (and notified) before the error is returned.
   */
  async rotate(ctx: OrgContext, dto: RotateSecretDto) {
    const w = writerOf(ctx);
    if (dto.payload) {
      await this.newVersion(w, dto.id, { payload: dto.payload, reason: dto.reason || 'Manual rotation', eventType: 'secret.rotated', trigger: 'MANUAL' });
      return this.detail(ctx, dto.id);
    }
    const s = await this.secret(ctx.org.id, dto.id);
    const provider = s.rotationStrategy === 'provider' || (!generatableSecretFields(this.typeOf(s.typeKey, s.organizationId)).length && !!SECRET_PROVIDER_CAPABILITIES[s.typeKey]?.rotate);
    try {
      await this.newVersion(w, dto.id, { generate: !provider, provider, reason: dto.reason || (provider ? 'Manual rotation at the provider' : 'Manual rotation (generated value)'), eventType: 'secret.rotated', trigger: 'MANUAL' });
    } catch (e) {
      if (e instanceof HttpError && !['SECRET_NOT_WRITABLE', 'CONFLICT', 'NOT_FOUND'].includes(e.code)) await this.recordRotationFailure(w, s, e, { trigger: 'MANUAL', final: true, strategy: provider ? 'provider' : 'generated' });
      throw e;
    }
    return this.detail(ctx, dto.id);
  }

  /**
   * Runs a generated rotation for the lifecycle job (scheduled or before expiry). On failure the
   * job is retried later when the webhook or its key service was unavailable (up to 3 attempts),
   * otherwise it fails at once; either way the previous version stays active.
   */
  async runRotationJob(jobId: string): Promise<'SUCCEEDED' | 'RETRY' | 'FAILED' | 'SKIPPED'> {
    const job = await db.findOneBy(RotationJobEntity, { id: jobId });
    if (!job || job.status !== 'PENDING') return 'SKIPPED';
    const s = await db.findOneBy(SecretEntity, { id: job.secretId });
    if (!s || !RETRIEVABLE_SECRET_STATUSES.includes(effectiveStatus(s))) {
      await db.update(RotationJobEntity, { id: job.id }, { status: 'CANCELLED', errorMessage: 'The secret is no longer active', finishedAt: now(), nextAttemptAt: null });
      return 'SKIPPED';
    }
    const t = now();
    await db.update(RotationJobEntity, { id: job.id }, { status: 'RUNNING', attempts: job.attempts + 1, startedAt: job.startedAt ?? t });
    await db.update(SecretEntity, { id: s.id }, { status: 'ROTATING' });
    const w = systemWriter(s.organizationId);
    try {
      const provider = job.strategy === 'provider';
      await this.newVersion(w, s.id, { generate: !provider, provider, reason: `${job.trigger === 'EXPIRY' ? 'Rotation before expiry' : 'Scheduled rotation'}${provider ? ' at the provider' : ''}`, eventType: 'secret.rotated', trigger: job.trigger });
      return 'SUCCEEDED';
    } catch (e) {
      const attempts = job.attempts + 1;
      const retry = PROVIDER_FAILURE_CODES.includes((e as HttpError).code) && attempts < 3;
      await this.recordRotationFailure(w, s, e, { trigger: job.trigger, final: !retry, jobId: job.id, attempts });
      return retry ? 'RETRY' : 'FAILED';
    }
  }

  /** Records a failed rotation: the job, the secret's status back to normal, audit and notification. */
  private async recordRotationFailure(w: Writer, s: SecretEntity, e: unknown, opts: { trigger: SecretRotationTrigger; final: boolean; jobId?: string; attempts?: number; strategy?: 'generated' | 'provider' }) {
    const err = e instanceof HttpError ? e : new HttpError(500, 'ROTATION_FAILED', 'The rotation failed');
    const policy = resolvePolicy(await policiesOf(w.orgId), s, getSecretType(s.typeKey, s.organizationId));
    const t = now();
    const retryAt = new Date(Date.now() + ((opts.attempts ?? 1) === 1 ? 15 : 60) * 60_000).toISOString();
    await transaction(async (ex) => {
      const locked = await this.secret(w.orgId, s.id, ex, true);
      // A manual attempt that fails is its own record: a rotation already waiting for its value stays open.
      const job = opts.jobId ? await ex.findOneBy(RotationJobEntity, { id: opts.jobId }) : null;
      const jobChanges = { errorCode: err.code, errorMessage: err.message.slice(0, 300), ...(opts.final ? { status: 'FAILED' as const, finishedAt: t, nextAttemptAt: null } : { status: 'PENDING' as const, nextAttemptAt: retryAt }) };
      if (job) await ex.update(RotationJobEntity, { id: job.id }, { ...jobChanges, attempts: opts.attempts ?? job.attempts + 1 });
      else await ex.insert(RotationJobEntity, { id: newId('rot'), organizationId: w.orgId, secretId: s.id, trigger: opts.trigger, strategy: opts.strategy ?? 'generated', attempts: 1, fromVersion: s.activeVersion, toVersion: null, requestedBy: w.userId, requestedByName: w.userName, scheduledFor: t, startedAt: t, createdAt: t, ...jobChanges, status: 'FAILED', finishedAt: t, nextAttemptAt: null });
      // The previous version stays active; the secret goes back to its normal state.
      if (locked.status === 'ROTATING') await ex.update(SecretEntity, { id: s.id }, { status: expiryStatus(locked.expiresAt, policy.expiryWarningDays.value) });
      // A failed scheduled rotation is tried again tomorrow, not on every run of the job.
      if (opts.final && opts.trigger !== 'MANUAL' && locked.rotationEnabled) await ex.update(SecretEntity, { id: s.id }, { nextRotationAt: addDays(1) });
      const target = { type: 'secret', id: s.id, name: s.name };
      if (PROVIDER_FAILURE_CODES.includes(err.code)) await recordEvent({ orgId: w.orgId, actor: w.actor, eventType: 'secret.provider_failure', target, outcome: 'FAILURE', severity: 'warning', metadata: { errorCode: err.code, trigger: opts.trigger, attempts: opts.attempts ?? 1, ...(opts.final ? {} : { nextAttemptAt: retryAt }) } }, ex);
      if (opts.final) await recordEvent({ orgId: w.orgId, actor: w.actor, eventType: 'secret.rotation_failed', target, outcome: 'FAILURE', severity: 'warning', metadata: { errorCode: err.code, trigger: opts.trigger, attempts: opts.attempts ?? 1, version: s.activeVersion } }, ex);
    });
  }

  /** Rollback (spec 4.9.8): a new active version with an older version's value; history is not rewritten. */
  async rollback(ctx: OrgContext, dto: SecretVersionDto) {
    await this.newVersion(writerOf(ctx), dto.id, { copyFrom: dto.version, reason: dto.reason || `Rollback to version ${dto.version}`, eventType: 'secret.rolled_back' });
    return this.detail(ctx, dto.id);
  }

  /**
   * Destroys versions on the webhook for the retention policy (system actor), each audited.
   * Returns how many were destroyed.
   */
  async destroyForRetention(s: SecretEntity, versions: SecretVersionEntity[], why: string): Promise<number> {
    const refs = versions.filter((v) => v.valueRef && v.state === 'PREVIOUS').map((v) => v.valueRef!);
    if (!refs.length) return 0;
    const destroyed = new Set(await this.destroyOnWebhook(await this.webhookOf(s.organizationId, s), s.organizationId, s.id, refs));
    // A ref the webhook no longer had is gone too.
    const gone = versions.filter((v) => v.valueRef && (destroyed.has(v.valueRef) || refs.includes(v.valueRef)));
    await transaction(async (ex) => {
      const t = now();
      for (const v of gone) {
        await ex.update(SecretVersionEntity, { id: v.id, state: 'PREVIOUS' }, { state: 'DESTROYED', valueRef: null, destroyedAt: t });
        await recordEvent({ orgId: s.organizationId, actor: SYSTEM_ACTOR, eventType: 'secret.version_destroyed', target: { type: 'secret', id: s.id, name: s.name }, metadata: { version: v.version, fingerprint: v.fingerprint, reason: why } }, ex);
      }
    });
    return gone.length;
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
    const type = getSecretType(s.typeKey, s.organizationId);
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
      if (action !== 'activate') await this.cancelOpenRotation(ex, s, `Secret ${action}d`);
      await ex.update(SecretEntity, { id: s.id }, { status: to, updatedBy: ctx.user.id, updatedByName: ctx.user.fullName, updatedAt: now() });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: `secret.${action === 'activate' ? 'activated' : `${action}d`}`, target: { type: 'secret', id: s.id, name: s.name }, severity: action === 'revoke' ? 'warning' : 'info', metadata: { from, to, reason: dto.reason } }, ex);
    });
    // Short-lived credentials issued from a revoked secret end with it (failures are retried by the lifecycle job).
    if (action === 'revoke') await leases.revokeAllFor((await db.findOneByOrFail(SecretEntity, { id: dto.id }))!, userActor(ctx), 'Secret revoked');
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
    // Leases must end at the provider while the credential that created them still exists.
    if ((await leases.revokeAllFor(s, userActor(ctx), 'Secret deleted')) > 0) throw new HttpError(409, 'LEASES_NOT_REVOKED', 'Some leases could not be ended at the provider; nothing was deleted. Retry when the provider is reachable');
    const versions = await db.findBy(SecretVersionEntity, { secretId: s.id });
    const refs = versions.filter((v) => v.valueRef).map((v) => v.valueRef!);
    await this.destroyOnWebhook(await this.webhookOf(ctx.org.id, s), ctx.org.id, s.id, refs);
    await transaction(async (ex) => {
      const t = now();
      await ex.update(SecretVersionEntity, { secretId: s.id, state: In(['ACTIVE', 'PREVIOUS']) }, { state: 'DESTROYED', valueRef: null, destroyedAt: t });
      await this.cancelOpenRotation(ex, s, 'Secret deleted');
      await ex.update(SecretEntity, { id: s.id }, { status: 'DELETED', activeVersion: null, deletedAt: t, updatedBy: ctx.user.id, updatedByName: ctx.user.fullName, updatedAt: t });
      // Grants naming this secret end with it (selector grants simply stop matching it).
      await ex.update(SecretAccessGrantEntity, { secretId: s.id, status: 'ACTIVE' }, { status: 'REVOKED', revokedAt: t, revokedBy: ctx.user.fullName, revocationReason: 'Secret deleted' });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret.deleted', target: { type: 'secret', id: s.id, name: s.name }, severity: 'warning', metadata: { from, destroyedVersions: refs.length } }, ex);
    });
    return { id: s.id, status: 'DELETED', destroyedVersions: refs.length };
  }

  /** A permission the route cannot express on its own (save: create vs update). */
  static require(ctx: OrgContext, p: Permission) {
    if (!has(ctx, p)) throw forbidden(`Your role (${ctx.role}) does not allow this action. Required: ${p}`);
  }
}
