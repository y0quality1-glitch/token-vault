import { createCipheriv, createHash, randomBytes, scrypt } from 'node:crypto';
import { promisify } from 'node:util';
import { In } from 'typeorm';
import { PERMISSIONS, ROLE_PERMISSIONS, type SecretExportFile, type SecretExportRequestView, type SecretPayload } from '@token-vault/shared';
import { config } from '../../config';
import { db, transaction } from '../../databases/client';
import { SecretEntity, SecretExportRequestEntity, SecretVersionEntity } from '../../entities';
import { HttpError, badRequest, forbidden, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { webhookRepo } from '../../store/repos';
import { recordEvent, userActor } from '../auditService/auditService.service';
import type { OrgContext } from '../baseService';
import { WebhookUnavailableError, callWebhook } from '../webhookService/webhook.client';

/**
 * Export of secret values (spec 4.9.14), a privileged workflow:
 *  1. disabled unless SECRET_EXPORT_ENABLED=true on the control plane;
 *  2. requested by a member with secret:export (at most 100 secrets; rate-limited per member and
 *     per organization);
 *  3. approved by another member with secret:manage_access (never the requester), valid 1 hour;
 *  4. prepared by the requester with a passphrase: the values are read from the customer webhook
 *     and encrypted (scrypt + AES-256-GCM) into a file only that passphrase opens;
 *  5. downloaded once by the requester through a link valid 10 minutes; the file is then deleted.
 * Every step, and every secret exported, is audited. `scripts/decrypt-export.mjs` opens a file.
 */

const APPROVAL_VALID_MS = 60 * 60_000;
const DOWNLOAD_VALID_MS = 10 * 60_000;
const MAX_SECRETS = 100;
const PER_MEMBER_PER_DAY = 5;
const PER_ORG_PER_DAY = 20;
const KDF = { N: 32_768, r: 8, p: 1 };
const scryptAsync = promisify(scrypt) as (password: string, salt: Buffer, keylen: number, opts: object) => Promise<Buffer>;

const now = () => new Date().toISOString();
const has = (ctx: OrgContext, p: string) => ROLE_PERMISSIONS[ctx.role!]?.includes(p as never) ?? false;
const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');

function enabled() {
  if (!config.secretExportEnabled) throw new HttpError(403, 'EXPORT_DISABLED', 'Exporting secret values is turned off for this control plane (SECRET_EXPORT_ENABLED)');
}

/** Encrypts the export with a key derived from the passphrase; the export id is bound as additional data. */
export async function encryptExport(plaintext: string, passphrase: string, exportId: string): Promise<SecretExportFile> {
  const salt = randomBytes(16);
  const key = await scryptAsync(passphrase, salt, 32, { ...KDF, maxmem: 128 * KDF.N * KDF.r * 2 });
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(exportId));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    format: 'token-vault-secret-export/v1',
    kdf: { name: 'scrypt', ...KDF, salt: salt.toString('base64') },
    cipher: { name: 'aes-256-gcm', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') },
    ciphertext: ct.toString('base64'),
    exportId,
    createdAt: now(),
  };
}

export default class SecretExportService {
  private effectiveStatus(r: SecretExportRequestEntity) {
    return (r.status === 'APPROVED' || r.status === 'READY') && r.expiresAt && Date.parse(r.expiresAt) <= Date.now() ? 'EXPIRED' : r.status;
  }

  private async views(ctx: OrgContext, rows: SecretExportRequestEntity[]): Promise<SecretExportRequestView[]> {
    const ids = [...new Set(rows.flatMap((r) => r.secretIds))];
    const names = new Map((ids.length ? await db.findBy(SecretEntity, { id: In(ids) }) : []).map((s) => [s.id, s.name]));
    return rows.map((r) => {
      const status = this.effectiveStatus(r);
      const mine = r.requestedBy === ctx.user.id;
      return {
        id: r.id,
        requestedBy: { id: r.requestedBy, name: r.requestedByName },
        secrets: r.secretIds.map((id) => ({ id, name: names.get(id) ?? id })),
        reason: r.reason,
        status,
        createdAt: r.createdAt,
        decidedBy: r.decidedBy ? { id: r.decidedBy, name: r.decidedByName ?? '' } : null,
        decidedAt: r.decidedAt,
        note: r.note,
        expiresAt: status === 'APPROVED' || status === 'READY' ? r.expiresAt : null,
        downloadedAt: r.downloadedAt,
        can: { decide: status === 'PENDING' && !mine && has(ctx, PERMISSIONS.SECRET_MANAGE_ACCESS), prepare: status === 'APPROVED' && mine, download: status === 'READY' && mine },
      };
    });
  }

  async list(ctx: OrgContext): Promise<{ items: SecretExportRequestView[]; enabled: boolean }> {
    const rows = await db.find(SecretExportRequestEntity, { where: { organizationId: ctx.org.id }, order: { createdAt: 'DESC' }, take: 100 });
    return { items: await this.views(ctx, rows), enabled: config.secretExportEnabled };
  }

  private async one(ctx: OrgContext, id: string) {
    const r = typeof id === 'string' && id ? await db.findOneBy(SecretExportRequestEntity, { id, organizationId: ctx.org.id }) : null;
    if (!r) throw notFound('Export request');
    return r;
  }

  async request(ctx: OrgContext, body: { secretIds?: unknown; reason?: unknown }): Promise<SecretExportRequestView> {
    enabled();
    const ids = Array.isArray(body.secretIds) ? [...new Set(body.secretIds.filter((x): x is string => typeof x === 'string'))] : [];
    const reason = typeof body.reason === 'string' ? body.reason.trim().slice(0, 500) : '';
    const fields: Record<string, string> = {};
    if (!ids.length || ids.length > MAX_SECRETS) fields.secretIds = `Choose between 1 and ${MAX_SECRETS} secrets`;
    if (reason.length < 10) fields.reason = 'Say why the values must leave Token Vault (at least 10 characters)';
    if (Object.keys(fields).length) throw badRequest('Request validation failed', { fields });
    const found = await db.findBy(SecretEntity, { id: In(ids), organizationId: ctx.org.id });
    const live = found.filter((s) => s.status !== 'DELETED' && s.activeVersion);
    if (live.length !== ids.length) throw badRequest('Request validation failed', { fields: { secretIds: 'Unknown, deleted or empty secrets in the list' } });
    const since = new Date(Date.now() - 86_400_000).toISOString();
    const recent = await db.createQueryBuilder(SecretExportRequestEntity, 'r').where('r.organization_id = :org AND r.created_at > :since', { org: ctx.org.id, since }).getMany();
    if (recent.filter((r) => r.requestedBy === ctx.user.id).length >= PER_MEMBER_PER_DAY || recent.length >= PER_ORG_PER_DAY) throw new HttpError(429, 'EXPORT_RATE_LIMITED', `At most ${PER_MEMBER_PER_DAY} export requests per member and ${PER_ORG_PER_DAY} per organization in 24 hours`);
    const row = Object.assign(new SecretExportRequestEntity(), { id: newId('sexp'), organizationId: ctx.org.id, requestedBy: ctx.user.id, requestedByName: ctx.user.fullName, secretIds: ids, reason, status: 'PENDING' as const, createdAt: now(), decidedBy: null, decidedByName: null, decidedAt: null, note: '', expiresAt: null, file: null, downloadTokenHash: null, downloadedAt: null });
    await transaction(async (ex) => {
      await ex.insert(SecretExportRequestEntity, row);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret_export.requested', target: { type: 'secret_export', id: row.id, name: `${ids.length} secret(s)` }, severity: 'warning', metadata: { secretIds: ids, reason } }, ex);
    });
    return (await this.views(ctx, [row]))[0]!;
  }

  /** Approve or reject: someone with secret:manage_access other than the requester. */
  async decide(ctx: OrgContext, body: { id?: unknown; note?: unknown }, outcome: 'APPROVED' | 'REJECTED'): Promise<SecretExportRequestView> {
    enabled();
    const r = await this.one(ctx, String(body.id ?? ''));
    if (r.requestedBy === ctx.user.id) throw new HttpError(403, 'SEPARATION_OF_DUTIES', 'Someone else must decide your own export request');
    if (r.status !== 'PENDING') throw new HttpError(409, 'EXPORT_NOT_PENDING', `This request is ${r.status.toLowerCase()}`);
    const note = typeof body.note === 'string' ? body.note.trim().slice(0, 300) : '';
    const t = now();
    await transaction(async (ex) => {
      const done = await ex.update(SecretExportRequestEntity, { id: r.id, status: 'PENDING' }, { status: outcome, decidedBy: ctx.user.id, decidedByName: ctx.user.fullName, decidedAt: t, note, expiresAt: outcome === 'APPROVED' ? new Date(Date.now() + APPROVAL_VALID_MS).toISOString() : null });
      if (!done.affected) throw new HttpError(409, 'EXPORT_NOT_PENDING', 'This request was decided meanwhile');
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: outcome === 'APPROVED' ? 'secret_export.approved' : 'secret_export.rejected', target: { type: 'secret_export', id: r.id, name: `${r.secretIds.length} secret(s)` }, severity: 'warning', metadata: { requestedBy: r.requestedByName, note } }, ex);
    });
    return (await this.views(ctx, [(await this.one(ctx, r.id))]))[0]!;
  }

  /** Reads the values from the customer webhook and encrypts them with the passphrase. Returns a one-time download link. */
  async prepare(ctx: OrgContext, body: { id?: unknown; passphrase?: unknown }): Promise<{ downloadUrl: string; expiresAt: string }> {
    enabled();
    if (!has(ctx, PERMISSIONS.SECRET_EXPORT)) throw forbidden(`Your role (${ctx.role}) cannot export secrets. Required: ${PERMISSIONS.SECRET_EXPORT}`);
    const r = await this.one(ctx, String(body.id ?? ''));
    if (r.requestedBy !== ctx.user.id) throw new HttpError(403, 'NOT_REQUESTER', 'Only the member who asked for the export can prepare it');
    if (this.effectiveStatus(r) !== 'APPROVED') throw new HttpError(409, 'EXPORT_NOT_APPROVED', `This request is ${this.effectiveStatus(r).toLowerCase()}`);
    const passphrase = typeof body.passphrase === 'string' ? body.passphrase : '';
    if (passphrase.length < 12) throw badRequest('Request validation failed', { fields: { passphrase: 'At least 12 characters: it is the only way to open the file' } });

    const secrets = await db.findBy(SecretEntity, { id: In(r.secretIds), organizationId: ctx.org.id });
    const out: Record<string, unknown>[] = [];
    for (const s of secrets) {
      const v = s.activeVersion ? await db.findOneBy(SecretVersionEntity, { secretId: s.id, version: s.activeVersion }) : null;
      if (s.status === 'DELETED' || !v?.valueRef) throw new HttpError(409, 'SECRET_VALUE_GONE', `${s.name} no longer has a value; ask for a new export`);
      const webhook = await webhookRepo.getWebhook(ctx.org.id, s.webhookId);
      if (!webhook) throw new HttpError(409, 'WEBHOOK_NOT_FOUND', `The webhook holding ${s.name} no longer exists`);
      let res;
      try {
        res = await callWebhook<{ payload: SecretPayload }>(webhook, 'POST', '/internal/v1/secrets/read', { org_id: ctx.org.id, secret_id: s.id, value_ref: v.valueRef });
      } catch (e) {
        if (e instanceof WebhookUnavailableError) throw new HttpError(503, 'WEBHOOK_UNAVAILABLE', `${e.message}. Nothing was exported.`);
        throw e;
      }
      if (res.status !== 200) throw new HttpError(502, 'WEBHOOK_REJECTED', `The customer webhook could not return ${s.name}`);
      out.push({ name: s.name, typeKey: s.typeKey, project: s.project, workspace: s.workspace, environment: s.environment, description: s.description, tags: s.tags, metadata: s.metadata, version: v.version, payload: res.body.payload });
    }
    const plaintext = JSON.stringify({ exportedAt: now(), organization: { id: ctx.org.id, name: ctx.org.name }, secrets: out });
    const file = await encryptExport(plaintext, passphrase, r.id);
    const token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + DOWNLOAD_VALID_MS).toISOString();
    await transaction(async (ex) => {
      const done = await ex.update(SecretExportRequestEntity, { id: r.id, status: 'APPROVED' }, { status: 'READY', file, downloadTokenHash: hashToken(token), expiresAt });
      if (!done.affected) throw new HttpError(409, 'EXPORT_NOT_APPROVED', 'This request changed meanwhile');
      for (const s of secrets) await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret.exported', target: { type: 'secret', id: s.id, name: s.name }, severity: 'critical', metadata: { exportId: r.id, version: s.activeVersion } }, ex);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret_export.prepared', target: { type: 'secret_export', id: r.id, name: `${secrets.length} secret(s)` }, severity: 'critical', metadata: { secrets: secrets.length, expiresAt } }, ex);
    });
    return { downloadUrl: `/api/v1/secretExport/download/${token}`, expiresAt };
  }

  /** The encrypted file, once, to the requester, before the link expires; then it is deleted. */
  async download(ctx: OrgContext, token: string): Promise<SecretExportFile> {
    enabled();
    const r = token ? await db.findOneBy(SecretExportRequestEntity, { downloadTokenHash: hashToken(token), organizationId: ctx.org.id }) : null;
    if (!r || r.requestedBy !== ctx.user.id) throw notFound('Export');
    if (this.effectiveStatus(r) !== 'READY' || !r.file) throw new HttpError(410, 'EXPORT_GONE', 'This download link has expired or was used');
    const file = r.file;
    await transaction(async (ex) => {
      const done = await ex.update(SecretExportRequestEntity, { id: r.id, status: 'READY' }, { status: 'DOWNLOADED', downloadedAt: now(), file: null, downloadTokenHash: null });
      if (!done.affected) throw new HttpError(410, 'EXPORT_GONE', 'This download link was used');
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret_export.downloaded', target: { type: 'secret_export', id: r.id, name: `${r.secretIds.length} secret(s)` }, severity: 'critical', metadata: {} }, ex);
    });
    return file;
  }

  /** Lifecycle job: deletes files of expired exports. */
  static async expireFiles(): Promise<number> {
    const r = await db.query(`UPDATE secret_export_requests SET status = 'EXPIRED', file = NULL, download_token_hash = NULL WHERE status IN ('APPROVED', 'READY') AND expires_at <= now()`);
    return Array.isArray(r) ? Number(r[1] ?? 0) : 0;
  }
}
