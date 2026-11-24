import { In } from 'typeorm';
import { RETRIEVABLE_SECRET_STATUSES, SECRET_PROVIDER_CAPABILITIES, type SecretLeaseIssued, type SecretLeaseStatus, type SecretLeaseView } from '@token-vault/shared';
import { db, transaction } from '../../databases/client';
import { SecretEntity, SecretLeaseEntity, SecretVersionEntity } from '../../entities';
import { HttpError, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { webhookRepo } from '../../store/repos';
import type { WebhookRecord } from '../../store/types';
import { recordEvent, type Actor } from '../auditService/auditService.service';
import { getSecretType, loadCustomTypes } from '../secretTypeService/registry';
import { WebhookUnavailableError, callWebhook } from '../webhookService/webhook.client';

/**
 * Leases of dynamic secrets (spec 4.9.3 J). A lease is a short-lived credential the customer
 * webhook creates at the provider (a PostgreSQL role with VALID UNTIL, AWS session credentials)
 * from the secret's stored administrative credential. The credential goes to the holder once
 * and is never stored here; the lease row keeps the provider identity, the expiry and the
 * lifecycle. Every lease is limited by the secret's longest lease, renewals included, and the
 * lifecycle job ends expired ones at the provider (automatic cleanup).
 */

export interface LeaseHolder {
  type: 'AGENT' | 'USER';
  id: string;
  name: string;
  actor: Actor;
}

const MINUTE = 60_000;
const now = () => new Date().toISOString();

export function leaseView(l: SecretLeaseEntity, s: Pick<SecretEntity, 'id' | 'name' | 'typeKey'>): SecretLeaseView {
  return {
    id: l.id,
    secret: { id: s.id, name: s.name, typeKey: s.typeKey },
    holder: { type: l.holderType, id: l.holderId, name: l.holderName },
    username: l.username,
    status: l.status,
    renewable: l.renewable,
    createdAt: l.createdAt,
    expiresAt: l.expiresAt,
    maxExpiresAt: l.maxExpiresAt,
    renewedAt: l.renewedAt,
    renewCount: l.renewCount,
    revokedAt: l.revokedAt,
    revokedBy: l.revokedBy,
    revocationReason: l.revocationReason,
    lastError: l.lastError,
    reason: l.reason,
  };
}

/** Default and longest lease of a secret (its metadata; the type's limits otherwise). */
export function leaseLimits(s: Pick<SecretEntity, 'typeKey' | 'metadata'>): { defaultMs: number; maxMs: number } {
  const sts = s.typeKey === 'aws-sts-dynamic';
  const num = (v: unknown, fallback: number) => (typeof v === 'number' && v > 0 ? v : fallback);
  const max = num(s.metadata.maxTtlMinutes, sts ? 60 : 1440);
  const def = Math.min(num(s.metadata.defaultTtlMinutes, 60), max);
  return { defaultMs: def * MINUTE, maxMs: max * MINUTE };
}

function failure(res: { status: number; body: any }): never {
  const err = res.body?.error ?? {};
  throw new HttpError(res.status === 503 ? 503 : res.status === 404 ? 410 : 409, err.code ?? 'WEBHOOK_REJECTED', err.message ?? 'The customer webhook could not complete the request');
}

async function webhookOf(s: SecretEntity): Promise<WebhookRecord> {
  const w = await webhookRepo.getWebhook(s.organizationId, s.webhookId);
  if (!w) throw new HttpError(409, 'WEBHOOK_NOT_FOUND', 'The webhook holding this secret no longer exists');
  return w;
}

async function activeRef(s: SecretEntity): Promise<string> {
  const v = s.activeVersion ? await db.findOneBy(SecretVersionEntity, { secretId: s.id, version: s.activeVersion }) : null;
  if (!v?.valueRef) throw new HttpError(409, 'SECRET_VERSION_DESTROYED', 'This secret has no active value');
  return v.valueRef;
}

async function call<T>(s: SecretEntity, path: string, body: Record<string, unknown>, what: string): Promise<T> {
  let res;
  try {
    res = await callWebhook<T>(await webhookOf(s), 'POST', path, { org_id: s.organizationId, secret_id: s.id, ...body });
  } catch (e) {
    if (e instanceof WebhookUnavailableError) throw new HttpError(503, 'WEBHOOK_UNAVAILABLE', `${e.message}. ${what}`);
    throw e;
  }
  if (res.status !== 200 && res.status !== 201) failure(res);
  return res.body;
}

export default class SecretLeaseService {
  /** Issues a lease to `holder`. Checks of who may ask are the caller's (grant, permission). */
  async issue(s: SecretEntity, holder: LeaseHolder, opts: { ttlSeconds?: number; reason?: string; grantId?: string | null; requestId?: string }): Promise<SecretLeaseIssued> {
    await loadCustomTypes(s.organizationId);
    const type = getSecretType(s.typeKey, s.organizationId);
    if (!type?.lifecycle.dynamic || !SECRET_PROVIDER_CAPABILITIES[s.typeKey]?.lease) throw new HttpError(409, 'SECRET_NOT_DYNAMIC', 'This secret does not issue short-lived credentials');
    if (!RETRIEVABLE_SECRET_STATUSES.includes(s.status)) throw new HttpError(409, 'SECRET_NOT_ACTIVE', `This secret is ${s.status.toLowerCase().replace('_', ' ')}`);
    const { defaultMs, maxMs } = leaseLimits(s);
    const wanted = opts.ttlSeconds && opts.ttlSeconds > 0 ? Math.max(opts.ttlSeconds * 1000, MINUTE) : defaultMs;
    const created = Date.now();
    const expires = new Date(created + Math.min(wanted, maxMs));
    const id = newId('lse');
    const target = { type: 'secret', id: s.id, name: s.name };

    let out: { username: string; credentials: Record<string, string>; expires_at: string; renewable: boolean };
    try {
      out = await call(s, '/internal/v1/secrets/lease', { value_ref: await activeRef(s), lease_id: id, expires_at: expires.toISOString() }, 'No lease was issued.');
    } catch (e) {
      const err = e as HttpError;
      await recordEvent({ orgId: s.organizationId, actor: holder.actor, eventType: 'secret.lease_failed', target, outcome: 'FAILURE', severity: 'warning', metadata: { errorCode: err.code, holderType: holder.type, holderId: holder.id, requestId: opts.requestId } });
      if (['WEBHOOK_UNAVAILABLE', 'PROVIDER_UNAVAILABLE'].includes(err.code)) await recordEvent({ orgId: s.organizationId, actor: holder.actor, eventType: 'secret.provider_failure', target, outcome: 'FAILURE', severity: 'warning', metadata: { errorCode: err.code, reason: 'Issuing a lease' } });
      throw e;
    }
    const row: SecretLeaseEntity = Object.assign(new SecretLeaseEntity(), {
      id,
      organizationId: s.organizationId,
      secretId: s.id,
      holderType: holder.type,
      holderId: holder.id,
      holderName: holder.name,
      grantId: opts.grantId ?? null,
      username: out.username,
      status: 'ACTIVE' as const,
      renewable: out.renewable,
      reason: (opts.reason ?? '').slice(0, 300),
      createdAt: new Date(created).toISOString(),
      expiresAt: out.expires_at,
      maxExpiresAt: new Date(created + maxMs).toISOString(),
      renewedAt: null,
      renewCount: 0,
      revokedAt: null,
      revokedBy: null,
      revocationReason: null,
      lastError: null,
    });
    try {
      await transaction(async (ex) => {
        await ex.insert(SecretLeaseEntity, row);
        await ex.update(SecretEntity, { id: s.id }, { lastRetrievedAt: row.createdAt });
        await recordEvent({ orgId: s.organizationId, actor: holder.actor, eventType: 'secret.lease_created', target, severity: 'warning', metadata: { leaseId: id, username: out.username, holderType: holder.type, holderId: holder.id, expiresAt: row.expiresAt, maxExpiresAt: row.maxExpiresAt, grantId: opts.grantId ?? null, reason: row.reason, requestId: opts.requestId } }, ex);
      });
    } catch (e) {
      // Not recorded: end the credential at the provider again.
      await call(s, '/internal/v1/secrets/lease/revoke', { value_ref: await activeRef(s), lease_id: id, username: out.username }, '').catch(() => undefined);
      throw e;
    }
    return { ...leaseView(row, s), credentials: out.credentials };
  }

  async renew(lease: SecretLeaseEntity, by: Actor, ttlSeconds?: number): Promise<SecretLeaseView> {
    const s = await db.findOneByOrFail(SecretEntity, { id: lease.secretId });
    if (lease.status !== 'ACTIVE' || Date.parse(lease.expiresAt) <= Date.now()) throw new HttpError(409, 'LEASE_NOT_ACTIVE', 'This lease has ended; ask for a new one');
    if (!lease.renewable) throw new HttpError(409, 'LEASE_NOT_RENEWABLE', 'Leases of this type cannot be lengthened; ask for a new one');
    if (!RETRIEVABLE_SECRET_STATUSES.includes(s.status)) throw new HttpError(409, 'SECRET_NOT_ACTIVE', `The secret is ${s.status.toLowerCase().replace('_', ' ')}`);
    const { defaultMs } = leaseLimits(s);
    const wanted = ttlSeconds && ttlSeconds > 0 ? Math.max(ttlSeconds * 1000, MINUTE) : defaultMs;
    const until = Math.min(Date.now() + wanted, Date.parse(lease.maxExpiresAt));
    if (until <= Date.parse(lease.expiresAt)) throw new HttpError(409, 'LEASE_AT_MAXIMUM', `This lease cannot go past ${lease.maxExpiresAt}; ask for a new one`);
    const expiresAt = new Date(until).toISOString();
    await call(s, '/internal/v1/secrets/lease/renew', { value_ref: await activeRef(s), lease_id: lease.id, username: lease.username, expires_at: expiresAt }, 'The lease was not lengthened.');
    const t = now();
    await transaction(async (ex) => {
      await ex.update(SecretLeaseEntity, { id: lease.id }, { expiresAt, renewedAt: t, renewCount: lease.renewCount + 1 });
      await recordEvent({ orgId: s.organizationId, actor: by, eventType: 'secret.lease_renewed', target: { type: 'secret', id: s.id, name: s.name }, metadata: { leaseId: lease.id, username: lease.username, expiresAt, renewCount: lease.renewCount + 1 } }, ex);
    });
    return leaseView((await db.findOneByOrFail(SecretLeaseEntity, { id: lease.id }))!, s);
  }

  /**
   * Ends a lease at the provider. When the provider cannot be reached the lease is REVOKE_FAILED
   * and the lifecycle job tries again; `final` is the status once it is gone.
   */
  async revoke(lease: SecretLeaseEntity, by: Actor, reason: string, final: Extract<SecretLeaseStatus, 'REVOKED' | 'EXPIRED'> = 'REVOKED'): Promise<SecretLeaseView> {
    const s = await db.findOneByOrFail(SecretEntity, { id: lease.secretId });
    if (lease.status !== 'ACTIVE' && lease.status !== 'REVOKE_FAILED') return leaseView(lease, s);
    const target = { type: 'secret', id: s.id, name: s.name };
    const t = now();
    try {
      const r = await call<{ revoked: boolean }>(s, '/internal/v1/secrets/lease/revoke', { value_ref: await activeRef(s), lease_id: lease.id, username: lease.username }, 'The lease is still active.');
      const status = lease.status === 'REVOKE_FAILED' && Date.parse(lease.expiresAt) <= Date.now() ? 'EXPIRED' : final;
      await transaction(async (ex) => {
        await ex.update(SecretLeaseEntity, { id: lease.id }, { status, revokedAt: t, revokedBy: by.name, revocationReason: reason || lease.revocationReason, lastError: null });
        await recordEvent({ orgId: s.organizationId, actor: by, eventType: status === 'EXPIRED' ? 'secret.lease_expired' : 'secret.lease_revoked', target, severity: 'info', metadata: { leaseId: lease.id, username: lease.username, reason, endedAtProvider: r.revoked } }, ex);
      });
    } catch (e) {
      const err = e as HttpError;
      await transaction(async (ex) => {
        await ex.update(SecretLeaseEntity, { id: lease.id }, { status: 'REVOKE_FAILED', lastError: `${err.code ?? 'ERROR'}: ${(err.message ?? '').slice(0, 200)}`, revocationReason: reason || lease.revocationReason, revokedBy: by.name });
        await recordEvent({ orgId: s.organizationId, actor: by, eventType: 'secret.lease_revoke_failed', target, outcome: 'FAILURE', severity: 'warning', metadata: { leaseId: lease.id, username: lease.username, errorCode: err.code, reason } }, ex);
        if (['WEBHOOK_UNAVAILABLE', 'PROVIDER_UNAVAILABLE'].includes(err.code)) await recordEvent({ orgId: s.organizationId, actor: by, eventType: 'secret.provider_failure', target, outcome: 'FAILURE', severity: 'warning', metadata: { errorCode: err.code, reason: 'Ending a lease' } }, ex);
      });
    }
    return leaseView((await db.findOneByOrFail(SecretLeaseEntity, { id: lease.id }))!, s);
  }

  /** Ends every live lease of a secret (it is revoked or deleted). Returns how many could not be ended. */
  async revokeAllFor(s: SecretEntity, by: Actor, reason: string): Promise<number> {
    const live = await db.findBy(SecretLeaseEntity, { secretId: s.id, status: In(['ACTIVE', 'REVOKE_FAILED']) });
    let failed = 0;
    for (const l of live) if ((await this.revoke(l, by, reason)).status === 'REVOKE_FAILED') failed++;
    return failed;
  }

  /** Lifecycle job: ends expired leases at the provider, and retries failed revocations. */
  async cleanUp(by: Actor): Promise<{ expired: number; failed: number }> {
    const due = await db
      .createQueryBuilder(SecretLeaseEntity, 'l')
      .where(`(l.status = 'ACTIVE' AND l.expires_at <= now()) OR l.status = 'REVOKE_FAILED'`)
      .orderBy('l.expires_at', 'ASC')
      .take(100)
      .getMany();
    let expired = 0;
    let failed = 0;
    for (const l of due) {
      try {
        const v = await this.revoke(l, by, l.status === 'REVOKE_FAILED' ? l.revocationReason ?? 'Retry' : 'Lease expired', 'EXPIRED');
        if (v.status === 'REVOKE_FAILED') failed++;
        else expired++;
      } catch (e) {
        failed++;
        console.warn(`[lifecycle] lease ${l.id}: ${(e as Error).message}`);
      }
    }
    return { expired, failed };
  }

  async list(orgId: string, body: { secretId?: unknown; status?: unknown; holderId?: unknown } = {}): Promise<{ items: SecretLeaseView[] }> {
    const where: Record<string, unknown> = { organizationId: orgId };
    for (const k of ['secretId', 'status', 'holderId'] as const) if (typeof body[k] === 'string' && body[k]) where[k] = body[k];
    const rows = await db.find(SecretLeaseEntity, { where, order: { createdAt: 'DESC' }, take: 200 });
    const secrets = new Map((rows.length ? await db.findBy(SecretEntity, { id: In([...new Set(rows.map((r) => r.secretId))]) }) : []).map((s) => [s.id, s]));
    return { items: rows.map((l) => leaseView(l, secrets.get(l.secretId) ?? { id: l.secretId, name: l.secretId, typeKey: '' })) };
  }

  async get(orgId: string, id: string): Promise<SecretLeaseEntity> {
    const l = typeof id === 'string' && id ? await db.findOneBy(SecretLeaseEntity, { id, organizationId: orgId }) : null;
    if (!l) throw notFound('Lease');
    return l;
  }
}
