import { In, IsNull } from 'typeorm';
import { config } from '../../config';
import { db, transaction } from '../../databases/client';
import { RotationJobEntity, SecretEntity, SecretPolicyEntity, SecretVersionEntity } from '../../entities';
import { newId } from '../../lib/ids';
import { SYSTEM_ACTOR, recordEvent } from '../auditService/auditService.service';
import { policiesOf, resolvePolicy } from '../secretPolicyService/secretPolicyService.service';
import { getSecretType } from '../secretTypeService/registry';
import { SECRET_PROVIDER_CAPABILITIES } from '@token-vault/shared';
import SecretService, { expiryStatus, systemWriter } from './secretService.service';
import SecretLeaseService from '../secretLeaseService/secretLeaseService.service';
import SecretExportService from '../secretExportService/secretExportService.service';

/**
 * The secret lifecycle job (spec 4.9.10–4.9.12, 4.9.8). Each run:
 *  1. expiry: ACTIVE secrets inside their warning window become EXPIRING (and a generated
 *     rotation is queued when rotation renews their lifetime); retrievable secrets past their
 *     expiry become EXPIRED; EXPIRING secrets whose expiry moved out of the window are ACTIVE again;
 *  2. scheduled rotation: secrets due for rotation get a rotation job: manual ones become
 *     ROTATION_PENDING and people are notified, generated ones are rotated by the webhook;
 *  3. rotation jobs waiting for a retry are run again;
 *  4. version retention: inactive versions outside the policy (newest n, or replaced less than
 *     d days ago, and never inside the rotation grace period) are destroyed on the webhook;
 *  5. leases of dynamic secrets that have expired are ended at the provider (and failed
 *     revocations retried): automatic cleanup, spec 4.9.3 J;
 *  6. provider health: secrets whose provider the webhook can reach are checked every
 *     PROVIDER_CHECK_EVERY_MS; a new failure is notified (secret.provider_failure).
 * Every change is audited (system actor) and notified like any other secret event. One instance
 * runs at a time: a PostgreSQL advisory lock is taken for the run, other instances skip it.
 */

const LOCK_KEY = 4_909_012; // "4.9.12"
const DAY = 86_400_000;
const service = new SecretService();
const leaseService = new SecretLeaseService();
const PROVIDER_CHECK_EVERY_MS = 15 * 60_000;

export interface LifecycleReport {
  expiring: number;
  expired: number;
  active: number;
  rotationsScheduled: number;
  rotationsSucceeded: number;
  rotationsRetrying: number;
  rotationsFailed: number;
  versionsDestroyed: number;
  leasesEnded: number;
  leasesFailed: number;
  providersChecked: number;
}

/** One run, if no other instance is running one. Returns null when skipped. */
export async function runSecretLifecycle(): Promise<LifecycleReport | null> {
  const qr = db.connection.createQueryRunner();
  await qr.connect();
  try {
    const [{ locked }] = (await qr.query('SELECT pg_try_advisory_lock($1) AS locked', [LOCK_KEY])) as { locked: boolean }[];
    if (!locked) return null;
    try {
      return await runOnce();
    } finally {
      await qr.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]);
    }
  } finally {
    await qr.release();
  }
}

function warn(what: string, e: unknown) {
  console.warn(`[lifecycle] ${what}: ${(e as Error).message}`);
}

async function runOnce(): Promise<LifecycleReport> {
  const report: LifecycleReport = { expiring: 0, expired: 0, active: 0, rotationsScheduled: 0, rotationsSucceeded: 0, rotationsRetrying: 0, rotationsFailed: 0, versionsDestroyed: 0, leasesEnded: 0, leasesFailed: 0, providersChecked: 0 };
  const policyCache = new Map<string, SecretPolicyEntity[]>();
  const policyFor = async (s: SecretEntity) => {
    if (!policyCache.has(s.organizationId)) policyCache.set(s.organizationId, await policiesOf(s.organizationId));
    return resolvePolicy(policyCache.get(s.organizationId)!, s, getSecretType(s.typeKey, s.organizationId));
  };

  // 1. Expiry.
  const candidates = await db
    .createQueryBuilder(SecretEntity, 's')
    .where(`s.status IN ('ACTIVE', 'EXPIRING', 'ROTATION_PENDING') AND s.expires_at IS NOT NULL AND s.expires_at <= now() + interval '366 days'`)
    .getMany();
  candidates.push(...(await db.findBy(SecretEntity, { status: 'EXPIRING', expiresAt: IsNull() })));
  for (const s of candidates) {
    try {
      const policy = await policyFor(s);
      const want = expiryStatus(s.expiresAt, policy.expiryWarningDays.value);
      if (want === 'EXPIRED') {
        if (await transitionIf(s, 'EXPIRED', 'secret.expired', { expiresAt: s.expiresAt })) report.expired++;
      } else if (want === 'EXPIRING' && s.status === 'ACTIVE') {
        const daysLeft = Math.max(0, Math.ceil((Date.parse(s.expiresAt!) - Date.now()) / DAY));
        if (await transitionIf(s, 'EXPIRING', 'secret.expiring', { expiresAt: s.expiresAt, daysLeft })) {
          report.expiring++;
          // Expiration-based rotation: a secret that can rotate by itself, and whose lifetime a rotation renews, rotates now.
          if (s.rotationEnabled && s.rotationStrategy === 'generated' && policy.defaultExpiresInDays.value && (await queueJob(s, 'EXPIRY'))) report.rotationsScheduled++;
        }
      } else if (want === 'ACTIVE' && s.status === 'EXPIRING') {
        if ((await db.update(SecretEntity, { id: s.id, status: 'EXPIRING' }, { status: 'ACTIVE' })).affected) report.active++;
      }
    } catch (e) {
      warn(`expiry of ${s.id}`, e);
    }
  }

  // 2. Rotations that are due.
  const due = await db
    .createQueryBuilder(SecretEntity, 's')
    .where(`s.rotation_enabled AND s.next_rotation_at <= now() AND s.status IN ('ACTIVE', 'EXPIRING')`)
    .andWhere(`NOT EXISTS (SELECT 1 FROM rotation_jobs j WHERE j.secret_id = s.id AND j.status IN ('PENDING', 'RUNNING', 'WAITING_FOR_VALUE'))`)
    .orderBy('s.next_rotation_at', 'ASC')
    .take(100)
    .getMany();
  for (const s of due) {
    try {
      if (await queueJob(s, 'SCHEDULED')) report.rotationsScheduled++;
    } catch (e) {
      warn(`scheduling rotation of ${s.id}`, e);
    }
  }

  // 3. Generated rotations to run (new, or retrying after the webhook was unavailable).
  const jobs = await db
    .createQueryBuilder(RotationJobEntity, 'j')
    .where(`j.status = 'PENDING' AND (j.next_attempt_at IS NULL OR j.next_attempt_at <= now())`)
    .orderBy('j.created_at', 'ASC')
    .take(20)
    .getMany();
  for (const j of jobs) {
    try {
      const r = await service.runRotationJob(j.id);
      if (r === 'SUCCEEDED') report.rotationsSucceeded++;
      else if (r === 'RETRY') report.rotationsRetrying++;
      else if (r === 'FAILED') report.rotationsFailed++;
    } catch (e) {
      warn(`rotation job ${j.id}`, e);
    }
  }

  // 4. Version retention.
  report.versionsDestroyed = await applyRetention();

  // 5. Expired leases end at the provider.
  const leases = await leaseService.cleanUp(SYSTEM_ACTOR);
  report.leasesEnded = leases.expired;
  report.leasesFailed = leases.failed;

  // Export files nobody downloaded in time are deleted.
  await SecretExportService.expireFiles();

  // 6. Provider health.
  const checkable = Object.entries(SECRET_PROVIDER_CAPABILITIES).filter(([, c]) => c.check).map(([k]) => k);
  const stale = await db
    .createQueryBuilder(SecretEntity, 's')
    .where(`s.type_key IN (:...types) AND s.status IN ('ACTIVE', 'EXPIRING', 'ROTATION_PENDING')`, { types: checkable })
    .andWhere(`(s.provider_checked_at IS NULL OR s.provider_checked_at <= :before)`, { before: new Date(Date.now() - PROVIDER_CHECK_EVERY_MS).toISOString() })
    .orderBy('s.provider_checked_at', 'ASC', 'NULLS FIRST')
    .take(20)
    .getMany();
  for (const s of stale) {
    try {
      await service.checkProvider(systemWriter(s.organizationId), s.id);
      report.providersChecked++;
    } catch (e) {
      warn(`provider check of ${s.id}`, e);
    }
  }

  const changed = Object.entries(report).filter(([, n]) => n > 0);
  if (changed.length) console.log(`[lifecycle] ${changed.map(([k, n]) => `${k}=${n}`).join(' ')}`);
  return report;
}

/** Moves a secret to `to` if it is still in the status it was read in, with the audit event (and so its notifications). */
async function transitionIf(s: SecretEntity, to: 'EXPIRING' | 'EXPIRED', eventType: string, metadata: Record<string, unknown>): Promise<boolean> {
  return transaction(async (ex) => {
    const r = await ex.update(SecretEntity, { id: s.id, status: s.status }, { status: to });
    if (!r.affected) return false;
    await recordEvent({ orgId: s.organizationId, actor: SYSTEM_ACTOR, eventType, target: { type: 'secret', id: s.id, name: s.name }, severity: 'warning', metadata: { from: s.status, to, ...metadata } }, ex);
    return true;
  });
}

/**
 * Queues a rotation. Generated: a PENDING job run in step 3. Manual: the secret becomes
 * ROTATION_PENDING and waits for someone to store the new value (which closes the job).
 * False if a rotation is already open (unique index) or the secret changed meanwhile.
 */
async function queueJob(s: SecretEntity, trigger: 'SCHEDULED' | 'EXPIRY'): Promise<boolean> {
  const t = new Date().toISOString();
  // Generated and provider rotations run by themselves; manual ones wait for a person.
  const generated = s.rotationStrategy !== 'manual';
  try {
    return await transaction(async (ex) => {
      const current = await ex.findOne(SecretEntity, { where: { id: s.id }, lock: { mode: 'pessimistic_write' } });
      if (!current || !['ACTIVE', 'EXPIRING'].includes(current.status)) return false;
      if (await ex.findOneBy(RotationJobEntity, { secretId: s.id, status: In(['PENDING', 'RUNNING', 'WAITING_FOR_VALUE']) })) return false;
      await ex.insert(RotationJobEntity, {
        id: newId('rot'),
        organizationId: s.organizationId,
        secretId: s.id,
        trigger,
        strategy: s.rotationStrategy,
        status: generated ? 'PENDING' : 'WAITING_FOR_VALUE',
        attempts: 0,
        fromVersion: current.activeVersion,
        toVersion: null,
        errorCode: null,
        errorMessage: null,
        requestedBy: null,
        requestedByName: null,
        scheduledFor: current.nextRotationAt ?? t,
        startedAt: null,
        finishedAt: null,
        nextAttemptAt: generated ? t : null,
        createdAt: t,
      });
      if (!generated) {
        await ex.update(SecretEntity, { id: s.id }, { status: 'ROTATION_PENDING' });
        // People must act: tell them (generated rotations report their outcome instead).
        await recordEvent({ orgId: s.organizationId, actor: SYSTEM_ACTOR, eventType: 'secret.rotation_scheduled', target: { type: 'secret', id: s.id, name: s.name }, severity: 'warning', metadata: { trigger, strategy: 'manual', version: current.activeVersion, reason: 'Store the new value to complete the rotation' } }, ex);
      }
      return true;
    });
  } catch (e) {
    if ((e as { driverError?: { code?: string } }).driverError?.code === '23505') return false;
    throw e;
  }
}

/** Destroys inactive versions that no retention rule keeps (organizations with a retention policy only). */
async function applyRetention(): Promise<number> {
  const orgs: { organization_id: string }[] = await db.query(`SELECT DISTINCT organization_id FROM secret_policies WHERE keep_versions IS NOT NULL OR keep_days IS NOT NULL`);
  let destroyed = 0;
  for (const { organization_id: orgId } of orgs) {
    const policies = await policiesOf(orgId);
    const secrets = await db
      .createQueryBuilder(SecretEntity, 's')
      .where(`s.organization_id = :orgId AND s.status <> 'DELETED'`, { orgId })
      .andWhere(`EXISTS (SELECT 1 FROM secret_versions v WHERE v.secret_id = s.id AND v.state = 'PREVIOUS')`)
      .getMany();
    for (const s of secrets) {
      try {
        const p = resolvePolicy(policies, s, getSecretType(s.typeKey, s.organizationId));
        const keepN = p.keepVersions.value;
        const keepD = p.keepDays.value;
        if (keepN == null && keepD == null) continue;
        const previous = await db.find(SecretVersionEntity, { where: { secretId: s.id, state: 'PREVIOUS' }, order: { version: 'DESC' } });
        const now = Date.now();
        const drop = previous.filter((v, i) => {
          const since = Date.parse(v.supersededAt ?? v.createdAt);
          if (!v.supersededAt) return false; // unknown replacement time: keep
          if (now - since < s.rotationGraceHours * 3_600_000) return false; // rotation grace period
          if (keepN != null && i < keepN) return false;
          if (keepD != null && now - since < keepD * DAY) return false;
          return true;
        });
        if (!drop.length) continue;
        const rule = [keepN != null ? `keep the newest ${keepN}` : null, keepD != null ? `keep ${keepD} days` : null].filter(Boolean).join(', ');
        destroyed += await service.destroyForRetention(s, drop, `Retention policy (${rule})`);
      } catch (e) {
        warn(`retention of ${s.id}`, e);
      }
    }
  }
  return destroyed;
}

let running = false;
export function startSecretLifecycle(): NodeJS.Timeout | null {
  if (!config.secretJobIntervalMs) return null;
  const tick = () => {
    if (running) return;
    running = true;
    void runSecretLifecycle()
      .catch((e) => warn('run failed', e))
      .finally(() => (running = false));
  };
  setTimeout(tick, 5_000).unref();
  return setInterval(tick, config.secretJobIntervalMs);
}
