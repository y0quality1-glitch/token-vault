import { In, type EntityManager } from 'typeorm';
import {
  RETRIEVABLE_SECRET_STATUSES,
  type AgentSecretInfo,
  type AgentSecretRetrieval,
  type SecretAccessGrantView,
  type SecretPayload,
  type SecretRetrievalApprovalView,
  type SecretSelector,
} from '@token-vault/shared';
import { db, transaction } from '../../databases/client';
import { AgentEntity, SecretAccessGrantEntity, SecretEntity, SecretRetrievalApprovalEntity, SecretVersionEntity } from '../../entities';
import { HttpError, badRequest, conflict, forbidden, notFound } from '../../lib/errors';
import { newId, requestId as newRequestId } from '../../lib/ids';
import { ipAllowed } from '../../lib/net';
import { agentRepo, orgRepo, webhookRepo } from '../../store/repos';
import type { AgentRecord } from '../../store/types';
import { recordEvent, userActor, type Actor } from '../auditService/auditService.service';
import type { OrgContext } from '../baseService';
import { authenticateCaller } from '../brokerService/brokerService.service';
import { effectiveStatus } from '../secretService/secretService.service';
import { getSecretType } from '../secretTypeService/registry';
import { WebhookUnavailableError, callWebhook } from '../webhookService/webhook.client';

/**
 * Application access to secrets (spec 4.9.6, 4.9.9, 4.9.15).
 *
 * Admins grant an agent (a service account or an AI agent) access to one secret or to every
 * secret matching a selector, optionally limited to some fields, to the active version, to
 * source IP ranges and in time, and optionally held for human approval. Agents retrieve with
 * their own key. Default deny: no matching grant, no value. Every decision is audited (never
 * the value).
 */

const APPROVAL_TTL_MS = 15 * 60_000;
const now = () => new Date().toISOString();

/** Agent API error: the code and message the agent sees; the audit gets the same code. */
export class SecretAccessError extends HttpError {}

type Grant = SecretAccessGrantEntity;

const grantActive = (g: Grant, at = Date.now()) => g.status === 'ACTIVE' && Date.parse(g.validFrom) <= at && (!g.expiresAt || Date.parse(g.expiresAt) > at);
const grantStatus = (g: Grant) => (g.status === 'REVOKED' ? 'REVOKED' : g.expiresAt && Date.parse(g.expiresAt) <= Date.now() ? 'EXPIRED' : 'ACTIVE');

/** Whether a grant covers a secret: by id, or every key of its selector matches. */
export function grantCovers(g: Pick<Grant, 'secretId' | 'selector'>, s: Pick<SecretEntity, 'id' | 'project' | 'workspace' | 'environment' | 'typeKey' | 'tags'>): boolean {
  if (g.secretId) return g.secretId === s.id;
  const sel = g.selector ?? {};
  return (!sel.project || sel.project === s.project) && (!sel.workspace || sel.workspace === s.workspace) && (!sel.environment || sel.environment === s.environment) && (!sel.typeKey || sel.typeKey === s.typeKey) && (!sel.tag || s.tags.includes(sel.tag));
}

/** Fields a grant lets the agent read from a secret of this type (empty: every field). */
const allowedFields = (g: Grant, typeFields: string[]) => (g.fields.length ? g.fields.filter((f) => typeFields.includes(f)) : typeFields);

export default class SecretAccessService {
  // ── admin: grants ──────────────────────────────────────────────

  private async views(orgId: string, rows: Grant[]): Promise<SecretAccessGrantView[]> {
    const agents = rows.length ? await db.findBy(AgentEntity, { id: In([...new Set(rows.map((g) => g.agentId))]) }) : [];
    const secretIds = [...new Set(rows.map((g) => g.secretId).filter((x): x is string => !!x))];
    const secrets = secretIds.length ? await db.findBy(SecretEntity, { id: In(secretIds), organizationId: orgId }) : [];
    return rows.map((g) => ({
      id: g.id,
      organizationId: g.organizationId,
      agent: { id: g.agentId, name: agents.find((a) => a.id === g.agentId)?.name ?? 'Deleted agent' },
      secret: g.secretId ? { id: g.secretId, name: secrets.find((s) => s.id === g.secretId)?.name ?? 'Deleted secret' } : null,
      selector: g.selector,
      description: g.description,
      fields: g.fields,
      versions: g.versions,
      allowedCidrs: g.allowedCidrs,
      requireApproval: g.requireApproval,
      validFrom: g.validFrom,
      expiresAt: g.expiresAt,
      status: grantStatus(g),
      createdBy: { id: g.createdBy, name: g.createdByName },
      createdAt: g.createdAt,
      revokedAt: g.revokedAt,
      revokedBy: g.revokedBy,
      revocationReason: g.revocationReason,
      lastUsedAt: g.lastUsedAt,
      useCount: g.useCount,
    }));
  }

  /** `{ secretId?, agentId?, status? }`. A secret's list includes the selector grants that cover it. */
  async list(orgId: string, body: { secretId?: unknown; agentId?: unknown; status?: unknown } = {}): Promise<{ items: SecretAccessGrantView[]; total: number }> {
    const q = db.createQueryBuilder(SecretAccessGrantEntity, 'g').where('g.organization_id = :orgId', { orgId }).orderBy('g.created_at', 'DESC');
    if (typeof body.agentId === 'string' && body.agentId) q.andWhere('g.agent_id = :agentId', { agentId: body.agentId });
    let rows = await q.getMany();
    if (typeof body.secretId === 'string' && body.secretId) {
      const s = await db.findOneBy(SecretEntity, { id: body.secretId, organizationId: orgId });
      rows = s ? rows.filter((g) => grantCovers(g, s)) : [];
    }
    let items = await this.views(orgId, rows);
    if (typeof body.status === 'string' && ['ACTIVE', 'REVOKED', 'EXPIRED'].includes(body.status)) items = items.filter((g) => g.status === body.status);
    return { items, total: items.length };
  }

  async create(
    ctx: OrgContext,
    dto: { agentId: string; secretId?: string; selector?: SecretSelector; description?: string; fields?: string[]; versions?: 'ACTIVE' | 'ANY'; allowedCidrs?: string[]; requireApproval?: boolean; validFrom?: string; expiresAt?: string | null },
  ): Promise<SecretAccessGrantView> {
    const fields: Record<string, string> = {};
    const agent = await agentRepo.getAgent(ctx.org.id, dto.agentId);
    if (!agent) fields.agentId = 'Unknown agent';
    const selector = dto.selector && Object.values(dto.selector).some((v) => v) ? Object.fromEntries(Object.entries(dto.selector).filter(([, v]) => v)) as SecretSelector : null;
    if (!!dto.secretId === !!selector) fields.secretId = 'Choose one secret, or a selector (project, workspace, environment, type or tag), not both';
    let typeFields: string[] | null = null;
    if (dto.secretId) {
      const s = await db.findOneBy(SecretEntity, { id: dto.secretId, organizationId: ctx.org.id });
      if (!s || s.status === 'DELETED') fields.secretId = 'Unknown secret';
      else typeFields = Object.keys(getSecretType(s.typeKey)?.fields ?? {});
    } else if (selector?.typeKey) {
      const t = getSecretType(selector.typeKey);
      if (!t) fields['selector.typeKey'] = 'Unknown secret type';
      else typeFields = Object.keys(t.fields);
    }
    const wanted = [...new Set(dto.fields ?? [])];
    if (wanted.length) {
      if (!typeFields) fields.fields = 'Field limits need one secret, or a selector with a secret type';
      else if (wanted.some((f) => !typeFields!.includes(f))) fields.fields = `Not fields of this secret type: ${wanted.filter((f) => !typeFields!.includes(f)).join(', ')}`;
    }
    if (dto.expiresAt && dto.validFrom && Date.parse(dto.expiresAt) <= Date.parse(dto.validFrom)) fields.expiresAt = 'Must be after the start';
    if (Object.keys(fields).length) throw badRequest('Request validation failed', { fields });

    const t = now();
    const g: Grant = Object.assign(new SecretAccessGrantEntity(), {
      id: newId('sag'),
      organizationId: ctx.org.id,
      agentId: agent!.id,
      secretId: dto.secretId ?? null,
      selector,
      description: dto.description ?? '',
      fields: wanted,
      versions: dto.versions ?? 'ACTIVE',
      allowedCidrs: dto.allowedCidrs ?? [],
      requireApproval: dto.requireApproval ?? false,
      validFrom: dto.validFrom ? new Date(dto.validFrom).toISOString() : t,
      expiresAt: dto.expiresAt ? new Date(dto.expiresAt).toISOString() : null,
      status: 'ACTIVE' as const,
      createdBy: ctx.user.id,
      createdByName: ctx.user.fullName,
      createdAt: t,
      revokedAt: null,
      revokedBy: null,
      revocationReason: null,
      lastUsedAt: null,
      useCount: 0,
    });
    await transaction(async (ex) => {
      await ex.insert(SecretAccessGrantEntity, g);
      await recordEvent(
        {
          orgId: ctx.org.id,
          actor: userActor(ctx),
          eventType: 'secret.access_granted',
          target: { type: 'secret_access_grant', id: g.id, name: agent!.name },
          metadata: { agentId: agent!.id, target: g.secretId ?? g.selector, fieldLimit: g.fields, versions: g.versions, requireApproval: g.requireApproval, allowedCidrs: g.allowedCidrs, expiresAt: g.expiresAt },
        },
        ex,
      );
    });
    return (await this.views(ctx.org.id, [g]))[0]!;
  }

  async revoke(ctx: OrgContext, dto: { id: string; reason?: string }): Promise<SecretAccessGrantView> {
    const g = await transaction(async (ex) => {
      const row = await ex.createQueryBuilder(SecretAccessGrantEntity, 'g').setLock('pessimistic_write').where('g.id = :id AND g.organization_id = :orgId', { id: dto.id, orgId: ctx.org.id }).getOne();
      if (!row) throw notFound('Grant');
      if (row.status === 'REVOKED') throw conflict('This grant is already revoked');
      const changes = { status: 'REVOKED' as const, revokedAt: now(), revokedBy: ctx.user.fullName, revocationReason: dto.reason || null };
      await ex.update(SecretAccessGrantEntity, { id: row.id }, changes);
      // Held retrievals under this grant can no longer be used.
      await ex.update(SecretRetrievalApprovalEntity, { grantId: row.id, status: In(['PENDING', 'APPROVED']) }, { status: 'EXPIRED' });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret.access_revoked', target: { type: 'secret_access_grant', id: row.id, name: row.agentId }, severity: 'warning', metadata: { agentId: row.agentId, reason: dto.reason ?? '' } }, ex);
      return Object.assign(row, changes);
    });
    return (await this.views(ctx.org.id, [g]))[0]!;
  }

  // ── admin: approvals ───────────────────────────────────────────

  private async approvalViews(rows: SecretRetrievalApprovalEntity[]): Promise<SecretRetrievalApprovalView[]> {
    const agents = rows.length ? await db.findBy(AgentEntity, { id: In([...new Set(rows.map((r) => r.agentId))]) }) : [];
    const secrets = rows.length ? await db.findBy(SecretEntity, { id: In([...new Set(rows.map((r) => r.secretId))]) }) : [];
    return rows.map((r) => ({
      id: r.id,
      grantId: r.grantId,
      agent: { id: r.agentId, name: agents.find((a) => a.id === r.agentId)?.name ?? 'Deleted agent' },
      secret: { id: r.secretId, name: secrets.find((s) => s.id === r.secretId)?.name ?? 'Deleted secret' },
      version: r.version,
      fields: r.fields,
      reason: r.reason,
      status: r.status === 'PENDING' || r.status === 'APPROVED' ? (Date.parse(r.expiresAt) <= Date.now() ? 'EXPIRED' : r.status) : r.status,
      requestedAt: r.requestedAt,
      expiresAt: r.expiresAt,
      decidedBy: r.decidedBy ? { id: r.decidedBy, name: r.decidedByName ?? '' } : null,
      decidedAt: r.decidedAt,
      note: r.note,
      usedAt: r.usedAt,
    }));
  }

  async listApprovals(orgId: string, body: { status?: unknown } = {}): Promise<{ items: SecretRetrievalApprovalView[]; total: number }> {
    const rows = await db.find(SecretRetrievalApprovalEntity, { where: { organizationId: orgId }, order: { requestedAt: 'DESC' }, take: 500 });
    let items = await this.approvalViews(rows);
    if (typeof body.status === 'string' && body.status) items = items.filter((a) => a.status === body.status);
    return { items, total: items.length };
  }

  /** Approve or reject a held retrieval. The agent's owner may not decide (separation of duties). */
  async decide(ctx: OrgContext, dto: { id: string; note?: string }, decision: 'APPROVED' | 'REJECTED'): Promise<SecretRetrievalApprovalView> {
    const row = await transaction(async (ex) => {
      const a = await ex.createQueryBuilder(SecretRetrievalApprovalEntity, 'a').setLock('pessimistic_write').where('a.id = :id AND a.organization_id = :orgId', { id: dto.id, orgId: ctx.org.id }).getOne();
      if (!a) throw notFound('Approval');
      if (a.status !== 'PENDING') throw new HttpError(409, 'APPROVAL_NOT_PENDING', `This request is ${a.status.toLowerCase()}`);
      if (Date.parse(a.expiresAt) <= Date.now()) throw new HttpError(409, 'APPROVAL_EXPIRED', 'This request expired; the agent must ask again');
      const agent = await agentRepo.getAgent(ctx.org.id, a.agentId, ex);
      if (agent?.ownerUserId === ctx.user.id) throw forbidden('You own this agent; another member must decide (separation of duties)');
      const changes = { status: decision, decidedBy: ctx.user.id, decidedByName: ctx.user.fullName, decidedAt: now(), note: dto.note ?? '' };
      await ex.update(SecretRetrievalApprovalEntity, { id: a.id }, changes);
      const secret = await ex.findOneBy(SecretEntity, { id: a.secretId });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: decision === 'APPROVED' ? 'secret.retrieval_approved' : 'secret.retrieval_rejected', target: { type: 'secret', id: a.secretId, name: secret?.name ?? a.secretId }, metadata: { approvalId: a.id, agentId: a.agentId, version: a.version, fieldsRequested: a.fields, note: dto.note ?? '' } }, ex);
      return Object.assign(a, changes);
    });
    return (await this.approvalViews([row]))[0]!;
  }

  // ── agent API ──────────────────────────────────────────────────

  /** Authenticates the agent by its own key. Sub-agents (delegation tokens) cannot read secrets. */
  private async agentOf(authorization: string | undefined, onPreviousKey?: (expiresAt: string) => void): Promise<AgentRecord> {
    const c = await authenticateCaller(authorization, onPreviousKey);
    if (!c) throw new SecretAccessError(401, 'AGENT_UNAUTHENTICATED', 'Invalid agent credential');
    if (c.delegation) throw new SecretAccessError(403, 'DELEGATION_NOT_ALLOWED', 'Sub-agents cannot read secrets; use the agent’s own key');
    return c.agent;
  }

  private async activeGrants(agent: AgentRecord, ex: EntityManager = db): Promise<Grant[]> {
    const rows = await ex.findBy(SecretAccessGrantEntity, { organizationId: agent.organizationId, agentId: agent.id, status: 'ACTIVE' });
    return rows.filter((g) => grantActive(g));
  }

  /** POST /agent/v1/secret/getall: the secrets this agent may read (metadata only). */
  async agentList(authorization: string | undefined, onPreviousKey?: (expiresAt: string) => void): Promise<{ items: AgentSecretInfo[] }> {
    const agent = await this.agentOf(authorization, onPreviousKey);
    if (agent.status !== 'ACTIVE') return { items: [] };
    const grants = await this.activeGrants(agent);
    if (!grants.length) return { items: [] };
    const secrets = await db.createQueryBuilder(SecretEntity, 's').where(`s.organization_id = :orgId AND s.status <> 'DELETED'`, { orgId: agent.organizationId }).orderBy('s.name', 'ASC').getMany();
    const items: AgentSecretInfo[] = [];
    for (const s of secrets) {
      const g = this.bestGrant(grants.filter((x) => grantCovers(x, s)));
      if (!g) continue;
      const typeFields = Object.keys(getSecretType(s.typeKey)?.fields ?? {});
      items.push({ secret_id: s.id, name: s.name, type_key: s.typeKey, project: s.project, workspace: s.workspace, environment: s.environment, status: effectiveStatus(s), active_version: s.activeVersion, expires_at: s.expiresAt, grant_id: g.id, fields: allowedFields(g, typeFields), versions: g.versions, requires_approval: g.requireApproval });
    }
    return { items };
  }

  /** Prefers a grant naming the secret over a selector, and one without approval. */
  /**
   * Whether `version` is the one the latest rotation replaced, less than the secret's grace period
   * ago (a plain value update or a rollback opens no grace period).
   */
  private async inRotationGrace(s: SecretEntity, version: number): Promise<boolean> {
    const v = await db.findOneBy(SecretVersionEntity, { secretId: s.id, version });
    return !!v && v.state === 'PREVIOUS' && v.version === (s.activeVersion ?? 0) - 1 && !!v.supersededAt && v.supersededAt === s.lastRotatedAt && Date.parse(v.supersededAt) + s.rotationGraceHours * 3_600_000 > Date.now();
  }

  private bestGrant(grants: Grant[]): Grant | null {
    return [...grants].sort((a, b) => Number(!a.secretId) - Number(!b.secretId) || Number(a.requireApproval) - Number(b.requireApproval))[0] ?? null;
  }

  /**
   * POST /agent/v1/secret/retrieve. Body: `{ secret_id }` or `{ name, project?, workspace?, environment? }`,
   * plus `version?`, `fields?`, `reason?`, `approval_id?`. Checks, in order: the agent's key and
   * status, the organization's emergency stop, the secret, a covering grant (default deny), source
   * IP, the secret's state and expiry, the version and fields the grant allows, and approval.
   */
  async agentRetrieve(input: { authorization: string | undefined; sourceIp: string; body: unknown; onPreviousKey?: (expiresAt: string) => void }): Promise<{ status: number; body: AgentSecretRetrieval | { approval_id: string; status: 'PENDING'; expires_at: string; decision_code: 'APPROVAL_REQUIRED'; reason: string } }> {
    const requestId = newRequestId();
    const agent = await this.agentOf(input.authorization, input.onPreviousKey);
    const actor: Actor = { type: 'AGENT', id: agent.id, name: agent.name };
    const b = (input.body && typeof input.body === 'object' ? input.body : {}) as Record<string, unknown>;
    const str = (v: unknown, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
    const version = Number.isInteger(b.version) && (b.version as number) > 0 ? (b.version as number) : null;
    const requested = Array.isArray(b.fields) ? [...new Set(b.fields.filter((f): f is string => typeof f === 'string').slice(0, 40))] : null;
    const reason = str(b.reason, 300);

    let secret: SecretEntity | null = null;
    const deny = async (status: number, code: string, message: string): Promise<never> => {
      await recordEvent({
        orgId: agent.organizationId,
        actor,
        eventType: 'secret.access_denied',
        target: secret ? { type: 'secret', id: secret.id, name: secret.name } : { type: 'secret', id: str(b.secret_id) || 'unknown', name: str(b.name) || 'unknown' },
        outcome: 'DENIED',
        severity: ['AGENT_DISABLED', 'EMERGENCY_STOP', 'SECRET_ACCESS_DENIED'].includes(code) ? 'critical' : 'warning',
        metadata: { reasonCode: code, requestId, sourceIp: input.sourceIp, version, fieldsRequested: requested ?? 'all' },
      });
      throw new SecretAccessError(status, code, message);
    };

    if (agent.status !== 'ACTIVE') await deny(403, 'AGENT_DISABLED', 'This agent is disabled');
    const org = await orgRepo.getOrganization(agent.organizationId);
    if (org?.emergencyStoppedAt) await deny(403, 'EMERGENCY_STOP', `An administrator stopped all agent access in this organization at ${org.emergencyStoppedAt}`);

    // The secret, by id or by name within a scope; never outside the agent's organization.
    if (str(b.secret_id)) secret = await db.findOneBy(SecretEntity, { id: str(b.secret_id), organizationId: agent.organizationId });
    else if (str(b.name)) {
      const q = db.createQueryBuilder(SecretEntity, 's').where(`s.organization_id = :orgId AND lower(s.name) = lower(:name) AND s.status <> 'DELETED'`, { orgId: agent.organizationId, name: str(b.name) });
      for (const k of ['project', 'workspace', 'environment'] as const) if (str(b[k])) q.andWhere(`s.${k} = :${k}`, { [k]: str(b[k]) });
      const found = await q.getMany();
      if (found.length > 1) throw new SecretAccessError(409, 'SECRET_AMBIGUOUS', `Several secrets are named "${str(b.name)}"; give project, workspace and environment, or secret_id`);
      secret = found[0] ?? null;
    } else throw new SecretAccessError(400, 'INVALID_REQUEST', 'Give secret_id, or name (with project, workspace and environment if needed)');
    // An unknown secret and a secret without a grant look the same to the agent.
    const grants = secret && secret.status !== 'DELETED' ? (await this.activeGrants(agent)).filter((g) => grantCovers(g, secret!)) : [];
    if (!secret || !grants.length) {
      const s = secret;
      secret = s && s.status !== 'DELETED' ? s : null;
      await deny(403, 'SECRET_ACCESS_DENIED', 'This agent has no grant for that secret');
    }
    const s = secret!;
    const ipOk = (g: Grant) => (!g.allowedCidrs.length || ipAllowed(input.sourceIp, g.allowedCidrs)) && (!agent.allowedCidrs.length || ipAllowed(input.sourceIp, agent.allowedCidrs));
    const fromIp = grants.filter(ipOk);
    if (!fromIp.length) await deny(403, 'IP_NOT_ALLOWED', `Requests from ${input.sourceIp} are not allowed for this secret`);

    const status = effectiveStatus(s);
    if (status === 'EXPIRED') await deny(409, 'SECRET_EXPIRED', 'This secret has expired');
    if (!RETRIEVABLE_SECRET_STATUSES.includes(status)) await deny(409, 'SECRET_NOT_ACTIVE', `This secret is ${status.toLowerCase().replace('_', ' ')}`);

    const typeFields = Object.keys(getSecretType(s.typeKey)?.fields ?? {});
    const unknown = (requested ?? []).filter((f) => !typeFields.includes(f));
    if (unknown.length) throw new SecretAccessError(400, 'SECRET_FIELD_UNKNOWN', `Not fields of this secret: ${unknown.join(', ')}`);
    // A grant that allows this version and every requested field (the best one first).
    // Without `fields`, the agent gets the fields its grant allows.
    // During a rotation's grace period the version it replaced stays readable under grants limited to the active version (spec 4.9.11).
    const inGrace = !!version && version !== s.activeVersion && (await this.inRotationGrace(s, version));
    const fits = (g: Grant) => (!version || version === s.activeVersion || g.versions === 'ANY' || inGrace) && (requested ?? []).every((f) => allowedFields(g, typeFields).includes(f));
    const grant = this.bestGrant(fromIp.filter(fits));
    if (!grant) {
      const versionProblem = version && version !== s.activeVersion && !inGrace && !fromIp.some((g) => g.versions === 'ANY');
      await deny(403, versionProblem ? 'SECRET_VERSION_NOT_PERMITTED' : 'SECRET_FIELDS_NOT_PERMITTED', versionProblem ? 'This agent may read only the active version' : `This agent may read only: ${allowedFields(fromIp[0]!, typeFields).join(', ')}`);
    }
    const g = grant!;
    const fields = requested ?? allowedFields(g, typeFields);
    const versionNo = version ?? s.activeVersion;
    const v = versionNo ? await db.findOneBy(SecretVersionEntity, { secretId: s.id, version: versionNo }) : null;
    if (!v) throw new SecretAccessError(404, 'SECRET_VERSION_NOT_FOUND', `Version ${versionNo} does not exist`);
    if (v.state === 'DESTROYED' || !v.valueRef) await deny(410, 'SECRET_VERSION_DESTROYED', `Version ${v.version} was destroyed`);

    // Approval: the exact request (agent, secret, version, fields), once, within 15 minutes.
    let approvalId: string | null = null;
    if (g.requireApproval) {
      const same = (a: SecretRetrievalApprovalEntity) => a.agentId === agent.id && a.secretId === s.id && a.grantId === g.id && (a.version ?? null) === version && JSON.stringify([...a.fields].sort()) === JSON.stringify([...fields].sort());
      const given = str(b.approval_id);
      if (given) {
        const a = await db.findOneBy(SecretRetrievalApprovalEntity, { id: given, organizationId: agent.organizationId });
        if (!a || !same(a)) await deny(403, 'APPROVAL_MISMATCH', 'That approval is for a different request');
        if (a!.status === 'REJECTED') await deny(403, 'APPROVAL_REJECTED', `The request was rejected${a!.note ? `: ${a!.note}` : ''}`);
        if (a!.status === 'USED') await deny(409, 'APPROVAL_USED', 'That approval was already used; ask again');
        if (a!.status === 'EXPIRED' || Date.parse(a!.expiresAt) <= Date.now()) await deny(409, 'APPROVAL_EXPIRED', 'That approval expired; ask again');
        if (a!.status === 'PENDING') return { status: 202, body: { approval_id: a!.id, status: 'PENDING', expires_at: a!.expiresAt, decision_code: 'APPROVAL_REQUIRED', reason: 'Waiting for a human to approve this retrieval' } };
        approvalId = a!.id;
      } else {
        const t = now();
        const pending = Object.assign(new SecretRetrievalApprovalEntity(), { id: newId('sapr'), organizationId: agent.organizationId, grantId: g.id, agentId: agent.id, secretId: s.id, version, fields, reason, status: 'PENDING' as const, requestedAt: t, expiresAt: new Date(Date.now() + APPROVAL_TTL_MS).toISOString(), decidedBy: null, decidedByName: null, decidedAt: null, note: '', usedAt: null });
        await transaction(async (ex) => {
          await ex.insert(SecretRetrievalApprovalEntity, pending);
          await recordEvent({ orgId: agent.organizationId, actor, eventType: 'secret.retrieval_held', target: { type: 'secret', id: s.id, name: s.name }, metadata: { approvalId: pending.id, grantId: g.id, version, fieldsRequested: fields, reason, requestId } }, ex);
        });
        return { status: 202, body: { approval_id: pending.id, status: 'PENDING', expires_at: pending.expiresAt, decision_code: 'APPROVAL_REQUIRED', reason: 'This grant requires a human to approve each retrieval; retry with approval_id once approved' } };
      }
    }

    const webhook = await webhookRepo.getWebhook(agent.organizationId, s.webhookId);
    if (!webhook) throw new SecretAccessError(409, 'WEBHOOK_NOT_FOUND', 'The webhook holding this secret no longer exists');
    let res;
    try {
      res = await callWebhook<{ payload: SecretPayload }>(webhook, 'POST', '/internal/v1/secrets/read', { org_id: agent.organizationId, secret_id: s.id, value_ref: v.valueRef, fields });
    } catch (e) {
      if (e instanceof WebhookUnavailableError) throw new SecretAccessError(503, 'WEBHOOK_UNAVAILABLE', `${e.message}. Nothing was retrieved.`);
      throw e;
    }
    if (res.status !== 200) throw new SecretAccessError(res.status === 503 ? 503 : 502, (res.body as { error?: { code?: string } })?.error?.code ?? 'WEBHOOK_REJECTED', 'The customer webhook could not return the value');

    const t = now();
    await transaction(async (ex) => {
      if (approvalId) {
        // Single use: only one retrieval can turn the approval into USED.
        const used = await ex.createQueryBuilder().update(SecretRetrievalApprovalEntity).set({ status: 'USED', usedAt: t }).where(`id = :id AND status = 'APPROVED'`, { id: approvalId }).execute();
        if (!used.affected) throw new SecretAccessError(409, 'APPROVAL_USED', 'That approval was already used; ask again');
      }
      await ex.createQueryBuilder().update(SecretAccessGrantEntity).set({ lastUsedAt: t, useCount: () => 'use_count + 1' }).where('id = :id', { id: g.id }).execute();
      await ex.update(SecretEntity, { id: s.id }, { lastRetrievedAt: t });
      await recordEvent(
        {
          orgId: agent.organizationId,
          actor,
          eventType: v.state === 'ACTIVE' ? 'secret.retrieved' : 'secret.version_retrieved',
          target: { type: 'secret', id: s.id, name: s.name },
          metadata: { version: v.version, fingerprint: v.fingerprint, grantId: g.id, fieldsRequested: fields, reason, requestId, sourceIp: input.sourceIp, ...(approvalId ? { approvalId } : {}) },
        },
        ex,
      );
    });
    return { status: 200, body: { secret_id: s.id, name: s.name, type_key: s.typeKey, version: v.version, payload: res.body.payload, expires_at: s.expiresAt, retrieved_at: t, grant_id: g.id, request_id: requestId } };
  }
}
