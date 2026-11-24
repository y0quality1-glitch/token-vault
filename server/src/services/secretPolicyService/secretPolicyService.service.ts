import type { EntityManager } from 'typeorm';
import type { EffectiveSecretPolicy, SecretPolicySettings, SecretPolicyView, SecretTypeDefinition } from '@token-vault/shared';
import { db, transaction } from '../../databases/client';
import type { SaveSecretPolicyDto } from '../../databases/repository/secret/secretLifecycle.dto';
import { SecretPolicyEntity } from '../../entities';
import { badRequest, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { recordEvent, userActor } from '../auditService/auditService.service';
import type { OrgContext } from '../baseService';

/**
 * Expiry and retention policies (spec 4.9.12: "expiration policies may be configured at
 * organization, project, workspace or secret level"; 4.9.8 version retention). For each setting
 * the most specific level that sets it wins: workspace, then project, then organization, then
 * the secret type's default. A secret's own expiry date and rotation settings override them all.
 */

const SETTINGS = ['expiryWarningDays', 'defaultExpiresInDays', 'keepVersions', 'keepDays'] as const satisfies readonly (keyof SecretPolicySettings)[];

export function policyView(p: SecretPolicyEntity): SecretPolicyView {
  return {
    id: p.id,
    scope: p.scope,
    project: p.project,
    workspace: p.workspace,
    expiryWarningDays: p.expiryWarningDays,
    defaultExpiresInDays: p.defaultExpiresInDays,
    keepVersions: p.keepVersions,
    keepDays: p.keepDays,
    updatedBy: { id: p.updatedBy, name: p.updatedByName },
    updatedAt: p.updatedAt,
  };
}

export function policiesOf(orgId: string, ex: EntityManager = db): Promise<SecretPolicyEntity[]> {
  return ex.findBy(SecretPolicyEntity, { organizationId: orgId });
}

/** The settings that apply to a secret in this project and workspace, and where each one comes from. */
export function resolvePolicy(policies: readonly SecretPolicyEntity[], s: { project: string; workspace: string }, type: SecretTypeDefinition | undefined): EffectiveSecretPolicy {
  const levels = [
    policies.find((p) => p.scope === 'WORKSPACE' && p.project === s.project && p.workspace === s.workspace),
    policies.find((p) => p.scope === 'PROJECT' && p.project === s.project),
    policies.find((p) => p.scope === 'ORGANIZATION'),
  ].filter((p): p is SecretPolicyEntity => !!p);
  const pick = <K extends (typeof SETTINGS)[number]>(k: K) => {
    const p = levels.find((l) => l[k] != null);
    return p ? { value: p[k] as number, source: p.scope } : null;
  };
  return {
    expiryWarningDays: pick('expiryWarningDays') ?? { value: type?.defaults.expiryWarningDays ?? 14, source: 'TYPE' },
    defaultExpiresInDays: pick('defaultExpiresInDays') ?? (type?.defaults.expiresInDays ? { value: type.defaults.expiresInDays, source: 'TYPE' } : { value: null, source: 'NONE' }),
    keepVersions: pick('keepVersions') ?? { value: null, source: 'NONE' },
    keepDays: pick('keepDays') ?? { value: null, source: 'NONE' },
  };
}

export default class SecretPolicyService {
  async list(orgId: string): Promise<{ items: SecretPolicyView[] }> {
    const rows = await db.find(SecretPolicyEntity, { where: { organizationId: orgId } });
    const rank = { ORGANIZATION: 0, PROJECT: 1, WORKSPACE: 2 } as const;
    rows.sort((a, b) => rank[a.scope] - rank[b.scope] || (a.project ?? '').localeCompare(b.project ?? '') || (a.workspace ?? '').localeCompare(b.workspace ?? ''));
    return { items: rows.map(policyView) };
  }

  /** Creates or replaces the policy of one level. A policy that sets nothing is removed. */
  async save(ctx: OrgContext, dto: SaveSecretPolicyDto): Promise<SecretPolicyView | { id: null; removed: true }> {
    const fields: Record<string, string> = {};
    if (dto.scope !== 'ORGANIZATION' && !dto.project) fields.project = 'Give the project';
    if (dto.scope === 'WORKSPACE' && !dto.workspace) fields.workspace = 'Give the workspace';
    if (Object.keys(fields).length) throw badRequest('Request validation failed', { fields });
    const project = dto.scope === 'ORGANIZATION' ? null : dto.project!;
    const workspace = dto.scope === 'WORKSPACE' ? dto.workspace! : null;
    const settings = Object.fromEntries(SETTINGS.map((k) => [k, dto[k] ?? null])) as Record<(typeof SETTINGS)[number], number | null>;
    const label = [dto.scope.toLowerCase(), project, workspace].filter(Boolean).join(' ');

    return transaction(async (ex) => {
      const existing = await ex
        .createQueryBuilder(SecretPolicyEntity, 'p')
        .where(`p.organization_id = :org AND p.scope = :scope AND coalesce(p.project, '') = :project AND coalesce(p.workspace, '') = :workspace`, { org: ctx.org.id, scope: dto.scope, project: project ?? '', workspace: workspace ?? '' })
        .setLock('pessimistic_write')
        .getOne();
      const empty = Object.values(settings).every((v) => v == null);
      const target = { type: 'secret_policy', id: existing?.id ?? '', name: label };
      if (empty) {
        if (existing) {
          await ex.delete(SecretPolicyEntity, { id: existing.id });
          await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret_policy.deleted', target, metadata: { scope: dto.scope, project, workspace } }, ex);
        }
        return { id: null, removed: true as const };
      }
      const row = { ...settings, updatedBy: ctx.user.id, updatedByName: ctx.user.fullName, updatedAt: new Date().toISOString() };
      const id = existing?.id ?? newId('spol');
      if (existing) await ex.update(SecretPolicyEntity, { id }, row);
      else await ex.insert(SecretPolicyEntity, { id, organizationId: ctx.org.id, scope: dto.scope, project, workspace, ...row });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: existing ? 'secret_policy.updated' : 'secret_policy.created', target: { ...target, id }, severity: 'warning', metadata: { scope: dto.scope, project, workspace, ...settings } }, ex);
      return policyView((await ex.findOneBy(SecretPolicyEntity, { id }))!);
    });
  }

  async remove(ctx: OrgContext, id: string): Promise<{ id: string; removed: true }> {
    await transaction(async (ex) => {
      const p = await ex.findOneBy(SecretPolicyEntity, { id, organizationId: ctx.org.id });
      if (!p) throw notFound('Secret policy');
      await ex.delete(SecretPolicyEntity, { id });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret_policy.deleted', target: { type: 'secret_policy', id, name: [p.scope.toLowerCase(), p.project, p.workspace].filter(Boolean).join(' ') }, severity: 'warning', metadata: { scope: p.scope, project: p.project, workspace: p.workspace } }, ex);
    });
    return { id, removed: true };
  }
}
