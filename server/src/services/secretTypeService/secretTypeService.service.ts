import { createHash } from 'node:crypto';
import { SECRET_CATEGORIES, SECRET_CATEGORY_LABELS, SECRET_PROVIDER_CAPABILITIES, SecretTypeError, canonicalJson, validateCustomSecretType, type SecretTypeDefinition, type SecretTypeInfo, type SecretTypesResponse } from '@token-vault/shared';
import { db, transaction } from '../../databases/client';
import { CustomSecretTypeEntity, SecretEntity } from '../../entities';
import { HttpError, badRequest, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { recordEvent, userActor } from '../auditService/auditService.service';
import type { OrgContext } from '../baseService';
import { isCustomTypeKey, loadCustomTypes, secretTypeSync, secretTypes } from './registry';

const withInfo = (def: SecretTypeDefinition, digest: string, source: SecretTypeInfo['source']): SecretTypeInfo => ({
  ...def,
  categoryLabel: SECRET_CATEGORY_LABELS[def.category],
  digest,
  source,
  provider: SECRET_PROVIDER_CAPABILITIES[def.key] ?? null,
});

const catalogInfo = (key: string): SecretTypeInfo | null => {
  const e = secretTypes.entry(key);
  return e ? withInfo(e.definition, e.digest, secretTypeSync ? 'catalog' : 'bundled') : null;
};

const digestOf = (def: SecretTypeDefinition) => createHash('sha256').update(canonicalJson(def)).digest('hex');

/**
 * The secret types the control plane trusts (spec 4.9.3): catalog types (verified from the CMS,
 * or predefined) and the organization's own types (spec 4.9.3 K), which follow the same schema,
 * so encryption, masking, access control and audit apply to them unchanged.
 */
export default class SecretTypeService {
  /** `{ search?, filters: { category? }, includeArchived? }`: search matches key, name, description and tags. */
  async list(orgId: string, body: { search?: unknown; filters?: { category?: unknown }; category?: unknown; includeArchived?: unknown } = {}): Promise<SecretTypesResponse> {
    const search = typeof body.search === 'string' ? body.search.trim().toLowerCase() : '';
    const category = typeof body.filters?.category === 'string' ? body.filters.category : typeof body.category === 'string' ? body.category : '';
    const custom = (await loadCustomTypes(orgId, true)).filter((r) => body.includeArchived === true || !r.archivedAt).map((r) => ({ ...withInfo(r.definition, r.digest, 'custom'), archived: !!r.archivedAt }));
    const all = [...secretTypes.list().map((t) => catalogInfo(t.key)!), ...custom];
    const types = all.filter((t) => (!category || t.category === category) && (!search || [t.key, t.name, t.description, ...t.tags].some((x) => x.toLowerCase().includes(search))));
    const s = secretTypeSync?.status;
    return {
      types,
      categories: SECRET_CATEGORIES.map((key) => ({ key, label: SECRET_CATEGORY_LABELS[key], count: all.filter((t) => t.category === key).length })).filter((c) => c.count > 0),
      catalog: s ? { url: s.url, keyIds: s.keyIds, lastSuccessAt: s.lastSuccessAt, lastError: s.lastError, refused: s.refused } : null,
    };
  }

  async get(orgId: string, key: string): Promise<SecretTypeInfo> {
    if (isCustomTypeKey(key)) {
      const r = (await loadCustomTypes(orgId, true)).find((x) => x.key === key);
      if (!r) throw notFound('Secret type');
      return withInfo(r.definition, r.digest, 'custom');
    }
    const t = catalogInfo(key);
    if (!t) throw notFound('Secret type');
    return t;
  }

  /**
   * Creates an organization-defined type, or a new version of one (the version number is
   * assigned here). Existing secrets keep their values; new values, and rollbacks, are checked
   * against the current version.
   */
  async saveCustom(ctx: OrgContext, raw: unknown): Promise<SecretTypeInfo> {
    // A type as this API returns it can be sent back: the descriptive fields added here are dropped.
    const { categoryLabel: _l, digest: _d, source: _s, provider: _p, archived: _a, ...input } = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
    const key = typeof input.key === 'string' ? input.key : '';
    const existing = key ? await db.findOneBy(CustomSecretTypeEntity, { organizationId: ctx.org.id, key }) : null;
    let def: SecretTypeDefinition;
    try {
      def = validateCustomSecretType({ category: 'custom', ...input, version: (existing?.version ?? 0) + 1 });
    } catch (e) {
      if (e instanceof SecretTypeError) throw badRequest('The secret type is not valid', { issues: e.issues });
      throw e;
    }
    const t = new Date().toISOString();
    const digest = digestOf(def);
    await transaction(async (ex) => {
      if (existing) await ex.update(CustomSecretTypeEntity, { id: existing.id }, { version: def.version, definition: def, digest, updatedBy: ctx.user.id, updatedByName: ctx.user.fullName, updatedAt: t, archivedAt: null });
      else await ex.insert(CustomSecretTypeEntity, { id: newId('cst'), organizationId: ctx.org.id, key: def.key, version: def.version, definition: def, digest, createdBy: ctx.user.id, createdByName: ctx.user.fullName, createdAt: t, updatedBy: ctx.user.id, updatedByName: ctx.user.fullName, updatedAt: t, archivedAt: null });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: existing ? 'secret_type.updated' : 'secret_type.created', target: { type: 'secret_type', id: def.key, name: def.name }, severity: 'warning', metadata: { key: def.key, version: def.version, digest, fields: Object.keys(def.fields), sensitiveFields: Object.entries(def.fields).filter(([, f]) => f.sensitive).map(([k]) => k) } }, ex);
    });
    await loadCustomTypes(ctx.org.id, true);
    return withInfo(def, digest, 'custom');
  }

  /** Archives a custom type: no new secrets of it; refused while live secrets use it. */
  async archiveCustom(ctx: OrgContext, key: string): Promise<{ key: string; archived: true }> {
    const r = await db.findOneBy(CustomSecretTypeEntity, { organizationId: ctx.org.id, key });
    if (!r) throw notFound('Secret type');
    const used = await db.createQueryBuilder(SecretEntity, 's').where(`s.organization_id = :org AND s.type_key = :key AND s.status <> 'DELETED'`, { org: ctx.org.id, key }).getCount();
    if (used) throw new HttpError(409, 'SECRET_TYPE_IN_USE', `${used} secret(s) still use this type; delete them first`);
    await transaction(async (ex) => {
      await ex.update(CustomSecretTypeEntity, { id: r.id }, { archivedAt: new Date().toISOString(), updatedBy: ctx.user.id, updatedByName: ctx.user.fullName });
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret_type.archived', target: { type: 'secret_type', id: key, name: r.definition.name }, metadata: { key, version: r.version } }, ex);
    });
    await loadCustomTypes(ctx.org.id, true);
    return { key, archived: true };
  }
}
