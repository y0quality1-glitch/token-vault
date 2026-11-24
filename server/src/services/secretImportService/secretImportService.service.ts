import { In } from 'typeorm';
import { PERMISSIONS, ROLE_PERMISSIONS, SECRET_NAME, SECRET_SCOPE_SLUG, validateSecretMetadata, validateSecretPayload, type Environment, type SecretImportOutcome, type SecretImportReport, type SecretImportResult } from '@token-vault/shared';
import { db } from '../../databases/client';
import { SecretEntity, SecretVersionEntity } from '../../entities';
import { HttpError, badRequest, forbidden } from '../../lib/errors';
import { recordEvent, userActor } from '../auditService/auditService.service';
import type { OrgContext } from '../baseService';
import SecretService from '../secretService/secretService.service';
import { customTypeRow, getSecretType, loadCustomTypes } from '../secretTypeService/registry';

/**
 * Secret import (spec 4.9.14): JSON (a list of secrets, or the decrypted content of an export)
 * or a `.env` file (one "Environment variables" secret). Each item is validated against its
 * type, then created through the normal path (the webhook validates and encrypts it again,
 * version 1, audited with source "import"). Duplicates: a name already used in the same scope
 * is skipped, gets a new version, or fails (onConflict); a value identical to another live
 * secret's (same keyed fingerprint) is reported. A dry run only validates.
 */

export interface ImportRequest {
  format: 'json' | 'env';
  /** The file's text. */
  content: string;
  /** .env: the secret's name. */
  name?: string;
  /** Defaults for items that do not say. */
  project?: string;
  workspace?: string;
  environment?: Environment;
  onConflict?: 'skip' | 'new_version' | 'fail';
  dryRun?: boolean;
}

const MAX_ITEMS = 200;
const ENVIRONMENTS = ['development', 'staging', 'production'];

interface Item {
  name: string;
  typeKey: string;
  project: string;
  workspace: string;
  environment: string;
  description?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
  payload: unknown;
}

/** KEY=VALUE lines; `export ` prefixes, comments, blank lines and surrounding quotes handled. */
export function parseDotEnv(text: string): { variables: Record<string, string>; issues: string[] } {
  const variables: Record<string, string> = {};
  const issues: string[] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (!m) return void issues.push(`line ${i + 1}: not KEY=VALUE`);
    let v = m[2]!;
    if (/^"(.*)"$/.test(v)) v = v.slice(1, -1).replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    else if (/^'(.*)'$/.test(v)) v = v.slice(1, -1);
    else v = v.replace(/\s+#.*$/, '');
    variables[m[1]!] = v;
  });
  return { variables, issues };
}

export default class SecretImportService {
  constructor(private readonly secrets = new SecretService()) {}

  private items(req: ImportRequest): Item[] {
    const defaults = { project: req.project ?? 'default', workspace: req.workspace ?? 'default', environment: req.environment ?? '' };
    if (req.format === 'env') {
      const { variables, issues } = parseDotEnv(req.content);
      if (issues.length) throw badRequest('The .env file has lines that are not KEY=VALUE', { fields: { content: issues.slice(0, 10).join('; ') } });
      if (!Object.keys(variables).length) throw badRequest('Request validation failed', { fields: { content: 'The file has no variables' } });
      if (!req.name) throw badRequest('Request validation failed', { fields: { name: 'Name the secret the variables go into' } });
      return [{ name: req.name, typeKey: 'env-vars', ...defaults, payload: { variables } }];
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(req.content);
    } catch {
      throw badRequest('Request validation failed', { fields: { content: 'Not valid JSON' } });
    }
    const list = Array.isArray(parsed) ? parsed : parsed && typeof parsed === 'object' && Array.isArray((parsed as { secrets?: unknown }).secrets) ? (parsed as { secrets: unknown[] }).secrets : null;
    if (!list) throw badRequest('Request validation failed', { fields: { content: 'Give a list of secrets, or {"secrets": [...]}' } });
    if (!list.length) throw badRequest('Request validation failed', { fields: { content: 'The list is empty' } });
    if (list.length > MAX_ITEMS) throw badRequest('Request validation failed', { fields: { content: `At most ${MAX_ITEMS} secrets per import` } });
    return list.map((raw) => {
      const x = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
      const str = (v: unknown) => (typeof v === 'string' ? v.trim() : '');
      return {
        name: str(x.name),
        typeKey: str(x.typeKey ?? x.type_key),
        project: str(x.project) || defaults.project,
        workspace: str(x.workspace) || defaults.workspace,
        environment: str(x.environment) || defaults.environment,
        description: typeof x.description === 'string' ? x.description : undefined,
        tags: Array.isArray(x.tags) ? (x.tags as string[]) : undefined,
        metadata: x.metadata && typeof x.metadata === 'object' ? (x.metadata as Record<string, unknown>) : undefined,
        payload: x.payload,
      };
    });
  }

  /** Problems with one item, by field (empty: valid). */
  private check(orgId: string, it: Item): Record<string, string> {
    const issues: Record<string, string> = {};
    if (!SECRET_NAME.test(it.name)) issues.name = 'Letters, digits, spaces and . _ / - (at most 120 characters)';
    if (!SECRET_SCOPE_SLUG.test(it.project)) issues.project = 'Lower-case letters, digits and dashes';
    if (!SECRET_SCOPE_SLUG.test(it.workspace)) issues.workspace = 'Lower-case letters, digits and dashes';
    if (!ENVIRONMENTS.includes(it.environment)) issues.environment = 'Choose development, staging or production';
    const type = it.typeKey ? getSecretType(it.typeKey, orgId) : undefined;
    if (!type || customTypeRow(orgId, it.typeKey)?.archivedAt) issues.typeKey = it.typeKey ? 'Unknown secret type' : 'Give the secret type';
    else {
      for (const [k, v] of Object.entries(validateSecretPayload(type, it.payload).issues)) issues[`payload.${k}`] = v;
      if (it.metadata) for (const [k, v] of Object.entries(validateSecretMetadata(type, it.metadata).issues)) issues[`metadata.${k}`] = v;
    }
    return issues;
  }

  private async existing(orgId: string, it: Item): Promise<SecretEntity | null> {
    return db
      .createQueryBuilder(SecretEntity, 's')
      .where(`s.organization_id = :orgId AND s.project = :project AND s.workspace = :workspace AND s.environment = :environment AND lower(s.name) = lower(:name) AND s.status <> 'DELETED'`, { orgId, ...it })
      .getOne();
  }

  /** Other live secrets whose active value has the same fingerprint. */
  private async sameValueAs(orgId: string, secretId: string): Promise<{ id: string; name: string }[]> {
    const mine = await db.findOneBy(SecretVersionEntity, { secretId, state: 'ACTIVE' });
    if (!mine) return [];
    const twins = await db.findBy(SecretVersionEntity, { organizationId: orgId, fingerprint: mine.fingerprint, state: 'ACTIVE' });
    const ids = twins.map((v) => v.secretId).filter((id) => id !== secretId);
    if (!ids.length) return [];
    return (await db.findBy(SecretEntity, { id: In(ids) })).filter((s) => s.status !== 'DELETED').map((s) => ({ id: s.id, name: s.name }));
  }

  async import(ctx: OrgContext, req: ImportRequest): Promise<SecretImportReport> {
    const onConflict = req.onConflict ?? 'skip';
    if (onConflict === 'new_version' && !ROLE_PERMISSIONS[ctx.role!]?.includes(PERMISSIONS.SECRET_UPDATE_VALUE)) throw forbidden(`Your role (${ctx.role}) cannot store new versions. Required: ${PERMISSIONS.SECRET_UPDATE_VALUE}`);
    await loadCustomTypes(ctx.org.id);
    const items = this.items(req);
    const results: SecretImportResult[] = [];
    const seen = new Set<string>();
    for (const [index, it] of items.entries()) {
      const result: SecretImportResult = { index, name: it.name, outcome: 'invalid', secretId: null, issues: this.check(ctx.org.id, it), sameValueAs: [] };
      results.push(result);
      const scopeKey = `${it.project}/${it.workspace}/${it.environment}/${it.name.toLowerCase()}`;
      if (seen.has(scopeKey)) result.issues.name = 'Appears more than once in this file';
      seen.add(scopeKey);
      if (Object.keys(result.issues).length) continue;
      const found = await this.existing(ctx.org.id, it);
      if (found && found.typeKey !== it.typeKey) {
        result.issues.typeKey = `"${it.name}" already exists with type ${found.typeKey}`;
        continue;
      }
      if (req.dryRun) {
        result.outcome = 'valid';
        if (found) result.issues.name = `Exists already: it would be ${onConflict === 'skip' ? 'skipped' : onConflict === 'new_version' ? 'given a new version' : 'refused'}`;
        continue;
      }
      try {
        if (found && onConflict === 'skip') {
          result.outcome = 'skipped';
          result.secretId = found.id;
          result.issues.name = 'A secret with this name exists in this scope';
        } else if (found && onConflict === 'fail') {
          result.outcome = 'failed';
          result.secretId = found.id;
          result.issues.name = 'A secret with this name exists in this scope';
        } else if (found) {
          await this.secrets.updateValue(ctx, { id: found.id, payload: it.payload as Record<string, unknown>, reason: 'Imported' });
          result.outcome = 'new_version';
          result.secretId = found.id;
        } else {
          const created = await this.secrets.create(ctx, { name: it.name, typeKey: it.typeKey, project: it.project, workspace: it.workspace, environment: it.environment as Environment, description: it.description, tags: it.tags, metadata: it.metadata, payload: it.payload as Record<string, unknown>, activate: true }, { source: 'import' });
          result.outcome = 'created';
          result.secretId = created.id;
        }
        if (result.secretId && result.outcome !== 'skipped' && result.outcome !== 'failed') result.sameValueAs = await this.sameValueAs(ctx.org.id, result.secretId);
      } catch (e) {
        const err = e as HttpError;
        result.outcome = err.status === 400 ? 'invalid' : 'failed';
        const fields = (err.details as { fields?: Record<string, string> } | undefined)?.fields;
        result.issues = fields && Object.keys(fields).length ? fields : { secret: err.message ?? 'Could not be stored' };
      }
    }
    const counts = Object.fromEntries((['created', 'new_version', 'skipped', 'invalid', 'failed', 'valid'] as SecretImportOutcome[]).map((o) => [o, results.filter((r) => r.outcome === o).length])) as Record<SecretImportOutcome, number>;
    if (!req.dryRun) await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'secret.import_completed', target: { type: 'organization', id: ctx.org.id, name: ctx.org.name }, severity: 'warning', metadata: { format: req.format, items: items.length, ...counts, onConflict } });
    return { dryRun: !!req.dryRun, results, counts };
  }
}
