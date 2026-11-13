import type { UserIssuer } from '@token-vault/shared';
import { transaction } from '../../databases/client';
import type { UserIssuerDto } from '../../databases/repository/userIssuer/userIssuer.dto';
import { badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parsePublicKey, verifyUserToken } from '../../lib/user-token';
import { userIssuerRepo } from '../../store/repos';
import type { AdminContext } from '../../types/express';
import { recordEvent, userActor } from '../auditService/auditService.service';

type OrgContext = AdminContext & { org: { id: string } };

function checkedKey(publicKey: string) {
  const key = parsePublicKey(publicKey);
  if (!key.ok) throw badRequest('Request validation failed', { fields: { publicKey: key.reason } });
  return key;
}

/**
 * User identity issuers: who may vouch for the users agents act for (Settings → User identity).
 * Managing them is a security decision (policy:manage: Owner, Security Administrator).
 */
export default class UserIssuerService {
  list(orgId: string) {
    return userIssuerRepo.listIssuers(orgId).then((items) => ({ items }));
  }

  /** Plain data for storage (the DTO is a class instance). */
  private fields(body: UserIssuerDto) {
    const { name, issuer, audience, publicKey, groupsClaim, maxTokenLifetimeSeconds, enabled } = body;
    return { name, issuer, audience, publicKey, groupsClaim, maxTokenLifetimeSeconds, enabled };
  }

  /** Registers an issuer (no `id`) or updates one (with `id`). Returns the issuer and whether it is new. */
  async save(ctx: OrgContext, body: UserIssuerDto): Promise<{ issuer: UserIssuer; created: boolean }> {
    const fields = this.fields(body);
    const key = checkedKey(fields.publicKey);
    if (!body.id) {
      const existing = await userIssuerRepo.listIssuers(ctx.org.id);
      if (existing.some((i) => i.issuer === fields.issuer)) throw conflict(`An issuer "${fields.issuer}" is already registered.`);
      const now = new Date().toISOString();
      const issuer = await transaction(async (tx) => {
        const created = await userIssuerRepo.insertIssuer({ id: newId('uis'), organizationId: ctx.org.id, ...fields, keyFingerprint: key.fingerprint, createdAt: now, updatedAt: now, lastUsedAt: null } satisfies UserIssuer, tx);
        await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'user_issuer.created', target: { type: 'user_issuer', id: created.id, name: created.name }, severity: 'warning', metadata: { issuer: created.issuer, audience: created.audience, keyFingerprint: created.keyFingerprint } }, tx);
        return created;
      });
      return { issuer, created: true };
    }
    const issuer = await transaction(async (tx) => {
      const existing = await userIssuerRepo.getIssuer(ctx.org.id, body.id!, tx);
      if (!existing) throw notFound('Issuer');
      const others = await userIssuerRepo.listIssuers(ctx.org.id, tx);
      if (others.some((i) => i.id !== existing.id && i.issuer === fields.issuer)) throw conflict(`An issuer "${fields.issuer}" is already registered.`);
      const updated = (await userIssuerRepo.updateIssuer(ctx.org.id, existing.id, { ...fields, keyFingerprint: key.fingerprint, updatedAt: new Date().toISOString() }, tx))!;
      const keyChanged = existing.keyFingerprint !== updated.keyFingerprint;
      await recordEvent(
        {
          orgId: ctx.org.id,
          actor: userActor(ctx),
          eventType: existing.enabled !== updated.enabled ? (updated.enabled ? 'user_issuer.enabled' : 'user_issuer.disabled') : keyChanged ? 'user_issuer.key_changed' : 'user_issuer.updated',
          target: { type: 'user_issuer', id: updated.id, name: updated.name },
          // A new key or a newly enabled issuer changes who can vouch for users.
          severity: keyChanged || (!existing.enabled && updated.enabled) || existing.issuer !== updated.issuer ? 'warning' : 'info',
          metadata: { issuer: updated.issuer, audience: updated.audience, keyFingerprint: updated.keyFingerprint, enabled: updated.enabled },
        },
        tx,
      );
      return updated;
    });
    return { issuer, created: false };
  }

  async remove(ctx: OrgContext, id: string): Promise<void> {
    await transaction(async (tx) => {
      const existing = await userIssuerRepo.getIssuer(ctx.org.id, id, tx);
      if (!existing) throw notFound('Issuer');
      await userIssuerRepo.deleteIssuer(ctx.org.id, existing.id, tx);
      await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'user_issuer.deleted', target: { type: 'user_issuer', id: existing.id, name: existing.name }, metadata: { issuer: existing.issuer } }, tx);
    });
  }

  /** Checks a user token against this organization's issuers, without running anything. */
  async verifyToken(orgId: string, token: string) {
    const result = verifyUserToken(token, await userIssuerRepo.listIssuers(orgId));
    return result.ok ? { valid: true, user: result.user } : { valid: false, reason: result.reason };
  }
}
