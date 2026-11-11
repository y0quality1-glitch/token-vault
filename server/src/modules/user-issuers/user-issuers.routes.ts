import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, type UserIssuer } from '@token-vault/shared';
import { badRequest, conflict, notFound } from '../../lib/errors';
import { newId } from '../../lib/ids';
import { parse } from '../../lib/validate';
import { USER_TOKEN_LIMITS, parsePublicKey, verifyUserToken } from '../../lib/user-token';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { transaction } from '../../db/client';
import { userIssuerRepo } from '../../store/repos';
import { recordEvent, userActor } from '../audit/audit.service';

/**
 * User identity issuers: who may vouch for the users agents act for (Settings → User identity).
 * Managing them is a security decision (policy:manage: Owner, Security Administrator).
 */
export const userIssuersRouter = Router();

const issuerSchema = z.object({
  name: z.string().trim().min(3, 'Name must be at least 3 characters').max(80),
  issuer: z.string().trim().min(1, 'Enter the issuer (the tokens\' "iss" claim)').max(300),
  audience: z.string().trim().min(1, 'Enter the audience (the tokens\' "aud" claim)').max(300),
  publicKey: z.string().trim().min(1, 'Paste the public key').max(10_000),
  groupsClaim: z
    .string()
    .trim()
    .regex(/^[a-zA-Z_][a-zA-Z0-9_:./-]{0,99}$/, 'Use a claim name such as groups or roles')
    .default('groups'),
  maxTokenLifetimeSeconds: z.number().int().min(USER_TOKEN_LIMITS.MIN_LIFETIME_S, 'At least 60 seconds').max(USER_TOKEN_LIMITS.MAX_LIFETIME_S, 'At most 24 hours (86400 seconds)').default(3600),
  enabled: z.boolean().default(true),
});

function checkedKey(publicKey: string) {
  const key = parsePublicKey(publicKey);
  if (!key.ok) throw badRequest('Request validation failed', { fields: { publicKey: key.reason } });
  return key;
}

userIssuersRouter.get('/user-issuers', async (req, res) => {
  const { org } = orgCtx(req);
  res.json({ items: await userIssuerRepo.listIssuers(org.id) });
});

userIssuersRouter.post('/user-issuers', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(issuerSchema, req.body);
  const key = checkedKey(body.publicKey);
  const existing = await userIssuerRepo.listIssuers(ctx.org.id);
  if (existing.some((i) => i.issuer === body.issuer)) throw conflict(`An issuer "${body.issuer}" is already registered.`);
  const now = new Date().toISOString();
  const created = await transaction(async (tx) => {
    const issuer = await userIssuerRepo.insertIssuer({ id: newId('uis'), organizationId: ctx.org.id, ...body, keyFingerprint: key.fingerprint, createdAt: now, updatedAt: now, lastUsedAt: null } satisfies UserIssuer, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'user_issuer.created', target: { type: 'user_issuer', id: issuer.id, name: issuer.name }, severity: 'warning', metadata: { issuer: issuer.issuer, audience: issuer.audience, keyFingerprint: issuer.keyFingerprint } }, tx);
    return issuer;
  });
  res.status(201).json(created);
});

userIssuersRouter.put('/user-issuers/:id', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const body = parse(issuerSchema, req.body);
  const key = checkedKey(body.publicKey);
  const updated = await transaction(async (tx) => {
    const existing = await userIssuerRepo.getIssuer(ctx.org.id, String(req.params.id), tx);
    if (!existing) throw notFound('Issuer');
    const others = await userIssuerRepo.listIssuers(ctx.org.id, tx);
    if (others.some((i) => i.id !== existing.id && i.issuer === body.issuer)) throw conflict(`An issuer "${body.issuer}" is already registered.`);
    const issuer = (await userIssuerRepo.updateIssuer(ctx.org.id, existing.id, { ...body, keyFingerprint: key.fingerprint, updatedAt: new Date().toISOString() }, tx))!;
    const keyChanged = existing.keyFingerprint !== issuer.keyFingerprint;
    await recordEvent(
      {
        orgId: ctx.org.id,
        actor: userActor(ctx),
        eventType: existing.enabled !== issuer.enabled ? (issuer.enabled ? 'user_issuer.enabled' : 'user_issuer.disabled') : keyChanged ? 'user_issuer.key_changed' : 'user_issuer.updated',
        target: { type: 'user_issuer', id: issuer.id, name: issuer.name },
        // A new key or a newly enabled issuer changes who can vouch for users.
        severity: keyChanged || (!existing.enabled && issuer.enabled) || existing.issuer !== issuer.issuer ? 'warning' : 'info',
        metadata: { issuer: issuer.issuer, audience: issuer.audience, keyFingerprint: issuer.keyFingerprint, enabled: issuer.enabled },
      },
      tx,
    );
    return issuer;
  });
  res.json(updated);
});

userIssuersRouter.delete('/user-issuers/:id', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  await transaction(async (tx) => {
    const existing = await userIssuerRepo.getIssuer(ctx.org.id, String(req.params.id), tx);
    if (!existing) throw notFound('Issuer');
    await userIssuerRepo.deleteIssuer(ctx.org.id, existing.id, tx);
    await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'user_issuer.deleted', target: { type: 'user_issuer', id: existing.id, name: existing.name }, metadata: { issuer: existing.issuer } }, tx);
  });
  res.status(204).end();
});

/** Checks a user token against this organization's issuers, without running anything. */
userIssuersRouter.post('/user-issuers/verify-token', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  const ctx = orgCtx(req);
  const { token } = parse(z.object({ token: z.string().trim().min(1, 'Paste a user token').max(USER_TOKEN_LIMITS.MAX_TOKEN_LENGTH) }), req.body);
  const result = verifyUserToken(token, await userIssuerRepo.listIssuers(ctx.org.id));
  res.json(result.ok ? { valid: true, user: result.user } : { valid: false, reason: result.reason });
});
