import { Router } from 'express';
import { z } from 'zod';
import { PERMISSIONS, type AccessReviewItem, type AccessReviewSummary } from '@token-vault/shared';
import { transaction } from '../../db/client';
import { conflict, notFound } from '../../lib/errors';
import { parse } from '../../lib/validate';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { auditRepo, grantRepo, orgRepo } from '../../store/repos';
import type { GrantRecord } from '../../store/types';
import { effectiveGrantStatus, loadLookups, toGrant } from '../../store/views';
import { recordEvent, userActor } from '../audit/audit.service';

/**
 * Access reviews (recertification): every active grant must be re-confirmed by a reviewer
 * at least every REVIEW_INTERVAL_DAYS. Reviewers see 30-day usage, so unused grants stand
 * out, and either keep (certify) or revoke each grant. Every decision is audited.
 */
export const REVIEW_INTERVAL_DAYS = 30;
const DAY = 86_400_000;

export function reviewDueAt(g: Pick<GrantRecord, 'lastReviewedAt' | 'createdAt'>): Date {
  return new Date(new Date(g.lastReviewedAt ?? g.createdAt).getTime() + REVIEW_INTERVAL_DAYS * DAY);
}

export async function buildReview(organizationId: string): Promise<AccessReviewSummary> {
  const now = Date.now();
  const [grants, usage] = await Promise.all([grantRepo.listGrants(organizationId), auditRepo.usageByGrant(organizationId, new Date(now - 30 * DAY).toISOString())]);
  const active = grants.filter((g) => effectiveGrantStatus(g) === 'ACTIVE');
  const lookups = await loadLookups(organizationId, active.map((g) => g.lastReviewedBy ?? '').filter(Boolean));
  const reviewers = await orgRepo.userNames(active.map((g) => g.lastReviewedBy ?? ''));
  const items: AccessReviewItem[] = active
    .map((g) => {
      const due = reviewDueAt(g);
      const u = usage.get(g.id) ?? { allowed: 0, denied: 0 };
      return {
        grant: toGrant(g, lookups),
        lastReviewedAt: g.lastReviewedAt ?? null,
        lastReviewedByName: g.lastReviewedBy ? reviewers.get(g.lastReviewedBy) ?? 'Unknown user' : null,
        reviewDueAt: due.toISOString(),
        due: due.getTime() <= now,
        uses30d: u.allowed,
        denied30d: u.denied,
      };
    })
    .sort((a, b) => Number(b.due) - Number(a.due) || Number(a.uses30d > 0) - Number(b.uses30d > 0) || a.grant.expiresAt.localeCompare(b.grant.expiresAt));
  return {
    intervalDays: REVIEW_INTERVAL_DAYS,
    due: items.filter((i) => i.due).length,
    unused30d: items.filter((i) => i.uses30d === 0).length,
    expiringSoon: items.filter((i) => new Date(i.grant.expiresAt).getTime() - now <= 3 * DAY).length,
    items,
  };
}

export const accessReviewsRouter = Router();

accessReviewsRouter.get('/access-reviews', async (req, res) => {
  const { org } = orgCtx(req);
  const summary = await buildReview(org.id);
  res.json(req.query.summary === '1' ? { ...summary, items: [] } : summary);
});

/** Certify ("keep") grants: records the review and restarts the review interval. */
accessReviewsRouter.post('/access-reviews/certify', requirePermission(PERMISSIONS.GRANT_REVOKE), async (req, res) => {
  const ctx = orgCtx(req);
  const { grantIds, note } = parse(z.object({ grantIds: z.array(z.string().min(1)).min(1, 'Select at least one grant').max(50), note: z.string().trim().max(240).default('') }), req.body);
  const certified = await transaction(async (tx) => {
    const now = new Date().toISOString();
    let n = 0;
    for (const id of [...new Set(grantIds)]) {
      const g = await grantRepo.getGrant(ctx.org.id, id, tx);
      if (!g) throw notFound(`Grant ${id}`);
      const status = effectiveGrantStatus(g);
      if (status !== 'ACTIVE') throw conflict(`Grant "${g.name}" is ${status.toLowerCase()}; only active grants can be certified`);
      await grantRepo.updateGrant(g.id, { lastReviewedAt: now, lastReviewedBy: ctx.user.id }, tx);
      await recordEvent(
        { orgId: ctx.org.id, actor: userActor(ctx), eventType: 'grant.certified', target: { type: 'grant', id: g.id, name: g.name }, metadata: { previousReviewAt: g.lastReviewedAt ?? null, nextReviewDue: reviewDueAt({ lastReviewedAt: now, createdAt: g.createdAt }).toISOString(), note } },
        tx,
      );
      n++;
    }
    return n;
  });
  res.json({ certified, summary: await buildReview(ctx.org.id) });
});
