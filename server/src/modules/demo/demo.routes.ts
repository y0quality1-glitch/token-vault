import { Router } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { resetDatabase } from '../../store/seed';
import { recordEvent, userActor } from '../audit/audit.service';
import { resetBrokerState } from '../broker/broker.service';
import { syncSeedCredentialMetadata } from '../webhooks/webhook.service';

export const demoRouter = Router();

/** Restores the seeded demonstration state atomically. Sessions are preserved (seed IDs are stable). */
demoRouter.post('/demo/reset', requirePermission(PERMISSIONS.DEMO_RESET), async (req, res) => {
  const ctx = orgCtx(req);
  await resetDatabase();
  resetBrokerState();
  await syncSeedCredentialMetadata();
  await recordEvent({ orgId: ctx.org.id, actor: userActor(ctx), eventType: 'demo.reset', target: { type: 'organization', id: ctx.org.id, name: ctx.org.name }, severity: 'warning' });
  res.json({ ok: true });
});
