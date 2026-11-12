import express, { Router } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { orgCtx, requirePermission } from '../../middleware/auth';
import { deleteSettings, getSettingsView, handleInteraction, saveSettings, sendTest } from './slack.service';

/** Settings → Notifications: the Slack workspace and channel approval requests go to. */
export const slackSettingsRouter = Router();

slackSettingsRouter.get('/slack-settings', async (req, res) => {
  res.json(await getSettingsView(orgCtx(req).org.id));
});
slackSettingsRouter.put('/slack-settings', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  res.json(await saveSettings(orgCtx(req), req.body));
});
slackSettingsRouter.delete('/slack-settings', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  await deleteSettings(orgCtx(req));
  res.status(204).end();
});
slackSettingsRouter.post('/slack-settings/test', requirePermission(PERMISSIONS.POLICY_MANAGE), async (req, res) => {
  res.json(await sendTest(orgCtx(req)));
});

/**
 * Slack's Interactivity Request URL. Public, but every request must carry a valid Slack
 * signature over its raw body (checked in handleInteraction), so the body is kept raw here.
 */
export const slackInteractionsRouter = Router();
slackInteractionsRouter.post('/interactions', express.raw({ type: 'application/x-www-form-urlencoded', limit: '64kb' }), async (req, res) => {
  const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
  const header = (name: string) => (typeof req.headers[name] === 'string' ? (req.headers[name] as string) : undefined);
  const { status } = await handleInteraction(raw, { timestamp: header('x-slack-request-timestamp'), signature: header('x-slack-signature') });
  res.status(status).end();
});
