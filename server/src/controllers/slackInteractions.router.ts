import express, { Router } from 'express';
import { handleInteraction } from '../services/slackService/slackService.service';

/**
 * Slack's Interactivity Request URL: POST /slack/interactions. Its request and response are
 * Slack's format (signed form body in, status only out), so it is not part of the admin API or
 * its envelope. Signature checks happen in the Slack service.
 */
export const slackInteractionsRouter = Router();
slackInteractionsRouter.post('/interactions', express.raw({ type: 'application/x-www-form-urlencoded', limit: '64kb' }), async (req, res) => {
  const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
  const header = (name: string) => (typeof req.headers[name] === 'string' ? (req.headers[name] as string) : undefined);
  const { status } = await handleInteraction(raw, { timestamp: header('x-slack-request-timestamp'), signature: header('x-slack-signature') });
  res.status(status).end();
});
