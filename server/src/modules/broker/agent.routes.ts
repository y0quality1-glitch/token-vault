import { Router, type Response } from 'express';
import { normalizeIp } from '../../lib/net';
import { authenticate, executeAgentRequest, getAgentOperations, getCapabilities, getOwnRequest } from './broker.service';
import { createFromAgent, getForAgent } from '../grant-requests/grant-requests.service';

/**
 * Agent-facing API. Authenticated ONLY by the agent API credential
 * (Authorization: Bearer tvak_...). Admin session cookies are ignored here.
 */
export const agentRouter = Router();

/**
 * Tells a caller that used a rotated key (during its grace period) when that key stops
 * working, so operators can find agents that still run with the old key.
 */
const keyNotice = (res: Response) => (expiresAt: string) => res.setHeader('Token-Vault-Key-Expires', expiresAt);

agentRouter.post('/execute', async (req, res) => {
  const result = await executeAgentRequest({
    authorization: req.headers.authorization,
    // Non-authoritative hint used only to attribute unauthenticated attempts in the audit log.
    orgHint: typeof req.headers['x-token-vault-org'] === 'string' ? req.headers['x-token-vault-org'] : undefined,
    sourceIp: normalizeIp(req.ip),
    source: req.headers['x-token-vault-client'] === 'playground' ? 'playground' : 'agent-api',
    body: req.body,
    onPreviousKey: keyNotice(res),
  });
  res.status(result.status).json(result.body);
});

agentRouter.get('/requests/:id', async (req, res) => {
  const r = await getOwnRequest(req.headers.authorization, String(req.params.id), keyNotice(res));
  if (r.status === 401) return void res.status(401).json({ error: { code: 'AGENT_UNAUTHENTICATED', message: 'Invalid agent credential' } });
  if (r.status === 404) return void res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Request not found' } });
  res.json(r.body);
});

agentRouter.get('/capabilities', async (req, res) => {
  const r = await getCapabilities(req.headers.authorization, keyNotice(res));
  if (r.status === 401) return void res.status(401).json({ error: { code: 'AGENT_UNAUTHENTICATED', message: 'Invalid agent credential' } });
  res.json(r.body);
});

agentRouter.get('/operations', async (req, res) => {
  const r = await getAgentOperations(req.headers.authorization, keyNotice(res));
  if (r.status === 401) return void res.status(401).json({ error: { code: 'AGENT_UNAUTHENTICATED', message: 'Invalid agent credential' } });
  res.json(r.body);
});

const unauthenticated = { error: { code: 'AGENT_UNAUTHENTICATED', message: 'Invalid agent credential' } };

/** Just-in-time access: the agent asks a human for a time-limited grant. */
agentRouter.post('/access-requests', async (req, res) => {
  const agent = await authenticate(req.headers.authorization, keyNotice(res));
  if (!agent) return void res.status(401).json(unauthenticated);
  const r = await createFromAgent(agent, req.body);
  res.status(r.status).json(r.body);
});

agentRouter.get('/access-requests/:id', async (req, res) => {
  const agent = await authenticate(req.headers.authorization, keyNotice(res));
  if (!agent) return void res.status(401).json(unauthenticated);
  const r = await getForAgent(agent, String(req.params.id));
  if (!r) return void res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Access request not found' } });
  res.json(r);
});
