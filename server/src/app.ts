import express, { Router } from 'express';
import { errorHandler, notFoundHandler, requestLogger, securityHeaders } from './middleware/http';
import { requireOrg, requireSession } from './middleware/auth';
import { authRouter } from './modules/auth/auth.routes';
import { organizationsRouter } from './modules/organizations/organizations.routes';
import { webhooksRouter } from './modules/webhooks/webhooks.routes';
import { integrationsRouter } from './modules/integrations/integrations.routes';
import { agentsRouter } from './modules/agents/agents.routes';
import { grantsRouter } from './modules/grants/grants.routes';
import { policiesRouter } from './modules/policies/policies.routes';
import { auditRouter } from './modules/audit/audit.routes';
import { dashboardRouter } from './modules/dashboard/dashboard.routes';
import { demoRouter } from './modules/demo/demo.routes';
import { grantRequestsRouter } from './modules/grant-requests/grant-requests.routes';
import { approvalsRouter } from './modules/approvals/approvals.routes';
import { userIssuersRouter } from './modules/user-issuers/user-issuers.routes';
import { delegationsRouter } from './modules/delegations/delegations.routes';
import { accessReviewsRouter } from './modules/access-reviews/access-reviews.routes';
import { agentRouter } from './modules/broker/agent.routes';
import { providersRouter } from './modules/providers/providers.routes';

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 'loopback'); // the Vite dev proxy runs on loopback
  app.use(securityHeaders);
  app.use(requestLogger);
  app.use(express.json({ limit: '32kb' }));

  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', service: 'token-vault-control-plane' });
  });

  // ---- Admin console API (session cookie + RBAC)
  const api = Router();
  api.use('/auth', authRouter);

  const orgScoped = Router();
  orgScoped.use(requireSession, requireOrg);
  orgScoped.use(organizationsRouter);
  orgScoped.use(dashboardRouter);
  orgScoped.use(webhooksRouter);
  orgScoped.use(providersRouter);
  orgScoped.use(integrationsRouter);
  orgScoped.use(agentsRouter);
  orgScoped.use(grantsRouter);
  orgScoped.use(grantRequestsRouter);
  orgScoped.use(approvalsRouter);
  orgScoped.use(accessReviewsRouter);
  orgScoped.use(policiesRouter);
  orgScoped.use(userIssuersRouter);
  orgScoped.use(delegationsRouter);
  orgScoped.use(auditRouter);
  orgScoped.use(demoRouter);
  api.use(orgScoped);

  app.use('/api/v1', api);

  // ---- Agent execution API (agent credential only)
  app.use('/agent/v1', agentRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
