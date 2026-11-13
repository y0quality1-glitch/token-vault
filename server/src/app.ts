import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { adminControllers, agentControllers } from './controllers';
import type { BaseController } from './controllers/baseController';
import { slackInteractionsRouter } from './controllers/slackInteractions.router';
import { errorMiddleware, notFoundMiddleware } from './core/ApiError';
import { decisionJwks } from './lib/decision-token';
import { requestLogger } from './middlewares/http.middleware';
import { registerSlackApprovals } from './services/slackService/slackService.service';
import { setupSwagger } from './swagger';

/** Admin console API (session cookie + RBAC). */
export const PATH = '/api/v1';
/** Agent API (agent credential only). */
export const AGENT_PATH = '/agent/v1';

/**
 * The Express application (template: src/app.ts): middlewares, the admin and agent controllers,
 * the external-format routes (health, JWKS, Slack), API docs, then 404 and a 4-argument error
 * handler (template fix B-14).
 */
export class App {
  public readonly app = express();

  constructor(
    private readonly admin: BaseController[] = adminControllers(),
    private readonly agent: BaseController[] = agentControllers(),
  ) {}

  build(): express.Application {
    const app = this.app;
    app.disable('x-powered-by');
    app.set('trust proxy', 'loopback'); // the Vite dev proxy runs on loopback
    app.use(requestLogger);
    app.use(helmet());
    // Same origin only (the console proxies /api); no cross-origin browser access.
    app.use(cors({ origin: false }));
    app.use(express.json({ limit: '32kb' }));
    app.use((_req, res, next) => {
      res.setHeader('Cache-Control', 'no-store');
      next();
    });

    app.get('/healthz', (_req, res) => void res.json({ status: 'ok', service: 'token-vault-control-plane' }));
    // Public keys for decision tokens (integrations in decision-only or short-lived credential mode).
    app.get('/.well-known/jwks.json', (_req, res) => void res.set('cache-control', 'public, max-age=300').json(decisionJwks()));
    app.use(PATH, ...this.admin.map((c) => c.init().router));
    app.use(AGENT_PATH, ...this.agent.map((c) => c.init().router));
    setupSwagger(app, () => this.routes);
    // Slack button clicks (signed by Slack; Slack's format, no session).
    app.use('/slack', slackInteractionsRouter);
    registerSlackApprovals();

    app.use(notFoundMiddleware);
    app.use(errorMiddleware);
    return app;
  }

  /** Every registered route, for logs and tests. */
  get routes(): string[] {
    return [...this.admin.flatMap((c) => c.routes.map((r) => `${r.method} ${PATH}${r.path}`)), ...this.agent.flatMap((c) => c.routes.map((r) => `${r.method} ${AGENT_PATH}${r.path}`))];
  }
}

/** Builds the app (kept for callers and tests that used createApp()). */
export function createApp(): express.Application {
  return new App().build();
}
