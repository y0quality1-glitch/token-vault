import express, { Router } from 'express';
import { errorHandler, requestLogger, securityHeaders } from './lib/http';
import { applicationsRouter } from './modules/applications';
import { auditRouter } from './modules/audit';
import { authRouter, requireSession } from './modules/auth';
import { catalogRouter } from './modules/catalog';

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 'loopback');
  app.use(securityHeaders);
  app.use(requestLogger);
  app.use(express.json({ limit: '256kb' }));

  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', service: 'token-vault-cms' });
  });

  // Admin UI API (session cookie + roles).
  const api = Router();
  api.use('/auth', authRouter);
  api.use(requireSession);
  api.use(applicationsRouter);
  api.use(auditRouter);
  app.use('/api/v1', api);

  // Public, signed catalog for consumers.
  app.use('/catalog/v1', catalogRouter);

  app.use((_req, res) => {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Route not found' } });
  });
  app.use(errorHandler);
  return app;
}
