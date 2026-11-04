import express from 'express';
import { config } from './config';
import { closeDatabase, describeError, runMigrations } from './db/client';
import { buildRouter } from './routes';
import { initStore } from './store/credential-store';

async function main() {
  await runMigrations();
  await initStore();

  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    const t = Date.now();
    // Log method, path and status only: never bodies or headers.
    res.on('finish', () => console.log(`[vault] ${req.method} ${req.path} ${res.statusCode} ${Date.now() - t}ms`));
    next();
  });
  app.use(buildRouter());
  app.use((_req, res) => res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found' } }));

  const server = app.listen(config.port, () => {
    console.log(`[vault] Customer webhook runtime listening on http://localhost:${config.port}`);
    console.log(`[vault] instance=${config.instanceId} github_mode=${config.githubMode} key_ref=${config.encryptionKeyRef} store=postgres`);
  });

  const shutdown = (signal: string) => {
    console.log(`[vault] ${signal} received, shutting down`);
    server.close(() => void closeDatabase().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((e) => {
  console.error('[vault] failed to start:', describeError(e));
  process.exit(1);
});
