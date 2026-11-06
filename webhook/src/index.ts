import express from 'express';
import { config } from './config';
import { closeDatabase, describeError, runMigrations } from './db/client';
import { buildRouter } from './routes';
import { initStore } from './store/credential-store';
import { catalogSync } from './providers/registry';

async function main() {
  await runMigrations();
  await initStore();
  // Never blocks startup: if the CMS is unreachable, the bundled definitions apply until the next poll.
  await catalogSync?.start();

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
    console.log(`[vault] instance=${config.instanceId} upstream=${config.githubMode}${Object.keys(config.providerModes).length ? ` (${Object.entries(config.providerModes).map(([k, v]) => `${k}=${v}`).join(",")})` : ""} key_ref=${config.encryptionKeyRef} store=postgres`);
    console.log(catalogSync ? `[vault] provider catalog ${config.cmsCatalogUrl} (pinned keys ${catalogSync.status.keyIds.join(', ')})` : '[vault] provider catalog: bundled definitions only (CMS_CATALOG_URL not set)');
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
