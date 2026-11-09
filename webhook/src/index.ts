import express from 'express';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { watchTlsFiles, type TlsFiles } from './security/tls';
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
  // Liveness for container orchestrators: says only that the process serves requests.
  // Identity, keys and catalog are reported by the signed /internal/v1/health only.
  app.get('/healthz', (_req, res) => void res.json({ status: 'ok' }));
  app.use(buildRouter());
  app.use((_req, res) => res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found' } }));

  // HTTPS with client certificates requested (mTLS) when configured. The handshake accepts a
  // missing certificate so probes reach /healthz; /internal/* refuses it (see requireSignature).
  const tlsOptions = (t: TlsFiles) => ({ cert: t.cert, key: t.key, ...(t.clientCa ? { ca: t.clientCa, requestCert: true, rejectUnauthorized: false } : {}), minVersion: 'TLSv1.2' as const });
  const server = config.tls ? createHttpsServer(tlsOptions(config.tls), app) : createHttpServer(app);
  if (config.tls) {
    watchTlsFiles(config.tls, (next) => {
      (server as HttpsServer).setSecureContext(tlsOptions(next));
      console.log('[vault] TLS certificate files changed: new connections use the new certificate');
    });
  }
  server.listen(config.port, () => {
    console.log(`[vault] Customer webhook runtime listening on ${config.tls ? 'https' : 'http'}://localhost:${config.port}${config.tls?.clientCa ? ` (client certificates required on /internal${config.tls.allowedClients.length ? `; allowed: ${config.tls.allowedClients.join(', ')}` : ''})` : ''}`);
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
