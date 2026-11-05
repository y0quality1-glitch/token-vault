import { createApp } from './app';
import { config } from './config';
import { closeDatabase, describeError, runMigrations } from './db/client';
import { initData } from './seed';
import { initSigning } from './modules/signing';

async function main() {
  await runMigrations();
  await initData();
  await initSigning();
  const server = createApp().listen(config.port, () => {
    console.log(`[cms] Provider CMS API listening on http://localhost:${config.port}`);
    console.log(`[cms] signing key ${config.keyId} (Ed25519); public key at /catalog/v1/public-key`);
  });
  const shutdown = (signal: string) => {
    console.log(`[cms] ${signal} received, shutting down`);
    server.close(() => void closeDatabase().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((e) => {
  console.error('[cms] failed to start:', describeError(e));
  process.exit(1);
});
