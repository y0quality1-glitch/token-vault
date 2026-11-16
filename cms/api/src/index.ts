import 'reflect-metadata';
import { App } from './app';
import { JWT_KEY_FINGERPRINT, SIGNING, PORT } from './config';
import { controllers } from './controllers';
import AppDatabase, { describeError } from './databases/database';
import { initData } from './seed/seed';
import { initSigning } from './services/signingService/signingService.service';

/**
 * Entry point (template: src/index.ts). The database is connected, migrated and seeded
 * before the server accepts traffic (template fix B-06), and SIGTERM/SIGINT close the server
 * and the pool.
 */
async function main() {
  const db = AppDatabase.getInstance();
  await db.connectToDB();
  const ran = await db.runMigrations();
  if (ran.length) console.log(`[cms] migrations applied: ${ran.join(', ')}`);
  await initData();
  await initSigning();

  const app = await new App(controllers()).build();
  const server = app.listen(PORT, () => {
    console.log(`[cms] Provider CMS API listening on http://localhost:${PORT} (API docs at /api-docs)`);
    console.log(`[cms] signing key ${SIGNING.keyId} (Ed25519); public key at /catalog/v1/public-key; session key ${JWT_KEY_FINGERPRINT}`);
  });
  const shutdown = (signal: string) => {
    console.log(`[cms] ${signal} received, shutting down`);
    server.close(() => void db.close().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((e) => {
  console.error('[cms] failed to start:', describeError(e));
  process.exit(1);
});
