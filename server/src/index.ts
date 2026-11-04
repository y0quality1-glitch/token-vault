import { config } from './config';
import { describeError } from './lib/errors';
import { sanitize } from './lib/sanitize';
import { createApp } from './app';
import { closeDatabase, runMigrations } from './db/client';
import { DEMO_PASSWORD, resetDatabase, seedIfEmpty } from './store/seed';
import { sessionRepo } from './store/repos';
import { startHeartbeat } from './modules/webhooks/webhook.service';

async function main() {
  await runMigrations();
  if (config.seedMode === 'reset') {
    console.warn('[api] SEED_MODE=reset: wiping control-plane data and reseeding demo state');
    await resetDatabase();
  } else if (await seedIfEmpty()) {
    console.log('[api] empty database: seeded demo data');
  }
  await sessionRepo.purgeExpiredSessions();

  const app = createApp();
  const server = app.listen(config.port, () => {
    console.log(`[api] Token Vault control plane listening on http://localhost:${config.port}`);
    console.log(`[api] Customer webhook expected at ${config.defaultWebhookUrl}`);
    console.log(`[api] Demo sign-in: owner@demo.test / ${DEMO_PASSWORD} (mock account, development only)`);
  });
  const heartbeat = startHeartbeat();

  const shutdown = (signal: string) => {
    console.log(`[api] ${signal} received, shutting down`);
    clearInterval(heartbeat);
    server.close(() => void closeDatabase().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((e) => {
  console.error('[api] failed to start:', sanitize(describeError(e)));
  process.exit(1);
});
