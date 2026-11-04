// Applies pending SQL migrations (drizzle/) and exits. The server also runs this on startup.
import { closeDatabase, runMigrations } from './client';

runMigrations()
  .then(() => console.log('[db] migrations applied'))
  .catch((e) => {
    console.error('[db] migration failed:', (e as Error).message);
    process.exitCode = 1;
  })
  .finally(() => void closeDatabase());
