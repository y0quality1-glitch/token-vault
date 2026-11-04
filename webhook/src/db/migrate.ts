// Applies pending SQL migrations (drizzle/) to the customer store and exits. The webhook also runs this on startup.
import { closeDatabase, describeError, runMigrations } from './client';

runMigrations()
  .then(() => console.log('[vault] migrations applied'))
  .catch((e) => {
    console.error('[vault] migration failed:', describeError(e));
    process.exitCode = 1;
  })
  .finally(() => void closeDatabase());
