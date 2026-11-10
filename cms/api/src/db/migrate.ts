// Applies pending SQL migrations (drizzle/) to the CMS database and exits. The CMS API also runs this on startup.
import { closeDatabase, describeError, runMigrations } from './client';

runMigrations()
  .then(() => console.log('[cms] migrations applied'))
  .catch((e) => {
    console.error('[cms] migration failed:', describeError(e));
    process.exitCode = 1;
  })
  .finally(() => void closeDatabase());
