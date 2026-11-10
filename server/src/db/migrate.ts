// Applies pending SQL migrations (drizzle/) and exits. The server also runs this on startup.
import { describeError } from '../lib/errors';
import { closeDatabase, runMigrations } from './client';

runMigrations()
  .then(() => console.log('[db] migrations applied'))
  .catch((e) => {
    console.error('[db] migration failed:', describeError(e));
    process.exitCode = 1;
  })
  .finally(() => void closeDatabase());
