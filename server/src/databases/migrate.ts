// Applies pending migrations and exits. The server also runs them on start-up.
import 'reflect-metadata';
import { describeError } from '../lib/errors';
import { closeDatabase, runMigrations } from './client';

runMigrations()
  .then((ran) => console.log(`[db] migrations applied${ran.length ? `: ${ran.join(', ')}` : ' (none pending)'}`))
  .catch((e) => {
    console.error('[db] migration failed:', describeError(e));
    process.exitCode = 1;
  })
  .finally(() => void closeDatabase());
