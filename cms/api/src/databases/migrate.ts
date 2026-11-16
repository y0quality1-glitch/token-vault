// Applies pending migrations to the CMS database and exits. The CMS API also runs them on start-up.
import 'reflect-metadata';
import AppDatabase, { describeError } from './database';

const db = AppDatabase.getInstance();
db.connectToDB()
  .then(() => db.runMigrations())
  .then((ran) => console.log(`[cms] migrations applied${ran.length ? `: ${ran.join(', ')}` : ' (none pending)'}`))
  .catch((e) => {
    console.error('[cms] migration failed:', describeError(e));
    process.exitCode = 1;
  })
  .finally(() => void db.close());
