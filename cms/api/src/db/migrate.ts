import { closeDatabase, runMigrations } from './client';

await runMigrations();
await closeDatabase();
console.log('[cms] migrations applied');
