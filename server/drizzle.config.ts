import { defineConfig } from 'drizzle-kit';

// Used only by `npm run db:generate` to produce SQL migrations from src/db/schema.ts.
export default defineConfig({
  dialect: 'postgresql',
  schema: './src/db/schema.ts',
  out: './drizzle',
  dbCredentials: { url: process.env.DATABASE_URL ?? 'postgres://token_vault:token_vault@localhost:5432/token_vault' },
});
