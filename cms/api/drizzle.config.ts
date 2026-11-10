import { defineConfig } from 'drizzle-kit';

// Used only by `npm run db:generate` to produce SQL migrations from src/db/schema.ts.
export default defineConfig({
  dialect: 'postgresql',
  schema: './src/db/schema.ts',
  out: './drizzle',
  dbCredentials: { url: process.env.CMS_DATABASE_URL ?? 'postgres://token_vault_cms:token_vault_cms@127.0.0.1:5432/token_vault_cms' },
});
