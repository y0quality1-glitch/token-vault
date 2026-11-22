import { defineConfig } from 'vitest/config';

// Database test files (store, secret values) reset the same WEBHOOK_TEST_DATABASE_URL, so they must not run concurrently.
export default defineConfig({ test: { fileParallelism: false } });
