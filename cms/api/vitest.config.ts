import { defineConfig } from 'vitest/config';

// Database tests reset the same CMS_TEST_DATABASE_URL, so they must not run concurrently.
export default defineConfig({ test: { fileParallelism: false } });
