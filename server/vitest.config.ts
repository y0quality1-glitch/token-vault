import { defineConfig } from 'vitest/config';

// Database test files reset the same TEST_DATABASE_URL, so they must not run concurrently.
export default defineConfig({ test: { fileParallelism: false } });
