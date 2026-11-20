import { defineConfig } from 'vitest/config';

// Database test files reset the same TEST_DATABASE_URL, so they must not run concurrently.
// reflect-metadata must load before any DTO (class-transformer reads decorator metadata).
export default defineConfig({ test: { fileParallelism: false, setupFiles: ['reflect-metadata'] } });
