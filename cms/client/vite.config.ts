import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

const dir = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// Reuses the Token Vault console's UI components (@ui) and hooks (@tv-hooks). Those files
// import "@/lib/utils" and "@/lib/api", which resolve to this app's own src/lib.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@ui': dir('../../client/src/components/ui'),
      '@tv-hooks': dir('../../client/src/hooks'),
      '@': dir('./src'),
    },
  },
  server: {
    port: 5174,
    proxy: { '/api': 'http://localhost:4200', '/catalog/v1': 'http://localhost:4200' },
    fs: { allow: [dir('../..')] },
  },
  preview: {
    port: 5174,
    proxy: { '/api': 'http://localhost:4200', '/catalog/v1': 'http://localhost:4200' },
  },
});
