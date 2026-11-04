import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// The dev server proxies the control-plane API so the session cookie stays same-origin.
// The browser never talks to the customer webhook directly.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:4000',
      '/agent/v1': 'http://localhost:4000',
    },
  },
  preview: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:4000',
      '/agent/v1': 'http://localhost:4000',
    },
  },
});
