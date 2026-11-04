import express from 'express';
import { config } from './config';
import { buildRouter } from './routes';
import { loadStore } from './store/credential-store';

loadStore();

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  const t = Date.now();
  // Log method, path and status only: never bodies or headers.
  res.on('finish', () => console.log(`[vault] ${req.method} ${req.path} ${res.statusCode} ${Date.now() - t}ms`));
  next();
});
app.use(buildRouter());
app.use((_req, res) => res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found' } }));

app.listen(config.port, () => {
  console.log(`[vault] Customer webhook runtime listening on http://localhost:${config.port}`);
  console.log(`[vault] instance=${config.instanceId} github_mode=${config.githubMode} key_ref=${config.encryptionKeyRef}`);
});
