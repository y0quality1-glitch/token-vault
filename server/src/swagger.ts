import express from 'express';
import { createRequire } from 'node:module';

const expressStatic = express.static;
const requireModule = createRequire(import.meta.url);

/**
 * OpenAPI description (template: src/swagger.ts), built from the routes the controllers
 * registered, so it cannot drift from the code. Served at /api-docs.json and, with
 * swagger-ui-dist available, browsable at /api-docs/.
 */
export function buildSpec(routes: string[]) {
  const envelope = {
    type: 'object',
    properties: {
      status: { type: 'string', example: '10000', description: '"10000" success, "10001" failure' },
      msg: { type: 'string' },
      error: { type: 'string', nullable: true },
      code: { type: 'string', description: 'Failures only: stable machine-readable code' },
      details: { description: 'The payload (failures: extra data such as { fields })' },
      totalRecords: { type: 'number' },
    },
  };
  const paths: Record<string, Record<string, object>> = {};
  for (const r of routes) {
    const [method, path] = r.split(' ') as [string, string];
    const openapiPath = path.replace(/:(\w+)/g, '{$1}');
    const agent = path.startsWith('/agent/');
    const tag = path.split('/')[3] ?? 'other';
    const params = [...path.matchAll(/:(\w+)/g)].map((m) => ({ name: m[1], in: 'path', required: true, schema: { type: 'string' } }));
    (paths[openapiPath] ??= {})[method.toLowerCase()] = {
      tags: [agent ? `agent: ${tag}` : tag],
      security: path.includes('/auth/login') || path.includes('/apiHealthCheck') ? [] : [agent ? { AgentKey: [] } : { SessionCookie: [] }],
      ...(params.length ? { parameters: params } : {}),
      ...(method === 'POST' ? { requestBody: { content: { 'application/json': { schema: { type: 'object' } } } } } : {}),
      responses: { default: { description: 'GenericResponse envelope', content: { 'application/json': { schema: { $ref: '#/components/schemas/GenericResponse' } } } } },
    };
  }
  return {
    openapi: '3.0.3',
    info: { title: 'Token Vault control plane API', version: '2.0.0', description: 'Admin API (/api/v1, session cookie) and agent API (/agent/v1, agent credential). Every route answers with the GenericResponse envelope.' },
    servers: [{ url: '/' }],
    components: {
      securitySchemes: {
        SessionCookie: { type: 'apiKey', in: 'cookie', name: 'tv_session' },
        AgentKey: { type: 'http', scheme: 'bearer', description: 'tvak_… agent key or tvdt_… delegation token' },
      },
      schemas: { GenericResponse: envelope },
    },
    paths,
  };
}

const PAGE = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Token Vault API</title><link rel="stylesheet" href="./swagger-ui.css"></head>
<body><div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script><script src="./init.js"></script></body>
</html>`;

/** Mounts /api-docs.json and the browsable page (scripts as files, so the CSP stays strict). */
export function setupSwagger(app: express.Application, routes: () => string[]): void {
  app.get('/api-docs.json', (_req, res) => void res.json(buildSpec(routes())));
  let dist: string;
  try {
    dist = (requireModule('swagger-ui-dist') as { getAbsoluteFSPath(): string }).getAbsoluteFSPath();
  } catch {
    return;
  }
  // Routing ignores a trailing slash, so one route serves both; the page's relative links need it.
  app.get('/api-docs', (req, res) => (req.originalUrl.split('?')[0]!.endsWith('/') ? void res.type('html').send(PAGE) : res.redirect(301, '/api-docs/')));
  app.get('/api-docs/init.js', (_req, res) => void res.type('js').send("window.ui = SwaggerUIBundle({ url: '/api-docs.json', dom_id: '#swagger-ui' });"));
  app.use('/api-docs', expressStatic(dist, { index: false }));
}
