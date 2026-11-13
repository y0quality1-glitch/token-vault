import express from 'express';

const expressStatic = express.static;
import { CATALOG_PATH, PATH } from './config';

/**
 * OpenAPI description of the CMS API (template: src/swagger.ts), served at /api-docs.json and,
 * when swagger-ui is available, as a browsable page at /api-docs.
 */
const envelope = (details: object = { type: 'object', nullable: true }) => ({
  type: 'object',
  properties: { status: { type: 'string', example: '10000' }, msg: { type: 'string' }, error: { type: 'string', nullable: true }, details, totalRecords: { type: 'number', example: 0 } },
});
const ok = (description: string) => ({ 200: { description, content: { 'application/json': { schema: { $ref: '#/components/schemas/GenericResponse' } } } }, default: { $ref: '#/components/responses/Failure' } });
const body = (properties: Record<string, object>, required: string[] = []) => ({ required: true, content: { 'application/json': { schema: { type: 'object', properties, required } } } });
const ref = { key: { type: 'string', example: 'slack' }, version: { type: 'integer', example: 2 } };
const secured = { security: [{ SessionCookie: [] }, { BearerAuth: [] }] };
const post = (tag: string, summary: string, props: Record<string, object> = {}, required: string[] = []) => ({ post: { tags: [tag], summary, ...secured, requestBody: body(props, required), responses: ok(summary) } });

export const swaggerSpec = {
  openapi: '3.0.3',
  info: { title: 'Token Vault Provider CMS API', version: '2.0.0', description: 'Author, review, sign and publish provider definitions. Admin routes return the GenericResponse envelope; the signed catalog does not.' },
  servers: [{ url: '/', description: 'This server' }],
  components: {
    securitySchemes: {
      SessionCookie: { type: 'apiKey', in: 'cookie', name: 'tv_cms_session' },
      BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
    },
    schemas: { GenericResponse: envelope() },
    responses: {
      Failure: {
        description: 'Failure envelope: status "10001", error (message), code (e.g. KEY_TAKEN), details (e.g. { fields } or { issues })',
        content: { 'application/json': { schema: { ...envelope(), properties: { ...envelope().properties, code: { type: 'string', example: 'VALIDATION_ERROR' } } } } },
      },
    },
  },
  paths: {
    [`${PATH}/apiHealthCheck/apihealth`]: { get: { tags: ['Health'], summary: 'Liveness and database check', responses: ok('Healthy') } },
    [`${PATH}/auth/login`]: { post: { tags: ['Auth'], summary: 'Sign in (sets the httpOnly session cookie)', requestBody: body({ email: { type: 'string' }, password: { type: 'string' } }, ['email', 'password']), responses: ok('Signed in') } },
    [`${PATH}/auth/logout`]: { post: { tags: ['Auth'], summary: 'Sign out (ends the session)', responses: ok('Signed out') } },
    [`${PATH}/auth/me`]: { get: { tags: ['Auth'], summary: 'The signed-in user', ...secured, responses: ok('Session') } },
    [`${PATH}/application/getall`]: post('Applications', 'List applications', { pageNumber: { type: 'integer', example: 1 }, pageSize: { type: 'integer', example: 25, maximum: 200 }, search: { type: 'string' } }),
    [`${PATH}/application/getbyid/{key}`]: { get: { tags: ['Applications'], summary: 'Application with every version', ...secured, parameters: [{ name: 'key', in: 'path', required: true, schema: { type: 'string' } }], responses: ok('Application') } },
    [`${PATH}/application/save`]: post('Applications', 'Create an application (starter draft as version 1)', { key: { type: 'string' }, name: { type: 'string' }, description: { type: 'string' } }, ['key', 'name']),
    [`${PATH}/application/newversion`]: post('Applications', 'Start a new draft', { key: ref.key, from: { type: 'integer' } }, ['key']),
    [`${PATH}/application/availability`]: post('Applications', 'One-click availability (administrators)', { key: ref.key, availability: { type: 'string', enum: ['available', 'coming_soon'] }, note: { type: 'string' } }, ['key', 'availability']),
    [`${PATH}/application/archive`]: post('Applications', 'Archive (administrators)', { key: ref.key, reason: { type: 'string' } }, ['key', 'reason']),
    [`${PATH}/version/getdatabyid`]: post('Versions', 'One version: definition, diff, signatures, allowed actions', ref, ['key', 'version']),
    [`${PATH}/version/save`]: post('Versions', "Replace a draft's definition", { ...ref, definition: { type: 'object' } }, ['key', 'version', 'definition']),
    [`${PATH}/version/submit`]: post('Versions', 'Submit a draft for review', ref, ['key', 'version']),
    [`${PATH}/version/withdraw`]: post('Versions', 'Withdraw from review', ref, ['key', 'version']),
    [`${PATH}/version/approve`]: post('Versions', 'Approve and publish (another publisher)', { ...ref, note: { type: 'string' }, acknowledgeHostChange: { type: 'boolean' } }, ['key', 'version']),
    [`${PATH}/version/publish`]: post('Versions', 'Publish directly (administrators)', { ...ref, note: { type: 'string' }, acknowledgeHostChange: { type: 'boolean' } }, ['key', 'version']),
    [`${PATH}/version/reject`]: post('Versions', 'Reject with a note', { ...ref, note: { type: 'string' } }, ['key', 'version', 'note']),
    [`${PATH}/version/preview`]: post('Versions', 'The request the webhook would send (no credential)', { ...ref, operation: { type: 'string' }, resource: { type: 'object' }, input: { type: 'object' } }, ['key', 'version', 'operation']),
    [`${PATH}/audit/getall`]: post('Audit', 'Audit log, newest first', { pageNumber: { type: 'integer' }, pageSize: { type: 'integer' }, application: { type: 'string' }, search: { type: 'string' } }),
    [`${CATALOG_PATH}/public-key`]: { get: { tags: ['Catalog (public)'], summary: 'Signing keys', responses: { 200: { description: 'Keys' } } } },
    [`${CATALOG_PATH}/definitions`]: { get: { tags: ['Catalog (public)'], summary: 'Every published definition, signed (ETag)', responses: { 200: { description: 'Catalog' }, 304: { description: 'Unchanged' } } } },
    [`${CATALOG_PATH}/definitions/{key}`]: { get: { tags: ['Catalog (public)'], summary: 'One published definition', parameters: [{ name: 'key', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Definition' } } } },
  },
};

const PAGE = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Token Vault CMS API</title><link rel="stylesheet" href="./swagger-ui.css"></head>
<body><div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script><script src="./init.js"></script></body>
</html>`;

/**
 * Mounts the spec at /api-docs.json and the browsable page at /api-docs/. The page is
 * swagger-ui-dist's files served by this app; the start-up script is a file too, so the
 * Content-Security-Policy (no inline scripts) stays in place.
 */
export async function setupSwagger(app: express.Application): Promise<void> {
  app.get('/api-docs.json', (_req, res) => void res.json(swaggerSpec));
  let dist: string;
  try {
    const mod = await import('swagger-ui-dist');
    dist = (mod.getAbsoluteFSPath ?? mod.default.getAbsoluteFSPath)();
  } catch {
    console.warn('[cms] swagger-ui-dist is not available: serving /api-docs.json only');
    return;
  }
  // Routing ignores a trailing slash, so one route serves both; the page's relative links need the slash.
  app.get('/api-docs', (req, res) => (req.originalUrl.split('?')[0]!.endsWith('/') ? void res.type('html').send(PAGE) : res.redirect(301, '/api-docs/')));
  app.get('/api-docs/init.js', (_req, res) => void res.type('js').send("window.ui = SwaggerUIBundle({ url: '/api-docs.json', dom_id: '#swagger-ui' });"));
  app.use('/api-docs', expressStatic(dist, { index: false }));
}
