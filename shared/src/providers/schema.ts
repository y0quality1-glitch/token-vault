import { z } from 'zod';
import { placeholdersIn } from './template';

/**
 * Provider definitions: everything Token Vault needs to know about an application,
 * expressed as data instead of code. The customer webhook executes them generically;
 * the control plane derives its catalog, operations and validation from them.
 *
 * Credentials are NEVER reachable from templates. They are injected only through the
 * definition's `auth` method, after the request has been built and its host checked.
 */

const NAME = /^[a-z][a-zA-Z0-9_]{0,39}$/;
/** Headers a definition may not set statically: credentials are injected by `auth` only. */
const RESERVED_HEADERS = /^(authorization|cookie|proxy-.*|host|content-length|x-api-key)$/i;

const fieldSpec = z.union([
  z.string().min(1).max(200), // dot path into the upstream JSON, e.g. "user.login"
  z
    .object({
      path: z.string().min(1).max(200).optional(),
      /** Constant output value. */
      const: z.union([z.string(), z.number(), z.boolean()]).optional(),
      /** Decode a base64 string (e.g. file contents). */
      decode: z.enum(['base64']).optional(),
      /** For an array of objects: keep only this property of each element. */
      pluck: z.string().min(1).max(100).optional(),
      maxLength: z.number().int().positive().max(1_000_000).optional(),
    })
    .strict()
    .refine((f) => (f.path === undefined) !== (f.const === undefined), 'set exactly one of path or const'),
]);
export type FieldSpec = z.infer<typeof fieldSpec>;

/** Allow-list of upstream response fields returned to Token Vault. Anything else is dropped. */
const responseMap = z
  .object({
    fields: z.record(z.string().regex(NAME), fieldSpec).refine((f) => Object.keys(f).length > 0, 'at least one field'),
    /** When the upstream returns an array: map each element, keeping at most `limit`. */
    limit: z.number().int().positive().max(100).default(10),
  })
  .strict();
export type ResponseMap = z.infer<typeof responseMap>;

const templateValue: z.ZodType<unknown> = z.lazy(() => z.union([z.string().max(2000), z.number(), z.boolean(), z.null(), z.array(templateValue).max(50), z.record(templateValue)]));

const requestTemplate = z
  .object({
    method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
    /** Path appended to api.baseUrl. Placeholders: {resource.<field>}, {input.<field>}, with optional "|default". */
    path: z
      .string()
      .min(1)
      .max(500)
      .regex(/^\//, 'must start with /')
      .refine((p) => !p.includes('://') && !p.includes('..') && !p.includes('?') && !p.includes('#'), 'must be a plain path (no scheme, "..", query or fragment)'),
    query: z.record(z.string().max(100), z.union([z.string().max(500), z.number(), z.boolean()])).optional(),
    body: templateValue.optional(),
  })
  .strict();
export type RequestTemplate = z.infer<typeof requestTemplate>;

const inputField = z
  .object({
    type: z.enum(['string', 'number', 'boolean']),
    label: z.string().max(100).optional(),
    required: z.boolean().default(false),
    maxLength: z.number().int().positive().max(100_000).optional(),
    multiline: z.boolean().optional(),
  })
  .strict();

/** A simulated upstream response, used in mock mode when no simulator exists for the provider's host. */
const mockResponse = z.object({ status: z.number().int().min(100).max(599), body: z.unknown() }).strict();

const operation = z
  .object({
    id: z.string().regex(/^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*){2,3}$/, 'use <provider>.<area>.<action>'),
    label: z.string().min(1).max(80),
    description: z.string().max(300).default(''),
    /** read / write are grantable; destructive operations need a Require approval policy, a human approval per request, and a webhook that allows them. */
    risk: z.enum(['read', 'write', 'destructive']),
    requiresResource: z.boolean().default(true),
    /** Provider-side permissions the operation needs; auth plugins that mint narrowed tokens use these. */
    providerPermissions: z.record(z.string().regex(NAME), z.enum(['read', 'write'])).default({}),
    input: z.record(z.string().regex(NAME), inputField).default({}),
    request: requestTemplate,
    response: responseMap,
    /** Simulated response used in mock mode when no simulator exists for the provider's host. */
    mock: mockResponse.optional(),
  })
  .strict();
export type OperationDefinition = z.infer<typeof operation>;

/**
 * OAuth 2.0 authorization-code flow with PKCE. The client secret, the PKCE verifier and
 * every token live only in the customer webhook, which also refreshes access tokens.
 */
const oauthConfig = z
  .object({
    authorizeUrl: z.string().url().max(500),
    /** Receives the client secret and refresh tokens: its host must be in api.allowedHosts. */
    tokenUrl: z.string().url().max(500),
    scopes: z.array(z.string().min(1).max(200)).max(30).default([]),
    scopeSeparator: z.string().max(3).default(' '),
    /** How the client authenticates at the token endpoint. */
    clientAuth: z.enum(['body', 'basic']).default('body'),
    /** Extra authorize parameters, e.g. {"access_type": "offline", "prompt": "consent"} for Google. */
    authorizeParams: z.record(z.string().regex(/^[a-z_]{1,40}$/), z.string().max(200)).default({}),
  })
  .strict();
export type OAuthConfig = z.infer<typeof oauthConfig>;

const authMethod = z
  .object({
    id: z.string().regex(/^[A-Z][A-Z0-9_]{1,30}$/),
    label: z.string().min(1).max(60),
    description: z.string().max(300).default(''),
    /**
     * bearer: "Authorization: Bearer <secret>"; header: <header>: <prefix><secret>;
     * basic: HTTP basic auth from "user:secret"; plugin: provider-specific code (e.g. github_app);
     * oauth2: authorization code + PKCE, access token sent as a bearer token and refreshed by the webhook.
     */
    kind: z.enum(['bearer', 'header', 'basic', 'plugin', 'oauth2']),
    oauth: oauthConfig.optional(),
    header: z.string().regex(/^[A-Za-z0-9-]{1,60}$/).optional(),
    prefix: z.string().max(40).optional(),
    plugin: z.enum(['github_app']).optional(),
    /** Validation for the secret entered by the admin (control plane and webhook). */
    secretPattern: z.string().max(300).optional(),
    secretHint: z.string().max(200).optional(),
    /** Request used to verify the credential; defaults to the definition's credentialTest. */
    test: z.object({ request: requestTemplate, response: responseMap, mock: mockResponse.optional() }).strict().optional(),
  })
  .strict()
  .superRefine((a, ctx) => {
    if (a.kind === 'header' && !a.header) ctx.addIssue({ code: 'custom', message: 'header auth needs "header"', path: ['header'] });
    if (a.kind === 'plugin' && !a.plugin) ctx.addIssue({ code: 'custom', message: 'plugin auth needs "plugin"', path: ['plugin'] });
    if (a.kind === 'oauth2' && !a.oauth) ctx.addIssue({ code: 'custom', message: 'oauth2 auth needs "oauth"', path: ['oauth'] });
    if (a.kind !== 'oauth2' && a.oauth) ctx.addIssue({ code: 'custom', message: '"oauth" only applies to kind oauth2', path: ['oauth'] });
    if (a.header && RESERVED_HEADERS.test(a.header) && a.header.toLowerCase() !== 'authorization' && a.header.toLowerCase() !== 'x-api-key') {
      ctx.addIssue({ code: 'custom', message: `cannot inject into ${a.header}`, path: ['header'] });
    }
  });
export type AuthMethodDefinition = z.infer<typeof authMethod>;

const resourceField = z
  .object({
    label: z.string().max(60),
    /** Anchored regular expression every value must match. */
    pattern: z.string().min(2).max(300),
    example: z.string().max(200).optional(),
    caseInsensitive: z.boolean().default(false),
  })
  .strict();

/** Icons the consoles can render for a provider (no remote images: nothing to fetch or track). */
export const CATALOG_ICONS = ['plug', 'github', 'mail', 'calendar', 'message-square', 'bot', 'ticket', 'database', 'cloud', 'file-text', 'credit-card', 'users', 'shield', 'git-branch', 'briefcase', 'bar-chart'] as const;
export type CatalogIcon = (typeof CATALOG_ICONS)[number];

/** How the provider is listed in Token Vault's Integration Catalog. */
const catalogInfo = z
  .object({
    category: z.string().trim().min(1).max(40).default('Other'),
    icon: z.enum(CATALOG_ICONS).default('plug'),
    /** coming_soon: listed in the catalog, but integrations cannot be connected yet. */
    availability: z.enum(['available', 'coming_soon']).default('available'),
    docsUrl: z.string().url().max(300).optional(),
    tags: z.array(z.string().trim().min(1).max(30)).max(10).default([]),
  })
  .strict();
export type CatalogInfo = z.infer<typeof catalogInfo>;

export const providerDefinitionSchema = z
  .object({
    key: z.string().regex(/^[a-z][a-z0-9-]{1,30}$/),
    version: z.number().int().positive(),
    name: z.string().min(1).max(60),
    description: z.string().max(500).default(''),
    catalog: catalogInfo.default({}),
    api: z
      .object({
        baseUrl: z.string().url().max(300),
        /** Hosts requests may go to (exact, or "*.example.com"). Credentials are never sent elsewhere. */
        allowedHosts: z.array(z.string().regex(/^(\*\.)?[a-z0-9.-]+\.[a-z]{2,}$/)).min(1).max(10),
        headers: z.record(z.string().regex(/^[A-Za-z0-9-]{1,60}$/), z.string().max(300)).default({}),
        timeoutMs: z.number().int().min(1000).max(30_000).default(10_000),
      })
      .strict(),
    /** The primary resource grants are scoped to (e.g. a repository), plus any extra request fields. */
    resource: z.object({ name: z.string().regex(NAME) }).merge(resourceField).strict(),
    resourceFields: z.record(z.string().regex(NAME), resourceField).default({}),
    auth: z.array(authMethod).min(1).max(5),
    /** Request used to check a credential. Its optional mock is the simulated answer (e.g. 401 to simulate a revoked credential). */
    credentialTest: z.object({ request: requestTemplate, response: responseMap, mock: mockResponse.optional() }).strict(),
    operations: z.array(operation).min(1).max(100),
  })
  .strict();

export type ProviderDefinition = z.infer<typeof providerDefinitionSchema>;
export type ProviderDefinitionInput = z.input<typeof providerDefinitionSchema>;

export class DefinitionError extends Error {
  constructor(public issues: string[]) {
    super(`Invalid provider definition: ${issues.join('; ')}`);
  }
}

export function hostAllowed(host: string, allowed: readonly string[]): boolean {
  const h = host.toLowerCase();
  return allowed.some((a) => (a.startsWith('*.') ? h.endsWith(a.slice(1)) && h.length > a.length - 1 : h === a));
}

/** Parses and semantically checks a definition. Throws DefinitionError with every problem found. */
export function validateProviderDefinition(raw: unknown): ProviderDefinition {
  const parsed = providerDefinitionSchema.safeParse(raw);
  if (!parsed.success) throw new DefinitionError(parsed.error.issues.map((i) => `${i.path.join('.') || 'definition'}: ${i.message}`));
  const def = parsed.data;
  const issues: string[] = [];

  if (def.catalog.docsUrl && !def.catalog.docsUrl.startsWith('https://')) issues.push('catalog.docsUrl: must use https');
  const base = new URL(def.api.baseUrl);
  if (base.protocol !== 'https:') issues.push('api.baseUrl: must use https');
  if (base.search || base.hash || base.username || base.password) issues.push('api.baseUrl: must not contain credentials, query or fragment');
  if (!hostAllowed(base.hostname, def.api.allowedHosts)) issues.push(`api.baseUrl: host ${base.hostname} is not in api.allowedHosts`);
  for (const h of Object.keys(def.api.headers)) if (RESERVED_HEADERS.test(h)) issues.push(`api.headers.${h}: credentials are injected by auth, not static headers`);
  for (const [h, v] of Object.entries(def.api.headers)) if (placeholdersIn(v).length) issues.push(`api.headers.${h}: placeholders are not allowed in headers`);

  const patterns: [string, string][] = [[`resource`, def.resource.pattern], ...Object.entries(def.resourceFields).map(([k, f]) => [`resourceFields.${k}`, f.pattern] as [string, string])];
  for (const [where, p] of patterns) {
    if (!p.startsWith('^') || !p.endsWith('$')) issues.push(`${where}.pattern: must be anchored with ^ and $`);
    try {
      new RegExp(p);
    } catch {
      issues.push(`${where}.pattern: not a valid regular expression`);
    }
  }
  if (def.resourceFields[def.resource.name]) issues.push(`resourceFields.${def.resource.name}: duplicates the primary resource`);
  const resourceNames = new Set([def.resource.name, ...Object.keys(def.resourceFields)]);

  const checkTemplate = (where: string, t: RequestTemplate, inputs: Set<string>) => {
    const strings: string[] = [t.path, ...Object.values(t.query ?? {}).map(String)];
    const walk = (v: unknown) => {
      if (typeof v === 'string') strings.push(v);
      else if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object') Object.values(v).forEach(walk);
    };
    walk(t.body);
    for (const s of strings) {
      for (const ph of placeholdersIn(s)) {
        const [ns, name] = ph.name.split('.', 2) as [string, string | undefined];
        if (ns === 'resource' && name && resourceNames.has(name)) continue;
        if (ns === 'input' && name && inputs.has(name)) continue;
        issues.push(`${where}: unknown placeholder {${ph.name}} (use resource.<${[...resourceNames].join('|')}> or a declared input)`);
      }
    }
    if (t.method === 'GET' && t.body !== undefined) issues.push(`${where}: GET requests cannot have a body`);
  };

  const ids = new Set<string>();
  for (const [i, op] of def.operations.entries()) {
    const where = `operations[${i}] ${op.id}`;
    if (!op.id.startsWith(`${def.key}.`)) issues.push(`${where}: id must start with "${def.key}."`);
    if (ids.has(op.id)) issues.push(`${where}: duplicate id`);
    ids.add(op.id);
    checkTemplate(`${where}.request`, op.request, new Set(Object.keys(op.input)));
    if (!op.requiresResource && placeholdersIn(op.request.path).some((p) => p.name === `resource.${def.resource.name}`)) issues.push(`${where}: uses the resource but requiresResource is false`);
  }
  checkTemplate('credentialTest.request', def.credentialTest.request, new Set());
  const authIds = new Set<string>();
  for (const a of def.auth) {
    if (authIds.has(a.id)) issues.push(`auth.${a.id}: duplicate id`);
    authIds.add(a.id);
    if (a.test) checkTemplate(`auth.${a.id}.test.request`, a.test.request, new Set());
    if (a.oauth) {
      const token = new URL(a.oauth.tokenUrl);
      const authorize = new URL(a.oauth.authorizeUrl);
      if (token.protocol !== 'https:' || authorize.protocol !== 'https:') issues.push(`auth.${a.id}.oauth: authorizeUrl and tokenUrl must use https`);
      if (!hostAllowed(token.hostname, def.api.allowedHosts)) issues.push(`auth.${a.id}.oauth.tokenUrl: host ${token.hostname} must be in api.allowedHosts (it receives the client secret)`);
      if (token.username || token.password || authorize.username || authorize.password || authorize.hash) issues.push(`auth.${a.id}.oauth: URLs must not contain credentials or fragments`);
    }
    if (a.secretPattern) {
      try {
        new RegExp(a.secretPattern);
      } catch {
        issues.push(`auth.${a.id}.secretPattern: not a valid regular expression`);
      }
    }
  }
  if (issues.length) throw new DefinitionError(issues);
  return def;
}
