import {
  DefinitionError,
  TemplateError,
  canonicalJson,
  mapResponse,
  renderBody,
  renderPath,
  renderString,
  validateProviderDefinition,
  type CmsDiff,
  type CmsPreviewResult,
  type ProviderDefinition,
} from '@token-vault/shared';

/** Validates without throwing: the normalized definition, or every problem found. */
export function check(definition: unknown): { normalized: ProviderDefinition | null; issues: string[] } {
  try {
    return { normalized: validateProviderDefinition(definition), issues: [] };
  } catch (e) {
    if (e instanceof DefinitionError) return { normalized: null, issues: e.issues };
    return { normalized: null, issues: [(e as Error).message] };
  }
}

/** A minimal, valid starting point for a new application. */
export function starterDefinition(key: string, name: string, description: string) {
  return {
    key,
    version: 1,
    name,
    description,
    api: { baseUrl: 'https://api.example.com', allowedHosts: ['api.example.com'], headers: { Accept: 'application/json' } },
    resource: { name: 'project', label: 'Project', pattern: '^[A-Za-z0-9_-]{1,64}$', example: 'demo-project' },
    auth: [{ id: 'API_KEY', label: 'API key', kind: 'bearer', secretHint: 'The API key from the provider settings' }],
    credentialTest: { request: { method: 'GET', path: '/me' }, response: { fields: { id: 'id', name: 'name' } } },
    operations: [
      {
        id: `${key}.items.list`,
        label: 'List items',
        description: 'GET /projects/{project}/items',
        risk: 'read',
        request: { method: 'GET', path: '/projects/{resource.project}/items', query: { limit: 10 } },
        response: { fields: { id: 'id', name: 'name' }, limit: 10 },
        mock: { status: 200, body: [{ id: 'item_1', name: 'First item' }] },
      },
    ],
  };
}

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const same = (a: unknown, b: unknown) => canonicalJson(a ?? null) === canonicalJson(b ?? null);

/** Where a draft differs from the published version, and whether credentials could go to a new host. */
export function diffDefinitions(draft: unknown, published: unknown | null, publishedVersion: number | null): CmsDiff {
  const d = obj(draft);
  const p = obj(published);
  const changes: CmsDiff['changes'] = [];
  const dApi = obj(d.api);
  const pApi = obj(p.api);
  const hostChange = published === null || !same(dApi.baseUrl, pApi.baseUrl) || !same([...((dApi.allowedHosts as string[]) ?? [])].sort(), [...((pApi.allowedHosts as string[]) ?? [])].sort());
  if (published !== null) {
    for (const area of ['name', 'description', 'api', 'resource', 'resourceFields', 'credentialTest'] as const) {
      if (!same(d[area], p[area])) changes.push({ area, kind: 'changed' });
    }
    const byId = (list: unknown, idKey: string) => new Map(((Array.isArray(list) ? list : []) as Record<string, unknown>[]).map((x) => [String(x[idKey]), x]));
    for (const [label, list, idKey] of [
      ['auth', 'auth', 'id'],
      ['operation', 'operations', 'id'],
    ] as const) {
      const dm = byId(d[list], idKey);
      const pm = byId(p[list], idKey);
      for (const [id, v] of dm) {
        if (!pm.has(id)) changes.push({ area: `${label} ${id}`, kind: 'added' });
        else if (!same(v, pm.get(id))) changes.push({ area: `${label} ${id}`, kind: 'changed' });
      }
      for (const id of pm.keys()) if (!dm.has(id)) changes.push({ area: `${label} ${id}`, kind: 'removed' });
    }
  }
  return { againstVersion: publishedVersion, hostChange, changes };
}

/**
 * Shows exactly what the webhook would send for an operation, without any credential:
 * the credential header is listed by name only, as "(injected by the customer webhook)".
 */
export function preview(def: ProviderDefinition, operationId: string, resource: Record<string, string>, input: Record<string, unknown>): CmsPreviewResult {
  const op = def.operations.find((o) => o.id === operationId);
  if (!op) return { request: { method: '', url: '', headers: [], body: null }, mockResponse: null, error: `Unknown operation ${operationId}` };
  const vars = { resource, input };
  try {
    const base = new URL(def.api.baseUrl);
    const url = new URL(base.origin + base.pathname.replace(/\/$/, '') + renderPath(op.request.path, vars));
    for (const [k, v] of Object.entries(op.request.query ?? {})) {
      const value = renderString(String(v), vars);
      if (value !== '') url.searchParams.set(k, value);
    }
    const auth = def.auth[0]!;
    const credentialHeader = auth.kind === 'header' ? auth.header! : 'Authorization';
    const headers = [...Object.keys(def.api.headers), ...(op.request.body !== undefined ? ['Content-Type'] : []), `${credentialHeader} (injected by the customer webhook)`];
    return {
      request: { method: op.request.method, url: url.toString(), headers, body: op.request.body === undefined ? null : renderBody(op.request.body, vars) },
      mockResponse: op.mock ? { status: op.mock.status, body: op.mock.status < 300 ? mapResponse(op.mock.body, op.response) : op.mock.body } : null,
      error: op.risk === 'destructive' ? 'Destructive operation: runs only for a request a human approved in Token Vault, and only on webhooks started with WEBHOOK_ALLOW_DESTRUCTIVE=true.' : null,
    };
  } catch (e) {
    return { request: { method: op.request.method, url: '', headers: [], body: null }, mockResponse: null, error: e instanceof TemplateError ? e.message : 'Could not build the request' };
  }
}
