import {
  TemplateError,
  hostAllowed,
  mapResponse,
  renderBody,
  renderPath,
  renderString,
  type AuthMethodDefinition,
  type OperationDefinition,
  type ProviderDefinition,
  type RequestTemplate,
  type ResponseMap,
} from '@token-vault/shared';
import { githubSimulator } from './simulators/github';
import { mockAccessTokenValid } from './simulators/oauth';
import type { Simulator, UpstreamRequest, UpstreamResponse } from './simulators/types';

/**
 * Generic provider executor (customer trust zone). Builds the upstream request from a
 * provider definition, checks where it is going, injects the credential last, and
 * returns only the response fields the definition allows.
 */

export interface ProviderCall {
  operation: string;
  resource: Record<string, string | undefined>;
  input: Record<string, unknown>;
  /** Set by the route only when this webhook allows destructive operations and the request carries a human approval. */
  allowDestructive?: boolean;
}

export interface ProviderResult {
  upstreamStatus: number;
  body: unknown;
  simulated: boolean;
}

/** How the credential is attached. Plugins (e.g. GitHub App) resolve to a bearer token first. */
export type AuthInjection = { kind: 'bearer'; secret: string } | { kind: 'header'; header: string; prefix?: string; secret: string } | { kind: 'basic'; secret: string };

export class ExecutionError extends Error {
  constructor(
    public code: 'UNSUPPORTED_OPERATION' | 'INVALID_REQUEST' | 'HOST_NOT_ALLOWED' | 'REDIRECT_REFUSED' | 'RESPONSE_TOO_LARGE' | 'CREDENTIAL_NOT_ISSUABLE',
    message: string,
  ) {
    super(message);
  }
}

const MAX_RESPONSE_BYTES = 1_000_000;

/** Simulated upstream hosts for mock mode. */
const SIMULATORS: Record<string, Simulator> = { 'api.github.com': githubSimulator };

export function injectAuth(headers: Record<string, string>, auth: AuthInjection): void {
  if (auth.kind === 'bearer') headers.authorization = `Bearer ${auth.secret}`;
  else if (auth.kind === 'basic') headers.authorization = `Basic ${Buffer.from(auth.secret).toString('base64')}`;
  else headers[auth.header.toLowerCase()] = `${auth.prefix ?? ''}${auth.secret}`;
}

/** Maps a definition auth method and a decrypted secret to an injection (non-plugin methods). */
export function injectionFor(method: AuthMethodDefinition, secret: string): AuthInjection {
  if (method.kind === 'header') return { kind: 'header', header: method.header!, prefix: method.prefix, secret };
  if (method.kind === 'basic') return { kind: 'basic', secret };
  return { kind: 'bearer', secret };
}

function validateCall(def: ProviderDefinition, op: OperationDefinition, call: ProviderCall) {
  const primary = call.resource[def.resource.name];
  if (op.requiresResource && (!primary || !new RegExp(def.resource.pattern).test(primary))) {
    throw new ExecutionError('INVALID_REQUEST', `resource.${def.resource.name} must match ${def.resource.pattern}`);
  }
  for (const [name, f] of Object.entries(def.resourceFields)) {
    const v = call.resource[name];
    if (v !== undefined && v !== '' && !new RegExp(f.pattern).test(v)) throw new ExecutionError('INVALID_REQUEST', `resource.${name} is not valid`);
  }
  for (const [name, f] of Object.entries(op.input)) {
    const v = call.input[name];
    if (v === undefined || v === null || v === '') {
      if (f.required) throw new ExecutionError('INVALID_REQUEST', `input.${name} is required`);
      continue;
    }
    if (typeof v !== f.type) throw new ExecutionError('INVALID_REQUEST', `input.${name} must be a ${f.type}`);
    if (f.maxLength && typeof v === 'string' && v.length > f.maxLength) throw new ExecutionError('INVALID_REQUEST', `input.${name} is longer than ${f.maxLength}`);
  }
}

function buildRequest(def: ProviderDefinition, t: RequestTemplate, call: ProviderCall, auth: AuthInjection): UpstreamRequest {
  const vars = { resource: call.resource, input: call.input };
  let url: URL;
  try {
    const base = new URL(def.api.baseUrl);
    url = new URL(base.origin + base.pathname.replace(/\/$/, '') + renderPath(t.path, vars));
    for (const [k, v] of Object.entries(t.query ?? {})) {
      const value = renderString(String(v), vars);
      if (value !== '') url.searchParams.set(k, value);
    }
  } catch (e) {
    throw new ExecutionError('INVALID_REQUEST', e instanceof TemplateError ? e.message : 'request URL could not be built');
  }
  // The credential is only ever sent to the definition's allowed hosts over https.
  if (url.protocol !== 'https:' || !hostAllowed(url.hostname, def.api.allowedHosts)) throw new ExecutionError('HOST_NOT_ALLOWED', `refusing to send credentials to ${url.host}`);

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(def.api.headers)) headers[k.toLowerCase()] = v;
  let body: string | undefined;
  if (t.body !== undefined) {
    body = JSON.stringify(renderBody(t.body, vars));
    headers['content-type'] = 'application/json';
  }
  injectAuth(headers, auth);
  return { method: t.method, url, headers, body };
}

async function liveTransport(req: UpstreamRequest, timeoutMs: number): Promise<UpstreamResponse> {
  const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  // Following a redirect would carry the credential to a host the definition never named.
  if (res.status >= 300 && res.status < 400) throw new ExecutionError('REDIRECT_REFUSED', `upstream redirected (HTTP ${res.status}); redirects are not followed`);
  if (Number(res.headers.get('content-length') ?? 0) > MAX_RESPONSE_BYTES) throw new ExecutionError('RESPONSE_TOO_LARGE', 'upstream response is too large');
  const text = await res.text();
  if (text.length > MAX_RESPONSE_BYTES) throw new ExecutionError('RESPONSE_TOO_LARGE', 'upstream response is too large');
  let body: unknown = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { message: 'Upstream returned a non-JSON response' };
  }
  return { status: res.status, body };
}

async function mockTransport(req: UpstreamRequest, fallback?: { status: number; body?: unknown }): Promise<UpstreamResponse> {
  // Access tokens from the simulated OAuth server must be live, like at a real provider.
  const bearer = /^Bearer (mock_oat_\S+)$/.exec(req.headers.authorization ?? '')?.[1];
  if (bearer && !mockAccessTokenValid(bearer)) return { status: 401, body: { message: 'invalid_token' } };
  const sim = SIMULATORS[req.url.host];
  if (sim) return sim(req);
  if (fallback) return { status: fallback.status, body: fallback.body };
  return { status: 200, body: {} };
}

async function run(
  mode: 'mock' | 'live',
  def: ProviderDefinition,
  t: RequestTemplate,
  response: ResponseMap,
  call: ProviderCall,
  auth: AuthInjection,
  mock?: { status: number; body?: unknown },
): Promise<ProviderResult> {
  const req = buildRequest(def, t, call, auth);
  const res = mode === 'live' ? await liveTransport(req, def.api.timeoutMs) : await mockTransport(req, mock);
  const ok = res.status >= 200 && res.status < 300;
  const message = (res.body as { message?: unknown } | null)?.message;
  return {
    upstreamStatus: res.status,
    simulated: mode === 'mock',
    body: ok ? mapResponse(res.body, response) : { message: typeof message === 'string' ? message.slice(0, 300) : 'Upstream error' },
  };
}

export function getExecutableOperation(def: ProviderDefinition, operationId: string, allowDestructive = false): OperationDefinition {
  const op = def.operations.find((o) => o.id === operationId);
  if (!op || (op.risk === 'destructive' && !allowDestructive)) throw new ExecutionError('UNSUPPORTED_OPERATION', 'This webhook does not execute that operation');
  return op;
}

/** Executes one operation of a definition with an already-resolved credential. */
export async function executeOperation(mode: 'mock' | 'live', def: ProviderDefinition, call: ProviderCall, auth: AuthInjection): Promise<ProviderResult> {
  const op = getExecutableOperation(def, call.operation, call.allowDestructive);
  validateCall(def, op, call);
  return run(mode, def, op.request, op.response, call, auth, op.mock);
}

/** Verifies a credential with the auth method's test request (or the definition's default). */
export async function testCredential(mode: 'mock' | 'live', def: ProviderDefinition, method: AuthMethodDefinition, auth: AuthInjection): Promise<ProviderResult> {
  const test = method.test ?? def.credentialTest;
  return run(mode, def, test.request, test.response, { operation: 'credential.test', resource: {}, input: {} }, auth, test.mock);
}
