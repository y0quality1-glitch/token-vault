import { describe, expect, it, vi } from 'vitest';
import { inspect } from 'node:util';
import type { ExecuteResponseBody } from '@token-vault/shared';
import { AccessDeniedError, AuthenticationError, ExecutionFailedError, TokenVault, TokenVaultError } from '../src';

const KEY = 'tvak_0123456789ab_abcdefghijklmnopqrstuvwxyz012345';

function body(overrides: Partial<ExecuteResponseBody> & { status?: ExecuteResponseBody['execution']['status']; upstream?: number | null } = {}): ExecuteResponseBody {
  const { status = 'SUCCEEDED', upstream = 201, ...rest } = overrides;
  return {
    request_id: 'req_1',
    correlation_id: 'corr_1',
    decision: 'ALLOW',
    decision_code: 'ALLOWED',
    reason: 'Authorized by grant "x".',
    matched_rule: { type: 'grant', id: 'grt_1' },
    grant_id: 'grt_1',
    execution: { status, webhook_status: 'OK', upstream_status: upstream, duration_ms: 12, simulated: true, idempotent_replay: false },
    result: { number: 44 },
    checks: [],
    ...rest,
  };
}

function client(response: unknown, status = 200) {
  const fetchMock = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => new Response(JSON.stringify(response), { status, headers: { 'content-type': 'application/json' } }));
  return { tv: new TokenVault({ apiKey: KEY, baseUrl: 'http://tv.test/', fetch: fetchMock as unknown as typeof fetch }), fetchMock };
}

describe('TokenVault SDK', () => {
  it('sends the credential as a bearer token and returns the sanitized result', async () => {
    const { tv, fetchMock } = client(body());
    const r = await tv.execute({ integrationId: 'int_1', operation: 'github.issues.create', resource: { repository: 'a/b' }, input: { title: 't' } });
    expect(r).toMatchObject({ data: { number: 44 }, requestId: 'req_1', upstreamStatus: 201 });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('http://tv.test/agent/v1/execute');
    expect((init!.headers as Record<string, string>).authorization).toBe(`Bearer ${KEY}`);
    const sent = JSON.parse(init!.body as string);
    expect(sent).toMatchObject({ integration_id: 'int_1', operation: 'github.issues.create', resource: { repository: 'a/b' } });
    expect(sent.idempotency_key).toMatch(/^sdk-/); // generated so retries are safe
  });

  it('throws AccessDeniedError with the decision code and request ID on denial', async () => {
    const { tv } = client(body({ decision: 'DENY', decision_code: 'GRANT_REVOKED', reason: 'Grant "x" was revoked.', status: 'NOT_EXECUTED', upstream: null }), 403);
    const err = await tv.execute({ integrationId: 'int_1', operation: 'github.issues.list' }).catch((e) => e);
    expect(err).toBeInstanceOf(AccessDeniedError);
    expect(err).toMatchObject({ code: 'GRANT_REVOKED', httpStatus: 403, requestId: 'req_1', message: 'Grant "x" was revoked.' });
  });

  it('distinguishes authentication failures and failed executions', async () => {
    const auth = client(body({ decision: 'DENY', decision_code: 'AGENT_UNAUTHENTICATED', status: 'NOT_EXECUTED' }), 401);
    await expect(auth.tv.execute({ integrationId: 'i', operation: 'github.issues.list' })).rejects.toBeInstanceOf(AuthenticationError);
    const failed = client(body({ decision_code: 'WEBHOOK_UNAVAILABLE', status: 'FAILED', upstream: null }), 503);
    await expect(failed.tv.execute({ integrationId: 'i', operation: 'github.issues.list' })).rejects.toBeInstanceOf(ExecutionFailedError);
  });

  it('executeRaw returns every outcome without throwing', async () => {
    const { tv } = client(body({ decision: 'DENY', decision_code: 'SCOPE_DENIED' }), 403);
    expect(await tv.executeRaw({ integrationId: 'i', operation: 'github.contents.read' })).toMatchObject({ httpStatus: 403, body: { decision_code: 'SCOPE_DENIED' } });
  });

  it('reports network failures as TokenVaultError NETWORK_ERROR', async () => {
    const tv = new TokenVault({ apiKey: KEY, fetch: (async () => { throw new TypeError('fetch failed'); }) as unknown as typeof fetch });
    await expect(tv.capabilities()).rejects.toMatchObject({ code: 'NETWORK_ERROR' });
    await expect(tv.capabilities()).rejects.toBeInstanceOf(TokenVaultError);
  });

  it('requires a well-formed key and never exposes it when logged or serialized', () => {
    expect(() => new TokenVault({ apiKey: 'nope' })).toThrow(AuthenticationError);
    const tv = new TokenVault({ apiKey: KEY });
    expect(JSON.stringify(tv)).not.toContain(KEY);
    expect(inspect(tv)).not.toContain(KEY);
    expect(String(Object.keys(tv))).not.toContain(KEY);
    expect(tv.keyId).toBe('0123456789ab');
  });

  it('requests access and surfaces server validation errors', async () => {
    const ok = client({ access_request_id: 'arq_1', status: 'PENDING', operations: ['github.issues.list'] }, 201);
    expect(await ok.tv.requestAccess({ integrationId: 'int_1', operations: ['github.issues.list'], justification: 'Need to triage open issues.' })).toMatchObject({ access_request_id: 'arq_1', status: 'PENDING' });
    expect(JSON.parse(ok.fetchMock.mock.calls[0]![1]!.body as string)).toMatchObject({ integration_id: 'int_1', operations: ['github.issues.list'], duration_minutes: 60 });
    const bad = client({ error: { code: 'VALIDATION_ERROR', message: 'Destructive operations cannot be requested: github.repositories.delete' } }, 400);
    await expect(bad.tv.requestAccess({ integrationId: 'int_1', operations: ['github.repositories.delete'], justification: 'Cleanup old repos.' })).rejects.toMatchObject({ code: 'VALIDATION_ERROR', httpStatus: 400 });
  });
});
