import { describe, expect, it, vi } from 'vitest';
import { inspect } from 'node:util';
import { AccessDeniedError, ApprovalRequiredError, AuthenticationError, TokenVault } from '../src';

const KEY = 'tvak_0123456789ab_abcdefghijklmnopqrstuvwxyz012345';
const ok = (details: unknown) => ({ status: '10000', msg: 'ok', error: null, details, totalRecords: 1 });
const fail = (code: string, error: string) => ({ status: '10001', msg: '', error, code, details: null, totalRecords: 0 });
const value = { secret_id: 'sec_0123456789abcdef', name: 'orders-db', type_key: 'postgresql', version: 2, payload: { password: 'pw-from-vault' }, expires_at: null, retrieved_at: '2026-11-23T10:00:00.000Z', grant_id: 'sag_1', request_id: 'req_1' };

/** A fake Token Vault answering the given (status, body) pairs in order, recording each request. */
function server(...answers: [number, unknown][]) {
  const calls: { url: string; body: any }[] = [];
  const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, body: init?.body ? JSON.parse(String(init.body)) : null });
    const [status, body] = answers[Math.min(calls.length - 1, answers.length - 1)]!;
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { tv: new TokenVault({ apiKey: KEY, baseUrl: 'http://tv', fetch: fetchImpl }), calls };
}

describe('tv.secrets', () => {
  it('get: by name, id or scope; only the fields asked for', async () => {
    const { tv, calls } = server([200, ok(value)]);
    expect(await tv.secrets.get('orders-db', { fields: ['password'], reason: 'deploy' })).toEqual(value);
    expect(calls[0]).toMatchObject({ url: 'http://tv/agent/v1/secret/retrieve', body: { name: 'orders-db', fields: ['password'], reason: 'deploy' } });
    await tv.secrets.get('sec_0123456789abcdef');
    expect(calls[1]!.body).toEqual({ secret_id: 'sec_0123456789abcdef' });
    await tv.secrets.get({ name: 'orders-db', project: 'shop', environment: 'production' }, { version: 1 });
    expect(calls[2]!.body).toMatchObject({ name: 'orders-db', project: 'shop', environment: 'production', version: 1 });
  });

  it('maps refusals to typed errors', async () => {
    await expect(server([403, fail('SECRET_ACCESS_DENIED', 'This agent has no grant for that secret')]).tv.secrets.get('x')).rejects.toMatchObject({ constructor: AccessDeniedError, code: 'SECRET_ACCESS_DENIED' });
    await expect(server([401, fail('AGENT_UNAUTHENTICATED', 'Invalid agent credential')]).tv.secrets.get('x')).rejects.toBeInstanceOf(AuthenticationError);
    await expect(server([409, fail('SECRET_EXPIRED', 'expired')]).tv.secrets.get('x')).rejects.toMatchObject({ code: 'SECRET_EXPIRED', httpStatus: 409 });
  });

  it('a held retrieval throws ApprovalRequiredError, or waits for the decision and then retrieves with the approval', async () => {
    const held = ok({ approval_id: 'sapr_1', status: 'PENDING', expires_at: '2026-11-23T10:15:00.000Z', decision_code: 'APPROVAL_REQUIRED', reason: 'held' });
    const e = await server([202, held]).tv.secrets.get('x').catch((x) => x);
    expect(e).toBeInstanceOf(ApprovalRequiredError);
    expect(e.approvalId).toBe('sapr_1');

    vi.useFakeTimers();
    try {
      const { tv, calls } = server([202, held], [202, held], [200, ok(value)]);
      const p = tv.secrets.get('x', { waitForApproval: { intervalMs: 1000 } });
      await vi.advanceTimersByTimeAsync(2500);
      expect(await p).toEqual(value);
      expect(calls.map((c) => c.body.approval_id)).toEqual([undefined, 'sapr_1', 'sapr_1']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('caches only when asked, in memory, and never exposes values in the client', async () => {
    const { tv, calls } = server([200, ok(value)]);
    await tv.secrets.get('orders-db', { cacheTtlMs: 60_000 });
    await tv.secrets.get('orders-db', { cacheTtlMs: 60_000 });
    expect(calls).toHaveLength(1);
    await tv.secrets.get('orders-db'); // no cache: asks again
    expect(calls).toHaveLength(2);
    expect(JSON.stringify(tv)).not.toContain('pw-from-vault');
    expect(inspect(tv, { depth: 5 })).not.toContain('pw-from-vault');
    tv.secrets.clearCache();
    await tv.secrets.get('orders-db', { cacheTtlMs: 60_000 });
    expect(calls).toHaveLength(3);
  });

  it('list: the secrets the agent may read', async () => {
    const { tv, calls } = server([200, ok({ items: [{ secret_id: 'sec_1', name: 'orders-db' }] })]);
    expect(await tv.secrets.list()).toEqual([{ secret_id: 'sec_1', name: 'orders-db' }]);
    expect(calls[0]!.url).toBe('http://tv/agent/v1/secret/getall');
  });

  it('lease: short-lived credentials from a dynamic secret, with renew() and revoke()', async () => {
    const issued = { lease_id: 'lse_0123456789', secret_id: 'sec_0123456789abcdef', name: 'orders-dynamic', type_key: 'postgresql-dynamic', credentials: { username: 'tv_lse_0123456789', password: 'lease-password' }, expires_at: '2026-11-23T11:00:00.000Z', max_expires_at: '2026-11-24T10:00:00.000Z', renewable: true, grant_id: 'sag_1', request_id: 'req_2' };
    const { tv, calls } = server([201, ok(issued)], [200, ok({ lease_id: 'lse_0123456789', status: 'ACTIVE', expires_at: '2026-11-23T12:00:00.000Z', max_expires_at: issued.max_expires_at, renew_count: 1 })], [200, ok({ lease_id: 'lse_0123456789', status: 'REVOKED' })]);
    const lease = await tv.secrets.lease('orders-dynamic', { ttlSeconds: 900, reason: 'report' });
    expect(lease).toEqual(issued);
    expect(calls[0]).toMatchObject({ url: 'http://tv/agent/v1/secret/lease', body: { name: 'orders-dynamic', ttl_seconds: 900, reason: 'report' } });
    expect((await lease.renew(3600)).renew_count).toBe(1);
    expect(calls[1]).toMatchObject({ url: 'http://tv/agent/v1/secret/lease/renew', body: { lease_id: 'lse_0123456789', ttl_seconds: 3600 } });
    await lease.revoke();
    expect(calls[2]).toMatchObject({ url: 'http://tv/agent/v1/secret/lease/revoke', body: { lease_id: 'lse_0123456789' } });
    await expect(server([409, fail('SECRET_NOT_DYNAMIC', 'static')]).tv.secrets.lease('x')).rejects.toMatchObject({ code: 'SECRET_NOT_DYNAMIC' });
  });
});
