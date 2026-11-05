import { describe, expect, it } from 'vitest';
import { DefinitionError, validateProviderDefinition, type ProviderDefinitionInput } from '@token-vault/shared';
import { executeOperation } from '../src/providers/executor';
import * as oauth from '../src/providers/oauth';

const calendar: ProviderDefinitionInput = {
  key: 'calendarx',
  version: 1,
  name: 'CalendarX',
  api: { baseUrl: 'https://api.calendarx.example.com/v1', allowedHosts: ['api.calendarx.example.com'] },
  resource: { name: 'calendar', label: 'Calendar', pattern: '^[a-z]+$' },
  auth: [
    {
      id: 'OAUTH',
      label: 'Sign in with CalendarX',
      kind: 'oauth2',
      oauth: {
        authorizeUrl: 'https://login.calendarx.example.com/authorize',
        tokenUrl: 'https://api.calendarx.example.com/oauth/token',
        scopes: ['events.read', 'offline_access'],
        authorizeParams: { prompt: 'consent' },
      },
    },
  ],
  credentialTest: { request: { method: 'GET', path: '/me' }, response: { fields: { id: 'id' } } },
  operations: [
    {
      id: 'calendarx.events.list',
      label: 'List events',
      risk: 'read',
      request: { method: 'GET', path: '/calendars/{resource.calendar}/events' },
      response: { fields: { id: 'id', title: 'title' } },
      mock: { status: 200, body: [{ id: 'e1', title: 'Standup', organizer_email: 'x@example.com' }] },
    },
  ],
};
const def = validateProviderDefinition(calendar);
const method = def.auth[0]!;
const client = { clientId: 'client_123', clientSecret: 'client-secret-value', redirectUri: 'http://localhost:5173/oauth/callback' };

async function connect(ttlS = 3600) {
  const s = oauth.start('mock', method, client);
  const code = new URL(s.authorizeUrl).searchParams.get('code')!;
  return oauth.complete('mock', def, method, s.credential, { code, state: s.state }, ttlS);
}

describe('OAuth 2.0 definitions', () => {
  it('requires https and a token endpoint on an allowed host (it receives the client secret)', () => {
    const bad = (patch: (d: any) => void) => {
      const d = structuredClone(calendar) as any;
      patch(d);
      return () => validateProviderDefinition(d);
    };
    expect(bad((d) => (d.auth[0].oauth.tokenUrl = 'https://evil.example.net/token'))).toThrow(/must be in api.allowedHosts/);
    expect(bad((d) => (d.auth[0].oauth.authorizeUrl = 'http://login.calendarx.example.com/authorize'))).toThrow(DefinitionError);
    expect(bad((d) => delete d.auth[0].oauth)).toThrow(/needs "oauth"/);
  });

  it('builds a PKCE authorize URL for the real provider', () => {
    const s = oauth.start('live', method, client);
    const url = new URL(s.authorizeUrl);
    expect(url.origin + url.pathname).toBe('https://login.calendarx.example.com/authorize');
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      response_type: 'code',
      client_id: 'client_123',
      redirect_uri: client.redirectUri,
      state: s.state,
      code_challenge_method: 'S256',
      code_challenge: oauth.sha256b64url(s.credential.pending!.codeVerifier),
      scope: 'events.read offline_access',
      prompt: 'consent',
    });
    expect(s.credential.pending!.stateHash).toBe(oauth.sha256b64url(s.state)); // only the hash is kept
    expect(url.searchParams.has('client_secret')).toBe(false);
  });
});

describe('OAuth 2.0 flow (simulated provider)', () => {
  it('connects: state checked, code exchanged with the PKCE verifier, tokens stored', async () => {
    const cred = await connect();
    expect(cred.pending).toBeUndefined();
    expect(cred.accessToken).toMatch(/^mock_oat_/);
    expect(cred.refreshToken).toMatch(/^mock_ort_/);
    expect(cred.scopes).toEqual(['events.read', 'offline_access']);
  });

  it('rejects a foreign state, a replayed code and a wrong PKCE verifier', async () => {
    const s = oauth.start('mock', method, client);
    const code = new URL(s.authorizeUrl).searchParams.get('code')!;
    await expect(oauth.complete('mock', def, method, s.credential, { code, state: 'attacker-state' }, 3600)).rejects.toMatchObject({ code: 'OAUTH_STATE_MISMATCH' });

    const tampered = { ...s.credential, pending: { ...s.credential.pending!, codeVerifier: 'x'.repeat(64) } };
    await expect(oauth.complete('mock', def, method, tampered, { code, state: s.state }, 3600)).rejects.toMatchObject({ code: 'OAUTH_EXCHANGE_FAILED' });
    // The code was consumed by the failed attempt: single use, even for the right verifier.
    await expect(oauth.complete('mock', def, method, s.credential, { code, state: s.state }, 3600)).rejects.toMatchObject({ code: 'OAUTH_EXCHANGE_FAILED' });
  });

  it('expires pending connections', async () => {
    const s = oauth.start('mock', method, client);
    const old = { ...s.credential, pending: { ...s.credential.pending!, startedAt: new Date(Date.now() - oauth.PENDING_TTL_MS - 1000).toISOString() } };
    await expect(oauth.complete('mock', def, method, old, { code: 'x', state: s.state }, 3600)).rejects.toMatchObject({ code: 'OAUTH_PENDING_EXPIRED' });
  });

  it('refreshes with rotating refresh tokens; a used refresh token is refused', async () => {
    const cred = await connect(1);
    expect(oauth.needsRefresh(cred)).toBe(true); // 1 s left is inside the refresh window
    const next = await oauth.refresh('mock', def, method, cred, 3600);
    expect(next.accessToken).not.toBe(cred.accessToken);
    expect(next.refreshToken).not.toBe(cred.refreshToken);
    expect(oauth.needsRefresh(next)).toBe(false);
    await expect(oauth.refresh('mock', def, method, cred, 3600)).rejects.toMatchObject({ code: 'OAUTH_REFRESH_FAILED' });
  });

  it('the simulated API rejects expired access tokens and accepts fresh ones', async () => {
    const cred = await connect(0);
    const call = (token: string) => executeOperation('mock', def, { operation: 'calendarx.events.list', resource: { calendar: 'team' }, input: {} }, { kind: 'bearer', secret: token });
    expect((await call(cred.accessToken!)).upstreamStatus).toBe(401);
    const fresh = await oauth.refresh('mock', def, method, cred, 3600);
    const ok = await call(fresh.accessToken!);
    expect(ok).toMatchObject({ upstreamStatus: 200, body: [{ id: 'e1', title: 'Standup' }] });
  });

  it('shares one refresh between concurrent requests', async () => {
    let calls = 0;
    const slow = () =>
      new Promise<oauth.OAuthCredential>((r) => {
        calls++;
        setTimeout(() => r({ type: 'oauth2', authMethod: 'OAUTH', clientId: 'c', clientSecret: 's' }), 20);
      });
    const [a, b] = await Promise.all([oauth.singleFlight('cref_x', slow), oauth.singleFlight('cref_x', slow)]);
    expect(a).toBe(b);
    expect(calls).toBe(1);
  });
});
