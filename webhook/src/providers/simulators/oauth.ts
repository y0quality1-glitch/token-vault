import { createHash, randomBytes } from 'node:crypto';

/**
 * Simulated OAuth 2.0 authorization server (mock mode). It consents immediately, enforces
 * PKCE, redirect URI and client binding, issues expiring access tokens, rotates refresh
 * tokens (a used refresh token is rejected), and lets the mock API reject expired tokens,
 * so the webhook's refresh logic is exercised for real.
 */
interface Code {
  clientId: string;
  challenge: string;
  redirectUri: string;
  scopes: string[];
  expiresAt: number;
}

const codes = new Map<string, Code>();
const accessTokens = new Map<string, { clientId: string; expiresAt: number }>();
const refreshTokens = new Map<string, { clientId: string; scopes: string[]; used: boolean }>();
const b64url = (b: Buffer) => b.toString('base64url');

export interface TokenResponse {
  status: number;
  body: Record<string, unknown>;
}

/** The provider's consent screen, approving at once: returns the redirect with a code. */
export function mockAuthorize(p: { clientId: string; redirectUri: string; state: string; challenge: string; scopes: string[] }): string {
  const code = `mock_code_${b64url(randomBytes(18))}`;
  codes.set(code, { clientId: p.clientId, challenge: p.challenge, redirectUri: p.redirectUri, scopes: p.scopes, expiresAt: Date.now() + 60_000 });
  const url = new URL(p.redirectUri);
  url.searchParams.set('code', code);
  url.searchParams.set('state', p.state);
  return url.toString();
}

function issue(clientId: string, scopes: string[], ttlS: number): TokenResponse {
  const access = `mock_oat_${b64url(randomBytes(24))}`;
  const refresh = `mock_ort_${b64url(randomBytes(24))}`;
  accessTokens.set(access, { clientId, expiresAt: Date.now() + ttlS * 1000 });
  refreshTokens.set(refresh, { clientId, scopes, used: false });
  return { status: 200, body: { access_token: access, refresh_token: refresh, token_type: 'Bearer', expires_in: ttlS, scope: scopes.join(' ') } };
}

const invalid = (description: string): TokenResponse => ({ status: 400, body: { error: 'invalid_grant', error_description: description } });

/** The token endpoint (form parameters already parsed, client credentials included). */
export function mockToken(form: Record<string, string>, ttlS: number): TokenResponse {
  if (!form.client_id || (form.client_secret ?? '').length < 8) return { status: 401, body: { error: 'invalid_client' } };
  if (form.grant_type === 'authorization_code') {
    const code = codes.get(form.code ?? '');
    codes.delete(form.code ?? ''); // single use
    if (!code || code.expiresAt < Date.now()) return invalid('unknown or expired code');
    if (code.clientId !== form.client_id) return invalid('code was issued to another client');
    if (code.redirectUri !== form.redirect_uri) return invalid('redirect_uri mismatch');
    const challenge = b64url(createHash('sha256').update(form.code_verifier ?? '').digest());
    if (challenge !== code.challenge) return invalid('PKCE verification failed');
    return issue(code.clientId, code.scopes, ttlS);
  }
  if (form.grant_type === 'refresh_token') {
    const r = refreshTokens.get(form.refresh_token ?? '');
    if (!r || r.clientId !== form.client_id) return invalid('unknown refresh token');
    if (r.used) return invalid('refresh token already used (rotation)');
    r.used = true;
    return issue(r.clientId, r.scopes, ttlS);
  }
  return { status: 400, body: { error: 'unsupported_grant_type' } };
}

/** For the simulated API: is this bearer token a live access token? */
export function mockAccessTokenValid(token: string): boolean {
  const t = accessTokens.get(token);
  return !!t && t.expiresAt > Date.now();
}
