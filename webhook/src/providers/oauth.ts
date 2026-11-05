import { createHash, randomBytes } from 'node:crypto';
import { hostAllowed, type AuthMethodDefinition, type OAuthConfig, type ProviderDefinition } from '@token-vault/shared';
import { mockAuthorize, mockToken } from './simulators/oauth';

/**
 * OAuth 2.0 authorization code + PKCE (customer trust zone). The client secret, the PKCE
 * verifier, and the access and refresh tokens are stored only here, encrypted. The control
 * plane relays the browser redirect and the single-use authorization code, which is
 * useless without the verifier and the client secret.
 */
export interface OAuthCredential {
  type: 'oauth2';
  authMethod: string;
  clientId: string;
  clientSecret: string;
  /** Present while the connection is pending (between start and complete). */
  pending?: { stateHash: string; codeVerifier: string; redirectUri: string; startedAt: string };
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: string | null;
  scopes?: string[];
}

export class OAuthError extends Error {
  constructor(
    public code: 'OAUTH_STATE_MISMATCH' | 'OAUTH_PENDING_EXPIRED' | 'OAUTH_EXCHANGE_FAILED' | 'OAUTH_REFRESH_FAILED' | 'OAUTH_NOT_CONNECTED' | 'OAUTH_CONFIG',
    message: string,
    public upstreamStatus: number | null = null,
  ) {
    super(message);
  }
}

export const PENDING_TTL_MS = 10 * 60_000;
/** Refresh when the access token has less than this left. */
export const REFRESH_SKEW_MS = 30_000;

const b64url = (b: Buffer) => b.toString('base64url');
export const sha256b64url = (s: string) => b64url(createHash('sha256').update(s).digest());

export function isOAuthCredential(secret: string): boolean {
  return secret.startsWith('{') && secret.includes('"type":"oauth2"');
}

export function oauthConfig(method: AuthMethodDefinition): OAuthConfig {
  if (method.kind !== 'oauth2' || !method.oauth) throw new OAuthError('OAUTH_CONFIG', `${method.id} is not an OAuth 2.0 method`);
  return method.oauth;
}

/** Begins a connection: PKCE pair and state, and the URL the admin's browser is sent to. */
export function start(mode: 'mock' | 'live', method: AuthMethodDefinition, p: { clientId: string; clientSecret: string; redirectUri: string }) {
  const cfg = oauthConfig(method);
  const state = b64url(randomBytes(24));
  const codeVerifier = b64url(randomBytes(48));
  const challenge = sha256b64url(codeVerifier);
  const credential: OAuthCredential = {
    type: 'oauth2',
    authMethod: method.id,
    clientId: p.clientId,
    clientSecret: p.clientSecret,
    pending: { stateHash: sha256b64url(state), codeVerifier, redirectUri: p.redirectUri, startedAt: new Date().toISOString() },
  };
  let authorizeUrl: string;
  if (mode === 'mock') {
    authorizeUrl = mockAuthorize({ clientId: p.clientId, redirectUri: p.redirectUri, state, challenge, scopes: cfg.scopes });
  } else {
    const url = new URL(cfg.authorizeUrl);
    const params: Record<string, string> = {
      response_type: 'code',
      client_id: p.clientId,
      redirect_uri: p.redirectUri,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      ...(cfg.scopes.length ? { scope: cfg.scopes.join(cfg.scopeSeparator) } : {}),
      ...cfg.authorizeParams,
    };
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    authorizeUrl = url.toString();
  }
  return { credential, state, authorizeUrl };
}

/** Calls the token endpoint (host checked against the definition before credentials are sent). */
async function tokenRequest(mode: 'mock' | 'live', def: ProviderDefinition, cfg: OAuthConfig, cred: OAuthCredential, form: Record<string, string>, ttlS: number) {
  const params: Record<string, string> = { ...form, client_id: cred.clientId };
  if (mode === 'mock') return mockToken({ ...params, client_secret: cred.clientSecret }, ttlS);
  const url = new URL(cfg.tokenUrl);
  if (url.protocol !== 'https:' || !hostAllowed(url.hostname, def.api.allowedHosts)) throw new OAuthError('OAUTH_CONFIG', `refusing to send client credentials to ${url.host}`);
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  if (cfg.clientAuth === 'basic') headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(cred.clientId)}:${encodeURIComponent(cred.clientSecret)}`).toString('base64')}`;
  else params.client_secret = cred.clientSecret;
  const res = await fetch(url, { method: 'POST', headers, body: new URLSearchParams(params).toString(), redirect: 'manual', signal: AbortSignal.timeout(10_000) });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: res.status, body };
}

function applyTokens(cred: OAuthCredential, body: Record<string, unknown>, requested: string[]): OAuthCredential {
  const expiresIn = Number(body.expires_in);
  const scope = typeof body.scope === 'string' ? body.scope.split(/[ ,]+/).filter(Boolean) : undefined;
  return {
    ...cred,
    pending: undefined,
    accessToken: String(body.access_token),
    // Providers may rotate refresh tokens; keep the old one if none was returned.
    refreshToken: typeof body.refresh_token === 'string' ? body.refresh_token : cred.refreshToken,
    expiresAt: Number.isFinite(expiresIn) && expiresIn > 0 ? new Date(Date.now() + expiresIn * 1000).toISOString() : null,
    scopes: scope ?? cred.scopes ?? requested,
  };
}

/** Completes a connection: checks the state, then exchanges the code using the PKCE verifier. */
export async function complete(mode: 'mock' | 'live', def: ProviderDefinition, method: AuthMethodDefinition, cred: OAuthCredential, p: { code: string; state: string }, ttlS: number): Promise<OAuthCredential> {
  const cfg = oauthConfig(method);
  if (!cred.pending) throw new OAuthError('OAUTH_STATE_MISMATCH', 'This connection is not waiting for an authorization code');
  if (Date.now() - new Date(cred.pending.startedAt).getTime() > PENDING_TTL_MS) throw new OAuthError('OAUTH_PENDING_EXPIRED', 'The authorization took too long; start again');
  if (sha256b64url(p.state) !== cred.pending.stateHash) throw new OAuthError('OAUTH_STATE_MISMATCH', 'The authorization response does not belong to this connection');
  const r = await tokenRequest(mode, def, cfg, cred, { grant_type: 'authorization_code', code: p.code, redirect_uri: cred.pending.redirectUri, code_verifier: cred.pending.codeVerifier }, ttlS);
  if (r.status !== 200 || typeof r.body.access_token !== 'string') {
    throw new OAuthError('OAUTH_EXCHANGE_FAILED', `The provider refused the authorization code (HTTP ${r.status}${typeof r.body.error === 'string' ? `: ${r.body.error}` : ''})`, r.status);
  }
  return applyTokens(cred, r.body, cfg.scopes);
}

export function needsRefresh(cred: OAuthCredential, now = Date.now()): boolean {
  return !!cred.expiresAt && new Date(cred.expiresAt).getTime() - now < REFRESH_SKEW_MS;
}

export async function refresh(mode: 'mock' | 'live', def: ProviderDefinition, method: AuthMethodDefinition, cred: OAuthCredential, ttlS: number): Promise<OAuthCredential> {
  const cfg = oauthConfig(method);
  if (!cred.refreshToken) throw new OAuthError('OAUTH_REFRESH_FAILED', 'The access token expired and the provider issued no refresh token; reconnect the integration');
  const r = await tokenRequest(mode, def, cfg, cred, { grant_type: 'refresh_token', refresh_token: cred.refreshToken }, ttlS);
  if (r.status !== 200 || typeof r.body.access_token !== 'string') {
    throw new OAuthError('OAUTH_REFRESH_FAILED', `The provider refused to refresh the access token (HTTP ${r.status}${typeof r.body.error === 'string' ? `: ${r.body.error}` : ''}); reconnect the integration`, r.status);
  }
  return applyTokens(cred, r.body, cfg.scopes);
}

export function maskOAuth(cred: Pick<OAuthCredential, 'clientId' | 'authMethod'>): string {
  const id = cred.clientId.length > 10 ? `${cred.clientId.slice(0, 6)}…${cred.clientId.slice(-4)}` : cred.clientId;
  return `OAuth client ${id}`;
}

/** One refresh at a time per credential (concurrent requests share the result). */
const inFlight = new Map<string, Promise<OAuthCredential>>();
export function singleFlight(ref: string, fn: () => Promise<OAuthCredential>): Promise<OAuthCredential> {
  let p = inFlight.get(ref);
  if (!p) {
    p = fn().finally(() => inFlight.delete(ref));
    inFlight.set(ref, p);
  }
  return p;
}
