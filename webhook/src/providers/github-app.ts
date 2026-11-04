import { createPrivateKey, createSign, randomBytes, type KeyObject } from 'node:crypto';

/**
 * GitHub App credentials (customer trust zone).
 *
 * The only long-lived secret is the App's private key. For each authorized request the
 * webhook signs a short-lived App JWT, asks GitHub for an installation access token
 * narrowed to exactly the requested repository and the permission the operation needs,
 * uses it once, then revokes it. A leaked minted token is limited to one repository,
 * one permission and at most one hour.
 *
 * mock mode (GITHUB_MODE=mock): JWTs are really signed with the provided key, and a
 * simulated GitHub enforces the minted token's repository and permission scope.
 */
export interface GitHubAppCredential {
  type: 'github_app';
  appId: string;
  installationId: string;
  /** Where the private key comes from: stored encrypted in this webhook, or the webhook's environment. */
  keySource: 'stored' | 'webhook_env';
  /** PEM, only when keySource = 'stored'. */
  privateKey?: string;
  account?: string;
}

export type InstallationPermission = 'metadata' | 'contents' | 'issues';
export type PermissionLevel = 'read' | 'write';

/** Least privilege per operation: the minted token gets only this. */
export const OPERATION_PERMISSIONS: Record<string, Partial<Record<InstallationPermission, PermissionLevel>>> = {
  'credential.test': { metadata: 'read' },
  'github.repositories.read': { metadata: 'read' },
  'github.contents.read': { contents: 'read' },
  'github.issues.list': { issues: 'read' },
  'github.issues.create': { issues: 'write' },
};

export interface MintedToken {
  token: string;
  expiresAt: string;
  repositories: string[];
  permissions: Partial<Record<InstallationPermission, PermissionLevel>>;
}

export class GitHubAppError extends Error {
  constructor(
    public code: 'INVALID_PRIVATE_KEY' | 'APP_KEY_NOT_CONFIGURED' | 'INSTALLATION_NOT_FOUND' | 'TOKEN_MINT_FAILED' | 'APP_AUTH_FAILED',
    message: string,
    public upstreamStatus: number | null = null,
  ) {
    super(message);
  }
}

// ---------------------------------------------------------------- keys and JWT

export function parsePrivateKey(pem: string): KeyObject {
  try {
    const key = createPrivateKey(pem);
    if (key.asymmetricKeyType !== 'rsa') throw new Error('not RSA');
    return key;
  } catch {
    throw new GitHubAppError('INVALID_PRIVATE_KEY', 'The private key is not a valid RSA private key in PEM format (download it from the GitHub App settings).');
  }
}

/** Resolves the key for a credential: stored PEM, or the webhook's GITHUB_APP_PRIVATE_KEY. */
export function resolvePrivateKey(cred: GitHubAppCredential, envPem: string | undefined): KeyObject {
  if (cred.keySource === 'stored') return parsePrivateKey(cred.privateKey ?? '');
  if (!envPem) throw new GitHubAppError('APP_KEY_NOT_CONFIGURED', 'This webhook has no GITHUB_APP_PRIVATE_KEY configured.');
  return parsePrivateKey(envPem);
}

const b64url = (b: Buffer | string) => Buffer.from(b).toString('base64url');

/** RS256 App JWT valid for 9 minutes (GitHub allows at most 10), backdated 60 s for clock skew. */
export function createAppJwt(appId: string, key: KeyObject, now = Date.now()): string {
  const iat = Math.floor(now / 1000) - 60;
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ iat, exp: iat + 9 * 60, iss: appId }));
  const signature = createSign('RSA-SHA256').update(`${header}.${payload}`).sign(key);
  return `${header}.${payload}.${b64url(signature)}`;
}

// ---------------------------------------------------------------- mock GitHub App backend

/** Minted mock tokens and their scope, enforced by the mock GitHub API. */
const mockTokens = new Map<string, MintedToken>();

export function mockTokenScope(token: string): MintedToken | undefined {
  const t = mockTokens.get(token);
  if (t && new Date(t.expiresAt).getTime() < Date.now()) {
    mockTokens.delete(token);
    return undefined;
  }
  return t;
}

/** Mock installations: every App ID has installation 1 on the demo-org account. */
const MOCK_INSTALLATION = { id: '1', account: 'demo-org' };

// ---------------------------------------------------------------- GitHub API calls

async function gh(method: string, path: string, auth: string, body?: unknown): Promise<{ status: number; json: any }> {
  const res = await fetch(`https://api.github.com${path}`, {
    method,
    headers: { Authorization: auth, Accept: 'application/vnd.github+json', 'User-Agent': 'token-vault-poc-webhook', 'X-GitHub-Api-Version': '2022-11-28', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10_000),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

/**
 * Validates an App + key and resolves the installation (if not given, the App must have
 * exactly one). Returns the installation ID and the account it is installed on.
 */
export async function resolveInstallation(mode: 'mock' | 'live', appId: string, key: KeyObject, installationId?: string): Promise<{ installationId: string; account: string }> {
  const jwt = createAppJwt(appId, key);
  if (mode === 'mock') {
    if (installationId && installationId !== MOCK_INSTALLATION.id) throw new GitHubAppError('INSTALLATION_NOT_FOUND', `Installation ${installationId} not found for App ${appId} (mock GitHub has installation ${MOCK_INSTALLATION.id}).`, 404);
    return { installationId: MOCK_INSTALLATION.id, account: MOCK_INSTALLATION.account };
  }
  if (installationId) {
    const r = await gh('GET', `/app/installations/${encodeURIComponent(installationId)}`, `Bearer ${jwt}`);
    if (r.status === 401) throw new GitHubAppError('APP_AUTH_FAILED', 'GitHub rejected the App JWT: check the App ID and private key.', 401);
    if (r.status !== 200) throw new GitHubAppError('INSTALLATION_NOT_FOUND', `Installation ${installationId} not found for App ${appId}.`, r.status);
    return { installationId, account: String(r.json?.account?.login ?? '') };
  }
  const r = await gh('GET', '/app/installations', `Bearer ${jwt}`);
  if (r.status === 401) throw new GitHubAppError('APP_AUTH_FAILED', 'GitHub rejected the App JWT: check the App ID and private key.', 401);
  const list: any[] = Array.isArray(r.json) ? r.json : [];
  if (list.length !== 1) throw new GitHubAppError('INSTALLATION_NOT_FOUND', list.length === 0 ? 'The App is not installed on any account yet.' : `The App has ${list.length} installations; enter the installation ID.`, r.status);
  return { installationId: String(list[0].id), account: String(list[0].account?.login ?? '') };
}

/**
 * Mints an installation token narrowed to one repository (when given) and the
 * operation's permission. GitHub rejects narrowing to a repository the installation
 * cannot access, which is reported as a scoped failure, not a broad fallback.
 */
export async function mintInstallationToken(mode: 'mock' | 'live', cred: GitHubAppCredential, key: KeyObject, operation: string, repository?: string): Promise<MintedToken> {
  const permissions = OPERATION_PERMISSIONS[operation];
  if (!permissions) throw new GitHubAppError('TOKEN_MINT_FAILED', `No permission mapping for operation ${operation}`);
  const repoName = repository?.split('/')[1];
  const jwt = createAppJwt(cred.appId, key);

  if (mode === 'mock') {
    if (cred.installationId !== MOCK_INSTALLATION.id) throw new GitHubAppError('INSTALLATION_NOT_FOUND', 'Installation not found (mock).', 404);
    const token = `ghs_${randomBytes(18).toString('hex')}`;
    const minted: MintedToken = { token, expiresAt: new Date(Date.now() + 3600_000).toISOString(), repositories: repository ? [repository.toLowerCase()] : [], permissions };
    void jwt; // signed for real above: proves the key works even in mock mode
    mockTokens.set(token, minted);
    return minted;
  }

  const r = await gh('POST', `/app/installations/${encodeURIComponent(cred.installationId)}/access_tokens`, `Bearer ${jwt}`, { ...(repoName ? { repositories: [repoName] } : {}), permissions });
  if (r.status !== 201 || typeof r.json?.token !== 'string') {
    throw new GitHubAppError(r.status === 401 ? 'APP_AUTH_FAILED' : 'TOKEN_MINT_FAILED', `GitHub refused to mint a scoped installation token (HTTP ${r.status}${r.json?.message ? `: ${r.json.message}` : ''}).`, r.status);
  }
  return { token: r.json.token, expiresAt: String(r.json.expires_at), repositories: repository ? [repository.toLowerCase()] : [], permissions: r.json.permissions ?? permissions };
}

/** Revokes a minted token as soon as the request is done (best effort). */
export async function revokeInstallationToken(mode: 'mock' | 'live', token: string): Promise<boolean> {
  if (mode === 'mock') return mockTokens.delete(token);
  try {
    const r = await gh('DELETE', '/installation/token', `Bearer ${token}`);
    return r.status === 204;
  } catch {
    return false;
  }
}

export function isGitHubAppCredential(secret: string): boolean {
  return secret.startsWith('{') && secret.includes('"github_app"');
}

export function maskApp(cred: Pick<GitHubAppCredential, 'appId' | 'installationId'>): string {
  return `GitHub App ${cred.appId} · installation ${cred.installationId}`;
}
