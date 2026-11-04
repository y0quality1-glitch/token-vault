import { describe, expect, it } from 'vitest';
import { createVerify, generateKeyPairSync } from 'node:crypto';
import { callGitHub } from '../src/providers/github';
import {
  GitHubAppError,
  OPERATION_PERMISSIONS,
  createAppJwt,
  isGitHubAppCredential,
  mintInstallationToken,
  parsePrivateKey,
  resolveInstallation,
  resolvePrivateKey,
  revokeInstallationToken,
  type GitHubAppCredential,
} from '../src/providers/github-app';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const cred: GitHubAppCredential = { type: 'github_app', appId: '123456', installationId: '1', keySource: 'stored', privateKey: PEM };

describe('GitHub App credentials', () => {
  it('signs an RS256 App JWT GitHub can verify (iss = App ID, ≤10 min lifetime)', () => {
    const jwt = createAppJwt('123456', parsePrivateKey(PEM), Date.parse('2026-11-04T12:00:00Z'));
    const [h, p, sig] = jwt.split('.');
    expect(JSON.parse(Buffer.from(h!, 'base64url').toString())).toEqual({ alg: 'RS256', typ: 'JWT' });
    const claims = JSON.parse(Buffer.from(p!, 'base64url').toString());
    expect(claims.iss).toBe('123456');
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
    expect(createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(sig!, 'base64url'))).toBe(true);
  });

  it('rejects invalid keys and a missing webhook key', () => {
    expect(() => parsePrivateKey('not a key')).toThrow(GitHubAppError);
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    expect(() => parsePrivateKey(ec)).toThrow(/RSA/);
    expect(() => resolvePrivateKey({ ...cred, keySource: 'webhook_env', privateKey: undefined }, undefined)).toThrow(/GITHUB_APP_PRIVATE_KEY/);
  });

  it('maps each operation to the least permission it needs', () => {
    expect(OPERATION_PERMISSIONS['github.issues.create']).toEqual({ issues: 'write' });
    expect(OPERATION_PERMISSIONS['github.issues.list']).toEqual({ issues: 'read' });
    expect(OPERATION_PERMISSIONS['github.contents.read']).toEqual({ contents: 'read' });
    expect(OPERATION_PERMISSIONS['github.repositories.read']).toEqual({ metadata: 'read' });
  });

  it('resolves the (mock) installation', async () => {
    await expect(resolveInstallation('mock', '123456', parsePrivateKey(PEM))).resolves.toEqual({ installationId: '1', account: 'demo-org' });
    await expect(resolveInstallation('mock', '123456', parsePrivateKey(PEM), '999')).rejects.toMatchObject({ code: 'INSTALLATION_NOT_FOUND' });
  });

  it('mints per-request tokens that GitHub (mock) enforces: one repository, one permission, revocable', async () => {
    const key = parsePrivateKey(PEM);
    const read = await mintInstallationToken('mock', cred, key, 'github.issues.list', 'demo-org/demo-repo');
    expect(read).toMatchObject({ repositories: ['demo-org/demo-repo'], permissions: { issues: 'read' } });
    expect(read.token).toMatch(/^ghs_/);
    const call = (op: string, repo: string, token = read.token) => callGitHub('mock', token, { operation: op, resource: { repository: repo }, input: { title: 'x' } });

    expect((await call('github.issues.list', 'demo-org/demo-repo')).upstreamStatus).toBe(200);
    expect((await call('github.issues.create', 'demo-org/demo-repo')).upstreamStatus).toBe(403); // read token cannot write
    expect((await call('github.issues.list', 'demo-org/other-repo')).upstreamStatus).toBe(404); // other repositories are invisible

    expect(await revokeInstallationToken('mock', read.token)).toBe(true);
    expect((await call('github.issues.list', 'demo-org/demo-repo')).upstreamStatus).toBe(401); // revoked after use
  });

  it('recognises stored App credentials', () => {
    expect(isGitHubAppCredential(JSON.stringify(cred))).toBe(true);
    expect(isGitHubAppCredential('ghp_abcdefghijklmnopqrstuvwxyz')).toBe(false);
  });
});
