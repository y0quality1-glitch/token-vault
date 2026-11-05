import express, { Router, type Request, type Response, type NextFunction } from 'express';
import { config } from './config';
import { describeError } from './db/client';
import { PgNonceStore } from './security/nonce-store';
import { hmacHex, signResponse, verifySignedRequest } from './security/signature';
import * as store from './store/credential-store';
import { createHash } from 'node:crypto';
import type { AuthMethodDefinition, ProviderDefinition } from '@token-vault/shared';
import { ExecutionError, executeOperation, getExecutableOperation, injectionFor, testCredential, type ProviderCall, type ProviderResult } from './providers/executor';
import * as app from './providers/github-app';
import { catalogSync, registry } from './providers/registry';

// Shared across instances via PostgreSQL: a replayed request is rejected by any instance.
const nonces = new PgNonceStore(config.maxClockSkewMs * 2);
const startedAt = Date.now();

interface SignedRequest extends Request {
  rawBody?: Buffer;
  tvNonce?: string;
  json?: any;
}

/** Every internal endpoint requires a valid control-plane signature. No unauthenticated secret retrieval exists. */
async function requireSignature(req: SignedRequest, res: Response, next: NextFunction) {
  const raw = req.rawBody ?? Buffer.alloc(0);
  const result = await verifySignedRequest({
    secret: config.signingSecret,
    method: req.method,
    path: req.originalUrl,
    body: raw,
    headers: req.headers,
    nonces,
    maxSkewMs: config.maxClockSkewMs,
  });
  if (!result.ok) {
    console.warn(`[vault] rejected ${req.method} ${req.path}: ${result.reason}`);
    res.status(401).json({ error: { code: 'SIGNATURE_INVALID', message: result.reason } });
    return;
  }
  req.tvNonce = result.nonce;
  try {
    req.json = raw.length ? JSON.parse(raw.toString('utf8')) : {};
  } catch {
    res.status(400).json({ error: { code: 'BAD_JSON', message: 'Body is not valid JSON' } });
    return;
  }
  next();
}

/** Signs the response body so the control plane can verify it came from this webhook. */
function signedJson(req: SignedRequest, res: Response, status: number, body: unknown) {
  const text = JSON.stringify(body);
  res.status(status).set('x-tv-response-signature', signResponse(config.signingSecret, req.tvNonce ?? '', text)).type('application/json').send(text);
}

/** Maps credential-use failures to signed, non-revealing responses. */
function credentialFailure(req: SignedRequest, res: Response, e: unknown, context: string) {
  if (e instanceof store.CredentialUnreadableError) {
    console.warn(`[vault] ${context}: credential ${e.credentialRef} cannot be decrypted with the configured key`);
    return signedJson(req, res, 500, { error: { code: 'CREDENTIAL_UNREADABLE', message: 'The stored credential cannot be decrypted by this webhook; rotate it or restore the original key' } });
  }
  console.warn(`[vault] ${context} failed: ${(e as Error).name}`);
  return signedJson(req, res, 502, { error: { code: 'UPSTREAM_UNREACHABLE', message: 'Upstream provider could not be reached' } });
}

/** Non-secret description of the credential actually used, for the control plane and audit. */
export interface CredentialUse {
  type: 'github_app_installation_token';
  repositories: string[];
  permissions: Record<string, string>;
  expires_at: string;
  revoked: boolean;
}

/** The definition's auth method a stored (non-plugin) secret is used with. */
function secretAuthMethod(def: ProviderDefinition, metadata: Record<string, string>): AuthMethodDefinition {
  const methods = def.auth.filter((a) => a.kind !== 'plugin');
  const chosen = methods.find((a) => a.id === metadata.auth_method) ?? methods[0];
  if (!chosen) throw new ExecutionError('UNSUPPORTED_OPERATION', `${def.name} has no secret-based auth method`);
  return chosen;
}

function definitionFor(provider: string): ProviderDefinition {
  const def = registry.get(provider);
  if (!def) throw new ExecutionError('UNSUPPORTED_OPERATION', `No provider definition for "${provider}"`);
  return def;
}

/**
 * Runs one upstream call (or a credential test) with a stored credential, through the
 * generic executor. A plain secret is injected as the definition's auth method says.
 * A GitHub App credential mints an installation token narrowed to this call's
 * repository and the operation's declared permissions, uses it once and revokes it.
 */
async function runWithCredential(rec: store.CredentialRecord, secret: string, call: ProviderCall): Promise<ProviderResult & { credential?: CredentialUse }> {
  const def = definitionFor(rec.provider);
  const isTest = call.operation === 'credential.test';
  if (!app.isGitHubAppCredential(secret)) {
    const method = secretAuthMethod(def, rec.metadata);
    const auth = injectionFor(method, secret);
    return isTest ? testCredential(config.githubMode, def, method, auth) : executeOperation(config.githubMode, def, call, auth);
  }
  const method = def.auth.find((a) => a.kind === 'plugin' && a.plugin === 'github_app');
  if (!method) throw new ExecutionError('UNSUPPORTED_OPERATION', `${def.name} does not support GitHub App credentials`);
  const permissions = isTest ? app.TEST_PERMISSIONS : getExecutableOperation(def, call.operation).providerPermissions;
  const cred = JSON.parse(secret) as app.GitHubAppCredential;
  const key = app.resolvePrivateKey(cred, config.githubAppPrivateKey);
  const repository = call.resource[def.resource.name];
  const minted = await app.mintInstallationToken(config.githubMode, cred, key, permissions, repository);
  try {
    const auth = { kind: 'bearer' as const, secret: minted.token };
    const result = isTest ? await testCredential(config.githubMode, def, method, auth) : await executeOperation(config.githubMode, def, call, auth);
    const revoked = await app.revokeInstallationToken(config.githubMode, minted.token);
    return { ...result, credential: { type: 'github_app_installation_token', repositories: minted.repositories, permissions: minted.permissions, expires_at: minted.expiresAt, revoked } };
  } catch (e) {
    await app.revokeInstallationToken(config.githubMode, minted.token);
    throw e;
  }
}

/** Execution errors raised before or around the upstream call (never contain secrets). */
function executionFailure(req: SignedRequest, res: Response, e: ExecutionError) {
  console.warn(`[vault] execution refused: ${e.code}`);
  const status = e.code === 'UNSUPPORTED_OPERATION' || e.code === 'INVALID_REQUEST' ? 400 : 502;
  return signedJson(req, res, status, { error: { code: e.code, message: e.message } });
}

/** Validates a GitHub App registration request and resolves its installation. */
async function prepareAppCredential(body: any): Promise<app.GitHubAppCredential> {
  const appId = String(body?.app_id ?? '');
  if (!/^\d{1,12}$/.test(appId)) throw new app.GitHubAppError('APP_AUTH_FAILED', 'app_id must be the numeric GitHub App ID');
  const keySource = body?.key_source === 'webhook_env' ? 'webhook_env' : 'stored';
  const installationId = body?.installation_id ? String(body.installation_id) : undefined;
  if (installationId && !/^\d{1,15}$/.test(installationId)) throw new app.GitHubAppError('INSTALLATION_NOT_FOUND', 'installation_id must be numeric');
  const cred: app.GitHubAppCredential = { type: 'github_app', appId, installationId: installationId ?? '', keySource, ...(keySource === 'stored' ? { privateKey: String(body?.private_key ?? '') } : {}) };
  const key = app.resolvePrivateKey(cred, config.githubAppPrivateKey);
  const found = await app.resolveInstallation(config.githubMode, appId, key, installationId);
  return { ...cred, installationId: found.installationId, account: found.account };
}

function appFailure(req: SignedRequest, res: Response, e: unknown) {
  if (e instanceof app.GitHubAppError) {
    console.warn(`[vault] GitHub App: ${e.code}`);
    return signedJson(req, res, e.code === 'TOKEN_MINT_FAILED' || e.code === 'APP_AUTH_FAILED' ? 502 : 400, { error: { code: e.code, message: e.message } });
  }
  return credentialFailure(req, res, e, 'github app');
}

function validSecret(method: AuthMethodDefinition, secret: unknown): secret is string {
  if (typeof secret !== 'string' || secret.length < 8 || secret.length > 4096) return false;
  return method.secretPattern ? new RegExp(method.secretPattern).test(secret) : true;
}

function stringRecord(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) if (typeof x === 'string') out[k] = x;
  return out;
}

function str(v: unknown, max = 200): string {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

export function buildRouter() {
  const r = Router();
  r.use(express.raw({ type: '*/*', limit: '64kb' }), (req: SignedRequest, _res, next) => {
    req.rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    next();
  });

  // Signed health check / identity challenge.
  r.get('/internal/v1/health', requireSignature, async (req: SignedRequest, res) => {
    const challenge = str(req.query.challenge, 128);
    signedJson(req, res, 200, {
      status: 'ok',
      instance_id: config.instanceId,
      version: config.version,
      github_mode: config.githubMode,
      uptime_s: Math.round((Date.now() - startedAt) / 1000),
      credentials_stored: await store.countCredentials(),
      providers: registry.list().map((e) => ({ key: e.definition.key, version: e.definition.version, source: e.source, digest: (e.digest ?? createHash('sha256').update(JSON.stringify(e.definition)).digest('hex')).slice(0, 16) })),
      catalog: catalogSync ? { key_id: catalogSync.status.keyId, last_success_at: catalogSync.status.lastSuccessAt, last_error: catalogSync.status.lastError, restored_from: catalogSync.status.restored?.savedAt ?? null } : null,
      challenge_response: hmacHex(config.signingSecret, `health:${challenge}:${config.instanceId}`),
    });
  });

  // Register a credential: a PAT (encrypted immediately) or a GitHub App (App ID + private key).
  r.post('/internal/v1/credentials', requireSignature, async (req: SignedRequest, res) => {
    const { org_id, provider, secret, metadata, type } = req.json ?? {};
    const def = typeof provider === 'string' ? registry.get(provider) : undefined;
    if (!str(org_id) || !def) {
      return signedJson(req, res, 400, { error: { code: 'INVALID_CREDENTIAL_REQUEST', message: 'org_id and a known provider are required' } });
    }
    const safeMeta: Record<string, string> = {};
    for (const [k, v] of Object.entries(metadata ?? {})) if (typeof v === 'string') safeMeta[k.slice(0, 40)] = v.slice(0, 200);

    if (type === 'github_app') {
      if (!def.auth.some((a) => a.plugin === 'github_app')) return signedJson(req, res, 400, { error: { code: 'INVALID_CREDENTIAL_REQUEST', message: `${def.name} does not support GitHub App credentials` } });
      try {
        const cred = await prepareAppCredential(req.json);
        const rec = await store.createCredential(org_id, provider, JSON.stringify(cred), { ...safeMeta, auth: 'github_app', app_id: cred.appId, installation_id: cred.installationId, account: cred.account ?? '', key_source: cred.keySource }, app.maskApp(cred));
        console.log(`[vault] stored GitHub App credential ${rec.credentialRef} app=${cred.appId} installation=${cred.installationId} key=${cred.keySource}`);
        return signedJson(req, res, 201, { ...store.publicView(rec), auth_type: 'GITHUB_APP', app_id: cred.appId, installation_id: cred.installationId, account: cred.account ?? null });
      } catch (e) {
        return appFailure(req, res, e);
      }
    }

    const method = def.auth.find((a) => a.kind !== 'plugin' && (!req.json?.auth_method || a.id === req.json.auth_method));
    if (!method) return signedJson(req, res, 400, { error: { code: 'INVALID_CREDENTIAL_REQUEST', message: 'Unknown auth method for this provider' } });
    if (!validSecret(method, secret)) {
      return signedJson(req, res, 400, { error: { code: 'INVALID_CREDENTIAL_REQUEST', message: method.secretHint ? `Invalid secret: ${method.secretHint}` : 'A 20-512 character secret is required' } });
    }
    const rec = await store.createCredential(org_id, provider, secret, { ...safeMeta, auth: method.id === 'PAT' ? 'pat' : method.id.toLowerCase(), auth_method: method.id });
    console.log(`[vault] stored credential ${rec.credentialRef} provider=${provider} (encrypted, AES-256-GCM)`);
    signedJson(req, res, 201, { ...store.publicView(rec), auth_type: 'PAT' });
  });

  r.post('/internal/v1/credentials/:ref/rotate', requireSignature, async (req: SignedRequest, res) => {
    const { org_id, secret, private_key } = req.json ?? {};
    const existing = await store.get(String(req.params.ref), str(org_id));
    if (!existing) return signedJson(req, res, 404, { error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Unknown credential reference' } });
    try {
      const current = await store.withSecret(existing, async (s) => s);
      if (app.isGitHubAppCredential(current)) {
        const cred = JSON.parse(current) as app.GitHubAppCredential;
        if (cred.keySource === 'webhook_env') {
          return signedJson(req, res, 400, { error: { code: 'KEY_MANAGED_BY_WEBHOOK', message: 'This App key lives in the webhook environment (GITHUB_APP_PRIVATE_KEY); rotate it there.' } });
        }
        const key = app.parsePrivateKey(String(private_key ?? ''));
        await app.resolveInstallation(config.githubMode, cred.appId, key, cred.installationId); // the new key must work
        const next: app.GitHubAppCredential = { ...cred, privateKey: String(private_key) };
        const rec = await store.rotateCredential(existing.credentialRef, str(org_id), JSON.stringify(next), app.maskApp(next));
        console.log(`[vault] rotated GitHub App key for ${existing.credentialRef}`);
        return signedJson(req, res, 200, store.publicView(rec!));
      }
    } catch (e) {
      if (e instanceof app.GitHubAppError) return appFailure(req, res, e);
      return credentialFailure(req, res, e, `rotate ${existing.credentialRef}`);
    }
    const def = registry.get(existing.provider);
    if (!def || !validSecret(secretAuthMethod(def, existing.metadata), secret)) {
      return signedJson(req, res, 400, { error: { code: 'INVALID_CREDENTIAL_REQUEST', message: 'A 20-512 character secret is required' } });
    }
    const rec = await store.rotateCredential(existing.credentialRef, str(org_id), secret);
    console.log(`[vault] rotated credential ${existing.credentialRef}`);
    signedJson(req, res, 200, store.publicView(rec!));
  });

  r.post('/internal/v1/credentials/:ref/test', requireSignature, async (req: SignedRequest, res) => {
    const rec = await store.get(String(req.params.ref), str(req.json?.org_id));
    if (!rec) return signedJson(req, res, 404, { error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Unknown credential reference' } });
    try {
      const result = await store.withSecret(rec, (secret) => runWithCredential(rec, secret, { operation: 'credential.test', resource: {}, input: {} }));
      signedJson(req, res, 200, { valid: result.upstreamStatus === 200, upstream_status: result.upstreamStatus, simulated: result.simulated, ...store.publicView(rec) });
    } catch (e) {
      if (e instanceof app.GitHubAppError || e instanceof ExecutionError) {
        return signedJson(req, res, 200, { valid: false, upstream_status: e instanceof app.GitHubAppError ? e.upstreamStatus : null, simulated: config.githubMode === 'mock', error_code: e.code, ...store.publicView(rec) });
      }
      credentialFailure(req, res, e, `test ${rec.credentialRef}`);
    }
  });

  r.post('/internal/v1/credentials/:ref/delete', requireSignature, async (req: SignedRequest, res) => {
    const ok = await store.deleteCredential(String(req.params.ref), str(req.json?.org_id));
    signedJson(req, res, ok ? 200 : 404, { deleted: ok });
  });

  // Execute a brokered operation with credential injection.
  r.post('/internal/v1/execute', requireSignature, async (req: SignedRequest, res) => {
    const started = Date.now();
    const claims = req.json ?? {};
    // Validate the short-lived execution claims (defense in depth on top of the HMAC).
    if (claims.aud !== config.instanceId) return signedJson(req, res, 401, { error: { code: 'AUDIENCE_MISMATCH', message: 'Execution request not addressed to this webhook' } });
    if (typeof claims.exp !== 'number' || claims.exp < Date.now()) return signedJson(req, res, 401, { error: { code: 'EXECUTION_EXPIRED', message: 'Execution request expired' } });
    if (typeof claims.iat !== 'number' || claims.exp - claims.iat > config.maxExecutionTtlMs) return signedJson(req, res, 401, { error: { code: 'EXECUTION_TTL_TOO_LONG', message: 'Execution request validity window too long' } });

    const rec = await store.get(str(claims.credential_ref), str(claims.org_id));
    if (!rec) return signedJson(req, res, 404, { error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Credential reference cannot be resolved' } });
    if (rec.status !== 'ACTIVE') return signedJson(req, res, 409, { error: { code: 'CREDENTIAL_DISABLED', message: 'Credential is disabled' } });
    // The operation must belong to the credential's provider definition (a GitHub token is never used for another provider's call).
    const known = () => registry.get(rec.provider)?.operations.some((o) => o.id === claims.operation && o.risk !== 'destructive');
    // The control plane may have seen a newer catalog: refresh once before refusing.
    if (typeof claims.operation === 'string' && !known() && catalogSync) await catalogSync.refresh();
    if (typeof claims.operation !== 'string' || !known()) {
      return signedJson(req, res, 400, { error: { code: 'UNSUPPORTED_OPERATION', message: 'This webhook does not execute that operation' } });
    }

    try {
      const result = await store.withSecret(rec, (secret) =>
        runWithCredential(rec, secret, { operation: claims.operation, resource: stringRecord(claims.resource), input: claims.input && typeof claims.input === 'object' ? claims.input : {} }),
      );
      console.log(`[vault] execute ${claims.request_id} op=${claims.operation} ref=${rec.credentialRef} upstream=${result.upstreamStatus}${result.credential ? ' (minted App token, revoked)' : ''}`);
      signedJson(req, res, 200, {
        request_id: claims.request_id,
        upstream_status: result.upstreamStatus,
        simulated: result.simulated,
        result: result.body,
        duration_ms: Date.now() - started,
        ...(result.credential ? { credential: result.credential } : {}),
      });
    } catch (e) {
      if (e instanceof app.GitHubAppError) return appFailure(req, res, e);
      if (e instanceof ExecutionError) return executionFailure(req, res, e);
      credentialFailure(req, res, e, `execute ${claims.request_id}`);
    }
  });

  // Database or other unexpected errors: generic, unsigned 500 without internals.
  r.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    console.error('[vault] unhandled error:', describeError(err));
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Webhook internal error' } });
  });

  return r;
}
