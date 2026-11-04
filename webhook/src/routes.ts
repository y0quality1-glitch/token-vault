import express, { Router, type Request, type Response, type NextFunction } from 'express';
import { config } from './config';
import { NonceCache, hmacHex, signResponse, verifySignedRequest } from './security/signature';
import * as store from './store/credential-store';
import { SUPPORTED_OPERATIONS, callGitHub } from './providers/github';

const nonces = new NonceCache(config.maxClockSkewMs * 2);
const startedAt = Date.now();

interface SignedRequest extends Request {
  rawBody?: Buffer;
  tvNonce?: string;
  json?: any;
}

/** Every internal endpoint requires a valid control-plane signature. No unauthenticated secret retrieval exists. */
function requireSignature(req: SignedRequest, res: Response, next: NextFunction) {
  const raw = req.rawBody ?? Buffer.alloc(0);
  const result = verifySignedRequest({
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
  r.get('/internal/v1/health', requireSignature, (req: SignedRequest, res) => {
    const challenge = str(req.query.challenge, 128);
    signedJson(req, res, 200, {
      status: 'ok',
      instance_id: config.instanceId,
      version: config.version,
      github_mode: config.githubMode,
      uptime_s: Math.round((Date.now() - startedAt) / 1000),
      credentials_stored: store.count(),
      challenge_response: hmacHex(config.signingSecret, `health:${challenge}:${config.instanceId}`),
    });
  });

  // Register a credential. The secret is encrypted immediately and only a reference is returned.
  r.post('/internal/v1/credentials', requireSignature, (req: SignedRequest, res) => {
    const { org_id, provider, secret, metadata } = req.json ?? {};
    if (!str(org_id) || provider !== 'github' || typeof secret !== 'string' || secret.length < 20 || secret.length > 512) {
      return signedJson(req, res, 400, { error: { code: 'INVALID_CREDENTIAL_REQUEST', message: 'org_id, provider=github and a 20-512 character secret are required' } });
    }
    const safeMeta: Record<string, string> = {};
    for (const [k, v] of Object.entries(metadata ?? {})) if (typeof v === 'string') safeMeta[k.slice(0, 40)] = v.slice(0, 200);
    const rec = store.createCredential(org_id, provider, secret, safeMeta);
    console.log(`[vault] stored credential ${rec.credentialRef} provider=${provider} (encrypted, AES-256-GCM)`);
    signedJson(req, res, 201, store.publicView(rec));
  });

  r.post('/internal/v1/credentials/:ref/rotate', requireSignature, (req: SignedRequest, res) => {
    const { org_id, secret } = req.json ?? {};
    if (typeof secret !== 'string' || secret.length < 20 || secret.length > 512) {
      return signedJson(req, res, 400, { error: { code: 'INVALID_CREDENTIAL_REQUEST', message: 'A 20-512 character secret is required' } });
    }
    const rec = store.rotateCredential(String(req.params.ref), str(org_id), secret);
    if (!rec) return signedJson(req, res, 404, { error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Unknown credential reference' } });
    console.log(`[vault] rotated credential ${rec.credentialRef}`);
    signedJson(req, res, 200, store.publicView(rec));
  });

  r.post('/internal/v1/credentials/:ref/test', requireSignature, async (req: SignedRequest, res) => {
    const rec = store.get(String(req.params.ref), str(req.json?.org_id));
    if (!rec) return signedJson(req, res, 404, { error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Unknown credential reference' } });
    const result = await store.withSecret(rec, (token) => callGitHub(config.githubMode, token, { operation: 'credential.test', resource: {}, input: {} }));
    signedJson(req, res, 200, { valid: result.upstreamStatus === 200, upstream_status: result.upstreamStatus, simulated: result.simulated, ...store.publicView(rec) });
  });

  r.post('/internal/v1/credentials/:ref/delete', requireSignature, (req: SignedRequest, res) => {
    const ok = store.deleteCredential(String(req.params.ref), str(req.json?.org_id));
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
    if (!SUPPORTED_OPERATIONS.includes(claims.operation)) return signedJson(req, res, 400, { error: { code: 'UNSUPPORTED_OPERATION', message: 'This webhook does not execute that operation' } });

    const rec = store.get(str(claims.credential_ref), str(claims.org_id));
    if (!rec) return signedJson(req, res, 404, { error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Credential reference cannot be resolved' } });
    if (rec.status !== 'ACTIVE') return signedJson(req, res, 409, { error: { code: 'CREDENTIAL_DISABLED', message: 'Credential is disabled' } });

    try {
      const result = await store.withSecret(rec, (token) =>
        callGitHub(config.githubMode, token, { operation: claims.operation, resource: claims.resource ?? {}, input: claims.input ?? {} }),
      );
      console.log(`[vault] execute ${claims.request_id} op=${claims.operation} ref=${rec.credentialRef} upstream=${result.upstreamStatus}`);
      signedJson(req, res, 200, {
        request_id: claims.request_id,
        upstream_status: result.upstreamStatus,
        simulated: result.simulated,
        result: result.body,
        duration_ms: Date.now() - started,
      });
    } catch (e) {
      console.warn(`[vault] execute ${claims.request_id} failed: ${(e as Error).name}`);
      signedJson(req, res, 502, { error: { code: 'UPSTREAM_UNREACHABLE', message: 'Upstream provider could not be reached' } });
    }
  });

  return r;
}
