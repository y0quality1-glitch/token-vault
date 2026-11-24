import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { BUILTIN_SECRET_TYPES, summarizeSecretPayload, validateSecretPayload, validateSecretTypeDefinition, type CertificateInfo, type SecretPayload, type SecretTypeDefinition } from '@token-vault/shared';

/**
 * Secret Management phase 6 against a real PostgreSQL database: certificates (expiry and metadata
 * from the certificate, renewal requests completed by an upload or a CA secret, cancelled or
 * expired), and keys used through the agent API without being read (grants that only allow
 * operations, usage policies, deactivated versions, approvals bound to the input). The customer
 * webhook is an in-memory stand-in; its cryptography is tested in the webhook's own suite.
 * Skipped unless TEST_DATABASE_URL is set. The database is reseeded.
 */
const url = process.env.TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;

const vault = vi.hoisted(() => ({
  values: new Map<string, { org: string; secret: string; version: number; type: string; payload: Record<string, unknown> }>(),
  calls: [] as { path: string; body: Record<string, any> }[],
  /** What the next certificate stored "says". */
  cert: null as null | object,
}));
vi.mock('../src/services/webhookService/webhook.client', async (orig) => {
  const real = await orig<typeof import('../src/services/webhookService/webhook.client')>();
  const types = new Map<string, SecretTypeDefinition>(BUILTIN_SECRET_TYPES.map((t) => [t.key, validateSecretTypeDefinition(t)]));
  let n = 0;
  const fp = (p: unknown) => `fp_${createHash('sha256').update(JSON.stringify(p)).digest('hex').slice(0, 16)}`;
  const isCert = (k: string) => ['tls-certificate', 'ca-certificate', 'pkcs12'].includes(k);
  const put = (v: { org: string; secret: string; version: number; type: string; payload: Record<string, unknown> }, extra = {}) => {
    const ref = `sval_${++n}`;
    vault.values.set(ref, v);
    const type = types.get(v.type);
    return { status: 201, latencyMs: 1, body: { value_ref: ref, version: v.version, fingerprint: fp(v.payload), summary: type ? summarizeSecretPayload(type, v.payload as SecretPayload) : {}, type_version: type?.version ?? 1, ...(type && isCert(type.key) ? { certificate: vault.cert } : {}), ...extra } };
  };
  const err = (status: number, code: string, message = code) => ({ status, latencyMs: 1, body: { error: { code, message } } });
  return {
    ...real,
    callWebhook: async (_wh: unknown, _method: string, path: string, body: Record<string, any>) => {
      vault.calls.push({ path, body });
      if (path === '/internal/v1/secrets/store') {
        const type = types.get(body.type_key)!;
        const { issues, value } = validateSecretPayload(type, body.payload);
        if (Object.keys(issues).length) return { status: 400, latencyMs: 1, body: { error: { code: 'SECRET_INVALID', details: { fields: issues } } } };
        return put({ org: body.org_id, secret: body.secret_id, version: body.version, type: type.key, payload: value });
      }
      if (path === '/internal/v1/secrets/destroy') {
        const destroyed = (body.value_refs as string[]).filter((r) => vault.values.get(r)?.secret === body.secret_id && vault.values.delete(r));
        return { status: 200, latencyMs: 1, body: { destroyed } };
      }
      if (path === '/internal/v1/secrets/certificate/complete') {
        const pending = vault.values.get(body.request_ref);
        if (!pending || pending.secret !== body.request_id) return err(404, 'CERTIFICATE_REQUEST_NOT_FOUND');
        if (body.issuer && vault.values.get(body.issuer.value_ref)?.type !== 'ca-certificate') return err(409, 'CERTIFICATE_ISSUER_INVALID');
        if (body.certificate === 'not for this key') return { status: 400, latencyMs: 1, body: { error: { code: 'CERTIFICATE_KEY_MISMATCH', message: 'This certificate is not for the key of this request', details: { fields: { certificate: 'Not for this request’s key' } } } } };
        vault.values.delete(body.request_ref);
        return put({ org: body.org_id, secret: body.secret_id, version: body.version, type: body.type_key, payload: { certificate: body.certificate ?? 'issued', privateKey: pending.payload.privateKey } }, { issued: !!body.issuer });
      }
      const v = vault.values.get(body.value_ref ?? body.from_ref);
      if (!v || v.org !== body.org_id || v.secret !== body.secret_id) return err(404, 'SECRET_VALUE_NOT_FOUND');
      switch (path) {
        case '/internal/v1/secrets/read':
          return { status: 200, latencyMs: 1, body: { version: v.version, payload: v.payload } };
        case '/internal/v1/secrets/certificate/request': {
          const r = put({ org: body.org_id, secret: body.request_id, version: 1, type: 'certificate-request', payload: { privateKey: 'new-key', csr: 'csr' } });
          return { status: 201, latencyMs: 1, body: { request_ref: r.body.value_ref, csr: '-----BEGIN CERTIFICATE REQUEST-----\nTUlJ\n-----END CERTIFICATE REQUEST-----\n', subject: 'CN=api.example.test', subject_alt_names: ['DNS:api.example.test'], key_algorithm: body.key_algorithm ?? 'EC-P256' } };
        }
        case '/internal/v1/secrets/key': {
          if (body.version !== v.version) return err(409, 'INVALID_KEY_REQUEST');
          const alg = body.algorithm ?? 'ES256';
          if (body.operation === 'sign') return { status: 200, latencyMs: 1, body: { algorithm: alg, signature: Buffer.from(`sig:${v.version}:${body.data}`).toString('base64') } };
          if (body.operation === 'verify') return { status: 200, latencyMs: 1, body: { algorithm: alg, valid: body.signature === Buffer.from(`sig:${v.version}:${body.data}`).toString('base64') } };
          if (body.operation === 'encrypt') return { status: 200, latencyMs: 1, body: { algorithm: 'A256GCM', ciphertext: `tv:v${v.version}:${body.data}` } };
          if (body.operation === 'decrypt') return { status: 200, latencyMs: 1, body: { algorithm: 'A256GCM', plaintext: String(body.ciphertext).split(':')[2] } };
          return { status: 200, latencyMs: 1, body: { algorithm: body.algorithm ?? 'HS256', mac: 'bWFj' } };
        }
        default:
          return err(404, 'NOT_FOUND');
      }
    },
  };
});

const DAY = 86_400_000;
const certInfo = (cn: string, days: number, extra: Partial<CertificateInfo> = {}): CertificateInfo => ({
  subject: `CN=${cn}`,
  commonName: cn,
  issuer: 'CN=Test CA',
  serialNumber: randomBytes(8).toString('hex').toUpperCase(),
  notBefore: new Date(Date.now() - DAY).toISOString(),
  notAfter: new Date(Math.floor((Date.now() + days * DAY) / 1000) * 1000).toISOString(),
  subjectAltNames: [`DNS:${cn}`],
  fingerprintSha256: 'AA:BB',
  publicKey: 'EC P-256',
  isCA: false,
  selfSigned: false,
  privateKey: 'matches',
  chain: [],
  chainValid: null,
  ...extra,
});
const PEM_CERT = '-----BEGIN CERTIFICATE-----\nTUlJQ2Vy\n-----END CERTIFICATE-----';
const PEM_KEY = '-----BEGIN PRIVATE KEY-----\nTUlJRXZn\n-----END PRIVATE KEY-----';

suite('Keys and certificates: certificate expiry and renewal, key operations without reading the key', () => {
  let m: {
    client: typeof import('../src/databases/client');
    seed: typeof import('../src/store/seed');
    repos: typeof import('../src/store/repos');
    crypto: typeof import('../src/lib/crypto');
    entities: typeof import('../src/entities');
    job: typeof import('../src/services/secretService/secretLifecycle.job');
    secrets: InstanceType<typeof import('../src/services/secretService/secretService.service').default>;
    access: InstanceType<typeof import('../src/services/secretAccessService/secretAccessService.service').default>;
  };
  let owner: any;
  let security: any;
  let agentId = '';
  let agentKey = '';
  const auth = () => `Bearer ${agentKey}`;
  const keyOp = (operation: string, body: Record<string, unknown>) => m.access.agentKeyOperation({ authorization: auth(), sourceIp: '127.0.0.1', operation, body });
  const events = async (targetId: string) => ((await m.client.db.find(m.entities.AuditEventEntity, { where: { targetId }, order: { createdAt: 'ASC' } })) as any[]).map((e) => e.eventType);

  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.WEBHOOK_SIGNING_SECRET ??= randomBytes(32).toString('base64url');
    process.env.AUDIT_SIGNING_KEY ??= randomBytes(32).toString('base64url');
    process.env.DB_POOL_MAX = '4';
    process.env.CMS_CATALOG_URL = '';
    m = {
      client: await import('../src/databases/client'),
      seed: await import('../src/store/seed'),
      repos: await import('../src/store/repos'),
      crypto: await import('../src/lib/crypto'),
      entities: await import('../src/entities'),
      job: await import('../src/services/secretService/secretLifecycle.job'),
      secrets: new (await import('../src/services/secretService/secretService.service')).default(),
      access: new (await import('../src/services/secretAccessService/secretAccessService.service')).default(),
    };
    await m.client.runMigrations();
    await m.seed.resetDatabase();
    agentId = m.seed.IDS.agtAssistant;
    const cred = m.crypto.generateAgentCredential();
    await m.repos.agentRepo.updateAgent(agentId, { credentialKeyId: cred.keyId, credentialHash: cred.hash });
    agentKey = cred.apiKey;
    owner = { user: { id: m.seed.IDS.owner, fullName: 'Avery Chen' }, org: { id: m.seed.IDS.demoOrg, name: 'Demo Organization' }, role: 'OWNER' };
    const sec = (await m.client.db.query(`SELECT u.id, u.full_name FROM users u JOIN organization_members om ON om.user_id = u.id WHERE om.organization_id = $1 AND om.role = 'SECURITY_ADMIN' LIMIT 1`, [m.seed.IDS.demoOrg]))[0];
    security = { user: { id: sec.id, fullName: sec.full_name }, org: owner.org, role: 'SECURITY_ADMIN' };
  }, 60_000);
  beforeEach(() => {
    vault.cert = null;
  });
  afterAll(async () => {
    await m?.client.closeDatabase();
  });

  it('a certificate sets its secret’s expiry and searchable metadata; the expiry cannot be moved past it', async () => {
    vault.cert = certInfo('api.example.test', 20);
    const s = await m.secrets.create(owner, { name: 'api-tls', typeKey: 'tls-certificate', environment: 'production', project: 'web', payload: { certificate: PEM_CERT, privateKey: PEM_KEY } } as any);
    expect(s.expiresAt).toBe((vault.cert as any).notAfter);
    // Within the type's 30-day warning window.
    expect(s.status).toBe('EXPIRING');
    expect(s.metadata).toMatchObject({ commonName: 'api.example.test', issuer: 'CN=Test CA', notAfter: (vault.cert as any).notAfter });
    expect(s.certificate).toMatchObject({ commonName: 'api.example.test', privateKey: 'matches' });
    expect(s.versions[0]!.certificate).toMatchObject({ serialNumber: (vault.cert as any).serialNumber });
    expect(s.key).toBeNull();
    await expect(m.secrets.updateMetadata(owner, { id: s.id, name: 'api-tls', expiresAt: new Date(Date.now() + 60 * DAY).toISOString() } as any)).rejects.toMatchObject({ details: { fields: { expiresAt: expect.stringContaining('certificate is valid until') } } });
    // An earlier expiry is fine.
    expect((await m.secrets.updateMetadata(owner, { id: s.id, name: 'api-tls', expiresAt: new Date(Date.now() + 10 * DAY).toISOString() } as any)).expiresAt).not.toBe((vault.cert as any).notAfter);
    const found = await m.secrets.list(owner.org.id, { search: 'api-tls' });
    expect(found.items[0]).toMatchObject({ certificate: { commonName: 'api.example.test' } });
  });

  it('renewal: one request at a time; completed with the CA’s certificate, the new one sets the expiry; cancel and expiry destroy the waiting key', async () => {
    vault.cert = certInfo('svc.example.test', 5);
    const s = await m.secrets.create(owner, { name: 'svc-tls', typeKey: 'tls-certificate', environment: 'production', project: 'web', payload: { certificate: PEM_CERT, privateKey: PEM_KEY } } as any);
    const r = await m.secrets.requestCertificate(owner, { id: s.id, keyAlgorithm: 'EC-P384' } as any);
    expect(r).toMatchObject({ status: 'PENDING', keyAlgorithm: 'EC-P384', subject: 'CN=api.example.test', csr: expect.stringContaining('CERTIFICATE REQUEST') });
    await expect(m.secrets.requestCertificate(owner, { id: s.id } as any)).rejects.toMatchObject({ code: 'CERTIFICATE_REQUEST_PENDING' });
    expect((await m.secrets.detail(owner, s.id)).certificateRequests).toHaveLength(1);

    await expect(m.secrets.completeCertificate(owner, { requestId: r.id, certificate: 'not for this key', reason: '' } as any)).rejects.toMatchObject({ code: 'CERTIFICATE_KEY_MISMATCH', details: { fields: { 'payload.certificate': expect.any(String) } } });
    await expect(m.secrets.completeCertificate(owner, { requestId: r.id, reason: '' } as any)).rejects.toMatchObject({ details: { fields: { certificate: expect.any(String) } } });
    vault.cert = certInfo('svc.example.test', 90);
    const done = await m.secrets.completeCertificate(owner, { requestId: r.id, certificate: PEM_CERT, reason: '' } as any);
    expect(done).toMatchObject({ activeVersion: 2, status: 'ACTIVE', expiresAt: (vault.cert as any).notAfter, certificateRequests: [{ status: 'COMPLETED', completedVersion: 2 }] });
    expect(done.versions.map((v) => v.reason)).toEqual(['Renewed certificate', 'Initial value']);
    expect(await events(s.id)).toEqual(expect.arrayContaining(['secret.certificate_requested', 'secret.certificate_renewed']));
    await expect(m.secrets.completeCertificate(owner, { requestId: r.id, certificate: PEM_CERT, reason: '' } as any)).rejects.toMatchObject({ code: 'CERTIFICATE_REQUEST_NOT_PENDING' });

    // Issued by a CA secret of the organization.
    vault.cert = certInfo('Internal CA', 3650, { isCA: true });
    const ca = await m.secrets.create(owner, { name: 'internal-ca', typeKey: 'ca-certificate', environment: 'production', project: 'pki', payload: { certificate: PEM_CERT, privateKey: PEM_KEY } } as any);
    const r2 = await m.secrets.requestCertificate(owner, { id: s.id } as any);
    vault.cert = certInfo('svc.example.test', 30);
    await expect(m.secrets.completeCertificate(owner, { requestId: r2.id, issuerSecretId: s.id, reason: '' } as any)).rejects.toMatchObject({ code: 'CERTIFICATE_ISSUER_INVALID' });
    const issued = await m.secrets.completeCertificate(owner, { requestId: r2.id, issuerSecretId: ca.id, validityDays: 30, reason: '' } as any);
    expect(issued.certificateRequests[0]).toMatchObject({ status: 'COMPLETED', issuer: { id: ca.id, name: 'internal-ca' } });
    expect(vault.calls.at(-1)!.body).toMatchObject({ issuer: { secret_id: ca.id }, validity_days: 30 });
    expect(await events(ca.id)).toContain('secret.certificate_issued');

    // Cancelled: the waiting key is destroyed on the webhook.
    const r3 = await m.secrets.requestCertificate(owner, { id: s.id } as any);
    const ref3 = (await m.client.db.findOneBy(m.entities.CertificateRequestEntity, { id: r3.id }))!.requestRef!;
    expect(vault.values.has(ref3)).toBe(true);
    expect(await m.secrets.cancelCertificate(owner, { requestId: r3.id, reason: 'wrong CA' } as any)).toMatchObject({ status: 'CANCELLED', cancelledReason: 'wrong CA' });
    expect(vault.values.has(ref3)).toBe(false);

    // Expired: the lifecycle job ends it.
    const r4 = await m.secrets.requestCertificate(owner, { id: s.id } as any);
    await m.client.db.query(`UPDATE certificate_requests SET expires_at = now() - interval '1 second' WHERE id = $1`, [r4.id]);
    const report = await m.job.runSecretLifecycle();
    expect(report?.certificateRequestsExpired).toBe(1);
    expect((await m.client.db.findOneBy(m.entities.CertificateRequestEntity, { id: r4.id }))).toMatchObject({ status: 'EXPIRED', requestRef: null });

    // Other certificate types are not renewed this way.
    await expect(m.secrets.requestCertificate(owner, { id: ca.id } as any)).rejects.toMatchObject({ code: 'CERTIFICATE_NOT_RENEWABLE' });
  });

  it('a grant can allow using a key without reading it; usage policy, grant and version all have to allow it', async () => {
    const s = await m.secrets.create(owner, { name: 'release-signing', typeKey: 'ecc-private-key', environment: 'production', project: 'release', payload: { privateKey: PEM_KEY } } as any);
    expect(s.key).toEqual({ operations: ['sign', 'verify'], supported: ['sign', 'verify'], external: null });
    expect(s.versions[0]!.keyEnabled).toBe(true);
    await expect(m.access.create(owner, { agentId, secretId: s.id, allowRetrieve: false })).rejects.toMatchObject({ details: { fields: { allowRetrieve: expect.any(String) } } });
    await expect(m.access.create(owner, { agentId, secretId: s.id, keyOperations: ['encrypt'] })).rejects.toMatchObject({ details: { fields: { keyOperations: expect.stringContaining('sign, verify') } } });
    const grant = await m.access.create(owner, { agentId, secretId: s.id, allowRetrieve: false, keyOperations: ['sign'] });
    expect(grant).toMatchObject({ allowRetrieve: false, keyOperations: ['sign'] });

    await expect(m.access.agentRetrieve({ authorization: auth(), sourceIp: '127.0.0.1', body: { secret_id: s.id } })).rejects.toMatchObject({ code: 'RETRIEVE_NOT_PERMITTED' });
    expect((await m.access.agentList(auth())).items.find((i) => i.secret_id === s.id)).toMatchObject({ retrieve: false, key_operations: ['sign'] });
    const data = Buffer.from('release 1.2.3').toString('base64');
    const signed = await keyOp('sign', { name: 'release-signing', data, reason: 'release 1.2.3' });
    expect(signed).toMatchObject({ status: 200, body: { secret_id: s.id, operation: 'sign', version: 1, algorithm: 'ES256', signature: expect.any(String), grant_id: grant.id } });
    expect(vault.calls.at(-1)).toMatchObject({ path: '/internal/v1/secrets/key', body: { operation: 'sign', version: 1, data } });
    expect(await events(s.id)).toContain('secret.key_used');
    await expect(keyOp('verify', { secret_id: s.id, data, signature: (signed.body as any).signature })).rejects.toMatchObject({ code: 'KEY_OPERATION_NOT_PERMITTED' });
    await expect(keyOp('encrypt', { secret_id: s.id, data })).rejects.toMatchObject({ code: 'KEY_OPERATION_NOT_SUPPORTED' });
    await expect(keyOp('wrap', { secret_id: s.id, data })).rejects.toMatchObject({ code: 'KEY_OPERATION_UNKNOWN' });

    // Version 2: signing uses it; verifying a version-1 signature names version 1.
    await m.secrets.updateValue(owner, { id: s.id, payload: { privateKey: PEM_KEY }, reason: 'new key' } as any);
    await m.access.create(owner, { agentId, secretId: s.id, allowRetrieve: false, keyOperations: ['verify'] });
    expect((await keyOp('sign', { secret_id: s.id, data })).body).toMatchObject({ version: 2 });
    expect((await keyOp('verify', { secret_id: s.id, data, signature: (signed.body as any).signature, version: 1 })).body).toMatchObject({ version: 1, valid: true });
    expect((await keyOp('verify', { secret_id: s.id, data, signature: (signed.body as any).signature })).body).toMatchObject({ version: 2, valid: false });

    // Deactivating a version stops every use of it.
    await m.secrets.setKeyVersion(owner, { id: s.id, version: 1, reason: 'compromised' } as any, false);
    await expect(keyOp('verify', { secret_id: s.id, data, signature: (signed.body as any).signature, version: 1 })).rejects.toMatchObject({ code: 'KEY_VERSION_DISABLED' });
    expect(await events(s.id)).toContain('secret.key_version_disabled');
    await m.secrets.setKeyVersion(owner, { id: s.id, version: 1, reason: '' } as any, true);
    expect((await keyOp('verify', { secret_id: s.id, data, signature: (signed.body as any).signature, version: 1 })).body).toMatchObject({ valid: true });

    // The key's usage policy wins over grants.
    const narrowed = await m.secrets.updateMetadata(owner, { id: s.id, name: 'release-signing', keyOperations: ['verify'] } as any);
    expect(narrowed.key!.operations).toEqual(['verify']);
    await expect(keyOp('sign', { secret_id: s.id, data })).rejects.toMatchObject({ code: 'KEY_OPERATION_NOT_ALLOWED' });
    await expect(m.secrets.updateMetadata(owner, { id: s.id, name: 'release-signing', keyOperations: ['encrypt'] } as any)).rejects.toMatchObject({ details: { fields: { keyOperations: expect.any(String) } } });
    await expect(m.secrets.setKeyVersion(owner, { id: (await m.secrets.create(owner, { name: 'not-a-key', typeKey: 'api-key', environment: 'production', payload: { apiKey: 'k-123456' } } as any)).id, version: 1, reason: '' } as any, false)).rejects.toMatchObject({ code: 'SECRET_NOT_A_KEY' });
  });

  it('decrypt picks the version its ciphertext names; held operations need an approval for that exact input', async () => {
    const s = await m.secrets.create(owner, { name: 'pii-key', typeKey: 'aes-key', environment: 'production', project: 'data', payload: { key: randomBytes(32).toString('base64') } } as any);
    await m.access.create(owner, { agentId, secretId: s.id, allowRetrieve: false, keyOperations: ['encrypt', 'decrypt'] });
    const ct = (await keyOp('encrypt', { secret_id: s.id, data: 'aGVsbG8=' })).body as any;
    expect(ct.ciphertext).toBe('tv:v1:aGVsbG8=');
    await m.secrets.updateValue(owner, { id: s.id, payload: { key: randomBytes(32).toString('base64') }, reason: 'rotate' } as any);
    expect((await keyOp('decrypt', { secret_id: s.id, ciphertext: ct.ciphertext })).body).toMatchObject({ version: 1, plaintext: 'aGVsbG8=' });
    expect((await keyOp('encrypt', { secret_id: s.id, data: 'aGVsbG8=' })).body).toMatchObject({ version: 2 });
    await expect(keyOp('decrypt', { secret_id: s.id, ciphertext: 'tv:v9:aGVsbG8=' })).rejects.toMatchObject({ code: 'SECRET_VERSION_NOT_FOUND' });
    await expect(keyOp('decrypt', { secret_id: s.id, ciphertext: 'garbage' })).rejects.toMatchObject({ code: 'KEY_INPUT_INVALID' });

    const hmac = await m.secrets.create(owner, { name: 'webhook-mac', typeKey: 'hmac-secret', environment: 'production', project: 'data', payload: { secret: randomBytes(32).toString('base64url') } } as any);
    await m.access.create(owner, { agentId, secretId: hmac.id, allowRetrieve: false, keyOperations: ['mac'], requireApproval: true });
    const held = await keyOp('mac', { secret_id: hmac.id, data: 'cGF5bG9hZA==' });
    expect(held.status).toBe(202);
    const approvalId = (held.body as any).approval_id;
    const pending = (await m.access.listApprovals(owner.org.id, { status: 'PENDING' })).items.find((a) => a.id === approvalId)!;
    expect(pending).toMatchObject({ operation: 'mac', inputDigest: expect.stringMatching(/^[0-9a-f]{64}$/), fields: [] });
    await m.access.decide(security, { id: approvalId }, 'APPROVED');
    await expect(keyOp('mac', { secret_id: hmac.id, data: 'b3RoZXI=', approval_id: approvalId })).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    expect((await keyOp('mac', { secret_id: hmac.id, data: 'cGF5bG9hZA==', approval_id: approvalId })).body).toMatchObject({ operation: 'mac', mac: 'bWFj' });
    await expect(keyOp('mac', { secret_id: hmac.id, data: 'cGF5bG9hZA==', approval_id: approvalId })).rejects.toMatchObject({ code: 'APPROVAL_USED' });
  });
});
