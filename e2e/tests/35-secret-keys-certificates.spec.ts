import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { createPrivateKey, generateKeyPairSync, verify as cryptoVerify, webcrypto, X509Certificate } from 'node:crypto';
import { expect, test, type APIRequestContext } from '@playwright/test';
import { DEMO_PASSWORD, details, login as signIn, trackPageErrors } from './helpers';

/**
 * Secret Management phase 6 through the real stack: certificates read by the customer webhook
 * (expiry and metadata follow the certificate), renewed with a new key and CSR and completed by a
 * CA secret or with an outside CA's certificate; keys an application uses through the agent API
 * without ever reading them (signatures checked here with the public key alone).
 */
const API = 'http://localhost:4000';
x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const EC = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;
const DAY = 86_400_000;
const pem = (der: ArrayBuffer, label: string) => `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END ${label}-----\n`;

async function ca(name: string) {
  const keys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: '0a', name, notBefore: new Date(Date.now() - DAY), notAfter: new Date(Date.now() + 3650 * DAY), keys, signingAlgorithm: EC, extensions: [new x509.BasicConstraintsExtension(true, undefined, true)] });
  return { cert, keys, certificate: cert.toString('pem'), privateKey: pem(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY') };
}
async function leaf(issuer: Awaited<ReturnType<typeof ca>>, cn: string, days: number) {
  const keys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: '1b', subject: `CN=${cn}`, issuer: issuer.cert.subject, notBefore: new Date(Date.now() - DAY), notAfter: new Date(Date.now() + days * DAY), publicKey: keys.publicKey, signingKey: issuer.keys.privateKey, signingAlgorithm: EC, extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: cn }])] });
  return { certificate: cert.toString('pem'), privateKey: pem(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY') };
}
async function signCsr(csrPem: string, issuer: Awaited<ReturnType<typeof ca>>, days: number) {
  const csr = new x509.Pkcs10CertificateRequest(csrPem);
  const san = csr.getExtension('2.5.29.17') as x509.SubjectAlternativeNameExtension | null;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: '2c', subject: csr.subjectName, issuer: issuer.cert.subjectName, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + days * DAY), publicKey: csr.publicKey, signingKey: issuer.keys.privateKey, signingAlgorithm: EC, extensions: san ? [new x509.SubjectAlternativeNameExtension(san.names.toJSON())] : [] });
  return cert.toString('pem');
}

test.describe.serial('secret keys and certificates', () => {
  let owner: APIRequestContext;
  let app: APIRequestContext;
  let agentId = '';
  let internalCa: Awaited<ReturnType<typeof ca>>;
  let caId = '';
  let tlsId = '';
  let signingKeyId = '';

  test.beforeAll(async ({ playwright }) => {
    owner = await playwright.request.newContext({ baseURL: API });
    expect((await owner.post('/api/v1/auth/login', { data: { email: 'owner@demo.test', password: DEMO_PASSWORD } })).ok()).toBe(true);
    expect((await owner.post('/api/v1/auth/selectOrganization', { data: { organizationId: 'org_demo0000000001' } })).ok()).toBe(true);
    const agent = await details(await owner.post('/api/v1/agent/save', { data: { name: 'Release Signer', environment: 'production', ownerTeam: 'Release', agentType: 'SERVICE' } }));
    agentId = agent.agent.id;
    app = await playwright.request.newContext({ baseURL: API, extraHTTPHeaders: { authorization: `Bearer ${agent.credential.apiKey}` } });
    internalCa = await ca('CN=E2E Internal CA, O=Token Vault');
  });
  test.afterAll(async () => {
    await Promise.all([owner?.dispose(), app?.dispose()]);
  });

  test('a TLS certificate: the webhook reads it; expiry and metadata follow it; a key that is not its own is refused', async () => {
    const ca1 = await owner.post('/api/v1/secret/save', { data: { name: 'e2e-internal-ca', typeKey: 'ca-certificate', project: 'pki', environment: 'production', payload: { certificate: internalCa.certificate, privateKey: internalCa.privateKey } } });
    expect(ca1.status(), await ca1.text()).toBe(201);
    caId = (await details(ca1)).id;

    const l = await leaf(internalCa, 'shop.e2e.test', 12);
    const other = await leaf(internalCa, 'other.e2e.test', 12);
    const bad = await owner.post('/api/v1/secret/save', { data: { name: 'shop-tls', typeKey: 'tls-certificate', project: 'web', environment: 'production', payload: { certificate: l.certificate, privateKey: other.privateKey } } });
    expect(bad.status()).toBe(400);
    expect(await bad.json()).toMatchObject({ code: 'CERTIFICATE_KEY_MISMATCH' });

    const r = await owner.post('/api/v1/secret/save', { data: { name: 'shop-tls', typeKey: 'tls-certificate', project: 'web', environment: 'production', payload: { certificate: l.certificate, privateKey: l.privateKey, chain: internalCa.certificate } } });
    expect(r.status(), await r.text()).toBe(201);
    const s = await details(r);
    tlsId = s.id;
    const notAfter = new X509Certificate(l.certificate).validToDate.toISOString();
    expect(s).toMatchObject({ status: 'EXPIRING', expiresAt: notAfter, metadata: { commonName: 'shop.e2e.test', notAfter }, certificate: { commonName: 'shop.e2e.test', subjectAltNames: ['DNS:shop.e2e.test'], chainValid: true, privateKey: 'matches' } });
    expect(JSON.stringify(s)).not.toContain('PRIVATE KEY');
  });

  test('renewal: a new key and CSR on the webhook; issued by the CA secret; then once more with an outside CA’s certificate', async () => {
    const req = await details(await owner.post('/api/v1/secret/certificate/request', { data: { id: tlsId } }));
    expect(req).toMatchObject({ status: 'PENDING', keyAlgorithm: 'EC-P256', subjectAltNames: ['DNS:shop.e2e.test'] });
    expect(await new x509.Pkcs10CertificateRequest(req.csr).verify()).toBe(true);
    expect((await owner.post('/api/v1/secret/certificate/request', { data: { id: tlsId } })).status()).toBe(409);

    const renewed = await details(await owner.post('/api/v1/secret/certificate/complete', { data: { requestId: req.id, issuerSecretId: caId, validityDays: 60 } }));
    expect(renewed).toMatchObject({ activeVersion: 2, status: 'ACTIVE', certificate: { commonName: 'shop.e2e.test', issuer: expect.stringContaining('E2E Internal CA'), chainValid: true }, certificateRequests: [{ status: 'COMPLETED', issuer: { id: caId } }] });
    expect(Date.parse(renewed.expiresAt)).toBeGreaterThan(Date.now() + 59 * DAY);
    // The stored value: a new key, and a certificate for it signed by the CA.
    const v2 = (await details(await owner.post('/api/v1/secret/retrieve', { data: { id: tlsId } }))).payload;
    const cert2 = new X509Certificate(v2.certificate);
    expect(cert2.checkPrivateKey(createPrivateKey(v2.privateKey))).toBe(true);
    expect(cert2.verify(new X509Certificate(internalCa.certificate).publicKey)).toBe(true);

    const req2 = await details(await owner.post('/api/v1/secret/certificate/request', { data: { id: tlsId, keyAlgorithm: 'RSA-2048' } }));
    const outsideCa = await ca('CN=Outside CA');
    const done = await details(await owner.post('/api/v1/secret/certificate/complete', { data: { requestId: req2.id, certificate: await signCsr(req2.csr, outsideCa, 30), chain: outsideCa.certificate } }));
    expect(done).toMatchObject({ activeVersion: 3, certificate: { publicKey: 'RSA 2048', issuer: 'CN=Outside CA', privateKey: 'matches' } });

    const events = (await details(await owner.post('/api/v1/auditEvent/getall', { data: { eventType: 'secret.certificate', targetId: tlsId } }))).items.map((e: { eventType: string }) => e.eventType);
    expect(events).toEqual(expect.arrayContaining(['secret.certificate_requested', 'secret.certificate_renewed']));
  });

  test('an application signs with a key it can never read; the signature checks out with the public key', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const k = await details(await owner.post('/api/v1/secret/save', { data: { name: 'artifact-signing', typeKey: 'ecc-private-key', project: 'release', environment: 'production', payload: { privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKey: publicKey.export({ type: 'spki', format: 'pem' }) } } }));
    signingKeyId = k.id;
    expect(k.key).toMatchObject({ supported: ['sign', 'verify'] });
    expect((await owner.post('/api/v1/secretAccess/save', { data: { agentId, secretId: k.id, allowRetrieve: false, keyOperations: ['sign', 'verify'], description: 'Release signing' } })).status()).toBe(201);

    expect((await (await app.post('/agent/v1/secret/retrieve', { data: { secret_id: k.id } })).json()).code).toBe('RETRIEVE_NOT_PERMITTED');
    const data = Buffer.from('token-vault-1.6.0.tgz sha256:9f2c').toString('base64');
    const r = await app.post('/agent/v1/secret/key/sign', { data: { name: 'artifact-signing', data, reason: 'release 1.6.0' } });
    expect(r.status(), await r.text()).toBe(200);
    const sig = await details(r);
    expect(sig).toMatchObject({ operation: 'sign', algorithm: 'ES256', version: 1 });
    expect(cryptoVerify('sha256', Buffer.from(data, 'base64'), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig.signature, 'base64'))).toBe(true);
    expect((await details(await app.post('/agent/v1/secret/key/verify', { data: { secret_id: k.id, data, signature: sig.signature } }))).valid).toBe(true);
    expect((await (await app.post('/agent/v1/secret/key/encrypt', { data: { secret_id: k.id, data } })).json()).code).toBe('KEY_OPERATION_NOT_SUPPORTED');

    // Deactivating the version stops signing with it.
    expect((await owner.post('/api/v1/secret/keyVersion/disable', { data: { id: k.id, version: 1, reason: 'e2e' } })).ok()).toBe(true);
    expect((await (await app.post('/agent/v1/secret/key/sign', { data: { secret_id: k.id, data } })).json()).code).toBe('KEY_VERSION_DISABLED');
    expect((await owner.post('/api/v1/secret/keyVersion/enable', { data: { id: k.id, version: 1 } })).ok()).toBe(true);

    const used = (await details(await owner.post('/api/v1/auditEvent/getall', { data: { eventType: 'secret.key', targetId: k.id } }))).items.map((e: { eventType: string }) => e.eventType);
    expect(used).toEqual(expect.arrayContaining(['secret.key_used', 'secret.key_version_disabled', 'secret.key_version_enabled']));
  });

  test('an AES key encrypts and decrypts for an application, across a key rotation', async () => {
    const k = await details(await owner.post('/api/v1/secret/save', { data: { name: 'pii-key', typeKey: 'aes-key', project: 'data', environment: 'production', payload: { key: Buffer.alloc(32, 7).toString('base64') } } }));
    await owner.post('/api/v1/secretAccess/save', { data: { agentId, secretId: k.id, allowRetrieve: false, keyOperations: ['encrypt', 'decrypt'] } });
    const enc = await details(await app.post('/agent/v1/secret/key/encrypt', { data: { secret_id: k.id, data: Buffer.from('4242 4242 4242 4242').toString('base64'), aad: Buffer.from('customer-17').toString('base64') } }));
    expect(enc.ciphertext).toMatch(/^tv:v1:/);
    await owner.post('/api/v1/secret/rotate', { data: { id: k.id, reason: 'e2e' } });
    const dec = await details(await app.post('/agent/v1/secret/key/decrypt', { data: { secret_id: k.id, ciphertext: enc.ciphertext, aad: Buffer.from('customer-17').toString('base64') } }));
    expect(dec).toMatchObject({ version: 1 });
    expect(Buffer.from(dec.plaintext, 'base64').toString()).toBe('4242 4242 4242 4242');
    expect((await details(await app.post('/agent/v1/secret/key/encrypt', { data: { secret_id: k.id, data: 'eA==' } }))).ciphertext).toMatch(/^tv:v2:/);
  });

  test('in the console: the certificate card, a renewal issued by the CA secret, and deactivating a key version', async ({ page }) => {
    const errors = trackPageErrors(page);
    await signIn(page, 'owner@demo.test');
    await page.getByRole('button', { name: /Demo Organization/ }).click();
    await expect(page).not.toHaveURL(/select-org/);

    await page.goto(`/secrets/${tlsId}`);
    await expect(page.getByTestId('secret-certificate-cn')).toContainText('shop.e2e.test');
    await expect(page.getByTestId('secret-certificate-chain')).toHaveAttribute('data-valid', 'true');
    await expect(page.getByTestId('secret-certificate-private-key')).toHaveAttribute('data-private-key', 'matches');
    await page.getByTestId('secret-cert-renew').click();
    await page.getByTestId('secret-cert-renew-confirm').click();
    const pending = page.getByTestId('secret-cert-pending');
    await expect(pending).toBeVisible();
    const requestId = (await pending.getAttribute('data-request-id'))!;
    await expect(page.getByTestId('secret-cert-csr')).toHaveValue(/BEGIN CERTIFICATE REQUEST/);
    await page.getByTestId('secret-cert-issuer-select').selectOption(caId);
    await page.getByTestId('secret-cert-issuer-days').fill('45');
    await page.getByTestId('secret-cert-complete-issue').click();
    await expect(page.locator(`[data-testid="secret-cert-request"][data-request-id="${requestId}"]`)).toHaveAttribute('data-status', 'COMPLETED');
    const days = Number(await page.getByTestId('secret-certificate-card').getAttribute('data-days-left'));
    expect(days).toBeGreaterThanOrEqual(43);
    expect(days).toBeLessThanOrEqual(45);

    await page.goto(`/secrets/${signingKeyId}`);
    await expect(page.getByTestId('secret-key-card')).toHaveAttribute('data-external', 'none');
    await expect(page.getByTestId('secret-key-op-sign')).toBeChecked();
    await page.getByTestId('secret-version-actions-1').getByTestId('secret-key-version-disable').click();
    await page.getByTestId('secret-key-version-reason').fill('suspected leak');
    await page.getByTestId('secret-key-version-confirm').click();
    await expect(page.getByTestId('secret-key-version-state').first()).toHaveAttribute('data-key-enabled', 'false');
    const data = Buffer.from('after deactivation').toString('base64');
    expect((await (await app.post('/agent/v1/secret/key/sign', { data: { secret_id: signingKeyId, data } })).json()).code).toBe('KEY_VERSION_DISABLED');
    await page.getByTestId('secret-version-actions-1').getByTestId('secret-key-version-enable').click();
    await page.getByTestId('secret-key-version-confirm').click();
    await expect(page.getByTestId('secret-key-version-state').first()).toHaveAttribute('data-key-enabled', 'true');
    expect((await app.post('/agent/v1/secret/key/sign', { data: { secret_id: signingKeyId, data } })).status()).toBe(200);
    expect(errors).toEqual([]);
  });
});
