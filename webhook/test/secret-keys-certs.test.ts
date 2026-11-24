import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { constants, createHmac, createPublicKey, generateKeyPairSync, publicEncrypt, randomBytes, randomUUID, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import forge from 'node-forge';
import { CreateKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { signCsr, testCa, testLeaf, x509 } from './helpers/x509';

/**
 * Keys and certificates on the customer webhook (Secret Management phase 6): certificates are read
 * when stored (key match, chain, expiry), renewals make a new key and CSR and complete with a
 * certificate for that key (uploaded, or issued by a CA secret), and keys are used without ever
 * leaving: locally, in Vault Transit (VAULT_TEST_ADDR) and in AWS KMS (KMS_TEST_ENDPOINT).
 * Skipped unless WEBHOOK_TEST_DATABASE_URL is set.
 */
const url = process.env.WEBHOOK_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;
const vaultAddr = process.env.VAULT_TEST_ADDR;
const kmsEndpoint = process.env.KMS_TEST_ENDPOINT;

suite('keys and certificates (PostgreSQL)', () => {
  const signingSecret = randomBytes(32).toString('base64url');
  let server: Server;
  let base = '';
  let m: { client: typeof import('../src/db/client'); store: typeof import('../src/store/credential-store'); sig: typeof import('../src/security/signature'); config: typeof import('../src/config') };
  let n = 0;

  async function call(path: string, body: unknown) {
    const raw = JSON.stringify(body);
    const ts = String(Date.now());
    const nonce = randomUUID();
    const res = await fetch(base + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-tv-timestamp': ts, 'x-tv-nonce': nonce, 'x-tv-signature': m.sig.hmacHex(signingSecret, m.sig.canonicalString('POST', path, ts, nonce, raw)) },
      body: raw,
    });
    return { status: res.status, body: (await res.json()) as any };
  }
  const store = (type_key: string, payload: object, secret_id = `sec_kc${++n}`, version = 1) => call('/internal/v1/secrets/store', { org_id: 'org_k', secret_id, version, type_key, payload });
  const key = (stored: { value_ref: string; version: number }, secret_id: string, operation: string, extra: object = {}) => call('/internal/v1/secrets/key', { org_id: 'org_k', secret_id, value_ref: stored.value_ref, version: stored.version, operation, ...extra });
  const b64 = (s: string | Buffer) => Buffer.from(s).toString('base64');

  beforeAll(async () => {
    process.env.WEBHOOK_DATABASE_URL = url;
    process.env.VAULT_ENCRYPTION_KEY = randomBytes(32).toString('base64');
    process.env.WEBHOOK_SIGNING_SECRET = signingSecret;
    process.env.SEED_MODE = 'reset';
    process.env.CMS_CATALOG_URL = '';
    if (vaultAddr) process.env.PROVIDER_ALLOWED_HOSTS = `${new URL(vaultAddr).hostname}:${new URL(vaultAddr).port || 80}`;
    if (kmsEndpoint) process.env.AWS_KMS_ENDPOINT = kmsEndpoint;
    m = { client: await import('../src/db/client'), store: await import('../src/store/credential-store'), sig: await import('../src/security/signature'), config: await import('../src/config') };
    await m.client.runMigrations();
    await m.store.initStore();
    const express = (await import('express')).default;
    const { buildRouter } = await import('../src/routes');
    const app = express();
    app.use(buildRouter());
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }, 60_000);

  afterAll(async () => {
    server?.close();
    await m?.client.closeDatabase();
  });

  it('reads a TLS certificate when it is stored: names, validity, chain, and that the key is its own', async () => {
    const ca = await testCa();
    const leaf = await testLeaf('CN=api.example.test, O=Example', { ca, dns: ['api.example.test', 'www.example.test'] });
    const r = await store('tls-certificate', { certificate: leaf.certificate, privateKey: leaf.privateKey, chain: ca.certificate });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.certificate).toMatchObject({
      commonName: 'api.example.test',
      subjectAltNames: ['DNS:api.example.test', 'DNS:www.example.test'],
      publicKey: 'EC P-256',
      isCA: false,
      selfSigned: false,
      privateKey: 'matches',
      chainValid: true,
      notAfter: new X509Certificate(leaf.certificate).validToDate.toISOString(),
    });
    expect(r.body.certificate.chain).toEqual([expect.objectContaining({ subject: expect.stringContaining('CN=Test Root CA') })]);
    expect(JSON.stringify(r.body)).not.toContain('PRIVATE KEY');

    // A chain that does not link up is reported, not refused.
    const other = await testCa('CN=Other CA');
    expect((await store('tls-certificate', { certificate: leaf.certificate, privateKey: leaf.privateKey, chain: other.certificate })).body.certificate.chainValid).toBe(false);
  });

  it('refuses a key that is not the certificate’s, an expired certificate, and text that is not a certificate', async () => {
    const a = await testLeaf('CN=a.test');
    const b = await testLeaf('CN=b.test');
    const mismatch = await store('tls-certificate', { certificate: a.certificate, privateKey: b.privateKey });
    expect(mismatch.status).toBe(400);
    expect(mismatch.body.error).toMatchObject({ code: 'CERTIFICATE_KEY_MISMATCH', details: { fields: { privateKey: expect.any(String) } } });
    const expired = await testLeaf('CN=old.test', { days: -1 });
    expect((await store('tls-certificate', { certificate: expired.certificate, privateKey: expired.privateKey })).body.error.code).toBe('CERTIFICATE_EXPIRED');
    const bogus = await store('ca-certificate', { certificate: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----' });
    expect(bogus.status).toBe(400);
    expect(bogus.body.error.details.fields.certificate).toBeTruthy();
    // A CA certificate without its key is fine.
    const ca = await testCa();
    expect((await store('ca-certificate', { certificate: ca.certificate })).body.certificate).toMatchObject({ isCA: true, selfSigned: true, privateKey: 'absent' });
  });

  it('reads a PKCS#12 bundle with its passphrase; a wrong passphrase points at that field', async () => {
    const leaf = await testLeaf('CN=bundle.test', { rsa: true, dns: ['bundle.test'] });
    const p12 = forge.pkcs12.toPkcs12Asn1(forge.pki.privateKeyFromPem(leaf.privateKey), [forge.pki.certificateFromPem(leaf.certificate)], 'bundle-pass-123', { algorithm: '3des' });
    const bundle = Buffer.from(forge.asn1.toDer(p12).getBytes(), 'binary').toString('base64');
    const r = await store('pkcs12', { bundle, passphrase: 'bundle-pass-123' });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.certificate).toMatchObject({ commonName: 'bundle.test', publicKey: 'RSA 2048', privateKey: 'matches' });
    const wrong = await store('pkcs12', { bundle, passphrase: 'not the passphrase' });
    expect(wrong.status).toBe(400);
    expect(Object.keys(wrong.body.error.details.fields)).toEqual(['passphrase']);
  });

  it('renewal: a new key and CSR for the same names; completed by a CA secret, or with the certificate a CA returned', async () => {
    const ca = await testCa('CN=Internal Issuing CA');
    const caStored = await store('ca-certificate', { certificate: ca.certificate, privateKey: ca.privateKey }, 'sec_ca1');
    const leaf = await testLeaf('CN=svc.internal.test, O=Example', { ca, dns: ['svc.internal.test'], days: 10 });
    const current = await store('tls-certificate', { certificate: leaf.certificate, privateKey: leaf.privateKey, chain: ca.certificate }, 'sec_tls1');

    const reqA = await call('/internal/v1/secrets/certificate/request', { org_id: 'org_k', secret_id: 'sec_tls1', value_ref: current.body.value_ref, request_id: 'crq_aaaaaaaa01' });
    expect(reqA.status, JSON.stringify(reqA.body)).toBe(201);
    expect(reqA.body).toMatchObject({ key_algorithm: 'EC-P256', subject: 'CN=svc.internal.test, O=Example', subject_alt_names: ['DNS:svc.internal.test'] });
    const csr = new x509.Pkcs10CertificateRequest(reqA.body.csr);
    expect(await csr.verify()).toBe(true);
    expect(JSON.stringify(reqA.body)).not.toContain('PRIVATE KEY');

    // Issued by the CA secret: the webhook signs the CSR with the CA key it stores.
    const issued = await call('/internal/v1/secrets/certificate/complete', { org_id: 'org_k', secret_id: 'sec_tls1', type_key: 'tls-certificate', request_id: 'crq_aaaaaaaa01', request_ref: reqA.body.request_ref, version: 2, issuer: { secret_id: 'sec_ca1', value_ref: caStored.body.value_ref }, validity_days: 30 });
    expect(issued.status, JSON.stringify(issued.body)).toBe(201);
    expect(issued.body).toMatchObject({ version: 2, issued: true, certificate: { commonName: 'svc.internal.test', issuer: expect.stringContaining('Internal Issuing CA'), privateKey: 'matches', chainValid: true, subjectAltNames: ['DNS:svc.internal.test'] } });
    expect(Date.parse(issued.body.certificate.notAfter)).toBeGreaterThan(Date.now() + 29 * 86_400_000);
    // The pending key is gone once used.
    expect((await call('/internal/v1/secrets/certificate/complete', { org_id: 'org_k', secret_id: 'sec_tls1', type_key: 'tls-certificate', request_id: 'crq_aaaaaaaa01', request_ref: reqA.body.request_ref, version: 3, certificate: 'x' })).status).toBe(404);

    // Uploaded from an outside CA, RSA this time; a certificate for another key is refused.
    const reqB = await call('/internal/v1/secrets/certificate/request', { org_id: 'org_k', secret_id: 'sec_tls1', value_ref: issued.body.value_ref, request_id: 'crq_aaaaaaaa02', key_algorithm: 'RSA-2048' });
    expect(reqB.body.key_algorithm).toBe('RSA-2048');
    const unrelated = await testLeaf('CN=svc.internal.test', { ca });
    const refused = await call('/internal/v1/secrets/certificate/complete', { org_id: 'org_k', secret_id: 'sec_tls1', type_key: 'tls-certificate', request_id: 'crq_aaaaaaaa02', request_ref: reqB.body.request_ref, version: 3, certificate: unrelated.certificate });
    expect(refused.body.error.code).toBe('CERTIFICATE_KEY_MISMATCH');
    const done = await call('/internal/v1/secrets/certificate/complete', { org_id: 'org_k', secret_id: 'sec_tls1', type_key: 'tls-certificate', request_id: 'crq_aaaaaaaa02', request_ref: reqB.body.request_ref, version: 3, certificate: await signCsr(reqB.body.csr, ca), chain: ca.certificate });
    expect(done.status, JSON.stringify(done.body)).toBe(201);
    expect(done.body.certificate).toMatchObject({ publicKey: 'RSA 2048', privateKey: 'matches' });
    expect(done.body.issued).toBe(false);

    // A CA secret without its key cannot issue.
    const pub = await store('ca-certificate', { certificate: ca.certificate }, 'sec_ca2');
    const reqC = await call('/internal/v1/secrets/certificate/request', { org_id: 'org_k', secret_id: 'sec_tls1', value_ref: done.body.value_ref, request_id: 'crq_aaaaaaaa03' });
    expect((await call('/internal/v1/secrets/certificate/complete', { org_id: 'org_k', secret_id: 'sec_tls1', type_key: 'tls-certificate', request_id: 'crq_aaaaaaaa03', request_ref: reqC.body.request_ref, version: 4, issuer: { secret_id: 'sec_ca2', value_ref: pub.body.value_ref } })).body.error.code).toBe('CERTIFICATE_ISSUER_INVALID');
  });

  it('AES keys encrypt and decrypt (with associated data); the ciphertext names its version', async () => {
    const s = (await store('aes-key', { key: randomBytes(32).toString('base64') }, 'sec_aes1')).body;
    const enc = await key(s, 'sec_aes1', 'encrypt', { data: b64('card 4242'), aad: b64('order-17') });
    expect(enc.status, JSON.stringify(enc.body)).toBe(200);
    expect(enc.body).toMatchObject({ algorithm: 'A256GCM', ciphertext: expect.stringMatching(/^tv:v1:/) });
    const dec = await key(s, 'sec_aes1', 'decrypt', { ciphertext: enc.body.ciphertext, aad: b64('order-17') });
    expect(Buffer.from(dec.body.plaintext, 'base64').toString()).toBe('card 4242');
    expect((await key(s, 'sec_aes1', 'decrypt', { ciphertext: enc.body.ciphertext, aad: b64('order-18') })).body.error.code).toBe('DECRYPTION_FAILED');
    expect((await key(s, 'sec_aes1', 'decrypt', { ciphertext: enc.body.ciphertext.replace('tv:v1:', 'tv:v2:') })).body.error.code).toBe('KEY_INPUT_INVALID');
    expect((await key(s, 'sec_aes1', 'sign', { data: b64('x') })).body.error.code).toBe('KEY_OPERATION_NOT_SUPPORTED');
    // A key of the wrong length is refused when stored.
    expect((await store('aes-key', { key: randomBytes(20).toString('base64') })).body.error.details.fields.key).toBeTruthy();
  });

  it('RSA, EC and Ed25519 keys sign (checked with the public key alone) and verify; RSA also encrypts', async () => {
    const data = b64('release v1.2.3 sha256:abc');
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const r = (await store('rsa-private-key', { privateKey: rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }) }, 'sec_rsa1')).body;
    for (const alg of ['PS256', 'RS256']) {
      const sig = await key(r, 'sec_rsa1', 'sign', { data, algorithm: alg });
      expect(sig.body.algorithm).toBe(alg);
      const padding = alg === 'PS256' ? constants.RSA_PKCS1_PSS_PADDING : constants.RSA_PKCS1_PADDING;
      expect(cryptoVerify('sha256', Buffer.from(data, 'base64'), { key: rsa.publicKey, padding }, Buffer.from(sig.body.signature, 'base64'))).toBe(true);
      expect((await key(r, 'sec_rsa1', 'verify', { data, signature: sig.body.signature, algorithm: alg })).body.valid).toBe(true);
    }
    expect((await key(r, 'sec_rsa1', 'sign', { data })).body.algorithm).toBe('PS256');
    expect((await key(r, 'sec_rsa1', 'sign', { data, algorithm: 'ES256' })).body.error.code).toBe('KEY_ALGORITHM_NOT_SUPPORTED');
    const ct = (await key(r, 'sec_rsa1', 'encrypt', { data: b64('data key') })).body.ciphertext;
    expect(Buffer.from((await key(r, 'sec_rsa1', 'decrypt', { ciphertext: ct })).body.plaintext, 'base64').toString()).toBe('data key');
    // Encrypted elsewhere with the public key (RSA-OAEP-256), decrypted here.
    const outside = publicEncrypt({ key: rsa.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from('from outside')).toString('base64');
    expect(Buffer.from((await key(r, 'sec_rsa1', 'decrypt', { ciphertext: `tv:v1:${outside}` })).body.plaintext, 'base64').toString()).toBe('from outside');

    const ec = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const e = (await store('ecc-private-key', { privateKey: ec.privateKey.export({ type: 'pkcs8', format: 'pem' }) }, 'sec_ec1')).body;
    const esig = await key(e, 'sec_ec1', 'sign', { data });
    expect(esig.body.algorithm).toBe('ES384');
    expect(Buffer.from(esig.body.signature, 'base64')).toHaveLength(96); // r || s, as in JWS
    expect(cryptoVerify('sha384', Buffer.from(data, 'base64'), { key: ec.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(esig.body.signature, 'base64'))).toBe(true);
    expect((await key(e, 'sec_ec1', 'verify', { data: b64('tampered'), signature: esig.body.signature })).body.valid).toBe(false);

    const ed = generateKeyPairSync('ed25519');
    const d = (await store('signing-key', { privateKey: ed.privateKey.export({ type: 'pkcs8', format: 'pem' }), keyId: 'release-2026' }, 'sec_ed1')).body;
    const dsig = await key(d, 'sec_ed1', 'sign', { data });
    expect(dsig.body.algorithm).toBe('EdDSA');
    expect(cryptoVerify(null, Buffer.from(data, 'base64'), createPublicKey(ed.privateKey), Buffer.from(dsig.body.signature, 'base64'))).toBe(true);

    // An RSA key stored as an ECC key is refused.
    expect((await store('ecc-private-key', { privateKey: rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }) })).body.error.details.fields.privateKey).toBeTruthy();
  });

  it('HMAC secrets compute MACs and check them in constant time', async () => {
    const secret = randomBytes(32).toString('base64url');
    const s = (await store('hmac-secret', { secret }, 'sec_hm1')).body;
    const data = b64('{"event":"paid"}');
    const mac = await key(s, 'sec_hm1', 'mac', { data, algorithm: 'HS512' });
    expect(mac.body).toMatchObject({ algorithm: 'HS512', mac: createHmac('sha512', secret).update('{"event":"paid"}').digest('base64') });
    expect((await key(s, 'sec_hm1', 'verify', { data, mac: mac.body.mac, algorithm: 'HS512' })).body.valid).toBe(true);
    expect((await key(s, 'sec_hm1', 'verify', { data, mac: b64('nope'), algorithm: 'HS512' })).body.valid).toBe(false);
    expect((await key(s, 'sec_hm1', 'mac', { data: 'not base64!' })).body.error.code).toBe('KEY_INPUT_INVALID');
  });

  (vaultAddr ? it : it.skip)('Vault Transit keys: sign, verify, encrypt, decrypt and MAC in Vault; hosts off the allow-list are refused', async () => {
    const token = process.env.VAULT_TEST_TOKEN ?? '';
    const vault = (path: string, body: object) => fetch(`${vaultAddr}/v1/${path}`, { method: 'POST', headers: { 'x-vault-token': token }, body: JSON.stringify(body) });
    await vault('sys/mounts/transit', { type: 'transit' });
    const name = `tv-keys-${randomBytes(4).toString('hex')}`;
    expect((await vault(`transit/keys/${name}-ec`, { type: 'ecdsa-p256' })).status).toBeLessThan(300);
    expect((await vault(`transit/keys/${name}-aes`, { type: 'aes256-gcm96' })).status).toBeLessThan(300);
    const ec = (await store('vault-transit-key', { address: vaultAddr, keyName: `${name}-ec`, token }, 'sec_vt1')).body;
    const data = b64('signed in Vault');
    const sig = await key(ec, 'sec_vt1', 'sign', { data, algorithm: 'ES256' });
    expect(sig.status, JSON.stringify(sig.body)).toBe(200);
    expect(sig.body.signature).toMatch(/^vault:v1:/);
    expect((await key(ec, 'sec_vt1', 'verify', { data, signature: sig.body.signature, algorithm: 'ES256' })).body.valid).toBe(true);
    const aes = (await store('vault-transit-key', { address: vaultAddr, keyName: `${name}-aes`, token }, 'sec_vt2')).body;
    const enc = await key(aes, 'sec_vt2', 'encrypt', { data: b64('kept in vault') });
    expect(Buffer.from((await key(aes, 'sec_vt2', 'decrypt', { ciphertext: enc.body.ciphertext })).body.plaintext, 'base64').toString()).toBe('kept in vault');
    const mac = await key(aes, 'sec_vt2', 'mac', { data });
    expect((await key(aes, 'sec_vt2', 'verify', { data, mac: mac.body.mac })).body.valid).toBe(true);
    const elsewhere = (await store('vault-transit-key', { address: 'http://vault.elsewhere.test:8200', keyName: 'x', token }, 'sec_vt3')).body;
    expect((await key(elsewhere, 'sec_vt3', 'sign', { data })).body.error.code).toBe('PROVIDER_HOST_NOT_ALLOWED');
  });

  (kmsEndpoint ? it : it.skip)('AWS KMS keys: sign (r || s), verify, encrypt and decrypt in KMS', async () => {
    const admin = new KMSClient({ region: 'us-east-1', endpoint: kmsEndpoint, credentials: { accessKeyId: 'test', secretAccessKey: 'test' } });
    const ecKey = (await admin.send(new CreateKeyCommand({ KeySpec: 'ECC_NIST_P256', KeyUsage: 'SIGN_VERIFY' }))).KeyMetadata!.KeyId!;
    const aesKey = (await admin.send(new CreateKeyCommand({}))).KeyMetadata!.KeyId!;
    const creds = { region: 'us-east-1', accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' };
    const ec = (await store('aws-kms-key', { keyId: ecKey, ...creds }, 'sec_kms1')).body;
    const data = b64('signed in KMS');
    const sig = await key(ec, 'sec_kms1', 'sign', { data });
    expect(sig.status, JSON.stringify(sig.body)).toBe(200);
    expect(sig.body.algorithm).toBe('ES256');
    expect(Buffer.from(sig.body.signature, 'base64')).toHaveLength(64);
    expect((await key(ec, 'sec_kms1', 'verify', { data, signature: sig.body.signature })).body.valid).toBe(true);
    expect((await key(ec, 'sec_kms1', 'verify', { data: b64('other'), signature: sig.body.signature })).body.valid).toBe(false);
    const aes = (await store('aws-kms-key', { keyId: aesKey, ...creds }, 'sec_kms2')).body;
    const enc = await key(aes, 'sec_kms2', 'encrypt', { data: b64('kept in kms'), aad: b64('ctx') });
    expect(Buffer.from((await key(aes, 'sec_kms2', 'decrypt', { ciphertext: enc.body.ciphertext, aad: b64('ctx') })).body.plaintext, 'base64').toString()).toBe('kept in kms');
  });
});
