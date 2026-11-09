import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { request, createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { checkClient, describeCertificate, loadTlsConfig, watchTlsFiles, type TlsConfig } from '../src/security/tls';
import { devCerts, type DevCerts } from './helpers/certs';

const CLIENT_EXT = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n';

/** A webhook-shaped HTTPS server: client certificates requested, checked per request like /internal/*. */
function serve(tls: TlsConfig): Promise<Server> {
  const server = createServer({ cert: tls.cert, key: tls.key, ...(tls.clientCa ? { ca: tls.clientCa, requestCert: true, rejectUnauthorized: false } : {}), minVersion: 'TLSv1.2' }, (req, res) => {
    if (req.url === '/healthz') return void res.end('ok');
    const check = checkClient(req.socket as TLSSocket, tls);
    res.statusCode = check.ok ? 200 : 401;
    res.end(check.ok ? `ok:${check.identity}` : check.reason);
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server)));
}

function get(server: Server, path: string, ca: string, client?: { cert: string; key: string }): Promise<{ status: number; body: string }> {
  const { port } = server.address() as AddressInfo;
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, ca, servername: 'localhost', ...(client ?? {}), agent: false }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

describe('webhook mTLS (real certificates)', () => {
  let certs: DevCerts;
  let other: DevCerts;
  let stranger: { cert: string; key: string };
  let server: Server;
  let tls: TlsConfig;

  beforeAll(async () => {
    certs = devCerts();
    other = devCerts(); // a second, unrelated CA
    stranger = certs.issue('stranger', '/CN=stranger', `${CLIENT_EXT}subjectAltName=URI:spiffe://elsewhere/app\n`);
    tls = loadTlsConfig({
      WEBHOOK_TLS_CERT: certs.webhook.cert,
      WEBHOOK_TLS_KEY: certs.webhook.key,
      WEBHOOK_TLS_CLIENT_CA: certs.ca,
      WEBHOOK_TLS_ALLOWED_CLIENTS: 'URI:spiffe://token-vault/control-plane',
    })!;
    server = await serve(tls);
  });
  afterAll(() => {
    server?.close();
    for (const c of [certs, other]) if (c) rmSync(c.dir, { recursive: true, force: true });
  });

  it('accepts the control plane by its SPIFFE identity', async () => {
    expect(await get(server, '/internal/v1/health', certs.ca, certs.controlPlane)).toEqual({ status: 200, body: 'ok:URI:spiffe://token-vault/control-plane' });
  });

  it('keeps liveness open without a client certificate, and refuses /internal/* without one', async () => {
    expect((await get(server, '/healthz', certs.ca)).status).toBe(200);
    expect(await get(server, '/internal/v1/health', certs.ca)).toEqual({ status: 401, body: 'a client certificate is required' });
  });

  it('refuses a client certificate from another CA', async () => {
    const r = await get(server, '/internal/v1/health', certs.ca, other.controlPlane);
    expect(r.status).toBe(401);
    expect(r.body).toMatch(/^the client certificate is not trusted/);
  });

  it('refuses a trusted certificate whose identity is not allowed; any identity passes without an allowlist', async () => {
    expect(await get(server, '/internal/v1/health', certs.ca, stranger)).toEqual({ status: 401, body: 'the client certificate identity is not allowed' });
    const open = await serve({ ...tls, allowedClients: [] });
    try {
      expect(await get(open, '/internal/v1/health', certs.ca, stranger)).toEqual({ status: 200, body: 'ok:URI:spiffe://elsewhere/app' });
    } finally {
      open.close();
    }
  });

  it('describes the serving certificate without key material', () => {
    const d = describeCertificate(tls.cert);
    expect(d.subject).toBe('CN=webhook');
    expect(d.issuer).toContain('Token Vault development webhook CA');
    expect(d.subject_alt_names).toContain('DNS:webhook.token-vault-customer.svc.cluster.local');
    expect(JSON.stringify(d)).not.toContain('PRIVATE KEY');
  });

  it('picks up renewed certificate files and ignores half-written ones', async () => {
    const certFile = join(certs.dir, 'watched.pem');
    writeFileSync(certFile, certs.webhook.cert);
    const watched = loadTlsConfig({ WEBHOOK_TLS_CERT_FILE: certFile, WEBHOOK_TLS_KEY: certs.webhook.key })!;
    const seen: string[] = [];
    const timer = watchTlsFiles(watched, (next) => seen.push(next.cert), 20)!;
    try {
      writeFileSync(certFile, '-----BEGIN CERTIFICATE-----\ntrunc');
      await new Promise((r) => setTimeout(r, 80));
      expect(seen).toEqual([]);
      expect(watched.cert).toBe(certs.webhook.cert);
      writeFileSync(certFile, other.webhook.cert);
      await new Promise((r) => setTimeout(r, 80));
      expect(seen).toEqual([other.webhook.cert]);
      expect(watched.cert).toBe(other.webhook.cert);
    } finally {
      clearInterval(timer);
    }
  });
});

describe('webhook TLS configuration', () => {
  it('is off unless a certificate and key are set, and refuses half or malformed settings', () => {
    expect(loadTlsConfig({})).toBeNull();
    expect(() => loadTlsConfig({ WEBHOOK_TLS_CERT: 'x' })).toThrow(/both WEBHOOK_TLS_CERT and WEBHOOK_TLS_KEY/);
    expect(() => loadTlsConfig({ WEBHOOK_TLS_CLIENT_CA: 'x' })).toThrow(/need WEBHOOK_TLS_CERT/);
    expect(() => loadTlsConfig({ WEBHOOK_TLS_CERT: 'not pem', WEBHOOK_TLS_KEY: 'k' })).toThrow(/PEM certificates/);
  });
  it('validates the allowed-client list', () => {
    const c = devCerts();
    try {
      const base = { WEBHOOK_TLS_CERT: c.webhook.cert, WEBHOOK_TLS_KEY: c.webhook.key };
      expect(() => loadTlsConfig({ ...base, WEBHOOK_TLS_ALLOWED_CLIENTS: 'CN=x' })).toThrow(/needs WEBHOOK_TLS_CLIENT_CA/);
      expect(() => loadTlsConfig({ ...base, WEBHOOK_TLS_CLIENT_CA: c.ca, WEBHOOK_TLS_ALLOWED_CLIENTS: 'control-plane' })).toThrow(/is not URI:/);
      expect(loadTlsConfig({ ...base, WEBHOOK_TLS_CLIENT_CA: c.ca, WEBHOOK_TLS_ALLOWED_CLIENTS: 'URI:spiffe://a, DNS:b ,CN=c' })!.allowedClients).toEqual(['URI:spiffe://a', 'DNS:b', 'CN=c']);
    } finally {
      rmSync(c.dir, { recursive: true, force: true });
    }
  });
});
