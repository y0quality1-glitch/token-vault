import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { rmSync } from 'node:fs';
import { devCerts, type DevCerts } from '../../webhook/test/helpers/certs';

// config reads the environment when imported.
process.env.WEBHOOK_SIGNING_SECRET ??= 'demo-secret-for-the-webhook-tls-test-0001';
process.env.AUDIT_SIGNING_KEY ??= 'demo-secret-for-the-webhook-tls-test-0002';
process.env.DATABASE_URL ??= 'postgres://unused@localhost/unused';
const { config } = await import('../src/config');
const { callWebhook, WebhookUnavailableError } = await import('../src/modules/webhooks/webhook.client');

const hex = (key: string, s: string) => createHmac('sha256', key).update(s).digest('hex');
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

/** A webhook-shaped server: requires the control plane's client certificate and signs its response. */
function webhook(certs: DevCerts, server: { cert: string; key: string } = certs.webhook): Promise<Server> {
  const s = createServer({ ...server, ca: certs.ca, requestCert: true, rejectUnauthorized: true }, (req, res) => {
    const peer = (req.socket as TLSSocket).getPeerCertificate();
    const body = JSON.stringify({ client: peer.subjectaltname });
    res.setHeader('content-type', 'application/json');
    res.setHeader('connection', 'close'); // every call opens a new TLS connection
    res.setHeader('x-tv-response-signature', hex(config.webhookSigningSecret, ['response', String(req.headers['x-tv-nonce']), sha(body)].join('\n')));
    res.end(body);
  });
  return new Promise((r) => s.listen(0, '0.0.0.0', () => r(s)));
}
const url = (s: Server, host = 'localhost') => `https://${host}:${(s.address() as AddressInfo).port}`;

async function refusal(p: Promise<unknown>): Promise<{ reason: string; message: string }> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(WebhookUnavailableError);
    return e as { reason: string; message: string };
  }
  throw new Error('expected the call to be refused');
}

describe('control plane -> webhook over mutual TLS', () => {
  let certs: DevCerts;
  let other: DevCerts;
  let server: Server;
  const saved = { ...config.webhookTls };

  beforeAll(async () => {
    certs = devCerts();
    other = devCerts();
    server = await webhook(certs);
  });
  afterAll(() => {
    server?.close();
    Object.assign(config.webhookTls, saved);
    for (const c of [certs, other]) if (c) rmSync(c.dir, { recursive: true, force: true });
  });
  const use = (tls: Partial<typeof config.webhookTls>) => Object.assign(config.webhookTls, { ca: undefined, cert: undefined, key: undefined, requireTls: false, paths: {} }, tls);

  it('presents its client certificate, verifies the webhook and reports its certificate', async () => {
    use({ ca: certs.ca, cert: certs.controlPlane.cert, key: certs.controlPlane.key, requireTls: true });
    const res = await callWebhook({ endpointUrl: url(server), simulateOutage: false, authenticationType: 'MTLS' }, 'GET', 'internal/v1/health');
    expect(res.status).toBe(200);
    expect(res.body.client).toBe('URI:spiffe://token-vault/control-plane');
    expect(res.tls).toMatchObject({ subject: 'CN=webhook', issuer: 'CN=Token Vault development webhook CA' });
    expect(res.tls!.fingerprint256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(Date.parse(res.tls!.validTo)).toBeGreaterThan(Date.now());
    // Again, on a new connection: still a full handshake, so the certificate is reported.
    const again = await callWebhook({ endpointUrl: url(server), simulateOutage: false, authenticationType: 'MTLS' }, 'GET', 'internal/v1/health');
    expect(again.tls?.fingerprint256).toBe(res.tls!.fingerprint256);
  });

  it('refuses a webhook certificate from an untrusted CA', async () => {
    use({ ca: other.ca, cert: certs.controlPlane.cert, key: certs.controlPlane.key });
    const e = await refusal(callWebhook({ endpointUrl: url(server), simulateOutage: false }, 'GET', 'internal/v1/health'));
    expect(e.reason).toBe('TLS_ERROR');
    expect(e.message).toMatch(/not trusted.*WEBHOOK_TLS_CA/);
  });

  it('refuses a webhook certificate that does not name the host', async () => {
    use({ ca: certs.ca, cert: certs.controlPlane.cert, key: certs.controlPlane.key });
    const e = await refusal(callWebhook({ endpointUrl: url(server, '127.0.0.2'), simulateOutage: false }, 'GET', 'internal/v1/health'));
    expect(e.reason).toBe('TLS_ERROR');
    expect(e.message).toMatch(/does not name this host/);
  });

  it('fails the handshake when the webhook does not accept its client certificate', async () => {
    use({ ca: certs.ca, cert: other.controlPlane.cert, key: other.controlPlane.key });
    const e = await refusal(callWebhook({ endpointUrl: url(server), simulateOutage: false }, 'GET', 'internal/v1/health'));
    expect(e.reason).toBe('TLS_ERROR');
    expect(e.message).toMatch(/client certificate/);
  });

  it('never sends a request over plain HTTP when TLS is required, or to an MTLS webhook without a client certificate', async () => {
    use({ ca: certs.ca, requireTls: true });
    expect((await refusal(callWebhook({ endpointUrl: 'http://127.0.0.1:1', simulateOutage: false }, 'GET', 'internal/v1/health'))).reason).toBe('INSECURE_TRANSPORT');
    use({ ca: certs.ca });
    expect((await refusal(callWebhook({ endpointUrl: url(server), simulateOutage: false, authenticationType: 'MTLS' }, 'GET', 'internal/v1/health'))).reason).toBe('INSECURE_TRANSPORT');
    use({ ca: certs.ca, cert: certs.controlPlane.cert, key: certs.controlPlane.key });
    expect((await refusal(callWebhook({ endpointUrl: 'http://127.0.0.1:1', simulateOutage: false, authenticationType: 'MTLS' }, 'GET', 'internal/v1/health'))).reason).toBe('INSECURE_TRANSPORT');
  });
});
