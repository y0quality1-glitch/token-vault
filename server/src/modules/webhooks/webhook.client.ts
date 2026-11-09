import { request as httpRequest } from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https';
import type { TLSSocket } from 'node:tls';
import { config } from '../../config';
import { refreshWebhookTls } from '../../lib/webhook-tls';
import { hmacHex, safeEqualHex, sha256Hex } from '../../lib/crypto';
import { nonce as newNonce } from '../../lib/ids';
import type { WebhookRecord } from '../../store/types';

/**
 * Credential Broker transport: signed, short-lived control plane -> customer webhook calls.
 *
 * canonical = METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA256(body)    (HMAC-SHA256, shared secret from env)
 * Responses are verified with x-tv-response-signature bound to the request nonce.
 *
 * Transport: https with mTLS when configured (CA, client certificate, WEBHOOK_REQUIRE_TLS); the
 * HMAC layer (nonce, expiry, audience, signed responses) applies on top either way.
 */
export class WebhookUnavailableError extends Error {
  constructor(public reason: 'TIMEOUT' | 'UNREACHABLE' | 'SIMULATED_OUTAGE' | 'BAD_SIGNATURE' | 'NOT_VERIFIED' | 'TLS_ERROR' | 'INSECURE_TRANSPORT', message: string) {
    super(message);
  }
}

export interface WebhookResponse<T = any> {
  status: number;
  body: T;
  latencyMs: number;
  /** The webhook's certificate, when the link is TLS. */
  tls?: PeerCertificate;
}

/** Certificate the webhook presented (TLS only): non-secret, shown on Webhook Health. */
export interface PeerCertificate {
  subject: string;
  issuer: string;
  validTo: string;
  fingerprint256: string;
}

/** TLS errors, in words an operator can act on. */
const TLS_REASONS: Record<string, string> = {
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'its certificate is not issued by a trusted CA (check WEBHOOK_TLS_CA)',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'its certificate is not issued by a trusted CA (check WEBHOOK_TLS_CA)',
  SELF_SIGNED_CERT_IN_CHAIN: 'its certificate chain ends in an untrusted CA (check WEBHOOK_TLS_CA)',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'it presents a self-signed certificate that is not trusted (check WEBHOOK_TLS_CA)',
  CERT_HAS_EXPIRED: 'its certificate has expired',
  CERT_NOT_YET_VALID: 'its certificate is not valid yet',
  ERR_TLS_CERT_ALTNAME_INVALID: "its certificate does not name this host (the webhook URL's host must be in the certificate)",
};

let agent: HttpsAgent | null = null;
let agentFor: { ca?: string; cert?: string; key?: string } = {};
/** One keep-alive agent per set of TLS files; replaced when they change (renewal, rotation). */
function httpsAgent(): HttpsAgent {
  const tls = config.webhookTls;
  refreshWebhookTls(tls);
  if (!agent || agentFor.ca !== tls.ca || agentFor.cert !== tls.cert || agentFor.key !== tls.key) {
    agent?.destroy();
    agentFor = { ca: tls.ca, cert: tls.cert, key: tls.key };
    // No TLS session resumption: a resumed session reports no peer certificate, and Webhook Health
    // shows the certificate on every check. Keep-alive still avoids most handshakes.
    agent = new HttpsAgent({ keepAlive: true, maxSockets: 32, maxCachedSessions: 0, minVersion: 'TLSv1.2', ...(tls.ca ? { ca: tls.ca } : {}), ...(tls.cert && tls.key ? { cert: tls.cert, key: tls.key } : {}) });
  }
  return agent;
}

function send(url: URL, method: string, headers: Record<string, string>, body: string, timeoutMs: number): Promise<{ status: number; text: string; header: (name: string) => string; peer?: PeerCertificate }> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === 'https:';
    const req = (isHttps ? httpsRequest : httpRequest)(
      url,
      { method, headers: { ...headers, 'content-length': String(Buffer.byteLength(body)) }, ...(isHttps ? { agent: httpsAgent() } : {}), signal: AbortSignal.timeout(timeoutMs) },
      (res) => {
        // Read the certificate now: by 'end' a keep-alive socket is already back in the pool.
        const sock = res.socket as TLSSocket | null;
        const cert = isHttps && sock && typeof sock.getPeerCertificate === 'function' ? sock.getPeerCertificate() : null;
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (c: Buffer) => {
          size += c.length;
          if (size > 2 * 1024 * 1024) req.destroy(new Error('response too large'));
          else chunks.push(c);
        });
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            text: Buffer.concat(chunks).toString('utf8'),
            header: (n) => String(res.headers[n.toLowerCase()] ?? ''),
            peer: cert && Object.keys(cert).length ? { subject: cert.subject?.CN ? `CN=${cert.subject.CN}` : '', issuer: cert.issuer?.CN ? `CN=${cert.issuer.CN}` : '', validTo: new Date(cert.valid_to).toISOString(), fingerprint256: cert.fingerprint256 } : undefined,
          });
        });
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end(method === 'GET' ? undefined : body);
  });
}

export async function callWebhook<T = any>(webhook: Pick<WebhookRecord, 'endpointUrl' | 'simulateOutage'> & Partial<Pick<WebhookRecord, 'authenticationType'>>, method: 'GET' | 'POST', path: string, payload?: unknown): Promise<WebhookResponse<T>> {
  if (webhook.simulateOutage) {
    throw new WebhookUnavailableError('SIMULATED_OUTAGE', 'Customer webhook unavailable (simulated outage enabled)');
  }
  const url = new URL(path, webhook.endpointUrl.endsWith('/') ? webhook.endpointUrl : webhook.endpointUrl + '/');
  if (config.webhookTls.requireTls && url.protocol !== 'https:') {
    throw new WebhookUnavailableError('INSECURE_TRANSPORT', 'Refused: this webhook URL is not https:// and WEBHOOK_REQUIRE_TLS is on. Update the webhook URL.');
  }
  // A webhook set to mutual TLS is never called without it.
  if (webhook.authenticationType === 'MTLS' && (url.protocol !== 'https:' || !config.webhookTls.cert)) {
    throw new WebhookUnavailableError('INSECURE_TRANSPORT', 'Refused: this webhook requires mutual TLS, but the URL is not https:// or the control plane has no client certificate (CONTROL_PLANE_TLS_CERT).');
  }
  const body = payload === undefined ? '' : JSON.stringify(payload);
  const timestamp = String(Date.now());
  const nonce = newNonce();
  const signature = hmacHex(config.webhookSigningSecret, [method, path, timestamp, nonce, sha256Hex(body)].join('\n'));

  const started = Date.now();
  let res: Awaited<ReturnType<typeof send>>;
  try {
    res = await send(url, method, { 'content-type': 'application/json', 'x-tv-timestamp': timestamp, 'x-tv-nonce': nonce, 'x-tv-signature': signature }, body, config.webhookTimeoutMs);
  } catch (e) {
    const err = e as Error & { code?: string };
    if (err.name === 'TimeoutError' || err.name === 'AbortError') throw new WebhookUnavailableError('TIMEOUT', `Customer webhook did not respond within ${config.webhookTimeoutMs} ms`);
    const tlsReason = err.code ? TLS_REASONS[err.code] : undefined;
    if (tlsReason) throw new WebhookUnavailableError('TLS_ERROR', `TLS: the customer webhook at ${url.host} was not trusted: ${tlsReason}`);
    if (err.code === 'EPROTO' || /SSL|TLS|certificate|handshake/i.test(err.message)) {
      throw new WebhookUnavailableError('TLS_ERROR', `TLS handshake with the customer webhook at ${url.host} failed (is the URL https:// and does the webhook accept the control plane's client certificate?)`);
    }
    // TLS 1.3: a server that rejects the client certificate does so after the handshake, so the
    // client only sees the connection close.
    if (url.protocol === 'https:' && err.code === 'ECONNRESET') {
      throw new WebhookUnavailableError('TLS_ERROR', `The customer webhook at ${url.host} closed the TLS connection without answering (it may not accept the control plane's client certificate)`);
    }
    throw new WebhookUnavailableError('UNREACHABLE', `Customer webhook at ${url.origin} is unreachable`);
  }
  const latencyMs = Date.now() - started;
  const text = res.text;

  // Verify the response really came from a webhook holding the signing secret.
  const respSig = res.header('x-tv-response-signature');
  const signed = ['response', nonce, sha256Hex(text)].join('\n');
  const verified = config.webhookAcceptedSecrets.some((secret) => safeEqualHex(hmacHex(secret, signed), respSig));
  if (res.status !== 401 && !verified) {
    throw new WebhookUnavailableError('BAD_SIGNATURE', 'Webhook response signature could not be verified');
  }
  let json: any = {};
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = {};
  }
  return { status: res.status, body: json as T, latencyMs, tls: res.peer };
}
