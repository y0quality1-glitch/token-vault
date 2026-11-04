import { config } from '../../config';
import { hmacHex, safeEqualHex, sha256Hex } from '../../lib/crypto';
import { nonce as newNonce } from '../../lib/ids';
import type { WebhookRecord } from '../../store/types';

/**
 * Credential Broker transport: signed, short-lived control plane -> customer webhook calls.
 *
 * canonical = METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA256(body)    (HMAC-SHA256, shared secret from env)
 * Responses are verified with x-tv-response-signature bound to the request nonce.
 *
 * POC simplification: shared-secret HMAC. Production design: mTLS or asymmetric signatures.
 */
export class WebhookUnavailableError extends Error {
  constructor(public reason: 'TIMEOUT' | 'UNREACHABLE' | 'SIMULATED_OUTAGE' | 'BAD_SIGNATURE' | 'NOT_VERIFIED', message: string) {
    super(message);
  }
}

export interface WebhookResponse<T = any> {
  status: number;
  body: T;
  latencyMs: number;
}

export async function callWebhook<T = any>(webhook: Pick<WebhookRecord, 'endpointUrl' | 'simulateOutage'>, method: 'GET' | 'POST', path: string, payload?: unknown): Promise<WebhookResponse<T>> {
  if (webhook.simulateOutage) {
    throw new WebhookUnavailableError('SIMULATED_OUTAGE', 'Customer webhook unavailable (simulated outage enabled)');
  }
  const body = payload === undefined ? '' : JSON.stringify(payload);
  const timestamp = String(Date.now());
  const nonce = newNonce();
  const signature = hmacHex(config.webhookSigningSecret, [method, path, timestamp, nonce, sha256Hex(body)].join('\n'));
  const url = new URL(path, webhook.endpointUrl.endsWith('/') ? webhook.endpointUrl : webhook.endpointUrl + '/');

  const started = Date.now();
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: {
        'content-type': 'application/json',
        'x-tv-timestamp': timestamp,
        'x-tv-nonce': nonce,
        'x-tv-signature': signature,
      },
      body: method === 'GET' ? undefined : body,
      signal: AbortSignal.timeout(config.webhookTimeoutMs),
    });
  } catch (e) {
    const err = e as Error;
    if (err.name === 'TimeoutError') throw new WebhookUnavailableError('TIMEOUT', `Customer webhook did not respond within ${config.webhookTimeoutMs} ms`);
    throw new WebhookUnavailableError('UNREACHABLE', `Customer webhook at ${url.origin} is unreachable`);
  }
  const text = await res.text();
  const latencyMs = Date.now() - started;

  // Verify the response really came from a webhook holding the signing secret.
  const respSig = res.headers.get('x-tv-response-signature') ?? '';
  const expected = hmacHex(config.webhookSigningSecret, ['response', nonce, sha256Hex(text)].join('\n'));
  if (res.status !== 401 && !safeEqualHex(expected, respSig)) {
    throw new WebhookUnavailableError('BAD_SIGNATURE', 'Webhook response signature could not be verified');
  }
  let json: any = {};
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = {};
  }
  return { status: res.status, body: json as T, latencyMs };
}
