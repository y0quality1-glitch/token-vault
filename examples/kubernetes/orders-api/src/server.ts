/**
 * orders-api: an example Node service, deployed on Kubernetes, that uses Token Vault.
 *
 * Its configuration arrives as environment variables at boot, from your secrets manager via
 * External Secrets (or, locally, a Kubernetes Secret generated from a file):
 *   DATABASE_URL          the service's own database (an example of app config; unused here)
 *   TOKEN_VAULT_URL       Token Vault control plane, e.g. https://tokenvault.internal
 *   TOKEN_VAULT_API_KEY   this service's Token Vault agent key (tvak_…), its only provider-facing secret
 *   SLACK_INTEGRATION_ID  the Slack integration to post through, e.g. int_…
 *   SLACK_CHANNEL         channel to post to, e.g. C0123456789
 *   PORT                  default 8080
 *
 * There is no Slack token here: the service asks Token Vault to post, and the customer webhook
 * attaches the token. Rotating the Slack token needs no redeploy; a compromised pod cannot leak it.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { AccessDeniedError, AuthenticationError, TokenVault, TokenVaultError } from '@token-vault/sdk';

// ---------------------------------------------------------------- configuration (fail fast at boot)

function required(name: string): string {
  const v = process.env[name]?.trim();
  if (!v) {
    console.error(`[orders-api] missing required environment variable ${name}; check the ExternalSecret / Secret for this deployment`);
    process.exit(1);
  }
  return v;
}

const config = {
  port: Number(process.env.PORT ?? 8080),
  databaseUrl: required('DATABASE_URL'),
  slackIntegrationId: required('SLACK_INTEGRATION_ID'),
  slackChannel: required('SLACK_CHANNEL'),
};
required('TOKEN_VAULT_URL');
required('TOKEN_VAULT_API_KEY');

// Provider keys do not belong in this pod: they live in the Token Vault webhook.
for (const name of ['SLACK_BOT_TOKEN', 'SLACK_TOKEN', 'STRIPE_SECRET_KEY', 'GITHUB_TOKEN', 'OPENAI_API_KEY']) {
  if (process.env[name]) console.warn(`[orders-api] ${name} is set but unused: provider credentials belong in Token Vault, not in the pod's environment. Remove it from the secret.`);
}

const tv = new TokenVault({
  // Logged once per expiry, when a rotated key is still used during its grace period.
  onKeyExpiry: (at) => console.warn(`[orders-api] this Token Vault key was rotated and stops working at ${at}; the ExternalSecret should deliver the new key, then restart the pods`),
});

// ---------------------------------------------------------------- HTTP

const json = (res: ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
};

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 16_384) throw new Error('body too large');
  }
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
}

/** Readiness: config is present and Token Vault accepts our key (cached for 30 s, so probes stay cheap). */
let ready: { ok: boolean; at: number; detail: string } = { ok: false, at: 0, detail: 'not checked yet' };
async function checkReady() {
  if (Date.now() - ready.at < 30_000) return ready;
  try {
    const caps = await tv.capabilities();
    const granted = caps.grants.some((g) => g.integration_id === config.slackIntegrationId && g.status === 'ACTIVE');
    ready = { ok: true, at: Date.now(), detail: granted ? 'Token Vault reachable; Slack grant active' : 'Token Vault reachable; no active grant for the Slack integration yet' };
  } catch (e) {
    ready = { ok: false, at: Date.now(), detail: e instanceof TokenVaultError ? `Token Vault: ${e.code}` : 'Token Vault unreachable' };
  }
  return ready;
}

async function orderPaid(req: IncomingMessage, res: ServerResponse, orderId: string) {
  const body = await readJson(req);
  const amount = typeof body.amount === 'string' ? body.amount : '';
  try {
    const r = await tv.execute({
      integrationId: config.slackIntegrationId,
      operation: 'slack.messages.post',
      resource: { channel: config.slackChannel },
      input: { text: `Order ${orderId} paid${amount ? ` (${amount})` : ''}` },
      idempotencyKey: `order-paid-${orderId}`, // a retried request posts once
    });
    json(res, 200, { notified: true, slack: r.data, tokenVaultRequestId: r.requestId, simulated: r.simulated });
  } catch (e) {
    // The order is still paid; the notification is best effort. Report why, never any credential.
    if (e instanceof AccessDeniedError) return json(res, 202, { notified: false, reason: e.code, tokenVaultRequestId: e.requestId });
    if (e instanceof AuthenticationError) return json(res, 503, { notified: false, reason: 'TOKEN_VAULT_KEY_REJECTED' });
    json(res, 502, { notified: false, reason: e instanceof TokenVaultError ? e.code : 'UNEXPECTED_ERROR' });
  }
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/healthz') return json(res, 200, { status: 'ok' });
    if (req.method === 'GET' && url.pathname === '/readyz') {
      const r = await checkReady();
      return json(res, r.ok ? 200 : 503, { ready: r.ok, detail: r.detail });
    }
    const paid = /^\/orders\/([A-Za-z0-9_-]{1,64})\/paid$/.exec(url.pathname);
    if (req.method === 'POST' && paid) return await orderPaid(req, res, paid[1]!);
    json(res, 404, { error: 'not found' });
  } catch {
    json(res, 400, { error: 'bad request' });
  }
});

server.listen(config.port, () => {
  // Never log configuration values: key id only.
  console.log(`[orders-api] listening on :${config.port}; Token Vault ${tv.baseUrl} (key ${tv.keyId}); Slack via ${config.slackIntegrationId}`);
});

// Kubernetes sends SIGTERM on rollout: finish in-flight requests, then exit.
process.on('SIGTERM', () => {
  console.log('[orders-api] SIGTERM: draining');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
});
