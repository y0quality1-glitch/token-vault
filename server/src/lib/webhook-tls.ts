import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * The control plane's side of mTLS to customer webhooks.
 *
 *   WEBHOOK_TLS_CA[_FILE]                            CA(s) that issue webhook server certificates (default: system CAs)
 *   CONTROL_PLANE_TLS_CERT[_FILE], ..._KEY[_FILE]    client certificate presented to webhooks
 *   WEBHOOK_REQUIRE_TLS=true                          refuse http:// webhook URLs (registration and calls)
 *
 * Files are re-read when they change (cert-manager renewals); the next call uses them.
 */
export interface WebhookTls {
  ca?: string;
  cert?: string;
  key?: string;
  requireTls: boolean;
  paths: { ca?: string; cert?: string; key?: string };
}

function pem(env: Record<string, string | undefined>, name: string): { value?: string; path?: string } {
  const path = env[`${name}_FILE`]?.trim();
  if (path) return { value: readFileSync(path, 'utf8'), path };
  const inline = env[name]?.trim();
  return { value: inline ? inline.replace(/\\n/g, '\n') : undefined };
}

export function loadWebhookTls(env: Record<string, string | undefined>): WebhookTls {
  const ca = pem(env, 'WEBHOOK_TLS_CA');
  const cert = pem(env, 'CONTROL_PLANE_TLS_CERT');
  const key = pem(env, 'CONTROL_PLANE_TLS_KEY');
  if (!!cert.value !== !!key.value) throw new Error('set both CONTROL_PLANE_TLS_CERT and CONTROL_PLANE_TLS_KEY (or their _FILE variants)');
  try {
    if (ca.value) new X509Certificate(ca.value);
    if (cert.value) new X509Certificate(cert.value);
  } catch {
    throw new Error('WEBHOOK_TLS_CA / CONTROL_PLANE_TLS_CERT must be PEM certificates');
  }
  const flag = (env.WEBHOOK_REQUIRE_TLS ?? 'false').trim();
  if (flag !== 'true' && flag !== 'false') throw new Error('WEBHOOK_REQUIRE_TLS must be true or false');
  return { ca: ca.value, cert: cert.value, key: key.value, requireTls: flag === 'true', paths: { ca: ca.path, cert: cert.path, key: key.path } };
}

/** Re-reads changed files (at most once a minute); returns whether anything changed. */
let lastCheck = 0;
export function refreshWebhookTls(tls: WebhookTls, now = Date.now()): boolean {
  if (now - lastCheck < 60_000 || (!tls.paths.ca && !tls.paths.cert && !tls.paths.key)) return false;
  lastCheck = now;
  try {
    const next = {
      ca: tls.paths.ca ? readFileSync(tls.paths.ca, 'utf8') : tls.ca,
      cert: tls.paths.cert ? readFileSync(tls.paths.cert, 'utf8') : tls.cert,
      key: tls.paths.key ? readFileSync(tls.paths.key, 'utf8') : tls.key,
    };
    if (next.ca === tls.ca && next.cert === tls.cert && next.key === tls.key) return false;
    if (next.cert) new X509Certificate(next.cert); // a half-written file must not replace a working one
    Object.assign(tls, next);
    return true;
  } catch {
    return false;
  }
}
