import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { TLSSocket } from 'node:tls';

/**
 * mTLS for the control plane -> webhook link.
 *
 *   WEBHOOK_TLS_CERT[_FILE], WEBHOOK_TLS_KEY[_FILE]   serve HTTPS with this certificate and key
 *   WEBHOOK_TLS_CLIENT_CA[_FILE]                       require a client certificate issued by this CA
 *                                                      on /internal/* (the control plane's)
 *   WEBHOOK_TLS_ALLOWED_CLIENTS                        optional, comma-separated: accept only these
 *                                                      identities, e.g. URI:spiffe://token-vault/control-plane,
 *                                                      DNS:control-plane.token-vault.svc, or CN=control-plane
 *
 * Liveness (/healthz) stays reachable without a client certificate (probes do not have one);
 * every /internal/* request is refused unless the client certificate checks out. The signed
 * request layer (HMAC, nonce, expiry, audience) stays on top of TLS.
 */
export interface TlsFiles {
  cert: string;
  key: string;
  clientCa?: string;
  /** File paths, when loaded from files (watched for rotation). */
  paths: { cert?: string; key?: string; clientCa?: string };
}

export interface TlsConfig extends TlsFiles {
  allowedClients: string[];
}

function pem(env: Record<string, string | undefined>, name: string): { value?: string; path?: string } {
  const path = env[`${name}_FILE`]?.trim();
  if (path) return { value: readFileSync(path, 'utf8'), path };
  const inline = env[name]?.trim();
  return { value: inline ? inline.replace(/\\n/g, '\n') : undefined };
}

/** Reads the TLS settings; null when HTTPS is not configured. Throws on half-configured or malformed settings. */
export function loadTlsConfig(env: Record<string, string | undefined>): TlsConfig | null {
  const cert = pem(env, 'WEBHOOK_TLS_CERT');
  const key = pem(env, 'WEBHOOK_TLS_KEY');
  const clientCa = pem(env, 'WEBHOOK_TLS_CLIENT_CA');
  const allowedClients = (env.WEBHOOK_TLS_ALLOWED_CLIENTS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!cert.value && !key.value) {
    if (clientCa.value || allowedClients.length) throw new Error('WEBHOOK_TLS_CLIENT_CA / WEBHOOK_TLS_ALLOWED_CLIENTS need WEBHOOK_TLS_CERT and WEBHOOK_TLS_KEY (HTTPS)');
    return null;
  }
  if (!cert.value || !key.value) throw new Error('set both WEBHOOK_TLS_CERT and WEBHOOK_TLS_KEY (or their _FILE variants)');
  try {
    new X509Certificate(cert.value);
    if (clientCa.value) new X509Certificate(clientCa.value);
  } catch {
    throw new Error('WEBHOOK_TLS_CERT / WEBHOOK_TLS_CLIENT_CA must be PEM certificates');
  }
  if (allowedClients.length && !clientCa.value) throw new Error('WEBHOOK_TLS_ALLOWED_CLIENTS needs WEBHOOK_TLS_CLIENT_CA');
  for (const id of allowedClients) {
    if (!/^(URI:|DNS:|CN=)\S+$/.test(id)) throw new Error(`WEBHOOK_TLS_ALLOWED_CLIENTS: "${id}" is not URI:…, DNS:… or CN=…`);
  }
  return { cert: cert.value, key: key.value, clientCa: clientCa.value, allowedClients, paths: { cert: cert.path, key: key.path, clientCa: clientCa.path } };
}

/** The identities a peer certificate carries: its subject alternative names and CN. */
export function certificateIdentities(peer: { subjectaltname?: string; subject?: { CN?: string | string[] } }): string[] {
  const sans = (peer.subjectaltname ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const cn = peer.subject?.CN;
  return [...sans, ...(cn ? [`CN=${Array.isArray(cn) ? cn[0] : cn}`] : [])];
}

export type ClientCheck = { ok: true; identity: string } | { ok: false; reason: string };

/** Whether the TLS client may call /internal/*: a certificate from the client CA, and (if listed) an allowed identity. */
export function checkClient(socket: TLSSocket, tls: TlsConfig): ClientCheck {
  if (!tls.clientCa) return { ok: true, identity: 'none (client certificates not required)' };
  const peer = socket.getPeerCertificate?.();
  if (!peer || !Object.keys(peer).length) return { ok: false, reason: 'a client certificate is required' };
  if (!socket.authorized) return { ok: false, reason: `the client certificate is not trusted (${socket.authorizationError ?? 'unknown issuer'})` };
  const ids = certificateIdentities(peer);
  if (!tls.allowedClients.length) return { ok: true, identity: ids[0] ?? 'unnamed' };
  const match = ids.find((id) => tls.allowedClients.includes(id));
  return match ? { ok: true, identity: match } : { ok: false, reason: 'the client certificate identity is not allowed' };
}

/** Non-secret description of the serving certificate (for the signed health response). */
export function describeCertificate(certPem: string) {
  const c = new X509Certificate(certPem);
  return { subject: c.subject.replace(/\n/g, ', '), issuer: c.issuer.replace(/\n/g, ', '), valid_to: new Date(c.validTo).toISOString(), fingerprint256: c.fingerprint256, subject_alt_names: c.subjectAltName ?? '' };
}

/** Re-reads certificate files every interval and calls back when they changed (cert-manager renewals). */
export function watchTlsFiles(tls: TlsConfig, onChange: (next: TlsFiles) => void, intervalMs = 60_000): NodeJS.Timeout | null {
  if (!tls.paths.cert && !tls.paths.key && !tls.paths.clientCa) return null;
  let last = `${tls.cert}|${tls.key}|${tls.clientCa ?? ''}`;
  const timer = setInterval(() => {
    try {
      const next: TlsFiles = {
        cert: tls.paths.cert ? readFileSync(tls.paths.cert, 'utf8') : tls.cert,
        key: tls.paths.key ? readFileSync(tls.paths.key, 'utf8') : tls.key,
        clientCa: tls.paths.clientCa ? readFileSync(tls.paths.clientCa, 'utf8') : tls.clientCa,
        paths: tls.paths,
      };
      const now = `${next.cert}|${next.key}|${next.clientCa ?? ''}`;
      if (now === last) return;
      new X509Certificate(next.cert); // a half-written file must not replace a working certificate
      last = now;
      Object.assign(tls, next);
      onChange(next);
    } catch {
      /* keep the current certificate; try again next round */
    }
  }, intervalMs);
  timer.unref();
  return timer;
}
