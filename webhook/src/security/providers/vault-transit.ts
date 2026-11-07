import { readFileSync } from 'node:fs';
import { KeyAccessDeniedError, KeyServiceUnavailableError, type KeyProvider } from '../key-provider';

export interface VaultTransitOptions {
  addr: string;
  mount: string;
  key: string;
  /** Static token (VAULT_TOKEN). Prefer Kubernetes auth in clusters. */
  token?: string;
  /** Kubernetes auth: role, auth mount and the service-account token file. */
  k8sRole?: string;
  k8sMount?: string;
  k8sTokenPath?: string;
  /** Vault Enterprise namespace. */
  namespace?: string;
  timeoutMs?: number;
}

/**
 * HashiCorp Vault (or OpenBao) Transit: data keys are encrypted with a Transit key that never
 * leaves Vault. The webhook needs only "update" on <mount>/encrypt/<key> and <mount>/decrypt/<key>.
 * Records carry "vault-transit:<mount>/<key>", so a record still opens after the configured key
 * changes (Transit's own key versions are handled by Vault: rotate the key there, then rewrap).
 */
export function vaultTransitProvider(opts: VaultTransitOptions): KeyProvider {
  const base = opts.addr.replace(/\/+$/, '');
  const timeoutMs = opts.timeoutMs ?? 2000;
  let token = opts.token ?? '';
  let tokenExpires = opts.token ? Infinity : 0;

  async function call(path: string, body: unknown, auth = true): Promise<{ status: number; json: any }> {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (auth) headers['x-vault-token'] = token;
    if (opts.namespace) headers['x-vault-namespace'] = opts.namespace;
    let res: Response;
    try {
      res = await fetch(`${base}/v1/${path}`, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) {
      throw new KeyServiceUnavailableError(`Vault at ${new URL(base).host} is unreachable (${(e as Error).name})`);
    }
    const json = await res.json().catch(() => ({}));
    return { status: res.status, json };
  }

  async function login(force = false) {
    if (!opts.k8sRole) {
      if (!token) throw new KeyServiceUnavailableError('no Vault token configured (VAULT_TOKEN or VAULT_K8S_ROLE)');
      return;
    }
    if (!force && token && Date.now() < tokenExpires) return;
    let jwt: string;
    try {
      jwt = readFileSync(opts.k8sTokenPath ?? '/var/run/secrets/kubernetes.io/serviceaccount/token', 'utf8').trim();
    } catch {
      throw new KeyServiceUnavailableError('the Kubernetes service-account token is not mounted');
    }
    const r = await call(`auth/${opts.k8sMount ?? 'kubernetes'}/login`, { role: opts.k8sRole, jwt }, false);
    if (r.status !== 200 || !r.json?.auth?.client_token) {
      throw r.status >= 500 ? new KeyServiceUnavailableError(`Vault login failed (HTTP ${r.status})`) : new KeyServiceUnavailableError(`Vault refused the Kubernetes login for role ${opts.k8sRole} (HTTP ${r.status})`);
    }
    token = r.json.auth.client_token;
    // Renew at 80% of the lease.
    tokenExpires = Date.now() + Math.max(30, Number(r.json.auth.lease_duration) || 300) * 800;
  }

  async function transit(op: 'encrypt' | 'decrypt', key: string, body: Record<string, string>) {
    await login();
    let r = await call(`${opts.mount}/${op}/${key}`, body);
    if (r.status === 403 && opts.k8sRole) {
      await login(true); // the token may have been revoked or expired early
      r = await call(`${opts.mount}/${op}/${key}`, body);
    }
    if (r.status === 200) return r.json.data as Record<string, string>;
    const detail = Array.isArray(r.json?.errors) ? String(r.json.errors[0] ?? '').slice(0, 120) : '';
    if (r.status >= 500 || r.status === 429) throw new KeyServiceUnavailableError(`Vault could not ${op} (HTTP ${r.status})`);
    throw new KeyAccessDeniedError(`Vault refused to ${op} (HTTP ${r.status}${detail ? `: ${detail}` : ''})`);
  }

  const ref = `vault-transit:${opts.mount}/${opts.key}`;
  const keyOf = (recordRef: string) => recordRef.slice('vault-transit:'.length).split('/').slice(1).join('/') || opts.key;
  return {
    kind: 'vault-transit',
    ref,
    handles: (r) => r.startsWith(`vault-transit:${opts.mount}/`),
    async wrap(dataKey) {
      const data = await transit('encrypt', opts.key, { plaintext: dataKey.toString('base64') });
      if (!data?.ciphertext?.startsWith('vault:')) throw new KeyServiceUnavailableError('Vault returned no ciphertext');
      return data.ciphertext;
    },
    async unwrap(wrapped, _context, recordRef) {
      const data = await transit('decrypt', keyOf(recordRef), { ciphertext: wrapped });
      if (!data?.plaintext) throw new KeyAccessDeniedError('Vault returned no plaintext');
      return Buffer.from(data.plaintext, 'base64');
    },
  };
}
