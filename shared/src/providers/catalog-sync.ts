import { createPublicKey } from 'node:crypto';
import type { SignedDefinition } from './canonical';
import type { ProviderRegistry, RegistryUpdate } from './registry';
import { publicKeyId, verifySignedDefinition } from './signing';

/**
 * Keeps a ProviderRegistry in step with the CMS catalog (Node only; import
 * "@token-vault/shared/catalog-sync"). Every definition must verify against the pinned
 * CMS public key; if any entry in a snapshot fails, the whole snapshot is rejected and
 * the registry keeps what it had (a partially applied catalog could silently drop or
 * downgrade providers).
 */
export interface CatalogSyncOptions {
  /** e.g. http://localhost:4200/catalog/v1 */
  url: string;
  publicKeyPem: string;
  registry: ProviderRegistry;
  intervalMs?: number;
  log?: (msg: string) => void;
  fetchImpl?: typeof fetch;
}

export interface CatalogSyncStatus {
  url: string;
  keyId: string;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lastUpdate: RegistryUpdate | null;
}

export class CatalogSync {
  #etag: string | null = null;
  #timer: NodeJS.Timeout | null = null;
  #inFlight: Promise<void> | null = null;
  readonly status: CatalogSyncStatus;

  constructor(private opts: CatalogSyncOptions) {
    const keyId = publicKeyId(createPublicKey(opts.publicKeyPem)); // throws on a malformed pinned key
    this.status = { url: opts.url, keyId, lastAttemptAt: null, lastSuccessAt: null, lastError: null, lastUpdate: null };
  }

  /** Fetches and applies the catalog once. Never throws; failures are recorded in status. */
  refresh(): Promise<void> {
    this.#inFlight ??= this.#refresh().finally(() => {
      this.#inFlight = null;
    });
    return this.#inFlight;
  }

  async #refresh() {
    const log = this.opts.log ?? (() => undefined);
    this.status.lastAttemptAt = new Date().toISOString();
    try {
      const res = await (this.opts.fetchImpl ?? fetch)(`${this.opts.url.replace(/\/$/, '')}/definitions`, {
        headers: { accept: 'application/json', ...(this.#etag ? { 'if-none-match': this.#etag } : {}) },
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      if (res.status === 304) {
        this.#ok();
        return;
      }
      if (!res.ok) throw new Error(`catalog responded HTTP ${res.status}`);
      const body = (await res.json()) as { definitions?: SignedDefinition[] };
      if (!Array.isArray(body.definitions)) throw new Error('catalog response has no definitions array');
      const verified = body.definitions.map((env) => {
        try {
          return { definition: verifySignedDefinition(env, this.opts.publicKeyPem), digest: env.digest };
        } catch (e) {
          const key = (env?.definition as { key?: unknown } | undefined)?.key;
          throw new Error(`definition ${typeof key === 'string' ? key : '(unknown)'} rejected: ${(e as Error).message}`);
        }
      });
      const keys = verified.map((v) => v.definition.key);
      if (new Set(keys).size !== keys.length) throw new Error('catalog lists a provider twice');
      const update = this.opts.registry.applyCatalog(verified);
      this.#etag = res.headers.get('etag');
      this.status.lastUpdate = update;
      const changes = [...update.added.map((x) => `+${x}`), ...update.updated.map((x) => `~${x}`), ...update.removed.map((x) => `-${x}`)];
      if (changes.length) log(`catalog applied: ${changes.join(' ')}`);
      if (update.refused.length) log(`catalog refused (version downgrade): ${update.refused.join(', ')}`);
      this.#ok();
    } catch (e) {
      this.status.lastError = (e as Error).message;
      log(`catalog sync failed: ${this.status.lastError} (keeping ${this.opts.registry.list().length} known definitions)`);
    }
  }

  #ok() {
    this.status.lastSuccessAt = new Date().toISOString();
    this.status.lastError = null;
  }

  start(): Promise<void> {
    const first = this.refresh();
    this.#timer = setInterval(() => void this.refresh(), this.opts.intervalMs ?? 30_000);
    this.#timer.unref();
    return first;
  }

  stop() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }
}
