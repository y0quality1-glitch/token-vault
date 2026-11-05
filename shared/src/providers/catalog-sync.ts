import type { SignedDefinition } from './canonical';
import type { ProviderRegistry, RegistryUpdate } from './registry';
import { parsePinnedKeys, verifySignedDefinition, type PinnedKeys } from './signing';

/**
 * Keeps a ProviderRegistry in step with the CMS catalog (Node only; import
 * "@token-vault/shared/catalog-sync"). Every definition must verify against the pinned
 * CMS public key; if any entry in a snapshot fails, the whole snapshot is rejected and
 * the registry keeps what it had (a partially applied catalog could silently drop or
 * downgrade providers).
 */
/**
 * Durable state for a service's catalog: the signed envelopes it accepted (re-verified
 * on load, so a modified row cannot inject a definition) and the highest version
 * accepted per provider (so a replayed older version stays refused after a restart).
 */
export interface CatalogState {
  envelopes: SignedDefinition[];
  highWater: Record<string, number>;
  savedAt: string;
}

export interface CatalogCache {
  load(): Promise<CatalogState | null>;
  save(state: CatalogState): Promise<void>;
}

export interface CatalogSyncOptions {
  /** e.g. http://localhost:4200/catalog/v1 */
  url: string;
  /** One or more pinned CMS public keys (PEM, concatenated during a key rotation). */
  publicKeyPem: string;
  registry: ProviderRegistry;
  intervalMs?: number;
  log?: (msg: string) => void;
  fetchImpl?: typeof fetch;
  /** Persists the last verified catalog; without it the state lives only in memory. */
  cache?: CatalogCache;
}

export interface CatalogSyncStatus {
  url: string;
  /** Ids of the pinned CMS keys. */
  keyIds: string[];
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lastUpdate: RegistryUpdate | null;
  /** Set when definitions were restored from the persisted catalog at start-up. */
  restored: { savedAt: string; providers: string[] } | null;
  lastPersistError: string | null;
}

export class CatalogSync {
  #etag: string | null = null;
  #timer: NodeJS.Timeout | null = null;
  #inFlight: Promise<void> | null = null;
  /** Envelopes behind the registry's catalog entries, by provider key. */
  #accepted = new Map<string, SignedDefinition>();
  readonly status: CatalogSyncStatus;
  #keys: PinnedKeys;

  constructor(private opts: CatalogSyncOptions) {
    this.#keys = parsePinnedKeys(opts.publicKeyPem); // throws on a missing or malformed pinned key
    this.status = { url: opts.url, keyIds: [...this.#keys.keys()], lastAttemptAt: null, lastSuccessAt: null, lastError: null, lastUpdate: null, restored: null, lastPersistError: null };
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
      const verified = this.#verifyAll(body.definitions);
      const update = this.opts.registry.applyCatalog(verified);
      await this.#persist(body.definitions);
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

  /** Verifies a complete snapshot; any bad entry rejects all of it. */
  #verifyAll(envelopes: SignedDefinition[]) {
    const verified = envelopes.map((env) => {
      try {
        return { definition: verifySignedDefinition(env, this.#keys), digest: env.digest };
      } catch (e) {
        const key = (env?.definition as { key?: unknown } | undefined)?.key;
        throw new Error(`definition ${typeof key === 'string' ? key : '(unknown)'} rejected: ${(e as Error).message}`);
      }
    });
    const keys = verified.map((v) => v.definition.key);
    if (new Set(keys).size !== keys.length) throw new Error('catalog lists a provider twice');
    return verified;
  }

  /** Saves exactly what the registry accepted (never a refused, older envelope). */
  async #persist(envelopes: SignedDefinition[]) {
    if (!this.opts.cache) return;
    const registry = this.opts.registry;
    // Keep the envelope behind every catalog entry the registry holds, including a newer
    // one kept when this snapshot offered an older (refused) version.
    const candidates = [...envelopes, ...this.#accepted.values()];
    this.#accepted = new Map();
    for (const entry of registry.list()) {
      if (entry.source !== 'catalog') continue;
      const env = candidates.find((e) => e.digest === entry.digest);
      if (env) this.#accepted.set(entry.definition.key, env);
    }
    const accepted = [...this.#accepted.values()];
    try {
      await this.opts.cache.save({ envelopes: accepted, highWater: registry.highWater(), savedAt: new Date().toISOString() });
      this.status.lastPersistError = null;
    } catch (e) {
      this.status.lastPersistError = (e as Error).message;
      (this.opts.log ?? (() => undefined))(`could not persist the catalog: ${this.status.lastPersistError}`);
    }
  }

  /**
   * Restores the persisted catalog: high-water marks first, then the envelopes, which are
   * verified again against the pinned key. If they no longer verify (for example the key
   * was changed), they are ignored and only the bundled definitions apply until the CMS
   * answers.
   */
  async restore(): Promise<void> {
    const { cache, registry } = this.opts;
    const log = this.opts.log ?? (() => undefined);
    if (!cache) return;
    let state: CatalogState | null;
    try {
      state = await cache.load();
    } catch (e) {
      log(`could not read the persisted catalog: ${(e as Error).message}`);
      return;
    }
    if (!state) return;
    registry.restoreHighWater(state.highWater);
    try {
      const verified = this.#verifyAll(state.envelopes);
      registry.applyCatalog(verified);
      for (const env of state.envelopes) this.#accepted.set((env.definition as { key: string }).key, env);
      this.status.restored = { savedAt: state.savedAt, providers: verified.map((v) => `${v.definition.key} v${v.definition.version}`) };
      if (verified.length) log(`restored ${this.status.restored.providers.join(', ')} from the persisted catalog (saved ${state.savedAt})`);
    } catch (e) {
      log(`persisted catalog ignored: ${(e as Error).message}`);
    }
  }

  #ok() {
    this.status.lastSuccessAt = new Date().toISOString();
    this.status.lastError = null;
  }

  async start(): Promise<void> {
    await this.restore();
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
