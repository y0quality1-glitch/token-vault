import type { SignedDefinition } from '../providers/canonical';
import type { CatalogCache } from '../providers/catalog-sync';
import { definitionDigest, parsePinnedKeys, verifySignedSecretType, type PinnedKeys } from '../providers/signing';
import { validateSecretTypeDefinition, type SecretTypeDefinition, type SecretTypeDefinitionInput } from './schema';

/**
 * The secret types a service trusts (Node only; import "@token-vault/shared/secret-type-sync").
 * Every type comes from the CMS catalog at <url>/secret-types and must verify against the
 * pinned CMS key under the secret-type signature context. A snapshot with any bad entry is
 * rejected as a whole, and a version lower than one already accepted is refused (an old,
 * looser type could otherwise be replayed), also across restarts when a cache is given.
 */
export interface SecretTypeEntry {
  definition: SecretTypeDefinition;
  digest: string;
}

export interface SecretTypeSyncStatus {
  url: string;
  keyIds: string[];
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  types: number;
  refused: string[];
}

export interface SecretTypeSyncOptions {
  /** e.g. http://localhost:4200/catalog/v1 */
  url: string;
  publicKeyPem: string;
  intervalMs?: number;
  log?: (msg: string) => void;
  fetchImpl?: typeof fetch;
  cache?: CatalogCache;
}

export class SecretTypeRegistry {
  #types = new Map<string, SecretTypeEntry>();
  #highWater = new Map<string, number>();

  /**
   * A registry holding the predefined types, for a service run without a CMS
   * (CMS_CATALOG_URL unset). With a CMS, only verified catalog types are trusted.
   */
  static bundled(inputs: readonly SecretTypeDefinitionInput[]): SecretTypeRegistry {
    const r = new SecretTypeRegistry();
    r.apply(inputs.map((i) => {
      const definition = validateSecretTypeDefinition(i);
      return { definition, digest: definitionDigest(definition) };
    }));
    return r;
  }

  get(key: string): SecretTypeDefinition | undefined {
    return this.#types.get(key)?.definition;
  }
  entry(key: string): SecretTypeEntry | undefined {
    return this.#types.get(key);
  }
  list(): SecretTypeDefinition[] {
    return [...this.#types.values()].map((e) => e.definition).sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
  }
  highWater(): Record<string, number> {
    return Object.fromEntries(this.#highWater);
  }
  restoreHighWater(hw: Record<string, number>) {
    for (const [k, v] of Object.entries(hw)) if (Number.isInteger(v) && v > (this.#highWater.get(k) ?? 0)) this.#highWater.set(k, v);
  }

  /**
   * Replaces the set with a verified snapshot. Types missing from it are removed (unpublished
   * or archived); a lower version than one accepted before keeps the newer one.
   */
  apply(entries: SecretTypeEntry[]): { added: string[]; updated: string[]; removed: string[]; refused: string[] } {
    const out = { added: [] as string[], updated: [] as string[], removed: [] as string[], refused: [] as string[] };
    const next = new Map<string, SecretTypeEntry>();
    for (const e of entries) {
      const key = e.definition.key;
      const high = this.#highWater.get(key) ?? 0;
      const current = this.#types.get(key);
      if (e.definition.version < high) {
        out.refused.push(`${key} v${e.definition.version} (already accepted v${high})`);
        if (current) next.set(key, current);
        continue;
      }
      this.#highWater.set(key, e.definition.version);
      next.set(key, e);
      if (!current) out.added.push(`${key} v${e.definition.version}`);
      else if (current.digest !== e.digest) out.updated.push(`${key} v${e.definition.version}`);
    }
    for (const key of this.#types.keys()) if (!next.has(key)) out.removed.push(key);
    this.#types = next;
    return out;
  }
}

export class SecretTypeSync {
  readonly registry = new SecretTypeRegistry();
  readonly status: SecretTypeSyncStatus;
  #keys: PinnedKeys;
  #etag: string | null = null;
  #timer: NodeJS.Timeout | null = null;
  #inFlight: Promise<void> | null = null;
  #envelopes: SignedDefinition[] = [];

  constructor(private opts: SecretTypeSyncOptions) {
    this.#keys = parsePinnedKeys(opts.publicKeyPem);
    this.status = { url: opts.url, keyIds: [...this.#keys.keys()], lastAttemptAt: null, lastSuccessAt: null, lastError: null, types: 0, refused: [] };
  }

  /** Fetches and applies the secret types once. Never throws; failures are recorded in status. */
  refresh(): Promise<void> {
    this.#inFlight ??= this.#refresh().finally(() => {
      this.#inFlight = null;
    });
    return this.#inFlight;
  }

  #verifyAll(envelopes: SignedDefinition[]): SecretTypeEntry[] {
    const verified = envelopes.map((env) => {
      try {
        return { definition: verifySignedSecretType(env, this.#keys), digest: env.digest };
      } catch (e) {
        const key = (env?.definition as { key?: unknown } | undefined)?.key;
        throw new Error(`secret type ${typeof key === 'string' ? key : '(unknown)'} rejected: ${(e as Error).message}`);
      }
    });
    const keys = verified.map((v) => v.definition.key);
    if (new Set(keys).size !== keys.length) throw new Error('catalog lists a secret type twice');
    return verified;
  }

  async #refresh() {
    const log = this.opts.log ?? (() => undefined);
    this.status.lastAttemptAt = new Date().toISOString();
    try {
      const res = await (this.opts.fetchImpl ?? fetch)(`${this.opts.url.replace(/\/$/, '')}/secret-types`, {
        headers: { accept: 'application/json', ...(this.#etag ? { 'if-none-match': this.#etag } : {}) },
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      if (res.status !== 304) {
        if (!res.ok) throw new Error(`catalog responded HTTP ${res.status}`);
        const body = (await res.json()) as { secret_types?: SignedDefinition[] };
        if (!Array.isArray(body.secret_types)) throw new Error('catalog response has no secret_types array');
        const update = this.registry.apply(this.#verifyAll(body.secret_types));
        await this.#persist(body.secret_types);
        this.#etag = res.headers.get('etag');
        this.status.refused = update.refused;
        const changes = [...update.added.map((x) => `+${x}`), ...update.updated.map((x) => `~${x}`), ...update.removed.map((x) => `-${x}`)];
        if (changes.length) log(`secret types applied: ${changes.join(' ')}`);
        if (update.refused.length) log(`secret types refused (version downgrade): ${update.refused.join(', ')}`);
      }
      this.status.types = this.registry.list().length;
      this.status.lastSuccessAt = new Date().toISOString();
      this.status.lastError = null;
    } catch (e) {
      this.status.lastError = (e as Error).message;
      log(`secret type sync failed: ${this.status.lastError} (keeping ${this.registry.list().length} known types)`);
    }
  }

  /** Persists the envelopes behind the registry's entries (never a refused older one). */
  async #persist(fetched: SignedDefinition[]) {
    const candidates = [...fetched, ...this.#envelopes];
    this.#envelopes = this.registry
      .list()
      .map((d) => candidates.find((e) => e.digest === this.registry.entry(d.key)!.digest))
      .filter((e): e is SignedDefinition => !!e);
    if (!this.opts.cache) return;
    try {
      await this.opts.cache.save({ envelopes: this.#envelopes, highWater: this.registry.highWater(), savedAt: new Date().toISOString() });
    } catch (e) {
      (this.opts.log ?? (() => undefined))(`could not persist the secret types: ${(e as Error).message}`);
    }
  }

  /** Restores the persisted types, verified again against the pinned key. */
  async restore(): Promise<void> {
    const log = this.opts.log ?? (() => undefined);
    if (!this.opts.cache) return;
    try {
      const state = await this.opts.cache.load();
      if (!state) return;
      this.registry.restoreHighWater(state.highWater);
      this.registry.apply(this.#verifyAll(state.envelopes));
      this.#envelopes = state.envelopes;
      this.status.types = this.registry.list().length;
    } catch (e) {
      log(`persisted secret types ignored: ${(e as Error).message}`);
    }
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
