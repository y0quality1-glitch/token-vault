import { githubDefinition } from './github.definition';
import { validateProviderDefinition, type OperationDefinition, type ProviderDefinition } from './schema';

/** Where a definition the registry holds came from. */
export type DefinitionSource = 'bundled' | 'catalog';

export interface RegistryEntry {
  definition: ProviderDefinition;
  source: DefinitionSource;
  /** sha256 of the canonical definition (catalog entries; null for bundled). */
  digest: string | null;
}

export interface RegistryUpdate {
  added: string[];
  updated: string[];
  removed: string[];
  /** Entries refused because they would lower a version already accepted. */
  refused: string[];
}

/**
 * The set of provider definitions a service currently trusts.
 *
 * - Bundled definitions (shipped and reviewed with the code) are the baseline.
 * - Verified catalog definitions (signed by the CMS) replace them by key and add new
 *   providers. A catalog version lower than one already accepted is refused, so an old
 *   signed definition cannot be replayed to roll a provider back.
 * - A provider that disappears from the catalog (archived in the CMS) is removed,
 *   unless it is bundled, in which case the bundled version applies again.
 */
export class ProviderRegistry {
  #entries = new Map<string, RegistryEntry>();
  #bundled: ProviderDefinition[];
  /** Highest catalog version accepted per key during this process's lifetime. */
  #highWater = new Map<string, number>();
  #listeners = new Set<() => void>();

  constructor(bundled: readonly ProviderDefinition[]) {
    this.#bundled = [...bundled];
    for (const d of bundled) this.#entries.set(d.key, { definition: d, source: 'bundled', digest: null });
  }

  list(): RegistryEntry[] {
    return [...this.#entries.values()].sort((a, b) => a.definition.key.localeCompare(b.definition.key));
  }

  definitions(): ProviderDefinition[] {
    return this.list().map((e) => e.definition);
  }

  get(key: string): ProviderDefinition | undefined {
    return this.#entries.get(key)?.definition;
  }

  entry(key: string): RegistryEntry | undefined {
    return this.#entries.get(key);
  }

  findOperation(operationId: string): { definition: ProviderDefinition; operation: OperationDefinition } | undefined {
    for (const { definition } of this.#entries.values()) {
      const operation = definition.operations.find((o) => o.id === operationId);
      if (operation) return { definition, operation };
    }
    return undefined;
  }

  /** Highest catalog version accepted per provider (persisted so rollbacks stay refused across restarts). */
  highWater(): Record<string, number> {
    return Object.fromEntries(this.#highWater);
  }

  /** Restores persisted high-water marks; never lowers a mark already held. */
  restoreHighWater(marks: Record<string, number>): void {
    for (const [key, v] of Object.entries(marks)) {
      if (Number.isInteger(v) && v > (this.#highWater.get(key) ?? 0)) this.#highWater.set(key, v);
    }
  }

  onChange(fn: () => void): () => void {
    this.#listeners.add(fn);
    return () => this.#listeners.delete(fn);
  }

  /** Replaces the catalog part with an already-verified, complete catalog snapshot. */
  applyCatalog(verified: { definition: ProviderDefinition; digest: string }[]): RegistryUpdate {
    const update: RegistryUpdate = { added: [], updated: [], removed: [], refused: [] };
    const incoming = new Map(verified.map((v) => [v.definition.key, v]));

    for (const [key, v] of incoming) {
      const high = this.#highWater.get(key) ?? 0;
      if (v.definition.version < high) {
        update.refused.push(`${key} v${v.definition.version} (already accepted v${high})`);
        continue;
      }
      const current = this.#entries.get(key);
      if (current?.source === 'catalog' && current.digest === v.digest) continue;
      this.#entries.set(key, { definition: v.definition, source: 'catalog', digest: v.digest });
      this.#highWater.set(key, v.definition.version);
      (current ? update.updated : update.added).push(`${key} v${v.definition.version}`);
    }

    for (const [key, current] of [...this.#entries]) {
      if (current.source !== 'catalog' || incoming.has(key)) continue;
      const bundled = this.#bundled.find((d) => d.key === key);
      if (bundled) this.#entries.set(key, { definition: bundled, source: 'bundled', digest: null });
      else this.#entries.delete(key);
      update.removed.push(key);
    }

    if (update.added.length || update.updated.length || update.removed.length) for (const fn of this.#listeners) fn();
    return update;
  }
}

/** Definitions shipped with this build (validated at load time). */
export const BUNDLED_DEFINITIONS: readonly ProviderDefinition[] = [validateProviderDefinition(githubDefinition)];
/** @deprecated use a ProviderRegistry; kept for code that only needs the bundled set. */
export const PROVIDER_DEFINITIONS = BUNDLED_DEFINITIONS;

export function getProviderDefinition(key: string): ProviderDefinition | undefined {
  return BUNDLED_DEFINITIONS.find((d) => d.key === key);
}

/** Finds an operation in the bundled definitions. */
export function findOperation(operationId: string): { definition: ProviderDefinition; operation: OperationDefinition } | undefined {
  for (const definition of BUNDLED_DEFINITIONS) {
    const operation = definition.operations.find((o) => o.id === operationId);
    if (operation) return { definition, operation };
  }
  return undefined;
}
