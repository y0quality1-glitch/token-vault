import { PROVIDER_DEFINITIONS } from './providers/registry';
import type { ProviderDefinition } from './providers/schema';
import type { ProviderId } from './types';

export interface OperationDef {
  id: string;
  provider: ProviderId;
  label: string;
  description: string;
  /**
   * Whether an administrator may grant this operation without further conditions (read and
   * write). Destructive operations can be granted only where a REQUIRE_APPROVAL policy covers
   * them, and agents can never request them just in time.
   */
  grantable: boolean;
  destructive: boolean;
  risk: 'read' | 'write' | 'destructive';
  mutating: boolean;
  requiresRepository: boolean;
  /** Anchored pattern the primary resource (e.g. "owner/repo") must match. */
  resourcePattern: string;
  /** Name and label of the primary resource grants are scoped to (e.g. "repository", "Repository"). */
  resourceName: string;
  resourceLabel: string;
}

/** Operations derived from a set of provider definitions. */
export function operationsOf(definitions: readonly ProviderDefinition[]): OperationDef[] {
  return definitions.flatMap((d) =>
    d.operations.map((o) => ({
      id: o.id,
      provider: d.key,
      label: o.label,
      description: o.description,
      grantable: o.risk !== 'destructive',
      destructive: o.risk === 'destructive',
      risk: o.risk,
      mutating: o.risk !== 'read',
      requiresRepository: o.requiresResource,
      resourcePattern: d.resource.pattern,
      resourceName: d.resource.name,
      resourceLabel: d.resource.label,
    })),
  );
}

/** Operations of the bundled definitions. Services use their ProviderRegistry instead. */
export const OPERATIONS: OperationDef[] = operationsOf(PROVIDER_DEFINITIONS);

export const GRANTABLE_OPERATIONS = OPERATIONS.filter((o) => o.grantable);

export function getOperation(id: string): OperationDef | undefined {
  return OPERATIONS.find((o) => o.id === id);
}

export function operationLabel(id: string): string {
  return getOperation(id)?.label ?? id;
}

/** A provider as listed in the Integration Catalog, entirely from its definition. */
export interface CatalogItem {
  provider: ProviderId;
  name: string;
  description: string;
  authMethods: string[];
  /** False for providers listed as "coming soon": shown, but they cannot be connected. */
  available: boolean;
  category: string;
  icon: string;
  docsUrl: string | null;
  tags: string[];
  version: number;
}

/** The catalog is derived from the definitions only (bundled, or published in the CMS). */
export function catalogOf(definitions: readonly ProviderDefinition[]): CatalogItem[] {
  return definitions
    .map((d) => ({
      provider: d.key,
      name: d.name,
      description: d.description,
      authMethods: d.auth.map((a) => a.label),
      available: d.catalog.availability === 'available',
      category: d.catalog.category,
      icon: d.catalog.icon,
      docsUrl: d.catalog.docsUrl ?? null,
      tags: d.catalog.tags,
      version: d.version,
    }))
    .sort((a, b) => Number(b.available) - Number(a.available) || a.name.localeCompare(b.name));
}

export const PROVIDER_CATALOG: CatalogItem[] = catalogOf(PROVIDER_DEFINITIONS);
