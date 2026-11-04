import { githubDefinition } from './github.definition';
import { validateProviderDefinition, type OperationDefinition, type ProviderDefinition } from './schema';

/**
 * Provider definitions bundled with this build. Validated at load time, so an invalid
 * definition fails fast in every service instead of at request time.
 * (Later: pulled from the CMS as signed, versioned documents.)
 */
export const PROVIDER_DEFINITIONS: readonly ProviderDefinition[] = [validateProviderDefinition(githubDefinition)];

export function getProviderDefinition(key: string): ProviderDefinition | undefined {
  return PROVIDER_DEFINITIONS.find((d) => d.key === key);
}

/** Finds an operation together with the definition that owns it. */
export function findOperation(operationId: string): { definition: ProviderDefinition; operation: OperationDefinition } | undefined {
  for (const definition of PROVIDER_DEFINITIONS) {
    const operation = definition.operations.find((o) => o.id === operationId);
    if (operation) return { definition, operation };
  }
  return undefined;
}
