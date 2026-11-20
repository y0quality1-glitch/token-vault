import { useSyncExternalStore } from 'react';
import { OPERATIONS, type OperationDef, type ProviderInfo, type ProvidersResponse } from '@token-vault/shared';
import { api } from './api';

/**
 * Providers and operations as the control plane currently trusts them (bundled or
 * verified from the CMS catalog). Starts with the bundled set so labels render
 * immediately, then loads /providers once an organization is selected.
 */
interface State {
  providers: ProviderInfo[];
  operations: OperationDef[];
  catalog: ProvidersResponse['catalog'];
  loaded: boolean;
}

let state: State = { providers: [], operations: OPERATIONS, catalog: null, loaded: false };
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((fn) => fn());

export async function loadProviders(): Promise<void> {
  const r = await api.post<ProvidersResponse>('/provider/getall');
  state = { providers: r.providers, operations: r.providers.flatMap((p) => p.operations), catalog: r.catalog, loaded: true };
  emit();
}

export function useProviders() {
  const s = useSyncExternalStore(
    (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    () => state,
  );
  return { ...s, grantable: s.operations.filter((o) => o.grantable) };
}

export const getOperation = (id: string): OperationDef | undefined => state.operations.find((o) => o.id === id);
export const operationLabel = (id: string): string => getOperation(id)?.label ?? id;
export const getProvider = (key: string): ProviderInfo | undefined => state.providers.find((p) => p.key === key);
