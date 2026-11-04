import { PROVIDER_DEFINITIONS } from './providers/registry';
import type { ProviderId } from './types';

export interface OperationDef {
  id: string;
  provider: ProviderId;
  label: string;
  description: string;
  /** Whether an administrator may include this operation in a grant (POC: no destructive ops). */
  grantable: boolean;
  destructive: boolean;
  mutating: boolean;
  requiresRepository: boolean;
  /** Anchored pattern the primary resource (e.g. "owner/repo") must match. */
  resourcePattern: string;
}

/** Derived from the provider definitions: adding an operation there adds it everywhere. */
export const OPERATIONS: OperationDef[] = PROVIDER_DEFINITIONS.flatMap((d) =>
  d.operations.map((o) => ({
    id: o.id,
    provider: d.key,
    label: o.label,
    description: o.description,
    grantable: o.risk !== 'destructive',
    destructive: o.risk === 'destructive',
    mutating: o.risk !== 'read',
    requiresRepository: o.requiresResource,
    resourcePattern: d.resource.pattern,
  })),
);

export const GRANTABLE_OPERATIONS = OPERATIONS.filter((o) => o.grantable);

export function getOperation(id: string): OperationDef | undefined {
  return OPERATIONS.find((o) => o.id === id);
}

export function operationLabel(id: string): string {
  return getOperation(id)?.label ?? id;
}

export const PROVIDER_CATALOG: { provider: ProviderId; name: string; description: string; authMethods: string[]; available: boolean }[] = [
  ...PROVIDER_DEFINITIONS.map((d) => ({ provider: d.key, name: d.name, description: d.description, authMethods: d.auth.map((a) => a.label), available: true })),
  {
    provider: 'google',
    name: 'Google Workspace',
    description: 'Drive, Calendar and Gmail APIs. Planned for a later phase.',
    authMethods: ['OAuth 2.0'],
    available: false,
  },
  {
    provider: 'slack',
    name: 'Slack',
    description: 'Post messages and read channels with a bot token. Planned for a later phase.',
    authMethods: ['OAuth 2.0', 'Bot token'],
    available: false,
  },
  {
    provider: 'openai',
    name: 'OpenAI',
    description: 'Model inference with an organization API key. Planned for a later phase.',
    authMethods: ['API key'],
    available: false,
  },
];
