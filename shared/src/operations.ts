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
}

export const OPERATIONS: OperationDef[] = [
  {
    id: 'github.repositories.read',
    provider: 'github',
    label: 'Read repository metadata',
    description: 'GET /repos/{owner}/{repo}',
    grantable: true,
    destructive: false,
    mutating: false,
    requiresRepository: true,
  },
  {
    id: 'github.contents.read',
    provider: 'github',
    label: 'Read repository contents',
    description: 'GET /repos/{owner}/{repo}/contents/{path}',
    grantable: true,
    destructive: false,
    mutating: false,
    requiresRepository: true,
  },
  {
    id: 'github.issues.list',
    provider: 'github',
    label: 'List issues',
    description: 'GET /repos/{owner}/{repo}/issues',
    grantable: true,
    destructive: false,
    mutating: false,
    requiresRepository: true,
  },
  {
    id: 'github.issues.create',
    provider: 'github',
    label: 'Create issue',
    description: 'POST /repos/{owner}/{repo}/issues',
    grantable: true,
    destructive: false,
    mutating: true,
    requiresRepository: true,
  },
  // Recognised by the policy engine (so it can deny them explicitly) but never grantable in the POC.
  {
    id: 'github.repositories.delete',
    provider: 'github',
    label: 'Delete repository',
    description: 'DELETE /repos/{owner}/{repo} (destructive, never grantable)',
    grantable: false,
    destructive: true,
    mutating: true,
    requiresRepository: true,
  },
  {
    id: 'github.contents.write',
    provider: 'github',
    label: 'Write repository contents',
    description: 'PUT /repos/{owner}/{repo}/contents/{path} (destructive, never grantable)',
    grantable: false,
    destructive: true,
    mutating: true,
    requiresRepository: true,
  },
];

export const GRANTABLE_OPERATIONS = OPERATIONS.filter((o) => o.grantable);

export function getOperation(id: string): OperationDef | undefined {
  return OPERATIONS.find((o) => o.id === id);
}

export function operationLabel(id: string): string {
  return getOperation(id)?.label ?? id;
}

export const PROVIDER_CATALOG: { provider: ProviderId; name: string; description: string; authMethods: string[]; available: boolean }[] = [
  {
    provider: 'github',
    name: 'GitHub',
    description: 'Repositories, contents and issues via the GitHub REST API. Fully implemented POC connector.',
    authMethods: ['GitHub App', 'Personal Access Token'],
    available: true,
  },
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
