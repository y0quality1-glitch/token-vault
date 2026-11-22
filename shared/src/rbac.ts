import type { Role } from './types';

export const PERMISSIONS = {
  ORG_READ: 'org:read',
  ORG_MANAGE: 'org:manage',
  MEMBERS_MANAGE: 'members:manage',
  WEBHOOK_MANAGE: 'webhook:manage',
  INTEGRATION_MANAGE: 'integration:manage',
  AGENT_MANAGE: 'agent:manage',
  AGENT_MANAGE_ANY: 'agent:manage:any',
  GRANT_MANAGE: 'grant:manage',
  GRANT_REVOKE: 'grant:revoke',
  GRANT_APPROVE: 'grant:approve',
  POLICY_MANAGE: 'policy:manage',
  AUDIT_READ: 'audit:read',
  DEMO_RESET: 'demo:reset',
  // Secret Management (spec 4.9.9). Applications never get these: they need a secret access grant.
  SECRET_CREATE: 'secret:create',
  SECRET_READ_METADATA: 'secret:read_metadata',
  SECRET_RETRIEVE: 'secret:retrieve',
  SECRET_UPDATE_METADATA: 'secret:update_metadata',
  SECRET_UPDATE_VALUE: 'secret:update_value',
  SECRET_DELETE: 'secret:delete',
  SECRET_ROTATE: 'secret:rotate',
  SECRET_MANAGE_VERSIONS: 'secret:manage_versions',
  SECRET_MANAGE_ACCESS: 'secret:manage_access',
  SECRET_EXPORT: 'secret:export',
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

const P = PERMISSIONS;

/** Small fixed RBAC matrix for the POC (spec section 2). */
export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  OWNER: Object.values(P),
  VAULT_ADMIN: [
    P.ORG_READ,
    P.WEBHOOK_MANAGE,
    P.INTEGRATION_MANAGE,
    P.GRANT_MANAGE,
    P.GRANT_REVOKE,
    P.AUDIT_READ,
    P.SECRET_CREATE,
    P.SECRET_READ_METADATA,
    P.SECRET_RETRIEVE,
    P.SECRET_UPDATE_METADATA,
    P.SECRET_UPDATE_VALUE,
    P.SECRET_DELETE,
    P.SECRET_ROTATE,
    P.SECRET_MANAGE_VERSIONS,
    P.SECRET_MANAGE_ACCESS,
  ],
  SECURITY_ADMIN: [P.ORG_READ, P.POLICY_MANAGE, P.GRANT_REVOKE, P.GRANT_APPROVE, P.AUDIT_READ, P.SECRET_READ_METADATA, P.SECRET_MANAGE_ACCESS, P.SECRET_DELETE],
  DEVELOPER: [P.ORG_READ, P.AGENT_MANAGE, P.SECRET_READ_METADATA],
  AUDITOR: [P.ORG_READ, P.AUDIT_READ, P.SECRET_READ_METADATA],
};

export const ROLE_LABELS: Record<Role, string> = {
  OWNER: 'Organization Owner',
  VAULT_ADMIN: 'Vault Administrator',
  SECURITY_ADMIN: 'Security Administrator',
  DEVELOPER: 'Agent Developer',
  AUDITOR: 'Auditor (read-only)',
};

export const ROLE_DESCRIPTIONS: Record<Role, string> = {
  OWNER: 'Full access to organization configuration and user management.',
  VAULT_ADMIN: 'Manage webhook, integrations, credential metadata, and grants.',
  SECURITY_ADMIN: 'Manage policies, approve and revoke grants, and inspect audit events.',
  DEVELOPER: 'Register and manage assigned agents; view integration availability and grant status.',
  AUDITOR: 'Read-only access to audit, policy, and grant information.',
};

export function roleHas(role: Role | null | undefined, permission: Permission): boolean {
  if (!role) return false;
  return ROLE_PERMISSIONS[role].includes(permission);
}
