import { operationSelectorMatches, type OperationFacts } from './operation-selectors';
import type { ActingUser } from './types';

/**
 * Acting on behalf of a user: what the user's own token permits.
 *
 * The customer's application (or identity provider) knows what each user may do, and states
 * it in the signed user token's "token_vault" claim:
 *
 *   { "operations": ["github:write", "risk:read"], "resources": ["demo-org/*"] }
 *
 * A request for that user must fall within both the agent's grant and these permissions.
 * A missing list means no limit of that kind beyond the grant.
 */

/** "demo-org/*" matches any value starting with "demo-org/"; otherwise exact. Case-insensitive. */
export function resourcePatternMatches(pattern: string, value: string): boolean {
  const p = pattern.toLowerCase();
  const v = value.toLowerCase();
  if (p === '*') return true;
  return p.endsWith('*') ? v.startsWith(p.slice(0, -1)) : v === p;
}

/** Null when the user's permissions allow the request, otherwise why not. */
export function userPermissionProblem(user: Pick<ActingUser, 'permissions' | 'sub'>, operation: OperationFacts, resource: string | undefined): string | null {
  const p = user.permissions;
  if (!p) return null;
  if (p.operations && !p.operations.some((s) => operationSelectorMatches(s, operation))) {
    return `User ${user.sub} may not let an agent run ${operation.id} (their token permits: ${p.operations.join(', ') || 'no operations'}).`;
  }
  if (p.resources && resource !== undefined && resource !== '' && !p.resources.some((r) => resourcePatternMatches(r, resource))) {
    return `User ${user.sub} may not let an agent use ${resource} (their token permits: ${p.resources.join(', ') || 'no resources'}).`;
  }
  if (p.resources && (resource === undefined || resource === '') && !p.resources.includes('*')) {
    return `User ${user.sub}'s token limits resources, but this request names none.`;
  }
  return null;
}

/** "Ada Lovelace (ada@example.com)", or the subject when nothing else is known. */
export function actingUserLabel(u: Pick<ActingUser, 'sub' | 'email' | 'name'>): string {
  if (u.name && u.email) return `${u.name} (${u.email})`;
  return u.name || u.email || u.sub;
}
