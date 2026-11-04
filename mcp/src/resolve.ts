import type { AgentCapabilitiesBody } from '@token-vault/sdk';

export type Resolution = { ok: true; integrationId: string } | { ok: false; message: string };

/**
 * Picks the integration a tool call should target, from the agent's own capabilities.
 *
 * Deliberately permissive about *whether* the call is allowed: if the agent has a
 * candidate integration, the request still goes to Token Vault, which makes the actual
 * decision and audits it. Resolution only avoids asking the model for an opaque ID.
 *
 * 1. An explicit `integration` (ID or display name) wins.
 * 2. Otherwise, if exactly one integration for the provider is in the agent's grants, use it.
 * 3. Otherwise prefer integrations whose grant covers this operation (and repository).
 */
export function resolveIntegration(
  caps: AgentCapabilitiesBody,
  want: { provider: string; operation: string; repository?: string; integration?: string },
): Resolution {
  const grants = caps.grants.filter((g) => g.provider === want.provider);
  if (want.integration) {
    const needle = want.integration.trim().toLowerCase();
    const match = grants.find((g) => g.integration_id === want.integration || g.integration_name.toLowerCase() === needle);
    // Unknown names are passed through as IDs so Token Vault returns (and audits) the real reason.
    return { ok: true, integrationId: match?.integration_id ?? want.integration };
  }

  const integrations = [...new Map(grants.map((g) => [g.integration_id, g.integration_name])).entries()];
  if (integrations.length === 0) {
    return { ok: false, message: `This agent has no ${want.provider} integration in any Token Vault grant. Ask an administrator to create an access grant.` };
  }
  if (integrations.length === 1) return { ok: true, integrationId: integrations[0]![0] };

  const repo = want.repository?.toLowerCase();
  const covering = [
    ...new Set(
      grants
        .filter((g) => g.status === 'ACTIVE' && g.operations.includes(want.operation))
        .filter((g) => !repo || g.repositories.length === 0 || g.repositories.some((r) => r.toLowerCase() === repo))
        .map((g) => g.integration_id),
    ),
  ];
  if (covering.length === 1) return { ok: true, integrationId: covering[0]! };
  return {
    ok: false,
    message: `Several ${want.provider} integrations are available (${integrations.map(([id, name]) => `"${name}" (${id})`).join(', ')}). Pass the "integration" argument to choose one.`,
  };
}
