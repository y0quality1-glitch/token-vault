import { McpServer, type RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { DECISION_LABELS, operationLabel } from '@token-vault/shared';
import { TokenVault, TokenVaultError } from '@token-vault/sdk';
import { catalogTools } from './catalog-tools';
import { resolveIntegration } from './resolve';

export const SERVER_INFO = { name: 'token-vault', version: '0.1.0' };

const repository = z
  .string()
  .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, 'Use owner/repository, e.g. demo-org/demo-repo')
  .describe('Repository in owner/name form, e.g. demo-org/demo-repo');
const integration = z
  .string()
  .optional()
  .describe('Token Vault integration ID or name. Optional when this agent has only one GitHub integration (see token_vault_list_access).');

/** Denials a human can resolve with a just-in-time grant (not revocations, policies, disabled agents, …). */
const REQUESTABLE = new Set(['GRANT_MISSING', 'SCOPE_DENIED', 'RESOURCE_DENIED', 'GRANT_EXPIRED']);
const OPERATION_ID = /^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*){2,3}$/;

const text = (t: string, isError = false): CallToolResult => ({ content: [{ type: 'text', text: t }], ...(isError ? { isError: true } : {}) });

export type TokenVaultMcpServer = McpServer & {
  /**
   * Re-reads the operations of the applications this agent has grants on and adds, updates
   * or removes their tools (clients are notified with tools/list_changed). Returns whether
   * anything changed. Errors are thrown; the existing tools are kept.
   */
  refreshTools(): Promise<boolean>;
};

/**
 * MCP tools that perform operations through Token Vault. The agent's process holds only
 * its Token Vault API key; provider credentials stay in the customer webhook, which
 * injects them upstream. Every call is authorized and audited server-side.
 *
 * GitHub has hand-written tools. Every other operation of the applications this agent has
 * a grant on (as published in the provider CMS) becomes a tool named after its id, e.g.
 * slack_messages_post, with arguments typed from the definition.
 */
export function createServer(tv: TokenVault): TokenVaultMcpServer {
  const server = new McpServer(SERVER_INFO, {
    instructions:
      'Access to GitHub and other applications, brokered by Token Vault. Call token_vault_list_access first to see which integrations, operations and resources this agent is granted. ' +
      'If a call is denied, do not try other resources or operations to work around it. When the denial says access can be requested, you may call ' +
      'token_vault_request_access once, with a concrete justification for the specific task; a human decides. Do not resubmit or rephrase requests to get a different answer. ' +
      'Report denials and request IDs to the user.',
  });

  /** Labels of catalog operations (the shared lookup only knows the bundled ones). */
  const labels = new Map<string, string>();
  const labelOf = (id: string) => labels.get(id) ?? operationLabel(id);

  async function call(c: { provider: { key: string; name: string }; operation: string; resourceName: string; resource: Record<string, string>; input: Record<string, unknown>; integration?: string }): Promise<CallToolResult> {
    const { operation } = c;
    const primary = c.resource[c.resourceName];
    try {
      const caps = await tv.capabilities();
      const target = resolveIntegration(caps, { provider: c.provider.key, operation, repository: primary, integration: c.integration });
      if (!target.ok) return text(target.message, true);

      const { httpStatus, body } = await tv.executeRaw({ integrationId: target.integrationId, operation, resource: c.resource, input: c.input });
      const label = DECISION_LABELS[body.decision_code] ?? body.decision_code;

      if (body.decision === 'ALLOW' && body.execution.status === 'SUCCEEDED') {
        const mode = body.execution.simulated ? ` (simulated ${c.provider.name})` : '';
        return {
          content: [{ type: 'text', text: `${labelOf(operation)} succeeded${mode}. Token Vault request ${body.request_id}.\n\n${JSON.stringify(body.result, null, 2)}` }],
          structuredContent: { request_id: body.request_id, upstream_status: body.execution.upstream_status, simulated: body.execution.simulated, result: body.result },
        };
      }
      if (body.decision === 'DENY') {
        const next = REQUESTABLE.has(body.decision_code)
          ? `If this access is genuinely needed for the user's task, you may ask a human for it once with token_vault_request_access (operations: ["${operation}"]${primary ? `, resource: "${primary}"` : ''}, denied_request_id: "${body.request_id}"). Until a human approves, it stays denied.`
          : 'This denial cannot be resolved by requesting access. Do not retry with a different resource or operation; report it to the user.';
        return text(`Access denied by Token Vault: ${label} (${body.decision_code}, HTTP ${httpStatus}).\n${body.reason}\nRequest ID: ${body.request_id}.\n${next}`, true);
      }
      return text(`Authorized, but the operation failed: ${label} (${body.decision_code}).\n${body.reason}\nRequest ID: ${body.request_id}.`, true);
    } catch (e) {
      if (e instanceof TokenVaultError) return text(`Token Vault error (${e.code}): ${e.message}`, true);
      return text('Unexpected error while calling Token Vault.', true);
    }
  }

  const GITHUB = { key: 'github', name: 'GitHub' };
  const run = (operation: string, args: { repository: string; integration?: string; path?: string }, input: Record<string, unknown> = {}) =>
    call({ provider: GITHUB, operation, resourceName: 'repository', resource: { repository: args.repository, ...(args.path ? { path: args.path } : {}) }, input, integration: args.integration });

  server.registerTool(
    'token_vault_list_access',
    {
      title: 'List my Token Vault access',
      description: 'Lists the integrations, operations and resources (repositories, channels, …) this agent is currently granted, with grant status and expiry.',
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => {
      try {
        await refreshTools().catch(() => false); // a new grant may bring a new application's tools
        const caps = await tv.capabilities();
        if (caps.grants.length === 0) return text(`Agent "${caps.agent.name}" has no access grants. Everything is denied by default.`);
        const lines = caps.grants.map((g) =>
          [
            `- ${g.name} [${g.status}${g.integration_available ? '' : ', integration unavailable'}]`,
            `  integration: ${g.integration_name} (${g.integration_id}, ${g.provider})`,
            `  operations: ${g.operations.map(labelOf).join(', ')}`,
            `  resources: ${g.repositories.length ? g.repositories.join(', ') : 'any the integration allows'}`,
            `  expires: ${g.expires_at}; rate limit ${g.rate_limit_per_minute}/min`,
          ].join('\n'),
        );
        return {
          content: [{ type: 'text', text: `Agent "${caps.agent.name}" (${caps.agent.status}) in ${caps.agent.organization}:\n${lines.join('\n')}` }],
          structuredContent: caps as unknown as Record<string, unknown>,
        };
      } catch (e) {
        return text(e instanceof TokenVaultError ? `Token Vault error (${e.code}): ${e.message}` : 'Unexpected error while calling Token Vault.', true);
      }
    },
  );

  server.registerTool(
    'github_get_repository',
    {
      title: 'Get GitHub repository',
      description: 'Reads repository metadata (description, default branch, open issue count) through Token Vault.',
      inputSchema: { repository, integration },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    (args) => run('github.repositories.read', args),
  );

  server.registerTool(
    'github_read_file',
    {
      title: 'Read file from GitHub repository',
      description: 'Reads a file from a repository (defaults to README.md) through Token Vault.',
      inputSchema: { repository, path: z.string().min(1).max(240).default('README.md').describe('File path within the repository'), integration },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    (args) => run('github.contents.read', args),
  );

  server.registerTool(
    'github_list_issues',
    {
      title: 'List GitHub issues',
      description: 'Lists issues in a repository through Token Vault.',
      inputSchema: { repository, integration },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    (args) => run('github.issues.list', args),
  );

  server.registerTool(
    'github_create_issue',
    {
      title: 'Create GitHub issue',
      description: 'Creates an issue in a repository through Token Vault. Only works where an administrator has granted issue creation.',
      inputSchema: {
        repository,
        title: z.string().min(1).max(256).describe('Issue title'),
        body: z.string().max(10_000).optional().describe('Issue body (Markdown)'),
        integration,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    ({ title, body, ...args }) => run('github.issues.create', args, { title, body: body ?? '' }),
  );

  server.registerTool(
    'token_vault_request_access',
    {
      title: 'Request access from a human (just-in-time)',
      description:
        'Asks a Token Vault administrator for time-limited access the agent was denied. A human must approve; nothing changes until then. ' +
        'Use at most once per need, with a specific justification tied to the user’s task. Identical pending requests are not duplicated.',
      inputSchema: {
        operations: z.array(z.string().regex(OPERATION_ID, 'Use operation ids such as github.issues.create')).min(1).max(10).describe('Operations needed, all of one application, e.g. ["github.issues.create"] or ["slack.messages.post"]'),
        resource: z.string().min(1).max(500).optional().describe('Resource the access is for: a repository, channel, calendar, … (recommended: keeps the grant narrow)'),
        repository: repository.optional().describe('GitHub repository the access is for (same as resource)'),
        justification: z.string().min(10).max(500).describe('Why this access is needed for the current task; shown to the approver'),
        duration_minutes: z.number().int().min(15).max(480).default(60).describe('How long the access is needed (15–480 minutes)'),
        denied_request_id: z.string().optional().describe('Request ID from the denial, if any'),
        integration,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (args) => {
      try {
        const providers = [...new Set(args.operations.map((o) => o.split('.')[0]!))];
        if (providers.length > 1) return text(`Request access for one application at a time (got ${providers.join(', ')}).`, true);
        const resource = args.resource ?? args.repository;
        const caps = await tv.capabilities();
        const target = resolveIntegration(caps, { provider: providers[0]!, operation: args.operations[0]!, repository: resource, integration: args.integration });
        if (!target.ok) return text(`${target.message} If this agent has no grants yet, ask the user for the Token Vault integration ID and pass it as "integration".`, true);
        const r = await tv.requestAccess({
          integrationId: target.integrationId,
          operations: args.operations,
          repositories: resource ? [resource] : [],
          justification: args.justification,
          durationMinutes: args.duration_minutes,
          deniedRequestId: args.denied_request_id,
        });
        return {
          content: [{ type: 'text', text: `Access request ${r.access_request_id} is ${r.status}${r.duplicate ? ' (an identical request was already pending)' : ''}. A human administrator must approve it; check later with token_vault_check_access_request. It lapses at ${r.expires_at} if nobody decides.` }],
          structuredContent: r as unknown as Record<string, unknown>,
        };
      } catch (e) {
        return text(e instanceof TokenVaultError ? `Token Vault refused the access request (${e.code}): ${e.message}` : 'Unexpected error while calling Token Vault.', true);
      }
    },
  );

  server.registerTool(
    'token_vault_check_access_request',
    {
      title: 'Check an access request',
      description: 'Returns the status of an access request this agent submitted: PENDING, APPROVED (with grant expiry), REJECTED (with the approver’s note) or EXPIRED.',
      inputSchema: { access_request_id: z.string().min(1).max(64) },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ access_request_id }) => {
      try {
        const r = await tv.getAccessRequest(access_request_id);
        const detail =
          r.status === 'APPROVED'
            ? ` Granted until ${r.grant_expires_at}; retry the original operation now.`
            : r.status === 'REJECTED'
              ? ` Rejected${r.decision_note ? `: "${r.decision_note}"` : ''}. Do not resubmit the same request; tell the user.`
              : r.status === 'EXPIRED'
                ? ' Nobody decided in time.'
                : ' Still waiting for a human.';
        return { content: [{ type: 'text', text: `Access request ${r.access_request_id}: ${r.status}.${detail}` }], structuredContent: r as unknown as Record<string, unknown> };
      } catch (e) {
        return text(e instanceof TokenVaultError ? `Token Vault error (${e.code}): ${e.message}` : 'Unexpected error while calling Token Vault.', true);
      }
    },
  );

  // ------------------------------------------------------------ tools from the catalog
  const dynamic = new Map<string, RegisteredTool>();
  let version: string | null = null;
  let inFlight: Promise<boolean> | null = null;

  async function sync(): Promise<boolean> {
    const body = await tv.operations();
    if (body.version === version) return false;
    for (const t of dynamic.values()) t.remove();
    dynamic.clear();
    labels.clear();
    for (const p of body.providers) for (const o of p.operations) labels.set(o.id, o.label);
    for (const t of catalogTools(body)) {
      dynamic.set(
        t.name,
        server.registerTool(t.name, { title: t.title, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations }, (args: Record<string, unknown>) => {
          const { resource, input, integration } = t.split(args);
          return call({ provider: t.provider, operation: t.operation, resourceName: t.resourceName, resource, input, integration });
        }),
      );
    }
    version = body.version;
    return true;
  }
  /** Single-flight: concurrent refreshes share one request. */
  function refreshTools(): Promise<boolean> {
    inFlight ??= sync().finally(() => (inFlight = null));
    return inFlight;
  }

  return Object.assign(server, { refreshTools });
}
