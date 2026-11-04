import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { DECISION_LABELS, operationLabel } from '@token-vault/shared';
import { TokenVault, TokenVaultError, type GitHubOperation } from '@token-vault/sdk';
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

const text = (t: string, isError = false): CallToolResult => ({ content: [{ type: 'text', text: t }], ...(isError ? { isError: true } : {}) });

/**
 * MCP tools that perform GitHub operations through Token Vault. The agent's process
 * holds only its Token Vault API key; the GitHub credential stays in the customer
 * webhook, which injects it upstream. Every call is authorized and audited server-side.
 */
export function createServer(tv: TokenVault): McpServer {
  const server = new McpServer(SERVER_INFO, {
    instructions:
      'GitHub access brokered by Token Vault. Call token_vault_list_access first to see which repositories and operations this agent is granted. ' +
      'If a call is denied, do not try other repositories or operations to work around it: report the denial and its request ID to the user, who can ask an administrator for access.',
  });

  async function run(operation: GitHubOperation, args: { repository: string; integration?: string; path?: string }, input: Record<string, unknown> = {}): Promise<CallToolResult> {
    try {
      const caps = await tv.capabilities();
      const target = resolveIntegration(caps, { provider: 'github', operation, repository: args.repository, integration: args.integration });
      if (!target.ok) return text(target.message, true);

      const resource = { repository: args.repository, ...(args.path ? { path: args.path } : {}) };
      const { httpStatus, body } = await tv.executeRaw({ integrationId: target.integrationId, operation, resource, input });
      const label = DECISION_LABELS[body.decision_code] ?? body.decision_code;

      if (body.decision === 'ALLOW' && body.execution.status === 'SUCCEEDED') {
        const mode = body.execution.simulated ? ' (simulated GitHub)' : '';
        return {
          content: [{ type: 'text', text: `${operationLabel(operation)} succeeded${mode}. Token Vault request ${body.request_id}.\n\n${JSON.stringify(body.result, null, 2)}` }],
          structuredContent: { request_id: body.request_id, upstream_status: body.execution.upstream_status, simulated: body.execution.simulated, result: body.result },
        };
      }
      if (body.decision === 'DENY') {
        return text(
          `Access denied by Token Vault: ${label} (${body.decision_code}, HTTP ${httpStatus}).\n${body.reason}\nRequest ID: ${body.request_id}. ` +
            'Do not retry with a different repository or operation to work around this; ask the user to request access from a Token Vault administrator.',
          true,
        );
      }
      return text(`Authorized, but the operation failed: ${label} (${body.decision_code}).\n${body.reason}\nRequest ID: ${body.request_id}.`, true);
    } catch (e) {
      if (e instanceof TokenVaultError) return text(`Token Vault error (${e.code}): ${e.message}`, true);
      return text('Unexpected error while calling Token Vault.', true);
    }
  }

  server.registerTool(
    'token_vault_list_access',
    {
      title: 'List my Token Vault access',
      description: 'Lists the integrations, operations and repositories this agent is currently granted, with grant status and expiry.',
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => {
      try {
        const caps = await tv.capabilities();
        if (caps.grants.length === 0) return text(`Agent "${caps.agent.name}" has no access grants. Everything is denied by default.`);
        const lines = caps.grants.map((g) =>
          [
            `- ${g.name} [${g.status}${g.integration_available ? '' : ', integration unavailable'}]`,
            `  integration: ${g.integration_name} (${g.integration_id}, ${g.provider})`,
            `  operations: ${g.operations.map(operationLabel).join(', ')}`,
            `  repositories: ${g.repositories.length ? g.repositories.join(', ') : 'any the integration allows'}`,
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

  return server;
}
