import type { ProviderDefinitionInput } from './schema';

const REPO = '/repos/{resource.repository}';

/**
 * GitHub, expressed as a provider definition. Executed by the webhook's generic
 * executor; nothing GitHub-specific remains in code except the GitHub App token plugin.
 */
export const githubDefinition: ProviderDefinitionInput = {
  key: 'github',
  version: 1,
  name: 'GitHub',
  description: 'Repositories, contents and issues via the GitHub REST API.',
  api: {
    baseUrl: 'https://api.github.com',
    allowedHosts: ['api.github.com'],
    headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'token-vault-poc-webhook' },
  },
  resource: { name: 'repository', label: 'Repository', pattern: '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$', example: 'demo-org/demo-repo', caseInsensitive: true },
  resourceFields: { path: { label: 'File path', pattern: '^[^\\x00-\\x1f]{1,500}$', example: 'README.md' } },
  auth: [
    {
      id: 'GITHUB_APP',
      label: 'GitHub App',
      description: 'Only the App private key is stored; each request gets a token minted for one repository and one permission.',
      kind: 'plugin',
      plugin: 'github_app',
      test: { request: { method: 'GET', path: '/installation/repositories', query: { per_page: 1 } }, response: { fields: { total_count: 'total_count' } } },
    },
    {
      id: 'PAT',
      label: 'Personal Access Token',
      description: 'A long-lived token stored encrypted and injected as a bearer token.',
      kind: 'bearer',
      secretPattern: '^\\S{20,512}$',
      secretHint: 'At least 20 characters, no whitespace',
    },
  ],
  credentialTest: { request: { method: 'GET', path: '/user' }, response: { fields: { login: 'login', type: 'type' } } },
  operations: [
    {
      id: 'github.repositories.read',
      label: 'Read repository metadata',
      description: 'GET /repos/{owner}/{repo}',
      risk: 'read',
      providerPermissions: { metadata: 'read' },
      request: { method: 'GET', path: REPO },
      response: {
        fields: {
          full_name: 'full_name',
          private: 'private',
          description: 'description',
          default_branch: 'default_branch',
          stargazers_count: 'stargazers_count',
          open_issues_count: 'open_issues_count',
          html_url: 'html_url',
          updated_at: 'updated_at',
        },
      },
    },
    {
      id: 'github.contents.read',
      label: 'Read repository contents',
      description: 'GET /repos/{owner}/{repo}/contents/{path}',
      risk: 'read',
      providerPermissions: { contents: 'read' },
      request: { method: 'GET', path: `${REPO}/contents/{resource.path|README.md}` },
      response: { fields: { path: 'path', type: 'type', size: 'size', sha: 'sha', encoding: { const: 'utf-8' }, content: { path: 'content', decode: 'base64', maxLength: 100_000 } } },
    },
    {
      id: 'github.issues.list',
      label: 'List issues',
      description: 'GET /repos/{owner}/{repo}/issues',
      risk: 'read',
      providerPermissions: { issues: 'read' },
      request: { method: 'GET', path: `${REPO}/issues`, query: { per_page: 10 } },
      response: { fields: { number: 'number', title: 'title', state: 'state', labels: { path: 'labels', pluck: 'name' }, user: 'user.login', created_at: 'created_at' }, limit: 10 },
    },
    {
      id: 'github.issues.create',
      label: 'Create issue',
      description: 'POST /repos/{owner}/{repo}/issues',
      risk: 'write',
      providerPermissions: { issues: 'write' },
      input: { title: { type: 'string', label: 'Title', maxLength: 256 }, body: { type: 'string', label: 'Body', maxLength: 65_536, multiline: true } },
      request: { method: 'POST', path: `${REPO}/issues`, body: { title: '{input.title}', body: '{input.body}' } },
      response: { fields: { number: 'number', title: 'title', state: 'state', html_url: 'html_url', created_at: 'created_at', node_id: 'node_id' } },
    },
    // Known to the policy engine (so it can deny them explicitly) but never grantable or executed.
    {
      id: 'github.repositories.delete',
      label: 'Delete repository',
      description: 'DELETE /repos/{owner}/{repo} (destructive, never grantable)',
      risk: 'destructive',
      request: { method: 'DELETE', path: REPO },
      response: { fields: { message: 'message' } },
    },
    {
      id: 'github.contents.write',
      label: 'Write repository contents',
      description: 'PUT /repos/{owner}/{repo}/contents/{path} (destructive, never grantable)',
      risk: 'destructive',
      request: { method: 'PUT', path: `${REPO}/contents/{resource.path}` },
      response: { fields: { message: 'message' } },
    },
  ],
};
