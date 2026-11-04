import { randomUUID } from 'node:crypto';
import { OPERATION_PERMISSIONS, mockTokenScope } from './github-app';

/**
 * GitHub connector executed INSIDE the customer webhook. The decrypted token is
 * injected into the upstream Authorization header here and nowhere else.
 *
 * mock mode (default): simulated GitHub API, still requires a decrypted token to run.
 * live mode: calls https://api.github.com. Use a dedicated test org + fine-grained PAT only.
 */
export const SUPPORTED_OPERATIONS = [
  'github.repositories.read',
  'github.contents.read',
  'github.issues.list',
  'github.issues.create',
] as const;

export interface ProviderResult {
  upstreamStatus: number;
  body: unknown;
  simulated: boolean;
}

export interface ProviderCall {
  operation: string;
  resource: { repository?: string; path?: string };
  input: Record<string, unknown>;
}

// ---------------------------------------------------------------- mock provider
interface MockIssue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  created_at: string;
  user: string;
}

const now = Date.now();
const mockRepos: Record<string, { description: string; private: boolean; stars: number; issues: MockIssue[]; readme: string }> = {
  'demo-org/demo-repo': {
    description: 'Sandbox repository for the Token Vault POC',
    private: true,
    stars: 3,
    readme: '# demo-repo\n\nSandbox repository used by the Token Vault proof of concept.\n',
    issues: [
      { number: 41, title: 'Rotate staging deploy key', body: '', state: 'open', labels: ['security'], created_at: new Date(now - 86400e3 * 3).toISOString(), user: 'octo-admin' },
      { number: 42, title: 'Document agent onboarding', body: '', state: 'open', labels: ['docs'], created_at: new Date(now - 86400e3 * 2).toISOString(), user: 'github-assistant[bot]' },
      { number: 43, title: 'Flaky test in CI pipeline', body: '', state: 'closed', labels: ['ci'], created_at: new Date(now - 86400e3).toISOString(), user: 'octo-dev' },
    ],
  },
  'demo-org/other-repo': { description: 'A repository outside the demo grant', private: true, stars: 0, readme: '# other-repo\n', issues: [] },
  'demo-org/docs': { description: 'Public documentation site', private: false, stars: 12, readme: '# docs\n', issues: [] },
};

function looksLikeToken(token: string) {
  return /^(mock_|ghp_|github_pat_|gho_|ghs_)/.test(token) && token.length >= 20;
}

async function mockCall(token: string, call: ProviderCall): Promise<ProviderResult> {
  await new Promise((r) => setTimeout(r, 40 + Math.random() * 120)); // simulated network latency
  if (!looksLikeToken(token)) return { upstreamStatus: 401, body: { message: 'Bad credentials' }, simulated: true };
  // GitHub App installation tokens (ghs_): enforce the minted scope exactly like GitHub does.
  if (token.startsWith('ghs_')) {
    const scope = mockTokenScope(token);
    if (!scope) return { upstreamStatus: 401, body: { message: 'Bad credentials' }, simulated: true };
    const needed = OPERATION_PERMISSIONS[call.operation] ?? {};
    for (const [perm, level] of Object.entries(needed)) {
      const have = scope.permissions[perm as keyof typeof scope.permissions];
      if (!have || (level === 'write' && have !== 'write')) return { upstreamStatus: 403, body: { message: 'Resource not accessible by integration' }, simulated: true };
    }
    const repo = call.resource.repository?.toLowerCase();
    if (repo && scope.repositories.length && !scope.repositories.includes(repo)) return { upstreamStatus: 404, body: { message: 'Not Found' }, simulated: true };
  }
  if (call.operation === 'credential.test') return { upstreamStatus: 200, body: { login: token.startsWith('ghs_') ? 'token-vault-demo[bot]' : 'demo-bot', type: 'Bot' }, simulated: true };

  const repoName = call.resource.repository ?? '';
  const repo = mockRepos[repoName.toLowerCase()];
  if (!repo) return { upstreamStatus: 404, body: { message: 'Not Found' }, simulated: true };

  switch (call.operation) {
    case 'github.repositories.read':
      return {
        upstreamStatus: 200,
        simulated: true,
        body: {
          full_name: repoName,
          private: repo.private,
          description: repo.description,
          default_branch: 'main',
          stargazers_count: repo.stars,
          open_issues_count: repo.issues.filter((i) => i.state === 'open').length,
          html_url: `https://github.com/${repoName}`,
          updated_at: new Date().toISOString(),
        },
      };
    case 'github.contents.read': {
      const path = call.resource.path || 'README.md';
      if (path !== 'README.md') return { upstreamStatus: 404, body: { message: 'Not Found' }, simulated: true };
      return {
        upstreamStatus: 200,
        simulated: true,
        body: { path, type: 'file', size: repo.readme.length, encoding: 'utf-8', content: repo.readme },
      };
    }
    case 'github.issues.list':
      return {
        upstreamStatus: 200,
        simulated: true,
        body: repo.issues.map((i) => ({ number: i.number, title: i.title, state: i.state, labels: i.labels, user: i.user, created_at: i.created_at })),
      };
    case 'github.issues.create': {
      const title = String(call.input.title ?? '').trim();
      if (!title) return { upstreamStatus: 422, body: { message: 'Validation Failed', errors: [{ field: 'title', code: 'missing_field' }] }, simulated: true };
      // Documented hook for demonstrating "Upstream provider error" in the playground.
      if (title.includes('[simulate-upstream-500]')) return { upstreamStatus: 500, body: { message: 'Server Error (simulated)' }, simulated: true };
      const issue: MockIssue = {
        number: Math.max(...repo.issues.map((i) => i.number), 40) + 1,
        title,
        body: String(call.input.body ?? ''),
        state: 'open',
        labels: [],
        created_at: new Date().toISOString(),
        user: 'github-assistant[bot]',
      };
      repo.issues.push(issue);
      return {
        upstreamStatus: 201,
        simulated: true,
        body: { number: issue.number, title: issue.title, state: issue.state, html_url: `https://github.com/${repoName}/issues/${issue.number}`, created_at: issue.created_at, node_id: 'I_mock_' + randomUUID().slice(0, 8) },
      };
    }
    default:
      return { upstreamStatus: 400, body: { message: 'Unsupported operation' }, simulated: true };
  }
}

// ---------------------------------------------------------------- live provider
async function liveCall(token: string, call: ProviderCall): Promise<ProviderResult> {
  const repo = call.resource.repository ?? '';
  const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'token-vault-poc-webhook', 'X-GitHub-Api-Version': '2022-11-28' };
  let url: string;
  let init: RequestInit = { headers };
  switch (call.operation) {
    case 'credential.test':
      url = 'https://api.github.com/user';
      break;
    case 'github.repositories.read':
      url = `https://api.github.com/repos/${repo}`;
      break;
    case 'github.contents.read':
      url = `https://api.github.com/repos/${repo}/contents/${encodeURIComponent(call.resource.path || 'README.md')}`;
      break;
    case 'github.issues.list':
      url = `https://api.github.com/repos/${repo}/issues?per_page=10`;
      break;
    case 'github.issues.create':
      url = `https://api.github.com/repos/${repo}/issues`;
      init = { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ title: call.input.title, body: call.input.body }) };
      break;
    default:
      return { upstreamStatus: 400, body: { message: 'Unsupported operation' }, simulated: false };
  }
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(10_000) });
  const json = await res.json().catch(() => ({}));
  return { upstreamStatus: res.status, body: sanitizeLive(call.operation, json), simulated: false };
}

/** Allow-list the fields returned to the control plane; never echo headers or tokens. */
function sanitizeLive(operation: string, json: any): unknown {
  if (!json || typeof json !== 'object') return {};
  if (Array.isArray(json)) return json.slice(0, 10).map((i) => ({ number: i.number, title: i.title, state: i.state, user: i.user?.login, created_at: i.created_at }));
  switch (operation) {
    case 'credential.test':
      return { login: json.login, type: json.type };
    case 'github.repositories.read':
      return { full_name: json.full_name, private: json.private, description: json.description, default_branch: json.default_branch, stargazers_count: json.stargazers_count, open_issues_count: json.open_issues_count, html_url: json.html_url };
    case 'github.contents.read':
      return { path: json.path, type: json.type, size: json.size, sha: json.sha };
    case 'github.issues.create':
      return { number: json.number, title: json.title, state: json.state, html_url: json.html_url, created_at: json.created_at };
    default:
      return { message: json.message };
  }
}

export async function callGitHub(mode: 'mock' | 'live', token: string, call: ProviderCall): Promise<ProviderResult> {
  return mode === 'live' ? liveCall(token, call) : mockCall(token, call);
}
