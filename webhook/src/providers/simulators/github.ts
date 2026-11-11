import { randomUUID } from 'node:crypto';
import { mockTokenScope } from '../github-app';
import type { Simulator, UpstreamRequest, UpstreamResponse } from './types';

/**
 * Simulated api.github.com (GITHUB_MODE=mock). It speaks GitHub's REST API at the HTTP
 * level, so the generic executor builds and sends exactly the same request in mock and
 * live mode; only the transport differs. It enforces credentials like GitHub does,
 * including the repository and permission scope of minted App installation tokens.
 */

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

const json = (status: number, body: unknown): UpstreamResponse => ({ status, body });
const NOT_FOUND = json(404, { message: 'Not Found' });
const FORBIDDEN_APP = json(403, { message: 'Resource not accessible by integration' });

function looksLikeToken(token: string) {
  return /^(mock_|ghp_|github_pat_|gho_|ghs_)/.test(token) && token.length >= 20;
}

/** The installation permission GitHub requires for a request (App tokens only). */
function requiredPermission(method: string, rest: string[]): [string, 'read' | 'write'] {
  if (rest.length === 0 && method === 'DELETE') return ['administration', 'write'];
  if (rest[0] === 'contents') return ['contents', method === 'GET' ? 'read' : 'write'];
  if (rest[0] === 'issues') return ['issues', method === 'GET' ? 'read' : 'write'];
  return ['metadata', 'read'];
}

export const githubSimulator: Simulator = async (req: UpstreamRequest) => {
  await new Promise((r) => setTimeout(r, 40 + Math.random() * 120)); // simulated network latency
  const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? req.headers.Authorization ?? '')?.[1] ?? '';
  if (!looksLikeToken(token)) return json(401, { message: 'Bad credentials' });
  const app = token.startsWith('ghs_') ? mockTokenScope(token) : undefined;
  if (token.startsWith('ghs_') && !app) return json(401, { message: 'Bad credentials' });

  const segs = req.url.pathname.split('/').filter(Boolean).map(decodeURIComponent);

  if (req.method === 'GET' && segs.join('/') === 'user') return app ? FORBIDDEN_APP : json(200, { login: 'demo-bot', type: 'Bot', id: 1 });
  if (req.method === 'GET' && segs.join('/') === 'installation/repositories') {
    if (!app) return json(403, { message: 'This endpoint requires an installation token' });
    const repos = app.repositories.length ? app.repositories : Object.keys(mockRepos);
    return json(200, { total_count: repos.length, repositories: repos.map((full_name) => ({ full_name })) });
  }
  if (segs[0] !== 'repos' || segs.length < 3) return NOT_FOUND;

  const repoName = `${segs[1]}/${segs[2]}`;
  const rest = segs.slice(3);
  if (app) {
    const [perm, level] = requiredPermission(req.method, rest);
    const have = app.permissions[perm as keyof typeof app.permissions];
    if (!have || (level === 'write' && have !== 'write')) return FORBIDDEN_APP;
    if (app.repositories.length && !app.repositories.includes(repoName.toLowerCase())) return NOT_FOUND;
  }
  const repo = mockRepos[repoName.toLowerCase()];
  if (!repo) return NOT_FOUND;

  if (req.method === 'GET' && rest.length === 0) {
    return json(200, {
      id: 1,
      full_name: repoName,
      private: repo.private,
      description: repo.description,
      default_branch: 'main',
      stargazers_count: repo.stars,
      open_issues_count: repo.issues.filter((i) => i.state === 'open').length,
      html_url: `https://github.com/${repoName}`,
      updated_at: new Date().toISOString(),
    });
  }
  if (req.method === 'GET' && rest[0] === 'contents') {
    const path = rest.slice(1).join('/');
    if (path !== 'README.md') return NOT_FOUND;
    return json(200, { path, name: path, type: 'file', size: repo.readme.length, sha: 'mock' + repo.readme.length, encoding: 'base64', content: Buffer.from(repo.readme).toString('base64') });
  }
  if (rest.length === 1 && rest[0] === 'issues') {
    if (req.method === 'GET') {
      const perPage = Number(req.url.searchParams.get('per_page') ?? 30);
      return json(
        200,
        repo.issues.slice(0, perPage).map((i) => ({ number: i.number, title: i.title, state: i.state, labels: i.labels.map((name) => ({ name })), user: { login: i.user }, created_at: i.created_at })),
      );
    }
    if (req.method === 'POST') {
      let input: Record<string, unknown> = {};
      try {
        input = JSON.parse(req.body ?? '{}');
      } catch {
        return json(400, { message: 'Problems parsing JSON' });
      }
      const title = String(input.title ?? '').trim();
      if (!title) return json(422, { message: 'Validation Failed', errors: [{ field: 'title', code: 'missing_field' }] });
      // Documented hook for demonstrating "Upstream provider error" in the playground.
      if (title.includes('[simulate-upstream-500]')) return json(500, { message: 'Server Error (simulated)' });
      const issue: MockIssue = {
        number: Math.max(...repo.issues.map((i) => i.number), 40) + 1,
        title,
        body: String(input.body ?? ''),
        state: 'open',
        labels: [],
        created_at: new Date().toISOString(),
        user: 'github-assistant[bot]',
      };
      repo.issues.push(issue);
      return json(201, { number: issue.number, title: issue.title, state: issue.state, html_url: `https://github.com/${repoName}/issues/${issue.number}`, created_at: issue.created_at, node_id: 'I_mock_' + randomUUID().slice(0, 8) });
    }
  }
  // Destructive operations (run only after human approval). Simulated without changing the mock
  // repositories, so the demo data stays intact.
  if (req.method === 'DELETE' && rest.length === 0) return json(204, null);
  if (req.method === 'PUT' && rest[0] === 'contents' && rest.length > 1) {
    let input: Record<string, unknown> = {};
    try {
      input = JSON.parse(req.body ?? '{}');
    } catch {
      return json(400, { message: 'Problems parsing JSON' });
    }
    if (!input.message || typeof input.content !== 'string' || !/^[A-Za-z0-9+/=\s]*$/.test(input.content)) return json(422, { message: 'Invalid request: message and base64 content are required' });
    const path = rest.slice(1).join('/');
    const sha = 'mock' + randomUUID().replace(/-/g, '').slice(0, 12);
    return json(201, { content: { path, sha, html_url: `https://github.com/${repoName}/blob/main/${path}` }, commit: { sha: 'c' + sha } });
  }
  return NOT_FOUND;
};
