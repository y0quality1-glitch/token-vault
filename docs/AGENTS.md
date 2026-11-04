# Connecting AI Agents

An agent uses Token Vault with **its own Token Vault API key only**. It never receives the GitHub credential: Token Vault authorizes each request against the agent's grants and policies, and the customer webhook injects the credential into the upstream call. Every request, allowed or denied, is recorded in **Audit & Activity → Access Logs**.

There are two ways to connect:

- **MCP server** (`mcp/`): for MCP clients such as Claude Code and Claude Desktop. No code required.
- **TypeScript SDK** (`sdk/`): for agents and applications you write yourself.

## 1. Give the agent an identity and a grant

1. **Agents → Register agent** (or open an existing agent and choose **Rotate API credential**). Copy the `tvak_…` credential. It is shown once, and Token Vault keeps only a hash.
2. **Access Grants → Create grant**: choose the agent, the GitHub integration, the operations it needs and, ideally, a repository restriction and an expiry.

Without a grant, every request is denied.

## 2a. MCP server (Claude Code, Claude Desktop, any MCP client)

Print configuration with this checkout's absolute paths:

```bash
npm run mcp:config
```

**Recommended for Claude Code:** add the printed block to a project's `.mcp.json`. Its `env` section references `${TOKEN_VAULT_API_KEY}`, so the key stays in your shell rather than in a file. Then export the key in the shell you start Claude Code from:

```bash
export TOKEN_VAULT_API_KEY='tvak_…'
```

The one-line `claude mcp add …` command and the Claude Desktop JSON that the helper also prints both store the key in that client's config file. Treat that file as a secret.

**Tools**

| Tool | Token Vault operation |
| --- | --- |
| `token_vault_list_access` | Lists this agent's grants: integrations, operations, repositories, status, expiry |
| `github_get_repository` | `github.repositories.read` |
| `github_read_file` | `github.contents.read` |
| `github_list_issues` | `github.issues.list` |
| `github_create_issue` | `github.issues.create` |

Each GitHub tool takes `repository` (`owner/name`) and an optional `integration` (ID or name), which is needed only when the agent has more than one GitHub integration. Results include the Token Vault request ID. A denial comes back as a tool error that gives the reason, such as `GRANT_REVOKED`, `SCOPE_DENIED` or `RESOURCE_DENIED`, and tells the model not to work around it.

**Configuration** (environment only; command-line arguments are visible in the process list):

| Variable | Purpose |
| --- | --- |
| `TOKEN_VAULT_API_KEY` | The agent's credential (required) |
| `TOKEN_VAULT_URL` | Control plane URL (default `http://localhost:4000`) |
| `TOKEN_VAULT_ORG` | Optional org slug, used only to attribute failed authentication in the audit log |

The server speaks MCP over stdio and writes diagnostics to stderr only. It never prints the key.

**Try it in the demo:** register an agent, grant it *Create issue* on `demo-org/demo-repo`, connect Claude Code, and ask it to file an issue. Then revoke the grant in the console and ask again: the next tool call is denied with `GRANT_REVOKED`. Both requests appear in Access Logs. GitHub is simulated unless the webhook runs with `GITHUB_MODE=live`.

## 2b. TypeScript SDK

```ts
import { AccessDeniedError, TokenVault } from '@token-vault/sdk';

const tv = new TokenVault(); // reads TOKEN_VAULT_URL and TOKEN_VAULT_API_KEY

const { grants } = await tv.capabilities();

try {
  const issue = await tv.execute<{ number: number; html_url: string }>({
    integrationId: 'int_github_001',
    operation: 'github.issues.create',
    resource: { repository: 'demo-org/demo-repo' },
    input: { title: 'Filed through Token Vault', body: 'No GitHub token in this process.' },
  });
  console.log(issue.data.html_url, issue.requestId);
} catch (e) {
  if (e instanceof AccessDeniedError) console.error(`Denied: ${e.code} (${e.requestId})`);
  else throw e;
}
```

- `execute()` returns the sanitized result, or throws one of:
  - `AccessDeniedError`: denied by Token Vault;
  - `ExecutionFailedError`: authorized, but the webhook or GitHub failed;
  - `AuthenticationError`: bad or rotated key;
  - `TokenVaultError`: network failure or timeout.

  Each error carries `code`, `requestId` and `httpStatus`.
- `executeRaw()` returns the full decision for every outcome instead of throwing.
- An idempotency key is generated for every request, so retrying a creating operation is safe.
- The key is held in a private field: `console.log(tv)` and `JSON.stringify(tv)` show only `baseUrl` and the public `keyId`.

Inside this monorepo the SDK is consumed as TypeScript source (workspace package). Publishing it to a registry would need a build step, which this POC does not have.
