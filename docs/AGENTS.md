# Connecting AI Agents

An agent uses Token Vault with **its own Token Vault API key only**. It never receives the provider credential (GitHub, Slack, …): Token Vault authorizes each request against the agent's grants and policies, and the customer webhook injects the credential into the upstream call. Every request, allowed or denied, is recorded in **Audit & Activity → Access Logs**.

There are two ways to connect:

- **MCP server** (`mcp/`): for MCP clients such as Claude Code and Claude Desktop. No code required.
- **TypeScript SDK** (`sdk/`): for agents and applications you write yourself.

## 1. Give the agent an identity and a grant

1. **Agents → Register agent** (or open an existing agent and choose **Rotate API credential**). Copy the `tvak_…` credential. It is shown once, and Token Vault keeps only a hash. When rotating, choose a grace period so the old key keeps working while you deploy the new one: requests with the old key return a `Token-Vault-Key-Expires` header, the SDK reports it (`tv.keyExpiresAt`, `onKeyExpiry`), and the MCP server logs a warning.
2. **Access Grants → Create grant**: choose the agent, the integration (GitHub or any application from the catalog), the operations it needs and, ideally, a resource restriction (repository, channel, …) and an expiry.

Without a grant, every request is denied.

If the integration is a **GitHub App** (recommended), the agent does not change at all. Behind the scenes each allowed request runs on its own installation token, minted for that request's repository and the one permission the operation needs, then revoked. Even a compromised webhook process leaks at most a one-hour token for one repository and one permission. The SDK exposes the scope as `response.execution.credential`. See [GITHUB_APP.md](GITHUB_APP.md).

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
| *one tool per catalog operation* | e.g. `slack_messages_post` → `slack.messages.post`, `google_events_list` → `google.events.list` (see below) |
| `token_vault_request_access` | Asks a human for time-limited access (see below) |
| `token_vault_check_access_request` | Status of a request: `PENDING`, `APPROVED`, `REJECTED` or `EXPIRED` |
| `token_vault_check_approval` | For a request held for human approval: its status, and once `APPROVED`, runs the request exactly as approved (see below) |

**Tools for every application in the catalog.** Besides the hand-written GitHub tools, the server offers one tool for each non-destructive operation of every application this agent has a grant on, as published in the provider CMS. No code changes are needed.

- The tool name is the operation id with dots replaced, e.g. `slack.messages.post` becomes `slack_messages_post`. Its title is "<Application>: <operation label>".
- Arguments are typed from the definition. The resource (`channel`, `calendar`, `page`, …) is checked against the definition's pattern, and the inputs carry their types, required flags and maximum lengths. An input whose name is already taken by a resource field becomes `input_<name>`. Every tool also takes an optional `integration`.
- The definitions come from `GET /agent/v1/operations`, limited to the applications in the agent's own grants. A tool is offered for operations the agent is not granted too: calling it is denied (`SCOPE_DENIED`), and the agent may ask a human with `token_vault_request_access`.
- The server re-reads them at start-up, every `TOKEN_VAULT_TOOLS_REFRESH_S` seconds, and when `token_vault_list_access` is called. When something changed (a newly published version, a new grant on another application), it updates its tools and notifies the client with `tools/list_changed`. If the catalog cannot be read, the GitHub and Token Vault tools keep working.
- Destructive operations become tools only for an agent holding a grant for them, and every call waits for human approval (see *Destructive operations* below).

`token_vault_request_access` works for any application: pass operation ids of one application and, ideally, a `resource` (`repository` still works for GitHub).

Each GitHub tool takes `repository` (`owner/name`) and an optional `integration` (ID or name), which is needed only when the agent has more than one GitHub integration. Results include the Token Vault request ID. A denial comes back as a tool error that gives the reason, such as `GRANT_REVOKED`, `SCOPE_DENIED` or `RESOURCE_DENIED`, and tells the model not to work around it.

**Configuration** (environment only; command-line arguments are visible in the process list):

| Variable | Purpose |
| --- | --- |
| `TOKEN_VAULT_API_KEY` | The agent's credential (required) |
| `TOKEN_VAULT_URL` | Control plane URL (default `http://localhost:4000`) |
| `TOKEN_VAULT_ORG` | Optional org slug, used only to attribute failed authentication in the audit log |
| `TOKEN_VAULT_TOOLS_REFRESH_S` | How often to re-read the catalog for new or changed application tools (default 60; `0` = only at start-up) |

The server speaks MCP over stdio and writes diagnostics to stderr only. It never prints the key.

**Try it in the demo:** register an agent, grant it *Create issue* on `demo-org/demo-repo`, connect Claude Code, and ask it to file an issue. Then revoke the grant in the console and ask again: the next tool call is denied with `GRANT_REVOKED`. Both requests appear in Access Logs. GitHub is simulated unless the webhook runs GitHub live (`PROVIDER_MODES=github=live`).

## Just-in-time access requests

When a request is denied for a reason a human can fix (`GRANT_MISSING`, `SCOPE_DENIED`, `RESOURCE_DENIED` or `GRANT_EXPIRED`), the agent can ask for time-limited access instead of failing:

1. The agent calls `token_vault_request_access` (MCP) or `tv.requestAccess()` (SDK). It specifies the operations, ideally one repository, a duration of 15–480 minutes, a justification, and the denied request's ID.
2. The request appears in **Access Management → Access Requests**. The sidebar shows a pending count and the Overview shows an alert.
3. A Security Administrator or Owner reviews it. The agent's justification is shown as agent-written, untrusted text. The approver can approve, optionally narrowing operations, repositories or duration but never widening them, or reject it with a note.
4. Approval creates an ordinary grant that expires on its own. The agent's next call is authorized. The agent can check the outcome with `token_vault_check_access_request` or `tv.getAccessRequest()`.

**Guardrails**

- Destructive operations cannot be requested.
- Revocations, deny policies and disabled agents are not resolvable by request; the MCP server tells the model so.
- An agent can have at most 3 pending requests. Identical pending requests are returned rather than duplicated.
- Pending requests lapse after 24 hours.
- **Separation of duties:** the agent's owner cannot approve that agent's requests, though they can reject them.
- Each step is audited: `grant_request.created`, `grant_request.approved` or `grant_request.rejected`, and `grant.created` with `justInTime: true`.

An agent with no grants at all has no integration to infer. Pass `integration` (the integration ID, which the user can provide) to `token_vault_request_access`.

## Human approval of risky operations

A policy with the decision **Require approval** (Access Management → Policies) holds back matching requests that every other check allows, for example every `github.issues.create` by a given agent, or any operation in production. Unlike a just-in-time request, the agent already has the grant; a human approves one specific request.

1. The agent's call returns `APPROVAL_REQUIRED` (HTTP 202) with an `approval_id`. Nothing ran. The MCP tool result tells the model to inform the user and check back later, not to resend a changed request.
2. The request appears in **Access Management → Approvals** with the exact operation, resource and input, shown as agent-written text. The sidebar shows a waiting count.
3. A Security Administrator or Owner approves or rejects it. The agent's owner cannot approve it.
4. The agent runs it with `token_vault_check_approval` (MCP), `tv.executeApproved(approvalId)` (SDK), or simply by sending the identical request again.

**Guardrails**

- The approval covers exactly one request: a different input, resource or operation needs its own approval, and the approval can be used once, within 15 minutes of being approved.
- Every other check runs again when the approval is used: revoking the grant, a new deny policy, a disabled agent or the rate limit still win.
- A rejected request is answered with `APPROVAL_REJECTED` for 24 hours instead of asking again.
- An agent can have at most 10 approvals waiting; they lapse after 1 hour.
- Each step is audited: `access.approval_required`, `approval.requested`, `approval.approved` or `approval.rejected`, and the executed request's access record carries the `approvalId`.

## Argument rules, budgets and the emergency stop

These limit what an agent can do with access it already has. None of them can be resolved by `token_vault_request_access`; the MCP server tells the model to report them.

**Selecting operations.** A policy can name operations one by one, or use selectors that also cover operations the platform team publishes later: *Any operation*, *All read / write / destructive operations* (in every application), or *All GitHub operations* (one application). Through the API, `github:write` selects one risk in one application.

**Destructive operations** (for example *Delete repository*, *Write repository contents*) are never run on an agent's word alone:

1. They can be granted only where an enabled **Require approval** policy covers them for that agent, with no time window, source IP or argument rules (so no request can slip past it). Agents can't request them just in time.
2. Every request waits for a human under **Approvals**. If the approval policy is later disabled, the grant stops working (`APPROVAL_POLICY_MISSING`) rather than running without approval.
3. A Deny policy still wins. The Demo Organization's seeded *Block destructive GitHub operations* policy denies them until you disable it.
4. The customer webhook runs them only if its operator set `WEBHOOK_ALLOW_DESTRUCTIVE=true`, and only for a request carrying an approval.
5. The MCP server offers a destructive operation as a tool only to an agent that holds a grant for it, marked as destructive.

**Argument rules** (Access Management → Policies → *Argument rules*). A policy can carry up to 10 conditions on what the request contains: `input.<name>` or `resource.<name>`, with *equals*, *contains*, *matches pattern* (regular expression), *is one of*, *is longer than*, *is greater than*, *is less than* and their negations. Text comparisons ignore case. The policy applies only when every rule holds, so the same rules work with each decision:

| Example | Decision |
| --- | --- |
| `input.title` matches `pass(word)?\|secret` | Deny: `POLICY_DENIED` |
| `input.amount` is greater than `500` | Require approval: `APPROVAL_REQUIRED` |
| `resource.path` does not match `^docs/` | Deny writes outside `docs/` |

A missing field counts as empty text. For *is greater than* and *is less than*, a value that is not a number counts as matching, so a deny or approval rule fails closed.

**Budgets** (on a grant: *Budget: requests per 24 hours*, *Budget: writes per hour*). They are counted from the access log over rolling windows, so they hold across restarts and control-plane instances. Writes are every operation that is not a read. Requests held for approval or denied don't count. A request over budget is denied with `BUDGET_EXCEEDED` (HTTP 429). The grant page shows how much of each budget is used, and `token_vault_list_access` shows the budgets to the model.

**Emergency stop** (Overview → *Emergency stop*). One switch denies every agent request in the organization with `EMERGENCY_STOP` (HTTP 403) until someone resumes access. Grants, keys and credentials are not changed, so resuming restores access exactly as it was. A red banner is shown on every console page while it is on.

- Stopping needs `grant:revoke` (Owner, Vault Administrator, Security Administrator) and a reason, which is shown to agents.
- Resuming needs `grant:approve` (Owner, Security Administrator).
- Both are audited: `organization.emergency_stop` (critical) and `organization.emergency_stop_lifted`.
- To stop a single agent or integration instead, disable that agent or integration.

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
- `requestAccess({ integrationId, operations, repositories, justification, durationMinutes, deniedRequestId })` and `getAccessRequest(id)` implement just-in-time access.
- When a policy requires human approval, `execute()` throws `ApprovalRequiredError` (a subclass of `AccessDeniedError`) with `approvalId`. `waitForApproval(approvalId, { timeoutMs })` polls until a human decides, and `executeApproved(approvalId)` runs the request exactly as approved:

  ```ts
  try {
    await tv.execute({ integrationId, operation: 'github.issues.create', resource, input });
  } catch (e) {
    if (!(e instanceof ApprovalRequiredError)) throw e;
    const a = await tv.waitForApproval(e.approvalId);
    if (a.status === 'APPROVED') await tv.executeApproved(e.approvalId);
  }
  ```
- An idempotency key is generated for every request, so retrying a creating operation is safe.
- The key is held in a private field: `console.log(tv)` and `JSON.stringify(tv)` show only `baseUrl` and the public `keyId`.

Inside this monorepo the SDK is consumed as TypeScript source (workspace package). Publishing it to a registry would need a build step, which this POC does not have.
