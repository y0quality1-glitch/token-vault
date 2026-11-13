# Connecting AI Agents

An agent uses Token Vault with **its own Token Vault API key only**. It never receives the provider credential (GitHub, Slack, …): Token Vault authorizes each request against the agent's grants and policies, and the customer webhook injects the credential into the upstream call. Every request, allowed or denied, is recorded in **Audit & Activity → Access Logs**.

There are two ways to connect:

- **MCP server** (`mcp/`): for MCP clients such as Claude Code and Claude Desktop. No code required.
- **TypeScript SDK** (`sdk/`): for agents and applications you write yourself.

## 1. Give the agent an identity and a grant

1. **Agents → Register agent** (or open an existing agent and choose **Rotate API credential**). Copy the `tvak_…` credential. It is shown once, and Token Vault keeps only a hash. When rotating, choose a grace period so the old key keeps working while you deploy the new one: requests with the old key return a `Token-Vault-Key-Expires` header, the SDK reports it (`tv.keyExpiresAt`, `onKeyExpiry`), and the MCP server logs a warning.
2. **Access Grants → Create grant**: choose the agent, the integration (GitHub or any application from the catalog), the operations it needs and, ideally, a resource restriction (repository, channel, …) and an expiry.

An agent that needs several applications gets one grant per integration: select them all in step 2 of the wizard to create them in one go. It keeps one API key for all of them; MCP offers tools for every application it has a grant on, and with the SDK each call names its `integrationId` (listed by `tv.capabilities()`).

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
- The definitions come from `POST /agent/v1/operation/getall`, limited to the applications in the agent's own grants. A tool is offered for operations the agent is not granted too: calling it is denied (`SCOPE_DENIED`), and the agent may ask a human with `token_vault_request_access`.
- The server re-reads them at start-up, every `TOKEN_VAULT_TOOLS_REFRESH_S` seconds, and when `token_vault_list_access` is called. When something changed (a newly published version, a new grant on another application), it updates its tools and notifies the client with `tools/list_changed`. If the catalog cannot be read, the GitHub and Token Vault tools keep working.
- Destructive operations become tools only for an agent holding a grant for them, and every call waits for human approval (see *Destructive operations* below).

`token_vault_request_access` works for any application: pass operation ids of one application and, ideally, a `resource` (`repository` still works for GitHub).

Each GitHub tool takes `repository` (`owner/name`) and an optional `integration` (ID or name), which is needed only when the agent has more than one GitHub integration. Results include the Token Vault request ID. A denial comes back as a tool error that gives the reason, such as `GRANT_REVOKED`, `SCOPE_DENIED` or `RESOURCE_DENIED`, and tells the model not to work around it.

**Configuration** (environment only; command-line arguments are visible in the process list):

| Variable | Purpose |
| --- | --- |
| `TOKEN_VAULT_API_KEY` | The agent's credential, or a sub-agent's delegation token (`tvdt_…`) (required) |
| `TOKEN_VAULT_URL` | Control plane URL (default `http://localhost:4000`) |
| `TOKEN_VAULT_ORG` | Optional org slug, used only to attribute failed authentication in the audit log |
| `TOKEN_VAULT_TOOLS_REFRESH_S` | How often to re-read the catalog for new or changed application tools (default 60; `0` = only at start-up) |
| `TOKEN_VAULT_USER_TOKEN_FILE` | Optional: act on behalf of a user. A file with the user's signed token, re-read on every call |
| `TOKEN_VAULT_USER_TOKEN` | Optional: the user's signed token itself (it expires, so prefer the file) |
| `TOKEN_VAULT_SESSION_ID` / `TOKEN_VAULT_SESSION_LABEL` | Optional: the session every tool call belongs to (Audit → Sessions). Default: a new session per server start |

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
- With Slack connected (Settings → Slack approvals), each request is also posted to a Slack channel with **Approve** and **Reject** buttons (see [USER_JOURNEY.md](USER_JOURNEY.md#8-handle-approvals-and-access-requests)). Nothing changes for the agent.
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

## Acting on behalf of a user

Most agents work for a person: a support assistant answers for the signed-in customer, a coding assistant files issues for the developer who asked. Token Vault can limit such an agent to what **both** its own grant and that user allow, and record "agent X for user Y" in the access log.

**How the user is proven.** Your application (or identity provider) signs a short-lived JWT for the signed-in user. The agent sends it as `on_behalf_of` with each request. Token Vault checks it against an issuer registered under **Settings → User Identity**, using only that issuer's public key, so nothing in Token Vault can mint a user token.

1. **Register the issuer** (Settings → User Identity → *Add issuer*; Owner or Security Administrator): its `iss`, the `aud` your tokens name, and the public key (PEM or JWK; RSA 2048+, EC P-256/P-384 or Ed25519). A private key is refused. Set the longest token lifetime you accept (default 1 hour) and the claim holding the user's groups (default `groups`). *Check a user token* verifies a token without running anything.
2. **Choose per grant** (*Acting for users*):
   - *For itself or for a signed-in user* (default): requests may carry a user token.
   - *Only on behalf of a signed-in user*: a request without a valid user token is denied (`USER_REQUIRED`).
   - *Only for itself*: a request with a user token is denied (`USER_NOT_ALLOWED`), for background jobs.
   - *Allowed user groups* (optional): the user must be in one of them (`USER_NOT_ALLOWED` otherwise).
3. **Mint the token** in your application:

   ```json
   {
     "iss": "https://login.acme.com",
     "aud": "token-vault",
     "sub": "u_8f2c",
     "email": "ada@acme.com",
     "name": "Ada Lovelace",
     "groups": ["support"],
     "token_vault": { "operations": ["github:read", "github.issues.create"], "resources": ["acme/support-*"] },
     "iat": 1794405600,
     "exp": 1794406200
   }
   ```

   Signed with RS256/384/512, ES256/384 or EdDSA (never HS256 or `none`). `exp` is required; `sub` names the user.

**The user's own permissions.** The optional `token_vault` claim says what this user may let an agent do. `operations` are selectors (`github.issues.create`, `github.*`, `github:write`, `risk:read`); `resources` are values of the operation's primary resource, with `*` at the end matching any suffix (`acme/support-*`). A request outside them is denied with `USER_PERMISSION_DENIED`, even if the agent's grant would allow it. Without the claim, only the grant applies.

**Policies can name users** through argument rules: `user.sub`, `user.email`, `user.name`, `user.groups` (holds when any of the user's groups matches; a negated rule when none does) and `user.issuer`. They are empty when the agent acts for itself. Examples:

| Rule | Decision | Effect |
| --- | --- | --- |
| `user.groups` is one of `contractors` | Deny | Contractors can't have agents act for them here |
| `user.sub` equals `""` | Deny | No request without a user, for every grant the policy covers |
| `user.groups` is not one of `finance` | Require approval | A human approves requests for anyone outside finance |

**What is checked, in order.** An invalid token (forged, expired, unknown or disabled issuer, wrong audience, too long-lived) is denied with `USER_TOKEN_INVALID` before anything else, and recorded. Otherwise step 9 of the evaluation, *Acting user*, picks a grant that fits the user (or the absence of one) and applies the user's permissions.

**Approvals are per user.** An approval given for a request made for one user cannot run that request for another: the user is part of the approved request. Running it again needs a valid token for the same user.

**What is recorded.** Each access record keeps the verified user (subject, email, name, groups, permissions, issuer). The access log shows "for Ada Lovelace (ada@acme.com)" and filters by user. The customer webhook receives the user's subject, email and issuer (`acting_user`) and logs the subject.

**Connecting.**

- SDK: `tv.forUser(token)` returns a client that sends the token on every request; pass a function to fetch a fresh token each time. Or pass `onBehalfOf` per request.
- MCP: set `TOKEN_VAULT_USER_TOKEN_FILE` to a file holding the token (re-read on every call, so another process can refresh it), or `TOKEN_VAULT_USER_TOKEN`. `token_vault_list_access` says which grants need a user. User denials are reported to the model as not resolvable by an access request.
- Access Playground: paste a token into *On behalf of a user*.

## Sessions and tracing

An access log says *what* an agent did. A session says *why*: the calls an agent made while working on one conversation, task or job, in order.

**What the agent sends** (both optional):

- `session_id` (and `session_label`) in the request body: the agent's own id for the conversation, task or job, 1–128 letters, digits, `.`, `_`, `:` or `-`. The label is a short description, shown as agent-written text.
- The W3C `traceparent` header (`00-<trace-id>-<span-id>-<flags>`), as OpenTelemetry propagates it. An invalid header is ignored and a new trace starts, as the standard says.

**What Token Vault does.** It records the session, the trace id, the caller's span and its own new span on the access record, denied requests included. It answers with `"trace": { session_id, trace_id, span_id, parent_span_id }`, and passes `traceparent` and `session_id` to the customer webhook (which logs `trace=<trace-id>`), so its logs join the same trace. Requests with a traceparent but no session id are grouped by trace id. Requests with neither are not grouped.

**Where to see it.** **Audit & Activity → Sessions** lists sessions with their agent, request counts (allowed, denied, held for approval), integrations, users acted for and sub-agents, and is searchable by session id, label, trace id or agent. A session's page shows its timeline, oldest first, and the approvals asked for during it. Each access record links to its session, and each approval shows the session it came from and how many requests came before it.

**Connecting.**

- SDK: `tv.session('task-42', 'Triage new bugs').execute(…)`, or `sessionId` / `sessionLabel` in the options. Pass `traceparent` (a string, or a function returning the active one, e.g. from OpenTelemetry) to join your own traces.
- MCP: each server process (one client session) is one session with one trace, and each tool call is a span. Set `TOKEN_VAULT_SESSION_ID` and `TOKEN_VAULT_SESSION_LABEL` to choose them.

## Response filtering

What an application returns goes straight into the model's context. A **Filter responses** policy (Access Management → Policies → Decision: *Filter responses*) shapes it first, for the agents, applications and operations the policy's Who / Where / What select. It never changes whether a request is allowed.

| Setting | Effect |
| --- | --- |
| **Mask** | Replaces detected values with `[REDACTED:<kind>]`: email addresses, phone numbers, payment card numbers (Luhn-checked), IP addresses, and secrets (GitHub, AWS, Slack, Stripe and Google keys, JWTs, private keys, `password=…`, `Bearer …`, Token Vault keys) |
| **Custom patterns** | Up to 10 named regular expressions, e.g. `employee_id` = `EMP-\d{3,}` |
| **Remove fields** | A field name removes it everywhere (`email`); a path ending removes it only there (`author.email`) |
| **Prompt injection** | Looks for text that tries to instruct the model: "ignore previous instructions", role changes, chat markup, "send this to https://…", "don't tell the user". *Flag* passes the result with a warning; *Withhold the result* returns no result (`RESPONSE_WITHHELD`) |

**Where it runs.** The control plane sends the filter in the signed execution request, and the customer webhook applies it, so masked or removed values never leave your side. If a webhook doesn't apply exactly that filter (an older version), the control plane applies it instead: an agent never receives an unfiltered result. Several matching policies combine: everything any of them masks or removes, and the strictest prompt injection setting. A result too large or too deeply nested to inspect is withheld (fails closed).

**What agents see.** The response carries `filtering` (policies, what was masked and removed, prompt injection signals with their location). A withheld result is `decision: ALLOW`, `decision_code: RESPONSE_WITHHELD`, `result: null`: the operation ran, but its result is not passed on. The SDK throws `ResponseWithheldError`, and `execute()` results have `filtering`. The MCP server tells the model when a result contains flagged text, to treat it as data and not follow it, and that a withheld result should not be retried.

**What is recorded.** Each access record keeps the counts, the signals and whether the webhook or the control plane filtered. It never keeps the values. The access log marks requests *Filtered* or *Flagged*, and the request detail shows what happened.

Prompt injection detection is a heuristic: it catches common attacks, not every possible one. Combine it with narrow grants, approvals for writes, and agents that treat tool results as data.

## Access modes: when the agent makes the call itself

By default an integration is **Brokered**: the customer webhook calls the application and the agent gets the result, never a credential. An administrator can change that per integration (Integrations → *integration* → **Access mode**):

| Mode | What the agent gets after an allowed request | Use it when |
| --- | --- | --- |
| **Brokered** (default) | The result | Always, unless you can't |
| **Decision only** | A signed decision token, no result. The agent (or your service) calls the application with credentials of its own | The application is your own API, or calls must come from your network |
| **Short-lived credential** | A decision token and a token the webhook issued: a GitHub App token limited to the repository and the operation's permission (GitHub sets 1 hour), or the OAuth access token. The agent calls the application with it | A tool needs to talk to the application directly (git over HTTPS, a client library) |

Every check still runs first: grants, policies, approvals, budgets, the acting user and the audit. What changes is who makes the call. Keep in mind:

- In the two new modes Token Vault never sees the application's response, so it can't filter it. A request a Filter responses policy covers is denied with `FILTER_NEEDS_BROKERED`.
- An issued token can be used for anything it allows until it expires, not only for the request that was decided. GitHub App tokens are the narrowest; an OAuth access token has all the scopes of the connection. Stored keys and personal tokens are never handed out.
- The customer's webhook operator must allow issuing with `WEBHOOK_ALLOW_CREDENTIAL_ISSUE=true`.

The response has `execution.status: "HANDED_OFF"`, `result: null` and `authorization` (see [API.md](API.md#agent-api-agentv1)). With the SDK, `execute()` returns `authorization` and `data: null`. Your application can check a decision before acting on it:

```ts
import { verifyDecisionToken } from '@token-vault/sdk';

const claims = await verifyDecisionToken(token, {
  keys: 'https://vault.example.com/.well-known/jwks.json',
  expect: { operation: 'github.issues.create', resource: { repository: 'demo-org/demo-repo' }, input },
});
```

It checks the signature, the expiry, and that the token covers exactly that operation, resource and input. The MCP server does not pass issued tokens to the model: for an integration that isn't brokered, it tells the model the request was allowed but not run.

## Delegation to sub-agents

Multi-agent systems split work: a coordinator starts helpers, each needing a little of its access for a short time. Instead of sharing its API key, the agent **delegates**: it hands a sub-agent a narrower, short-lived slice of one grant, with its own token.

```ts
const tv = new TokenVault(); // the coordinator, with its own tvak_ key
const d = await tv.delegate({
  grantId: 'grt_…',
  label: 'Issue triage helper',          // shown to administrators and in the audit log
  operations: ['github.issues.list'],    // within the grant, never destructive
  resources: ['acme/support'],           // within the grant's; empty = as the grant allows
  expiresInSeconds: 900,                 // default 1 hour, at most 24 hours
  maxRequests: 50,                       // optional cap over the delegation's life
});
const helper = new TokenVault({ apiKey: d.token }); // tvdt_…, shown once
```

**It can only narrow.** Operations and resources must be within the grant (for a sub-agent delegating further: within its own delegation). Destructive operations cannot be delegated. The expiry never passes the grant's, the parent delegation's, or (when acting for a user) the user token's. A request cap is never above the parent's. Delegations nest at most 3 levels, and an agent can have at most 50 active ones.

**Every request is still the agent's.** A sub-agent's request is evaluated as the delegating agent's, restricted to the delegated grant, then step 10 (*Delegation limits*) checks the delegated operations, resources and request cap (`DELEGATION_DENIED`). Policies, budgets, rate limits and approvals of the agent apply as usual. So:

- revoking the grant, disabling the agent, or the emergency stop stops every delegation made from them;
- revoking a delegation (`DELEGATION_REVOKED`) stops it and everything delegated from it, from the next request;
- an expired one is denied with `DELEGATION_EXPIRED`;
- a new grant version (Edit restrictions) carries its delegations over, and they are narrowed by it.

**Users.** A delegation created on behalf of a user (`onBehalfOf`, or a client made with `forUser`) makes every sub-agent request for that user, and never outlives the user's token. A sub-agent cannot send a user token of its own (`DELEGATION_DENIED`). A delegation made for the agent itself cannot be used for a user.

**What a sub-agent can do through the agent API:** `POST /request/execute`, `POST /capability/getdata` (only its slice, plus a `delegation` block), `POST /operation/getall`, `GET /request/getbyid/:id` and `GET /approval/getbyid/:id` for its own requests, and `POST /delegation/save`, `/delegation/getall` and `/delegation/revoke` to delegate further, list and revoke what it delegated. It cannot request access just in time (`POST /accessRequest/save` answers 403): it may only narrow. Approvals are bound to the sub-agent that asked.

**Seeing and stopping them.** Each agent's **Access Grants** tab and each grant's page list its delegations: what was delegated, how many requests were used, status, and who it acts for. Owners, Vault Administrators and Security Administrators can **Revoke** one with a reason. The access log shows "via sub-agent <label>" on every request a sub-agent made, and the audit has `delegation.created` and `delegation.revoked`.

**MCP.** Start the sub-agent's MCP server with its delegation token as `TOKEN_VAULT_API_KEY`. `token_vault_list_access` tells the model it is a sub-agent and what it was delegated; delegation denials are reported as final.

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
- When a Filter responses policy applies, `execute()` results include `filtering` (what was masked, removed or flagged), and a withheld result throws `ResponseWithheldError` (code `RESPONSE_WITHHELD`): the operation ran, so don't simply retry.
- To hand part of a grant to a sub-agent, `tv.delegate({ grantId, label, operations, resources?, expiresInSeconds?, maxRequests? })` returns a `tvdt_` token for `new TokenVault({ apiKey: token })`; `listDelegations()` and `revokeDelegation(id)` manage them. See *Delegation to sub-agents*.
- To act on behalf of a user, use `const ada = tv.forUser(userToken)` (or a function returning a fresh token) and call `ada.execute(…)`, or pass `onBehalfOf` per request. User denials (`USER_REQUIRED`, `USER_NOT_ALLOWED`, `USER_PERMISSION_DENIED`, `USER_TOKEN_INVALID`) are thrown as `AccessDeniedError`. The token is never logged or serialized.
- An idempotency key is generated for every request, so retrying a creating operation is safe.
- The key is held in a private field: `console.log(tv)` and `JSON.stringify(tv)` show only `baseUrl` and the public `keyId`.

Inside this monorepo the SDK is consumed as TypeScript source (workspace package). Publishing it to a registry would need a build step, which this POC does not have.
