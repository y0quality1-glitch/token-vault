# Roadmap: features HashiCorp Vault does not offer for AI agents

This plan sets Token Vault apart from HashiCorp Vault for applications and AI agents. It does not try to copy Vault.

HashiCorp Vault answers *"who can read this secret?"* Token Vault answers *"what may this agent do, for whom, right now, and with how much damage possible?"* Every feature below builds on that difference. The statements about HashiCorp below come from general product knowledge, not from a recent check of HashiCorp's documentation.

## Where Token Vault stands today

| Area | Token Vault | HashiCorp Vault / Boundary |
| --- | --- | --- |
| Agent sees the credential | No: the customer webhook adds it to the upstream call | Vault: yes, the secret goes to the client. Boundary adds credentials only for SSH, RDP and TCP |
| Policy detail | Integration, operation, resource, explicit deny rules, validity window, rate limit, source IP | Paths to secrets (HCL). Sentinel in Enterprise |
| Revocation | Checked on every request, so it applies from the next call | Leases can be revoked, but a secret already handed out stays usable |
| Agent features | MCP server, SDK, access requests, access reviews | None specific to agents |
| Audit | Append-only, hash-chained and signed per organization | Audit devices with HMAC'd fields |
| Dynamic secrets, PKI, many login methods, HA and replication | Partial or missing | Mature and widely used |

## Phase 1: Control what agents do (done)

Built on branch `feat/approval-policies`. How to configure each feature is described in [AGENTS.md](AGENTS.md) and [USER_JOURNEY.md](USER_JOURNEY.md).

| Feature | Status | What shipped | Why HashiCorp Vault can't |
| --- | --- | --- | --- |
| Human approval for risky operations | Done, console only | A policy with the decision *Require approval* holds matching requests. The agent receives `APPROVAL_REQUIRED` (HTTP 202) and an approval ID. A person approves or rejects it under **Approvals**; the agent's owner can't approve. The approval covers that exact request, once, within 15 minutes. Destructive operations (delete a repository, write contents) can be granted only under such a policy, and the webhook runs them only with `WEBHOOK_ALLOW_DESTRUCTIVE=true`. SDK: `waitForApproval`, `executeApproved`; MCP: `token_vault_check_approval`. | Vault hands over the secret, so it never sees individual operations |
| Argument rules | Done | Up to 10 conditions per policy on `input.*` and `resource.*`: equals, contains, matches pattern, is one of, is longer than, greater or less than, and their negations. They work with Deny, Require approval and Allow. | Vault policies apply to secret paths, not to API arguments |
| Agent budgets | Done for calls; spend not yet | Per grant: requests per 24 hours and writes per hour, counted from the access log, so they hold across restarts and instances. Over budget returns `BUDGET_EXCEEDED` (HTTP 429), and the grant page shows usage. | Vault has no concept of per-operation usage |
| Emergency stop | Done for the organization | One switch denies every agent request in the organization with `EMERGENCY_STOP` until someone resumes access. Stopping and resuming are audited, and a banner shows on every console page. A single agent or integration is stopped by disabling it. | Revoking leases doesn't stop secrets already handed out |

Also shipped: operation selectors that cover operations published later (`github.*`, `risk:write`, `github:destructive`), and a policy editor organized as Who / Where / What with a one-sentence summary and searchable pickers for hundreds of applications.

**Left over from Phase 1**

- ~~Approving and rejecting from Slack.~~ Done: Settings → Slack approvals posts held requests with Approve / Reject buttons; clicks are signature-checked and mapped to members by email, with the console's rules.
- Budgets in money (for example $100 of spend), which needs a cost per operation in the provider definitions.
- One policy naming several agents or integrations (today: one agent or agent type, one application or integration).

## Phase 2: Identity and data safety (in progress)

| Feature | Status | What it does | Why it matters |
| --- | --- | --- | --- |
| Acting on behalf of a user | Done | The customer's application signs a short-lived user token (JWT); the agent sends it as `on_behalf_of`. Token Vault verifies it with the public key of an issuer registered under **Settings → User Identity**, then limits the request to both the agent's grant and the user's own permissions (`token_vault` claim). Grants choose whether the agent acts for itself, only for users, or either, and which user groups. Policies can match `user.*` fields. Approvals are bound to the user. The access log records and filters "Agent X for user Y". SDK: `tv.forUser(token)`; MCP: `TOKEN_VAULT_USER_TOKEN_FILE`. | Most real agents act for a person. Vault only knows the workload. |
| Delegation to sub-agents | Done | An agent can pass a narrower, short-lived grant to a sub-agent (fewer operations and resources, earlier expiry). Revoking the parent grant revokes everything delegated from it. | Multi-agent systems need this. Vault has no concept of narrower delegation. |
| Response filtering | Done | The webhook removes or masks fields (emails, tokens, personal data) and can flag likely prompt-injection text before the response reaches the model | Stops the model leaking data or being manipulated. Only possible because Token Vault sits in the request path. |
| Session tracing | Done | Each call carries the agent's session or trace ID (OpenTelemetry), so the audit links each tool call to the conversation or task that made it | Shows why an action happened, not just that it did |

## Phase 3: Platform reach and intelligence (about 8–10 weeks)

| Feature | What it does |
| --- | --- |
| Gateway for any MCP server | Applies Token Vault's policies, approvals, budgets and audit to any MCP server, not only to HTTP APIs. This would be the strongest differentiator. |
| Least-privilege suggestions | Uses 30-day usage data (already shown in access reviews) to suggest removing unused scopes, narrowing resources or shortening expiries, applied in one click |
| Agent behaviour alerts | Learns each agent's usual operations, volume and resources. Unusual activity raises a security event and can suspend the agent automatically. |
| Policy test and explain | Answers "what could this agent do?" and "would this request be allowed, and why?" without running it. Also tests a policy change against past traffic. |

## Basics needed alongside

These don't set Token Vault apart from HashiCorp, but enterprise customers won't trust the features above without them. Work on them in parallel with the phases.

1. **A separate signing secret for each webhook.** The control plane signs requests to every webhook with one secret, `WEBHOOK_SIGNING_SECRET` ([server/src/config.ts](../server/src/config.ts)). The `webhooks.signing_secret_ref` column already exists, but every row points to the environment secret. Generate a secret at registration, store it encrypted, and sign each request with that webhook's own secret.
2. **Shared state in Redis.** Rate limits and idempotency are kept in each process, so several control plane instances (needed for high availability) give inconsistent results.
3. **SSO for the admin console** (OIDC).
4. **Row-level security in Postgres**, so organizations stay isolated even if a query forgets to filter by organization.
5. **A second real provider in live mode** (for example Slack, defined in the CMS), to show that providers can be added as data, without code changes.
6. **Rotation of `AUDIT_SIGNING_KEY`.** Today the key can't be changed without breaking verification of existing audit records.

## Recommended next step

Phase 2 is complete, and so are the Slack approvals left over from Phase 1. Next: Phase 3, starting with the **gateway for any MCP server**.

Session tracing shipped: agents send a `session_id` and the W3C `traceparent` header; Token Vault records the session and trace on every access record (denials too), adds its own span, passes the trace to the webhook, and shows **Audit → Sessions** with each session's timeline, linked from the access log and from approvals. The SDK has `session()` and a `traceparent` option; the MCP server makes each client session one session and each tool call a span. Left open: exporting spans to an OpenTelemetry collector.

Response filtering shipped: a *Filter responses* policy masks emails, phone numbers, card numbers, IP addresses, secrets and custom patterns, removes fields, and flags or withholds results that look like prompt injection. The customer webhook applies it, so masked values never leave the customer side; the control plane applies it when a webhook did not. The access log records what was filtered, never the values. Left open: a model-based injection classifier as an option, and filtering request inputs (not only results).

Delegation to sub-agents shipped: an agent (or sub-agent, up to 3 levels) hands a narrower, short-lived, optionally request-capped slice of one grant to a sub-agent with its own `tvdt_` token (SDK `delegate()`). Requests run against the parent's grant, so revoking the grant, the agent, or any delegation up the chain stops everything below it. Delegations inherit the user they act for, show on the agent and grant pages with a Revoke action, and the access log says "via sub-agent".

Left open from acting on behalf of a user: fetching issuer keys from a JWKS URL (with rotation), budgets per user, and a console view of activity per user.

## Possible later integrations with HashiCorp

Token Vault already uses HashiCorp Vault: Vault Transit can protect the webhook's encryption key (`VAULT_KEY_PROVIDER=vault-transit`), and [examples/kubernetes](../examples/kubernetes/README.md) loads configuration through External Secrets. The two products work together rather than compete. Other integrations to consider later:

- Reading provider credentials from Vault KV by reference, instead of copying them into the webhook's store.
- Keeping each webhook's signing secret in the control plane's own Vault.
- Letting agents log in with Vault-issued identity tokens (JWT) instead of `tvak_` keys.
- Issuing webhook TLS certificates from Vault PKI for mTLS.
