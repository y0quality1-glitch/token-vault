# Configuring Token Vault: the user journey

This guide walks through setting up Token Vault for an organization, from an empty account to AI agents working under guardrails, and then the day-to-day tasks that follow. It is written for the administrators who do the setup: the platform or security team at the customer organization.

Each step says **who** does it, **where** in the console, and **how to check** it worked. For the screen-by-screen map and flow diagrams, see [SCREEN_MAP.md](SCREEN_MAP.md).

## Before you start

| You need | Why |
| --- | --- |
| A Token Vault organization and an Owner account | Owners can do every step and invite the others |
| A server or cluster in your own environment for the **customer webhook** | It holds your provider credentials; Token Vault never does. See [DEPLOYMENT.md](DEPLOYMENT.md) |
| Credentials for the applications agents will use (a GitHub App, a personal access token, or OAuth client details) | They are entered once and stored only in your webhook |
| The agents themselves: an MCP client such as Claude Code, or your own code using the SDK | They connect with their own Token Vault key |

## Roles

| Role | Typical person | Does |
| --- | --- | --- |
| **Owner** | Head of platform | Everything, including members and roles |
| **Vault Administrator** | Platform engineer | Webhook, integrations, grants |
| **Security Administrator** | Security engineer | Policies, approvals, access requests, reviews, revocation, emergency stop |
| **Agent Developer** | Engineer building an agent | Registers and manages their own agents |
| **Auditor** | Compliance | Reads everything, changes nothing |

The overview below shows the whole journey. Steps 1–7 are one-time setup; step 8 onward is ongoing.

| # | Step | Who | Where |
| --- | --- | --- | --- |
| 1 | Invite your team | Owner | Settings → Members & Roles |
| 2 | Deploy and register the webhook | Vault Administrator | Your infrastructure, then Webhook / Vault Agent → Webhook Setup |
| 3 | Connect applications | Vault Administrator | Integrations → Integration Catalog |
| 4 | Register agents | Agent Developer | Agents → Agent Registry |
| 5 | Grant access | Vault Administrator | Access Management → Access Grants |
| 6 | Add policies (guardrails) | Security Administrator | Access Management → Policies |
| 7 | Connect the agent | Agent Developer | The agent's machine |
| 8 | Handle approvals and access requests | Security Administrator | Access Management → Approvals / Access Requests |
| 9 | Review, rotate and audit | Security and Vault Administrators | Access Reviews, Credential Status, Audit & Activity |
| 10 | In an incident | Security Administrator | Overview → Emergency stop |

---

## 1. Invite your team

**Who:** Owner · **Where:** Settings → Members & Roles

1. Add each person and give them the narrowest role that fits (see *Roles* above).
2. Keep at least two people who can approve (Owner or Security Administrator): the owner of an agent may never approve that agent's requests.

**Check:** each member can sign in and sees only the actions their role allows.

## 2. Deploy and register the customer webhook

**Who:** Vault Administrator · **Where:** your infrastructure, then Webhook / Vault Agent → Webhook Setup

The webhook is the only component that ever decrypts a provider credential. It runs in your environment, with your database and your encryption key.

1. **Deploy it** with its own PostgreSQL database. Follow [DEPLOYMENT.md](DEPLOYMENT.md) for Docker Compose or Kubernetes.
2. **Give it its secrets**:
   - `WEBHOOK_SIGNING_SECRET`: shared with Token Vault; signs every request between the two.
   - An encryption key for stored credentials: `VAULT_ENCRYPTION_KEY`, or better, a key service with `VAULT_KEY_PROVIDER=aws-kms` or `vault-transit` (HashiCorp Vault).
   - Optionally TLS and mutual TLS certificates.
3. **Register it in the console**: open **Webhook Setup**, enter the webhook's URL, choose the authentication method, and send the signed health challenge.
4. Token Vault pins the webhook's identity. From now on it checks it on every heartbeat (every 30 seconds).

**Check:** **Health & Connectivity** shows the webhook as *Connected*, with the key that encrypts credentials.

> Real provider calls are off by default. When you are ready, set `PROVIDER_MODES=github=live` (one application at a time) on the webhook.

## 3. Connect applications

**Who:** Vault Administrator · **Where:** Integrations → Integration Catalog → *application* → Connect

1. Pick the application (GitHub, or any application your platform team has published in the provider catalog).
2. Choose how it authenticates:
   - **GitHub App** (recommended for GitHub): each agent request gets its own short-lived token, limited to one repository and one permission. See [GITHUB_APP.md](GITHUB_APP.md).
   - **OAuth**: you sign in to the provider; the webhook keeps and refreshes the tokens. See [OAUTH.md](OAUTH.md).
   - **Token / API key**: paste it once.
3. Name the integration, pick its environment (development, staging, production) and, optionally, the **allowed resources** (for example, only `demo-org/demo-repo`). Nothing outside them can ever be granted.
4. Optionally set a **rotation reminder** (30–365 days).

The secret goes straight to your webhook, which encrypts it. The console only ever shows a masked identifier and a fingerprint.

**Check:** **Connected Integrations** shows the integration as *Connected*; **Credential Status** shows when it was last tested (credentials are re-tested every 6 hours).

## 4. Register agents

**Who:** Agent Developer (or Vault Administrator) · **Where:** Agents → Agent Registry → Register agent

1. Give the agent a name, owner team, environment and type (AI agent, application, …).
2. Copy the **API key** (`tvak_…`). It is shown once; Token Vault keeps only a hash.
3. Store it where the agent runs, as a secret (for example `TOKEN_VAULT_API_KEY`).

Optionally restrict the agent to source IP ranges.

**Check:** the agent appears in the registry as *Active*. Without a grant, everything it tries is denied, which is expected at this point.

## 5. Grant access

**Who:** Vault Administrator · **Where:** Access Management → Access Grants → Create grant

The 5-step wizard asks for:

1. **Agent.**
2. **Integrations.** Select one, or several to give the agent several applications at once.
3. **Operations** the agent may perform (for example *Read repository*, *Create issue*). Destructive operations (for example *Delete repository*) can be granted only if a Require approval policy covers them for this agent; each request then waits for a human, and the webhook must allow destructive operations (`WEBHOOK_ALLOW_DESTRUCTIVE=true`).
4. **Restrictions**:
   - **Resources**: for example one repository. Recommended.
   - **Validity**: start and expiry (at most one year).
   - **Rate limit**: requests per minute.
   - **Budgets** (optional): requests per 24 hours, and writes (operations that change data) per hour. Over budget, requests are denied with `BUDGET_EXCEEDED`.
   - **Acting for users**: whether the agent works for itself, only on behalf of a signed-in user, or either; optionally only for users in certain groups. See step 6.
   - **Source IP** (optional).
   - **Approval required** (optional): the grant stays pending until a Security Administrator approves it.
5. **Review** and create.

With several integrations, step 3 asks for operations per application and step 4 for each grant's name and resources, then the validity, rate limit, budgets, user and IP settings once for all. One grant is created per application, all or none, so each can still be edited, reviewed or revoked on its own. The agent uses all of them with its one API key.

Changing restrictions later (**Edit restrictions** on the grant) creates a new version; the old one is kept for the audit trail.

**Check:** the grant shows *Active*. In **Access Playground**, choose the agent, click **Get a credential**, and send a request: it is allowed.

## 6. Add policies (guardrails)

**Who:** Security Administrator · **Where:** Access Management → Policies → New policy

Grants say what an agent *may* do. Policies add organization-wide rules on top, checked on every request. Each policy has a **decision**, conditions (agent, integration, operations, environment, source IP, time window) and optional **argument rules** on what the request contains (`input.<name>`, `resource.<name>`).

| Decision | Use it for | Example |
| --- | --- | --- |
| **Deny** | Things that must never happen | Deny *Delete repository* everywhere; deny issue titles matching `pass(word)?\|secret`; deny all agent activity 22:00–06:00 UTC |
| **Require approval** | Risky actions a human should check first | Any write in production; payments where `input.amount` is greater than `500` |
| **Allow** | Recording which rule a request fell under (it never grants access) | Mark routine read traffic |
| **Filter responses** | Shaping what an agent gets back: mask personal data and secrets, remove fields, catch prompt injection | Mask emails and tokens in everything the support agent reads; withhold results that try to instruct the model |

Deny is checked before grants and always wins. Require approval is checked last, only for requests every other check allows. Filter responses never changes the decision: it is applied to the result of an allowed request, in your webhook, before the agent sees it.

**Check:** send a request in the Playground that the policy should catch, and open it in **Audit & Activity → Access Logs**. The decision trace shows which policy matched.

More detail, with every argument operator: [AGENTS.md](AGENTS.md#argument-rules-budgets-and-the-emergency-stop).

### Agents that act on behalf of users (optional)

**Who:** Security Administrator · **Where:** Settings → User Identity

When an agent works for a signed-in person, Token Vault can limit it to what that person may do and record who it acted for.

1. Your application team issues short-lived signed tokens (JWTs) for signed-in users and gives you the issuer (`iss`), the audience (`aud`) and the **public** key.
2. **Add issuer** with those values. Use **Check a user token** on a sample token: it shows the user, groups and permissions Token Vault reads from it.
3. On grants used for people, set **Acting for users** to *Only on behalf of a signed-in user*, and optionally limit the user groups.
4. Optional policies on the user: argument rules on `user.groups`, `user.email` or `user.sub` (for example, deny when `user.groups` is one of `contractors`).

**Check:** in the Access Playground, paste a user token into *On behalf of a user* and send a request. In **Access Logs**, the record shows "for <user>", and the *On behalf of user* filter finds it. More detail: [AGENTS.md](AGENTS.md#acting-on-behalf-of-a-user).

## 7. Connect the agent

**Who:** Agent Developer · **Where:** the machine or service the agent runs on

- **MCP clients (Claude Code, Claude Desktop):** run `npm run mcp:config` for ready-to-paste configuration, and export the agent's key as `TOKEN_VAULT_API_KEY`. The agent gets tools such as `github_create_issue` and `token_vault_list_access`.
- **Your own code:** use the TypeScript SDK, `new TokenVault()` then `tv.execute({...})`. For an agent working for a person, `tv.forUser(userToken)`.
- **Services on Kubernetes:** load the key from your secrets manager at start-up; see [examples/kubernetes](../examples/kubernetes/README.md).

Either way, the agent holds only its Token Vault key, never the provider credential. Full guide: [AGENTS.md](AGENTS.md).

**Check:** ask the agent to do something it is granted. The request appears in **Access Logs** as allowed.

---

**Sub-agents.** An agent that starts helpers can delegate part of a grant to each (SDK: `tv.delegate(…)`): fewer operations and resources, a short expiry, an optional request cap. You don't configure anything for this. Delegations show on the agent's **Access Grants** tab and on the grant's page, where you can **Revoke** one; that also stops every delegation made from it. The access log shows "via sub-agent <label>". More: [AGENTS.md](AGENTS.md#delegation-to-sub-agents).

---

## 8. Handle approvals and access requests

**Who:** Security Administrator (or Owner) · **Where:** Access Management. The sidebar shows how many are waiting.

**Approvals** (from Require-approval policies). An agent with the right grant tried something a policy holds back.

1. Open **Approvals** and select the request. You see exactly what will run: the operation, resource and full input, shown as agent-written text.
2. **Approve** or **Reject**, with a note.
3. If approved, the agent can run that exact request once, within 15 minutes. All other checks run again at that moment.

**Access requests** (just-in-time). An agent was denied because it lacks access, and asked for it.

1. Open **Access Requests** and read the agent's justification (agent-written, so verify it).
2. **Approve**, optionally narrowing operations, resources or duration (never widening), or **Reject**.
3. Approval creates a grant that expires by itself (15 minutes to 24 hours).

In both cases you cannot approve requests from an agent you own.

**Sessions.** If your agents send a session id or W3C trace context (the MCP server and the SDK's `session()` do), **Audit & Activity → Sessions** shows what each agent did in each conversation or task, in order, and every approval shows the session that led to it.

## 9. Review, rotate and audit

| Task | Who | Where | How often |
| --- | --- | --- | --- |
| Re-certify active grants; revoke unused ones | Security Administrator | Access Management → Access Reviews | Every 30 days (grants are flagged when due) |
| Rotate provider credentials | Vault Administrator | Connected Integrations → integration → **Rotate credential**; due dates in Credential Status | As set by the rotation reminder |
| Rotate an agent's key, with a grace period for the old key | Agent Developer | Agents → agent → Rotate API credential | When required, or on suspicion |
| Rotate the webhook's encryption key or signing secret | Vault Administrator | On the webhook (`npm run vault:rotate-key`, `npm run webhook:rotate-secret`); progress in Health & Connectivity | Per your key policy |
| Check what agents did | Auditor, Security Administrator | Audit & Activity → Access Logs, Security Events | Ongoing |
| Prove the audit log was not tampered with | Auditor | Security Events → Verify integrity | Before audits |

## 10. In an incident

**Who:** Security Administrator, Vault Administrator or Owner

Choose the narrowest stop that contains the problem. Each takes effect on the agent's next request; there are no long-lived tokens to wait out.

| Problem | Action | Where |
| --- | --- | --- |
| One grant is too broad | Revoke the grant | Access Grants → grant → **Revoke grant** |
| One agent misbehaves or its key leaked | Disable the agent, or rotate its key with no grace period | Agents → agent → **Disable agent** / **Rotate API credential** |
| One integration's credential is at risk | Disable the integration, then rotate the credential | Connected Integrations → integration → **Disable integration**, then **Rotate credential** |
| Unclear scope, or many agents involved | **Emergency stop**: denies every agent request in the organization | Overview → Emergency stop → Stop all agent access |

The emergency stop needs a reason, which agents see. A red banner shows on every page while it is on. Grants, keys and credentials are not changed, so when the cause is fixed, an Owner or Security Administrator clicks **Resume agent access** and everything works as before. Both actions are recorded as security events.

## Where to go next

- [AGENTS.md](AGENTS.md): connecting agents, approvals, argument rules, budgets.
- [API.md](API.md): every endpoint, for automating these steps.
- [DEPLOYMENT.md](DEPLOYMENT.md): deploying the webhook and the rest of the stack.
- [SCREEN_MAP.md](SCREEN_MAP.md): every screen and the main flows as diagrams.
