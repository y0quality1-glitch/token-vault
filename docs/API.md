# API Reference

## Admin API: `/api/v1`

Authenticated with the `tv_session` httpOnly cookie, which is set by `POST /auth/login` (a JWT recorded as a server-side session; API clients may send it as `Authorization: Bearer`). Org-scoped routes require a selected organization. Mutations are guarded by the RBAC matrix in `shared/src/rbac.ts`. The API follows the service template in [fileStructure.md](fileStructure.md); browse it at `/api-docs/` (OpenAPI: `/api-docs.json`).

**Routes.** Lists are `POST /<module>/getall` (filters in the JSON body, same names as the table's filters), a record is `GET /<module>/getbyid/:id`, create and update are `POST /<module>/save` (with `id`: update), and other actions are `POST /<module>/<action>` with `{ id, … }` in the body.

**Every response uses one envelope** (admin and agent API):

```json
{ "status": "10000", "msg": "Grant Fetched Successfully", "error": null, "details": { … }, "totalRecords": 0 }
```

`details` is the payload described below (lists: `{ items, … }`, with `totalRecords` = the number of items). A failure keeps its HTTP status and answers `{ "status": "10001", "msg": "", "error": "<message>", "code": "<CODE>", "details": { "fields": { "name": "…" } }, "totalRecords": 0 }`. A known path called with the wrong method answers 405 `METHOD_NOT_ALLOWED`.

| Method | Path | Permission | Notes |
| --- | --- | --- | --- |
| POST | `/auth/login` | public | `{email, password}` → session info; auto-selects the org when the user has exactly one |
| POST | `/auth/logout` | session | |
| GET | `/auth/me` | session | user, memberships, current org, role, permissions |
| POST | `/auth/selectOrganization` | session | `{organizationId}` |
| POST | `/auth/forgotPassword` | public | placeholder |
| POST | `/organization/getdata` | any role | the current organization |
| POST | `/organization/save` | `org:manage` | |
| POST | `/member/getall` | any role | |
| POST | `/member/save` | `members:manage` | `{id, role}`; the last owner cannot be demoted |
| POST | `/dashboard/getdata` | any role | overview aggregation |
| POST | `/webhook/getall` | any role | |
| POST | `/webhook/save` | `webhook:manage` | without `id`, step 1: returns a `PENDING` webhook and a one-time `registrationChallenge` |
| GET | `/webhook/getbyid/:id` | any role | |
| POST | `/webhook/save` | `webhook:manage` | with `id`, step 2 / later changes: `authenticationType` (`MTLS` needs an `https://` URL and a control-plane client certificate) and `endpointUrl` (audited `webhook.endpoint_changed`) |
| POST | `/webhook/test` | `webhook:manage` | `{id}`: signed health challenge → `{webhook, result}` |
| POST | `/webhook/simulateOutage` | `webhook:manage` | demo: `{id, enabled}` |
| POST | `/integration/getCatalog` | any role | |
| POST | `/integration/getall` | any role | |
| POST | `/provider/getall` · GET `/provider/getbyid/:key` | any role | application definitions and catalog status |
| POST | `/integration/save` | `integration:manage` | create (no `id`). PAT: `{provider, webhookId, displayName, environment, accountLabel, authType: "PAT", secret, allowedResources, description}`. GitHub App: `{…, authType: "GITHUB_APP", appId, installationId (optional), keySource: "stored" \| "webhook_env", privateKey (PEM, when stored)}`; `accountLabel` is optional and defaults to the installation's account. Secrets are forwarded to the webhook and never stored. An invalid key or unknown installation returns 400 `INVALID_PRIVATE_KEY` / `INSTALLATION_NOT_FOUND` / `APP_KEY_NOT_CONFIGURED` |
| GET | `/integration/getbyid/:id` | any role | includes granted agents |
| POST | `/integration/save` | `integration:manage` | with `id`: metadata only |
| POST | `/integration/test` | `integration:manage` | `{id}`: webhook decrypts the credential and calls the provider |
| POST | `/integration/setAccessMode` | `integration:manage` | `{id, accessMode}`: `BROKERED` (default), `DECISION_ONLY` or `SHORT_LIVED_CREDENTIAL` (GitHub App and OAuth integrations only, else 400). Audited; leaving Brokered is a warning |
| POST | `/integration/setRotationPolicy` | `integration:manage` | `{id, intervalDays}` (7–730, or `null` to remove): rotation reminder; the detail returns `rotationIntervalDays`; audited |
| POST | `/integration/checkCredentials` | `integration:manage` | re-tests every credential of the organization now (the scheduled check): returns `{valid, rejected, unknown, skipped}`; rejected → Invalid, recovered → Connected, both audited |
| POST | `/integration/rotate` | `integration:manage` | `{id, …}`. PAT: `{secret}`. GitHub App: `{privateKey}` (400 `KEY_MANAGED_BY_WEBHOOK` if the key lives in the webhook's environment). OAuth: 400 `RECONNECT_REQUIRED` |
| POST | `/integration/oauthStart` | `integration:manage` | `{provider, authType, webhookId, displayName, environment, clientId, clientSecret, allowedResources, …}` → `{authorizeUrl}` (see [OAUTH.md](OAUTH.md)) |
| POST | `/integration/oauthComplete` | `integration:manage` | `{code, state}` from the provider redirect; only the admin who started, once, within 10 minutes (`OAUTH_STATE_INVALID` otherwise) → integration |
| POST | `/integration/oauthCancel` | `integration:manage` | `{state}`: discard a pending connection |
| POST | `/integration/disable` · `/integration/enable` | `integration:manage` | `{id}` |
| DELETE | `/integration/delete/:id` | `integration:manage` | webhook crypto-shreds the credential; grants are revoked |
| POST | `/agent/getall` · GET `/agent/getbyid/:id` | any role | |
| POST | `/agent/save` | `agent:manage` | create (no `id`): returns `{agent, credential: {apiKey, keyId, issuedAt}}`. **The key is shown once** |
| POST | `/agent/save` | `agent:manage` (owner) | with `id`: update |
| POST | `/agent/rotateCredential` | `agent:manage` (owner) | `{id, graceMinutes?}` (0–1440, default 0): how long the old key keeps working; returns the new key once |
| POST | `/agent/revokePreviousCredential` | `agent:manage` (owner) | `{id}`: ends the grace period: the old key stops working now |
| POST | `/agent/disable` · `/agent/enable` | `agent:manage` (owner) | `{id}` |
| POST | `/agent/revokeGrants` | `grant:revoke` | `{id, …}` |
| POST | `/apiClient/getall` | any role | key IDs and masked keys only |
| POST | `/grant/getall` | any role | `{status?, agentId?, integrationId?}` |
| POST | `/grant/savemulti` | `grant:manage` | one agent, several applications: `{agentId, items: [{integrationId, scopes, repositories, name?}] (1–10, each integration once), validFrom, expiresAt, rateLimitPerMinute, …}` with the same shared fields as `/grant/save`. Creates one grant per item, all or none; a problem is reported as `items.<n>.<field>`. Default names: "<agent> → <integration>". 201 `{items: GrantDetail[]}` |
| POST | `/grant/save` | `grant:manage` | optional budgets `maxRequestsPerDay` (rolling 24 h) and `maxWritesPerHour` (rolling hour); `null` = no limit; `onBehalfOf` (`ALLOWED` default, `REQUIRED`, `NOT_ALLOWED`) and `allowedUserGroups` for acting on behalf of users |
| GET | `/grant/getbyid/:id` | any role | usage, history, versions, matching policies |
| POST | `/grant/revoke` | `grant:revoke` | `{id, reason}`; takes effect on the next authorization check |
| POST | `/grant/approve` | `grant:approve` | `{id}`: simulated approval |
| POST | `/grant/extend` | `grant:manage` | `{id, expiresAt}` |
| POST | `/grant/newVersion` | `grant:manage` | `{id, …}`: edit restrictions → new version; the old version becomes `SUPERSEDED` |
| POST | `/grant/expireNow` | `grant:manage` | `{id}`: demo (Scenario E) |
| POST | `/policy/getall` | any role | |
| POST | `/policy/save` | `policy:manage` | create, or update with `id`; `effect`: `DENY`, `ALLOW`, `REQUIRE_APPROVAL` or `FILTER` (with `responseFilter: {mask: [email|phone|credit_card|ip_address|secret], customPatterns: [{name, pattern}], removeFields: [], promptInjection: off|flag|block}`); `conditions.operations`: exact operation ids or selectors that also cover operations published later (`*`, `github.*` for every operation of an application, `risk:read` / `risk:write` / `risk:destructive`, `github:write` for one risk in one application); `conditions.arguments`: up to 10 `{field, op, value}` argument rules (`field` is `input.<name>`, `resource.<name>`, or `user.sub`, `user.email`, `user.name`, `user.groups`, `user.issuer` for the user the agent acts for; `op` is one of `equals, not_equals, contains, not_contains, matches, not_matches, in, not_in, longer_than, greater_than, less_than`) |
| POST | `/organization/getEmergencyStop` | any role | `{stopped, stoppedAt, stoppedBy, stoppedByName, reason}` |
| POST | `/organization/emergencyStop` | `grant:revoke` | `{reason}`: denies every agent request with `EMERGENCY_STOP` until lifted |
| POST | `/organization/liftEmergencyStop` | `grant:approve` | `{note?}` |
| POST | `/accessRequest/getall` · GET `/accessRequest/getbyid/:id` | `audit:read` | filters (body): `agentId, integrationId, grantId, decision, operation, from, to, search, user, sessionId` (`user` matches the subject or email of the user the agent acted for); each record has `onBehalfOf` |
| POST | `/auditEvent/getall` · GET `/auditEvent/getbyid/:id` | `audit:read` | filters (body): `eventType, outcome, actorType, search, category=security` |
| POST | `/grantRequest/getall` · GET `/grantRequest/getbyid/:id` | any role | just-in-time access requests (`{status: "PENDING"}`); includes the `pending` count |
| POST | `/grantRequest/approve` | `grant:approve` | `{id, durationMinutes, operations?, repositories?, rateLimitPerMinute?, note?}`; may narrow but not widen the request; the agent's owner cannot approve it; creates an expiring grant |
| POST | `/grantRequest/reject` | `grant:approve` | `{id, note?}` |
| POST | `/approval/getall` · GET `/approval/getbyid/:id` | any role | requests held by `REQUIRE_APPROVAL` policies, with the exact operation, resource and input (`{status: "PENDING"}`); includes the `pending` count |
| POST | `/approval/approve` | `grant:approve` | `{id, note?}`; the agent's owner cannot approve it; the agent may then run that exact request once, within 15 minutes |
| POST | `/approval/reject` | `grant:approve` | `{id, note?}`; the same request is answered with `APPROVAL_REJECTED` for 24 hours |
| POST | `/session/getall` | `audit:read` | `{search?, agentId?}`: requests grouped by session id (or trace id) and agent: `sessionLabel`, `requests`, `allowed`, `denied`, `held`, `firstAt`, `lastAt`, `integrations`, `users`, `subAgents` |
| POST | `/session/getdatabyid` | `audit:read` | `{id: sessionId, agentId?}`: the summary plus `timeline` (every request, oldest first) and `approvals` asked for during the session |
| POST | `/delegation/getall` | any role | `{agentId?}` or `{grantId?}`: sub-agent delegations with effective `status` (`ACTIVE`, `EXPIRED`, `REVOKED`, also when one up the chain was revoked), `statusReason` and `used` |
| POST | `/delegation/revoke` | `grant:revoke` | `{id, reason}`; stops it and everything delegated from it |
| POST | `/slackSettings/getdata` | any role | the Slack connection (workspace, channel, token hint, `interactionsUrl`); secrets are never returned |
| POST | `/slackSettings/save` | `policy:manage` | `{botToken?, signingSecret?, channelId, enabled}`; a new token is checked with Slack (`auth.test`); both secrets are required the first time and stored encrypted |
| POST | `/slackSettings/test` · `/slackSettings/disconnect` | `policy:manage` | send a test message · disconnect |
| POST | `/userIssuer/getall` | any role | identity providers trusted to vouch for users (public keys only) |
| POST | `/userIssuer/save` | `policy:manage` | `{id?, name, issuer, audience, publicKey, groupsClaim?, maxTokenLifetimeSeconds?, enabled?}`; `publicKey` is PEM or JWK (RSA 2048+, EC P-256/P-384, Ed25519), private keys are refused; `issuer` is unique per organization |
| DELETE | `/userIssuer/delete/:id` | `policy:manage` | tokens from it are refused from the next request |
| POST | `/userIssuer/verifyToken` | `policy:manage` | `{token}` → `{valid: true, user}` or `{valid: false, reason}`; runs nothing |
| POST | `/auditEvent/verifyIntegrity` | `audit:read` | verifies both audit hash chains → `{ok, verifiedAt, chains: [{table, ok, chainedRecords, legacyRecords, headSeq, headHash, problems}]}` |
| POST | `/accessReview/getdata` | any role | active grants with review status, 30-day usage, due / unused / expiring counts (`{summary: "1"}` for counts only) |
| POST | `/accessReview/certify` | `grant:revoke` | `{grantIds[], note?}`: records the review and restarts the 30-day interval. Revoke with `/grant/revoke` |
| POST | `/demo/reset` | `demo:reset` | |
| POST | `/demo/tamperAudit` | `demo:reset` | demo only: edits the newest chained audit event directly in the database (bypassing the append-only trigger) to demonstrate detection |

## Agent API: `/agent/v1`

The same envelope as the admin API: `details` holds the bodies shown below (for `request/execute` the decision, also for denials, whose envelope has `status: "10001"`, `code` = `decision_code` and `error` = `reason`). Delegations: `POST /delegation/save`, `POST /delegation/getall`, `POST /delegation/revoke` `{id, reason?}`; `GET /accessRequest/getbyid/:id` reads a just-in-time request.

Authenticated **only** with `Authorization: Bearer tvak_<keyId>_<secret>`. Admin cookies are ignored here.

`POST /agent/v1/request/execute`

```json
{
  "integration_id": "int_github_001",
  "operation": "github.issues.create",
  "resource": { "repository": "demo-org/demo-repo" },
  "input": { "title": "Token Vault POC test", "body": "Created through credential brokering." },
  "idempotency_key": "demo-request-0001",
  "on_behalf_of": "eyJhbGciOiJFUzI1NiJ9.…"
}
```

`session_id` and `session_label` are optional: the agent's session (conversation, task, job) this call belongs to. The optional `traceparent` header carries W3C trace context. When either is sent, the response includes `"trace": { "session_id", "trace_id", "span_id", "parent_span_id" }` and the access record keeps it (see *Sessions* in [AGENTS.md](AGENTS.md#sessions-and-tracing)).

`on_behalf_of` is optional: a signed user token (JWT) from an issuer registered under Settings → User Identity. With it, the agent acts for that user (see below).

Response (the same shape for allow and deny):

```json
{
  "request_id": "req_…",
  "correlation_id": "corr_…",
  "decision": "ALLOW",
  "decision_code": "ALLOWED",
  "reason": "Authorized by grant \"GitHub Issue Creation\".",
  "matched_rule": { "type": "grant", "id": "grt_…", "name": "GitHub Issue Creation" },
  "grant_id": "grt_…",
  "execution": { "status": "SUCCEEDED", "webhook_status": "OK", "upstream_status": 201, "duration_ms": 182, "simulated": true, "idempotent_replay": false, "credential": null },
  "result": { "number": 44, "title": "Token Vault POC test", "state": "open", "html_url": "…" },
  "checks": [{ "step": 1, "name": "Authenticate caller", "passed": true, "detail": "…" }]
}
```

**Access modes.** When the integration is not brokered, an allowed request is not run. The response has `execution.status: "HANDED_OFF"`, `result: null` and:

```json
"authorization": {
  "mode": "DECISION_ONLY",
  "decision_token": "eyJhbGciOiJFZERTQSIs…",
  "expires_at": "2026-11-12T10:02:00.000Z"
}
```

In `SHORT_LIVED_CREDENTIAL` mode, `authorization.credential` adds the token the customer webhook issued: `{type, token, token_type: "Bearer", expires_at, repositories?, permissions?, scopes?}`. The audit records what was issued (`execution.credential`), never the token. The decision token is a compact JWS (`alg: EdDSA`, `typ: tv-decision+jwt`) with the claims `iss`, `sub` (agent), `jti` (request id), `iat`, `exp`, `org_id`, `integration_id`, `provider`, `operation`, `resource`, `input_sha256` (SHA-256 of the input as canonical JSON, keys sorted), `mode`, and when they apply `on_behalf_of`, `delegation_id`, `approval_id`. Verify it with the keys at `GET /.well-known/jwks.json` (public, cached 5 minutes), or with the SDK's `verifyDecisionToken`. A Filter responses policy can't apply outside Brokered mode, so a request it covers is denied with `FILTER_NEEDS_BROKERED` (403).

HTTP status codes: 200 allowed · 202 waiting for human approval · 400 malformed or unknown operation · 401 unauthenticated · 403 denied (including `APPROVAL_REJECTED`, `EMERGENCY_STOP` and the `USER_*` codes) · 404 unknown integration · 409 `APPROVAL_INVALID` · 429 rate limited or `BUDGET_EXCEEDED` · 502 upstream error · 503 webhook unavailable.

**Human approval.** When a `REQUIRE_APPROVAL` policy matches a request that every other check allows, nothing runs. The response is HTTP 202 with `decision: "DENY"`, `decision_code: "APPROVAL_REQUIRED"` and:

```json
"approval": { "approval_id": "apv_…", "status": "PENDING", "expires_at": "…" }
```

Sending the same request again returns the same pending approval rather than a new one. Once a human approves it, send the identical request again (same integration, operation, resource and input), optionally with `"approval_id": "apv_…"`. All checks run again, so a revoked grant still wins, and the approval is then used up: the response carries `approval.status: "EXECUTED"`. A request with an `approval_id` that is unknown, for a different request, expired or already used is denied with `APPROVAL_INVALID`. An agent can have at most 10 approvals waiting; pending approvals lapse after 1 hour.

**Acting on behalf of a user.** With `on_behalf_of`, the token is verified first: signature (RS256/384/512, ES256/384 or EdDSA with the issuer's public key), `iss` registered and enabled, `aud` matching, `exp` not passed, lifetime within the issuer's maximum, and a `sub`. Any failure is denied with `USER_TOKEN_INVALID` (403), recorded, and nothing runs. Then step 9 (*Acting user*) applies the grant's setting and the user's own permissions from the token's `token_vault` claim:

| Code | When |
| --- | --- |
| `USER_REQUIRED` | The grant works only on behalf of a user, and the request has no user token |
| `USER_NOT_ALLOWED` | The grant works only for the agent itself, or the user is not in its allowed groups |
| `USER_PERMISSION_DENIED` | The operation or resource is outside the user's `token_vault` permissions |

The response then carries `"acting_for": { "sub", "email", "name", "issuer" }`. Approvals are bound to the user: an approval for one user's request is `APPROVAL_INVALID` for another user. `GET /agent/v1/approval/getbyid/:id` includes `on_behalf_of` (`sub`, `issuer`), and capabilities include each grant's `on_behalf_of` (`ALLOWED`, `REQUIRED` or `NOT_ALLOWED`) and `allowed_user_groups`.

**Response filtering.** When `FILTER` policies match an allowed request, the result is filtered (by the customer webhook, or by the control plane if the webhook did not) and the response carries `"filtering": { "policies", "masked": [{kind, count}], "removed_fields", "prompt_injection": { "detected", "signals": [{path, signal}] }, "withheld" }`. A withheld result (likely prompt injection with `promptInjection: block`, or too large to inspect) returns HTTP 200 with `decision: "ALLOW"`, `decision_code: "RESPONSE_WITHHELD"` and `result: null`; the operation did run. Access records include `filtering` (counts and signals, never values, and `appliedBy`: `webhook` or `control-plane`).

**Delegation to sub-agents.** `Authorization: Bearer tvdt_…` (a delegation token) works on every agent endpoint except `POST /accessRequest/save` (403). The request is evaluated as the delegating agent's, restricted to the delegated grant, operations, resources and request cap; the response then carries `"delegation": { "delegation_id", "label", "used", "max_requests" }`.

| Code | HTTP | When |
| --- | --- | --- |
| `DELEGATION_DENIED` | 403 | Outside the delegated grant, operations or resources; the request cap is used up; or the sub-agent sent its own user token |
| `DELEGATION_REVOKED` | 403 | The delegation, or one it came from, was revoked |
| `DELEGATION_EXPIRED` | 403 | The delegation, or one it came from, expired |

`POST /agent/v1/delegation/save` `{grant_id, label, operations[], resources[]?, expires_in_seconds? (60–86400, default 3600), max_requests?, on_behalf_of?}` returns 201 with the delegation and its `token` (shown once). Called with a delegation token, it delegates further from that delegation (`grant_id` optional). 400 when it would widen anything or includes a destructive operation, 403 when the grant is not active or the depth would exceed 3, 429 at 50 active delegations. `POST /agent/v1/delegation/getall` lists what the caller delegated (with `status`, `used`); `POST /agent/v1/delegation/revoke` (`{id, reason?}`) `{reason?}` revokes one (and so everything delegated from it).

`GET /agent/v1/approval/getbyid/:id` returns one of the agent's own approvals: `status` (`PENDING`, `APPROVED`, `REJECTED`, `EXPIRED` or `EXECUTED`), the exact `integration_id`, `operation`, `resource` and `input` that were approved, `decision_note` and `executed_request_id`.

`GET /agent/v1/request/getbyid/:id` returns one of the calling agent's own requests.

`POST /agent/v1/accessRequest/save` submits a just-in-time access request: `{integration_id, operations[], repositories[], justification, duration_minutes, denied_request_id?}`. It returns 201 with a `PENDING` request, 200 with `duplicate: true` if an identical request is already pending, 400 for destructive or unknown operations, and 429 once the agent has 3 pending requests. `GET /agent/v1/accessRequest/getbyid/:id` returns the status of one of the agent's own requests, including `grant_id` and `grant_expires_at` once approved.

`POST /agent/v1/operation/getall` returns the shape of every operation of the applications the calling agent has a grant on (any status): the primary resource and extra resource fields (name, label, anchored pattern, example), and per operation its id, label, risk, whether the resource is required, and its inputs (type, required, maximum length). `version` changes whenever one of those definitions changes. Definitions are not secret; the MCP server uses this to offer typed tools. Authorization is still decided per request.

`POST /agent/v1/capability/getdata` returns the calling agent's own grants: integration, operations, repositories, status and expiry. Revoked and expired grants are listed with their status, and superseded versions are omitted. Agent tooling uses it to pick an integration and to show the model what it may do. Authorization is still decided per request by `/execute`. See [AGENTS.md](AGENTS.md) for the SDK and MCP server.

## Slack: `/slack/interactions`

Slack's Interactivity Request URL (public, no session). Each request must carry a valid Slack signature (`X-Slack-Signature`, v0 HMAC-SHA256 over `v0:<timestamp>:<raw body>` with the stored signing secret) and a timestamp within five minutes; otherwise 401. Approve / Reject clicks are mapped to a Token Vault member by the Slack user's email and decided with the same rules as `POST /approvals/:id/approve` and `/reject`; the reply goes to Slack's `response_url`.

## Customer webhook: `/internal/v1` (port 4100)

Every endpoint requires a valid control-plane signature: the `x-tv-timestamp`, `x-tv-nonce` and `x-tv-signature` headers carrying HMAC-SHA256 of `METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(body)`. Every response carries `x-tv-response-signature`. No endpoint returns secret material.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/internal/v1/health?challenge=` | identity proof: `challenge_response = HMAC("health:<challenge>:<instance_id>")` |
| POST | `/internal/v1/credentials` | encrypt and store → `{credential_ref, masked_identifier, fingerprint, …}` |
| POST | `/internal/v1/credentials/:ref/rotate` | re-encrypt with a new secret |
| POST | `/internal/v1/credentials/:ref/test` | decrypt and call the provider; returns validity only |
| POST | `/internal/v1/credentials/:ref/delete` | crypto-shred |
| POST | `/internal/v1/execute` | validate `aud`, `exp`, TTL and org, then inject the credential and return a sanitized result |
| POST | `/internal/v1/credentials/issue` | short-lived credential mode: the same checks as `execute`, then return a GitHub App token minted for the request's repository and the operation's permissions (not revoked), or the current OAuth access token (refreshed if about to expire). 403 `CREDENTIAL_ISSUE_DISABLED` unless `WEBHOOK_ALLOW_CREDENTIAL_ISSUE=true`; 409 `CREDENTIAL_NOT_ISSUABLE` for stored keys and tokens |

For a GitHub App integration, `execution.credential` describes the token the webhook minted for this one request (the token itself is never returned):

```json
{ "type": "github_app_installation_token", "repositories": ["demo-org/demo-repo"], "permissions": { "issues": "write" }, "expires_at": "2026-11-04T13:00:00.000Z", "revoked": true }
```

It is also recorded in the audit event's metadata. For PAT integrations it is `null`.

If a stored credential cannot be decrypted with the configured key, `test` and `execute` return HTTP 500 with `CREDENTIAL_UNREADABLE`. No secret material or ciphertext is included.
