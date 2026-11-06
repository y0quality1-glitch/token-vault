# API Reference

## Admin API: `/api/v1`

Authenticated with the `tv_session` httpOnly cookie, which is set by `POST /auth/login`. Org-scoped routes require a selected organization. Mutations are guarded by the RBAC matrix in `shared/src/rbac.ts`.

Errors use one shape: `{ "error": { "code": "…", "message": "…", "details": { "fields": { "name": "…" } } } }`.

| Method | Path | Permission | Notes |
| --- | --- | --- | --- |
| POST | `/auth/login` | public | `{email, password}` → session info; auto-selects the org when the user has exactly one |
| POST | `/auth/logout` | session | |
| GET | `/auth/me` | session | user, memberships, current org, role, permissions |
| POST | `/auth/select-organization` | session | `{organizationId}` |
| POST | `/auth/forgot-password` | public | placeholder |
| GET | `/organizations/current` | any role | |
| PATCH | `/organizations/current` | `org:manage` | |
| GET | `/organizations/current/members` | any role | |
| PATCH | `/organizations/current/members/:id` | `members:manage` | `{role}`; the last owner cannot be demoted |
| GET | `/dashboard` | any role | overview aggregation |
| GET | `/webhooks` | any role | |
| POST | `/webhooks` | `webhook:manage` | step 1: returns a `PENDING` webhook and a one-time `registrationChallenge` |
| GET | `/webhooks/:id` | any role | |
| PATCH | `/webhooks/:id` | `webhook:manage` | step 2: `authenticationType` (MTLS is rejected in the POC) |
| POST | `/webhooks/:id/test` | `webhook:manage` | signed health challenge → `{webhook, result}` |
| POST | `/webhooks/:id/simulate-outage` | `webhook:manage` | demo: `{enabled}` |
| GET | `/integrations/catalog` | any role | |
| GET | `/integrations` | any role | |
| POST | `/integrations` | `integration:manage` | PAT: `{provider, webhookId, displayName, environment, accountLabel, authType: "PAT", secret, allowedResources, description}`. GitHub App: `{…, authType: "GITHUB_APP", appId, installationId (optional), keySource: "stored" \| "webhook_env", privateKey (PEM, when stored)}`; `accountLabel` is optional and defaults to the installation's account. Secrets are forwarded to the webhook and never stored. An invalid key or unknown installation returns 400 `INVALID_PRIVATE_KEY` / `INSTALLATION_NOT_FOUND` / `APP_KEY_NOT_CONFIGURED` |
| GET | `/integrations/:id` | any role | includes granted agents |
| PATCH | `/integrations/:id` | `integration:manage` | metadata only |
| POST | `/integrations/:id/test` | `integration:manage` | webhook decrypts the credential and calls the provider |
| PUT | `/integrations/:id/rotation-policy` | `integration:manage` | `{intervalDays}` (7–730, or `null` to remove): rotation reminder; the detail returns `rotationIntervalDays`; audited |
| POST | `/integrations/check-credentials` | `integration:manage` | re-tests every credential of the organization now (the scheduled check): returns `{valid, rejected, unknown, skipped}`; rejected → Invalid, recovered → Connected, both audited |
| POST | `/integrations/:id/rotate` | `integration:manage` | PAT: `{secret}`. GitHub App: `{privateKey}` (400 `KEY_MANAGED_BY_WEBHOOK` if the key lives in the webhook's environment). OAuth: 400 `RECONNECT_REQUIRED` |
| POST | `/integrations/oauth/start` | `integration:manage` | `{provider, authType, webhookId, displayName, environment, clientId, clientSecret, allowedResources, …}` → `{authorizeUrl}` (see [OAUTH.md](OAUTH.md)) |
| POST | `/integrations/oauth/complete` | `integration:manage` | `{code, state}` from the provider redirect; only the admin who started, once, within 10 minutes (`OAUTH_STATE_INVALID` otherwise) → integration |
| POST | `/integrations/oauth/cancel` | `integration:manage` | `{state}`: discard a pending connection |
| POST | `/integrations/:id/disable` · `/enable` | `integration:manage` | |
| DELETE | `/integrations/:id` | `integration:manage` | webhook crypto-shreds the credential; grants are revoked |
| GET | `/agents` · `/agents/:id` | any role | |
| POST | `/agents` | `agent:manage` | returns `{agent, credential: {apiKey, keyId, issuedAt}}`. **The key is shown once** |
| PATCH | `/agents/:id` | `agent:manage` (owner) | |
| POST | `/agents/:id/rotate-credential` | `agent:manage` (owner) | `{graceMinutes?}` (0–1440, default 0): how long the old key keeps working; returns the new key once |
| POST | `/agents/:id/revoke-previous-credential` | `agent:manage` (owner) | ends the grace period: the old key stops working now |
| POST | `/agents/:id/disable` · `/enable` | `agent:manage` (owner) | |
| POST | `/agents/:id/revoke-grants` | `grant:revoke` | |
| GET | `/api-clients` | any role | key IDs and masked keys only |
| GET | `/grants` | any role | `?status=&agentId=&integrationId=` |
| POST | `/grants` | `grant:manage` | |
| GET | `/grants/:id` | any role | usage, history, versions, matching policies |
| POST | `/grants/:id/revoke` | `grant:revoke` | `{reason}`; takes effect on the next authorization check |
| POST | `/grants/:id/approve` | `grant:approve` | simulated approval |
| POST | `/grants/:id/extend` | `grant:manage` | `{expiresAt}` |
| POST | `/grants/:id/versions` | `grant:manage` | edit restrictions → new version; the old version becomes `SUPERSEDED` |
| POST | `/grants/:id/expire-now` | `grant:manage` | demo (Scenario E) |
| GET | `/policies` | any role | |
| POST | `/policies` · PUT `/policies/:id` | `policy:manage` | |
| GET | `/access-requests` · `/access-requests/:id` | `audit:read` | filters: `agentId, integrationId, grantId, decision, operation, from, to, search` |
| GET | `/audit-events` · `/audit-events/:id` | `audit:read` | filters: `eventType, outcome, actorType, search, category=security` |
| GET | `/grant-requests` · `/grant-requests/:id` | any role | just-in-time access requests (`?status=PENDING`); includes the `pending` count |
| POST | `/grant-requests/:id/approve` | `grant:approve` | `{durationMinutes, operations?, repositories?, rateLimitPerMinute?, note?}`; may narrow but not widen the request; the agent's owner cannot approve it; creates an expiring grant |
| POST | `/grant-requests/:id/reject` | `grant:approve` | `{note?}` |
| GET | `/audit-integrity` | `audit:read` | verifies both audit hash chains → `{ok, verifiedAt, chains: [{table, ok, chainedRecords, legacyRecords, headSeq, headHash, problems}]}` |
| GET | `/access-reviews` | any role | active grants with review status, 30-day usage, due / unused / expiring counts (`?summary=1` for counts only) |
| POST | `/access-reviews/certify` | `grant:revoke` | `{grantIds[], note?}`: records the review and restarts the 30-day interval. Revoke with `/grants/:id/revoke` |
| POST | `/demo/reset` | `demo:reset` | |
| POST | `/demo/tamper-audit` | `demo:reset` | demo only: edits the newest chained audit event directly in the database (bypassing the append-only trigger) to demonstrate detection |

## Agent API: `/agent/v1`

Authenticated **only** with `Authorization: Bearer tvak_<keyId>_<secret>`. Admin cookies are ignored here.

`POST /agent/v1/execute`

```json
{
  "integration_id": "int_github_001",
  "operation": "github.issues.create",
  "resource": { "repository": "demo-org/demo-repo" },
  "input": { "title": "Token Vault POC test", "body": "Created through credential brokering." },
  "idempotency_key": "demo-request-0001"
}
```

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

HTTP status codes: 200 allowed · 400 malformed or unknown operation · 401 unauthenticated · 403 denied · 404 unknown integration · 429 rate limited · 502 upstream error · 503 webhook unavailable.

`GET /agent/v1/requests/:id` returns one of the calling agent's own requests.

`POST /agent/v1/access-requests` submits a just-in-time access request: `{integration_id, operations[], repositories[], justification, duration_minutes, denied_request_id?}`. It returns 201 with a `PENDING` request, 200 with `duplicate: true` if an identical request is already pending, 400 for destructive or unknown operations, and 429 once the agent has 3 pending requests. `GET /agent/v1/access-requests/:id` returns the status of one of the agent's own requests, including `grant_id` and `grant_expires_at` once approved.

`GET /agent/v1/operations` returns the shape of every operation of the applications the calling agent has a grant on (any status): the primary resource and extra resource fields (name, label, anchored pattern, example), and per operation its id, label, risk, whether the resource is required, and its inputs (type, required, maximum length). `version` changes whenever one of those definitions changes. Definitions are not secret; the MCP server uses this to offer typed tools. Authorization is still decided per request.

`GET /agent/v1/capabilities` returns the calling agent's own grants: integration, operations, repositories, status and expiry. Revoked and expired grants are listed with their status, and superseded versions are omitted. Agent tooling uses it to pick an integration and to show the model what it may do. Authorization is still decided per request by `/execute`. See [AGENTS.md](AGENTS.md) for the SDK and MCP server.

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

For a GitHub App integration, `execution.credential` describes the token the webhook minted for this one request (the token itself is never returned):

```json
{ "type": "github_app_installation_token", "repositories": ["demo-org/demo-repo"], "permissions": { "issues": "write" }, "expires_at": "2026-11-04T13:00:00.000Z", "revoked": true }
```

It is also recorded in the audit event's metadata. For PAT integrations it is `null`.

If a stored credential cannot be decrypted with the configured key, `test` and `execute` return HTTP 500 with `CREDENTIAL_UNREADABLE`. No secret material or ciphertext is included.
