# Token Vault POC

An **identity-aware credential authorization and brokering platform for applications and AI agents**, built as a proof of concept.

It shows that an AI agent can perform an authorized GitHub operation **without ever holding the customer's long-lived provider credential**:

1. **Who is requesting access?** Every agent authenticates with its own Token Vault API credential.
2. **What is it allowed to access?** Scoped, time-bound grants per integration, operation and repository, plus explicit deny policies.
3. **Where is the credential handled?** Only inside the customer-controlled webhook / vault runtime. It is encrypted at rest there and injected into the upstream call there.

> **This is a proof of concept.** Provider responses are simulated by default (`UPSTREAM_MODE=mock`; switch applications to their real APIs one at a time with `PROVIDER_MODES`). Request signing, AES-256-GCM encryption, scrypt hashing and the policy engine are real code paths, but they are **not production-hardened**. Nothing here makes a production-security claim.

---

## Quick start

Requirements: **Node.js 20.11+** (tested on Node 22), npm 10+, and **PostgreSQL 16** (Docker Compose provides one).

```bash
npm install
```

```bash
npm run db:up       # starts PostgreSQL 16 in Docker (docker-compose.yml) with the control plane, customer and CMS databases (port 5432 on 127.0.0.1; POSTGRES_PORT in a root .env changes it)
```

```bash
npm run dev
```

`npm run dev` first runs `npm run setup`. That generates `server/.env`, `webhook/.env` and `cms/api/.env` with random development secrets (including the CMS's Ed25519 signing key) and local database URLs (all git-ignored). It then starts five processes. On startup the API applies any pending database migrations and, if the database is empty, seeds the demo data:

| Process | URL | Trust zone |
| --- | --- | --- |
| Admin console (React + Vite) | http://localhost:5173 | Browser |
| Control plane API (Express) | http://localhost:4000 | Token Vault |
| Customer webhook / vault runtime (Express) | http://localhost:4100 | **Customer** |
| Provider CMS UI (React + Vite) | http://localhost:5174 | Browser |
| Provider CMS API (Express) | http://localhost:4200 | Token Vault platform team |

Open **http://localhost:5173** and sign in with a mock demo account. The password for every account is `TokenVault-Demo-2026`.

| Account | Role | Notes |
| --- | --- | --- |
| `owner@demo.test` | Organization Owner | Member of **Demo Organization** (seeded) and **Sandbox Organization** (empty), so it sees organization selection |
| `vault.admin@demo.test` | Vault Administrator | Webhook, integrations, grants |
| `security@demo.test` | Security Administrator | Policies, grant approval, revocation |
| `developer@demo.test` | Agent Developer | Own agents only; gets **permission denied** on audit pages |
| `auditor@demo.test` | Auditor | Read-only |

The **provider CMS** (http://localhost:5174) is where the platform team defines applications as data: `editor@cms.test` drafts, `publisher@cms.test` reviews and publishes (a different person must approve), `admin@cms.test` can do both and archive. Same password. See [docs/CMS.md](docs/CMS.md).

Other scripts:

```bash
npm run typecheck   # every workspace
```

```bash
npm test            # policy engine, sanitizer, CIDR, AES-GCM and request-signature tests (Vitest)
```

The database tests in `server/test/db.test.ts` run only when `TEST_DATABASE_URL` is set. They wipe that database, so point it at the dedicated test database:

```bash
TEST_DATABASE_URL=postgres://token_vault:token_vault@127.0.0.1:5432/token_vault_test WEBHOOK_TEST_DATABASE_URL=postgres://token_vault_customer:token_vault_customer@127.0.0.1:5432/token_vault_customer_test npm test
```

`WEBHOOK_TEST_DATABASE_URL` enables the webhook's store tests (`webhook/test/store.test.ts`) the same way, and `CMS_TEST_DATABASE_URL=postgres://token_vault_cms:token_vault_cms@127.0.0.1:5432/token_vault_cms_test` the CMS workflow tests (`cms/api/test/workflow.test.ts`).

Control-plane schema changes: update the entity in `server/src/entities/` and add a TypeORM migration in `server/src/databases/migrations/` (listed in `dataSource.ts`). The first migration, `Baseline`, creates the schema on an empty database and brings databases created by the earlier Drizzle migrations up to date. `npm run db:migrate` applies migrations without starting the API.

```bash
npm run build       # production builds of the console and the CMS UI
```

```bash
npm run test:e2e    # Playwright: full demo script + scenarios in Chromium
```

The end-to-end suite starts all five services itself (ports 4000, 4100, 4200, 5173 and 5174 must be free), so stop `npm run dev` first. It uses its own databases, `token_vault_e2e`, `token_vault_customer_e2e` and `token_vault_cms_e2e` (created by `npm run db:up`; override with `E2E_DATABASE_URL`, `E2E_WEBHOOK_DATABASE_URL` and `E2E_CMS_DATABASE_URL`), which are wiped at the start of each run, so your local dev data is untouched. It generates throwaway secrets per run and passes them as environment variables. After the run, it fails if any token, agent credential, private key, signing secret or encryption key appears in the server, webhook or CMS logs. If Chromium is not installed yet, run `npx -w e2e playwright install chromium` once. The HTML report is in `e2e/playwright-report/`.

CI (`.github/workflows/ci.yml`) runs typecheck, unit tests and the build on every push to `main` and every pull request, then the end-to-end suite. On failure, the Playwright report and service logs are uploaded as an artifact.

### Secrets at runtime only

If `WEBHOOK_SIGNING_SECRET` and `VAULT_ENCRYPTION_KEY` are already set in the environment, `npm run setup` (and therefore `npm run dev`) writes no `.env` files. Variables set in the environment also take precedence over any existing `.env` values. Give the webhook both variables and the control plane only `WEBHOOK_SIGNING_SECRET`. The control plane also needs `AUDIT_SIGNING_KEY` (32+ characters) in that mode.

To run the processes one at a time: `npm run dev -w server`, `npm run dev -w webhook`, `npm run dev -w client`, `npm run dev -w cms/api`, `npm run dev -w cms/client`. In runtime-only mode the CMS API needs `CMS_DATABASE_URL` and `CMS_SIGNING_PRIVATE_KEY` (an Ed25519 PEM) in its environment.

---

## Connect a real AI agent

Token Vault ships an **MCP server** (`mcp/`) and a **TypeScript SDK** (`sdk/`), so Claude or your own agent can call GitHub through Token Vault using only its own Token Vault key. Register an agent, give it a grant, then:

```bash
npm run mcp:config
```

This prints ready-to-paste configuration for Claude Code and Claude Desktop. Revoke the grant and the agent's next tool call is denied. When an agent is denied, it can **request time-limited access**. A Security Administrator approves or rejects the request under **Access Management → Access Requests**, and an approval becomes an expiring grant. For risky operations, a **Require approval** policy holds a granted request until a human approves that exact request under **Access Management → Approvals**; the agent then runs it once. Policies can also check what a request contains (**argument rules**, e.g. deny issue titles that mention a password), grants can carry **budgets** (requests per 24 hours, writes per hour), and an **emergency stop** on the Overview denies every agent request in the organization until it is lifted. See [docs/AGENTS.md](docs/AGENTS.md).

### Deploying Token Vault

Container images for all five services, a full-stack Docker Compose setup (`node deploy/compose/generate-env.mjs`, then `docker compose -f deploy/compose/docker-compose.yml up -d --build --wait`), Kubernetes manifests with External Secrets, and a smoke test: see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

### Services on Kubernetes

[examples/kubernetes](examples/kubernetes/README.md) shows a Node service deployed on Kubernetes. Its configuration (database URL, its Token Vault key) is loaded as environment variables at boot from a secrets manager (HashiCorp Vault through External Secrets, or a local Secret), and it calls Slack only through Token Vault, so no provider token ever enters the pod. It includes the Dockerfile, kustomize manifests (base, `vault` and `local` overlays) and rotation steps.

## Demo script (5–8 minutes)

The in-app **Demo guide** (sidebar footer) repeats this with direct links.

1. Sign in as `owner@demo.test` and choose **Sandbox Organization** to show the empty first-run state.
2. **Webhook / Vault Agent → Webhook Setup**: register `http://localhost:4100`, then send the signed health challenge.
3. **Integrations → Integration Catalog → GitHub → Connect**: enter any mock token, such as `mock_ghp_` followed by 20 or more characters. **Never use a real token in a demo.**
4. Point out that only a credential reference, a masked identifier and a keyed fingerprint are displayed.
5. **Agents → Register agent** "GitHub Assistant". Copy the one-time credential and click **Use in Playground**.
6. **Access Grants → Create grant**: allow *Read repository metadata* and *Create issue*, restricted to `demo-org/demo-repo`.
7. **Access Playground**: run preset **A** (allowed, simulated 201 from GitHub), then **B** (explicit deny policy) and **C** (resource restriction).
8. **Audit & Activity → Access Logs**: show both decisions and open one to see the decision trace.
9. Revoke the grant, then run preset **D**. The previously allowed request is now denied with `GRANT_REVOKED`.
10. Open **Security Events** and the grant detail page to show traceability.

Switch to **Demo Organization** for the seeded data and the remaining scenarios:

| Scenario | How to trigger it in the Playground | Result |
| --- | --- | --- |
| A: Successful access | Preset A | `ALLOW`, upstream 201 |
| B: Scope violation | Preset "Destructive operation" / "Scope denied" | `POLICY_DENIED` / `SCOPE_DENIED` |
| C: Resource restriction | Preset C (`demo-org/other-repo`) | `RESOURCE_DENIED` |
| D: Revoked grant | Revoke "GitHub Issue Creation", then preset D | `GRANT_REVOKED` |
| E: Expired grant | Preset E (seeded staging grant expired yesterday), or **Expire now** on any grant | `GRANT_EXPIRED` |
| F: Webhook unavailable | Preset F → **Simulate outage** (or stop the webhook process) | Authorized, but execution fails safely: `WEBHOOK_UNAVAILABLE` |
| Unauthorized agent | Preset "Unauthorized agent" | `AGENT_UNAUTHENTICATED` (HTTP 401) |
| Missing grant | Preset "Missing grant" (Partner GitHub) | `GRANT_MISSING` |
| Integration unavailable | Disable the integration, then send any request | `INTEGRATION_UNAVAILABLE` |
| Upstream provider error | Preset "Upstream provider error" | `UPSTREAM_ERROR` (mock GitHub returns 500) |
| Rate limit exceeded | Preset "Rate limit exceeded" (12 requests; limit is 10/min) | `RATE_LIMITED` (HTTP 429) |
| Malformed request | Preset "Malformed request" | `MALFORMED_REQUEST` (HTTP 400) |

> Seeded agents are created with random API keys that are discarded immediately, so nobody knows them. In the Playground, click **Get a credential**. This rotates the agent's key and loads the new key into page memory only.

**Reset:** use **Settings → Organization → Reset demo data** or the button on the Demo guide (Owner only). Data persists in PostgreSQL across restarts; to wipe it at startup instead, run the API with `SEED_MODE=reset`.

---

## Architecture

For a visual walkthrough of the whole system, see the **[Token Vault application and configuration flow](https://claude.ai/artifact/WTuQ7dvF3XKiZetLRq7YaR)** page: trust zones, where every secret lives, the setup steps in order, the signed provider catalog, connecting integrations, granting access and the path of one agent request. The page is private: ask its owner for access if the link does not open.

```mermaid
flowchart LR
  subgraph Browser
    UI[Admin console<br/>React + TS]
  end
  subgraph TV[Token Vault control plane :4000]
    API[Express API<br/>session + RBAC]
    PE[Policy / grant engine]
    BR[Credential broker<br/>signs execution requests]
    AU[(Append-only audit)]
    DB[(Metadata store<br/>refs, grants, policies)]
  end
  subgraph CUST[Customer environment :4100]
    WH[Webhook / vault runtime]
    VS[(Encrypted credential store<br/>AES-256-GCM)]
  end
  GH[GitHub API<br/>mock by default]
  Agent[AI agent] -- "Bearer tvak_… (own identity)" --> API
  UI -- "httpOnly session cookie" --> API
  API --> PE --> BR
  BR -- "HMAC-signed, 30 s TTL, nonce, audience" --> WH
  WH --> VS
  WH -- "injected token" --> GH
  API --> AU
  API --> DB
```

**Agent request flow** (spec Flow B):

1. The agent calls `POST /agent/v1/request/execute` with `Authorization: Bearer tvak_<keyId>_<secret>`. Its identity is derived from that credential. No agent ID supplied by the caller is ever trusted.
2. The control plane verifies the scrypt hash (and a user token in `on_behalf_of`, if sent), then runs the deterministic engine in this order: no emergency stop and agent active → **explicit DENY policies** (including argument rules on the request's input and resource) → grant exists and is active → validity window → integration active → scope → resource → **acting user** (an optional signed user token: the grant must allow acting for that user, within the user's own permissions) → **delegation limits** (a sub-agent with a `tvdt_` delegation token: only the delegated grant, operations, resources and request cap) → rate limit and budgets → source IP → **human approval** (only where a `REQUIRE_APPROVAL` policy matches: the request waits with `APPROVAL_REQUIRED` until a human approves that exact request). Any failed check means deny.
3. On ALLOW, the broker sends the customer webhook a signed execution request containing `request_id`, `iat`, `exp` (+30 s), `nonce`, `aud` (the webhook instance ID) and the credential **reference**.
4. The webhook verifies the HMAC, timestamp window, nonce (replay cache), audience, expiry and organization. It then decrypts the credential in memory, calls GitHub, and returns a **sanitized**, signed response.
5. Every decision, allowed or denied, writes an access request record and an audit event.

Revocation needs no token expiry: grant state is evaluated on every request, so revocation takes effect on the next authorization check.

### Repository layout

```
token-vault/
├── package.json              npm workspaces + root scripts
├── scripts/setup.mjs         generates server/.env, webhook/.env and cms/api/.env (random secrets, CMS signing key)
├── shared/                   @token-vault/shared: domain types, provider definitions (GitHub), RBAC matrix, decision codes
├── sdk/                      @token-vault/sdk: TypeScript client for the agent API (typed errors, key never logged)
├── mcp/                      Token Vault MCP server (stdio): brokered GitHub tools, plus typed tools generated from the catalog for every granted application
├── server/                   Control plane, structured per docs/fileStructure.md (Express + TypeORM)
│   ├── src/
│   │   ├── index.ts          connect, migrate, seed, then listen; graceful shutdown
│   │   ├── app.ts            App: middlewares, admin controllers (/api/v1), agent controllers (/agent/v1), Slack, JWKS, API docs
│   │   ├── config.ts         environment, validated at start-up
│   │   ├── swagger.ts        OpenAPI built from the registered routes (/api-docs.json, /api-docs/)
│   │   ├── controllers/      BaseController + one controller per module (routes, permissions, DTO validation)
│   │   ├── services/         business logic per module, plus the policy engine, broker, audit chain, provider registry
│   │   ├── entities/         TypeORM entities (camelCase properties on the snake_case tables)
│   │   ├── databases/        DataSource, AppDatabase singleton, client (Executor, transaction), migrations, DTOs per module
│   │   ├── core/             GenericResponse envelope, ApiError handling, ErrorCodes, AppRoutes
│   │   ├── middlewares/      session auth (JWT) + RBAC, class-validator DTO validation, request logging
│   │   ├── store/            repositories (only code that queries Postgres), seed, DTO views
│   │   ├── utils/jwt/        session tokens
│   │   └── lib/              crypto (scrypt, HMAC), ids, CIDR matching, sanitizer
│   └── test/                 vitest; database tests need TEST_DATABASE_URL
├── webhook/                  Customer webhook / vault runtime (separate process, customer trust zone)
│   ├── src/
│   │   ├── security/         HMAC verification + replay cache, AES-256-GCM sealing, masking
│   │   ├── db/               customer-side schema (credentials, used_nonces), pg pool, migration runner
│   │   ├── store/            encrypted credential store in the customer's own Postgres database
│   │   ├── providers/        generic executor for provider definitions, GitHub App plugin, simulated GitHub API
│   │   └── routes.ts         /internal/v1/{health,credentials,execute} (all signature-protected)
│   └── test/security.test.ts
├── client/                   Admin console (React 18 + TypeScript + Vite + Tailwind + Lucide)
│   └── src/
│       ├── components/ui/    reusable component library (button, card, badge, form, dialog, drawer, table, tabs, stepper, toast, secret)
│       ├── components/       AppShell (sidebar + header), guards, TrustBoundary diagram
│       ├── context/          Auth (session), Playground (in-memory agent credential)
│       ├── hooks/useApi.ts   data fetching + mutations
│       ├── lib/              API client, formatting utils
│       └── pages/            one file per screen (see docs/SCREEN_MAP.md)
├── cms/                      Provider CMS (platform team): applications as signed, versioned definitions
│   ├── api/                  Express + Drizzle: draft/review/publish workflow, Ed25519 signing, public catalog, audit
│   └── client/               React UI; reuses the console's UI components via the @ui alias
├── deploy/                   images (docker/), full-stack compose + smoke test (compose/), Kubernetes manifests (k8s/)
├── examples/kubernetes/      Node service on Kubernetes: config from a secrets manager at boot, Slack only through Token Vault
└── docs/
    ├── CMS.md                provider CMS: roles, workflow, signing and the catalog API
    ├── PROVIDER_DEFINITIONS.md  provider definition format and safety rules
    ├── SCREEN_MAP.md         information architecture, screen map, journeys
    ├── AGENTS.md             connecting AI agents: MCP server and SDK
    └── API.md                endpoint reference
```

---

## Security model: what is real and what is simulated

| Concern | POC implementation | Production direction |
| --- | --- | --- |
| Provider secrets | Sent browser → control plane (TLS in prod) → webhook, **never persisted** by the control plane. They are removed from the request object after forwarding and are not logged. | Same, or direct browser → webhook upload |
| Encryption at rest | AES-256-GCM in the webhook, with the credential ref bound as AAD. Ciphertext lives in the customer's own Postgres database (`token_vault_customer`, separate role). Either an environment key, or **a KMS (AWS KMS or HashiCorp Vault Transit) with envelope encryption**: each credential has its own data key, wrapped by the KMS, so the master key never leaves the KMS and every unwrap is logged there. Never stored in the database; each record names the key that protects it. Keys can be rotated, or moved to a KMS, without losing credentials (see *Rotating keys*), and a KMS outage never marks credentials invalid. | HSM-backed KMS keys, per-tenant keys |
| Replay protection | Nonces of signed requests are recorded in the customer database, so a replay is rejected even when it reaches a different webhook instance | Same |
| Control plane ↔ webhook | Shared-secret HMAC-SHA256 over method, path, timestamp, nonce and body hash. Responses are signed too. 60 s skew window and a nonce replay cache. The secret can be rotated with no failed requests: the webhook accepts the old and new secret and answers with the one each request used (see *Rotating keys*). Optional **mutual TLS** underneath: the webhook accepts only the control plane's client certificate, and the control plane verifies the webhook's certificate (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#mutual-tls-between-the-control-plane-and-webhooks)). | The local dev setup runs plain HTTP; asymmetric request signatures |
| Webhook identity | A signed challenge/response at registration and on every heartbeat. The instance ID is pinned. | Certificate-bound identity |
| Agent credentials | `tvak_<keyId>_<secret>`. Only a **scrypt hash** is stored. Shown once. Rotation can keep the old key working for a grace period (up to 24 h) so the agent switches without failed requests; requests with it carry `Token-Vault-Key-Expires`, and an administrator can end the grace period early. | Same, plus optional workload identity federation |
| Admin sessions | Opaque token in an **httpOnly, SameSite=Strict** cookie. Nothing is kept in `localStorage`. | Enterprise SSO (out of scope) |
| Playground agent key | React state only. Lost on reload. Never placed in storage or URLs. | n/a |
| Audit | Append-only: Postgres triggers reject `UPDATE`/`DELETE` on `access_requests` and `audit_events`. A sanitizer redacts secret-looking keys and values before insert. Each access record and its audit event commit in one transaction. | Immutable store (WORM / ledger), separate DB role without TRUNCATE |
| Audit tamper evidence | Every audit record is hash-chained per organization and HMAC-signed with `AUDIT_SIGNING_KEY`, which lives outside the database. **Security Events → Verify integrity** detects edited, deleted, reordered or forged records, even if someone bypasses the append-only triggers with database access. Removing the *newest* records is detectable only against an external copy of the chain head. Records written before the chain existed are reported as legacy. | Anchor the chain head externally (e.g. signed and published periodically); key rotation with key IDs |
| Access reviews | Active grants must be re-certified every 30 days (**Access Management → Access Reviews**). The page shows 30-day usage so unused grants stand out; keep and revoke decisions are audited. Overview alerts for reviews due and grants expiring within 72 hours | Scheduled review campaigns with assigned reviewers and auto-revoke on missed reviews |
| Admin sessions at rest | Stored in Postgres as the SHA-256 of the cookie token, so a database dump holds no usable session | Same |
| Org isolation | Every query is scoped by `organizationId`. The webhook also checks `org_id` on each credential. | Same, plus row-level security |
| Logs | Method, path, status and latency only. No bodies, headers or query strings. | Structured logging with redaction |
| OAuth 2.0 connections | Authorization code + PKCE. The client secret, the PKCE verifier and all tokens live only in the customer webhook, which refreshes access tokens (single-flight, refresh-token rotation, one retry on 401). The control plane binds `state` to the admin who started, single use, and only relays the single-use code. See [docs/OAUTH.md](docs/OAUTH.md). | Token revocation at the provider on delete; client-credentials flow |
| GitHub App credentials | The webhook holds only the App's private key (encrypted in the customer store, or in its own environment via `GITHUB_APP_PRIVATE_KEY`). For each authorized request it mints an installation token **narrowed to the one repository and the one permission the operation needs** (e.g. `issues:write` for `github.issues.create`), uses it once and revokes it. The control plane and audit log only see the token's scope, never the token. See [docs/GITHUB_APP.md](docs/GITHUB_APP.md). | Same; keep the key in a KMS/HSM and sign the App JWT there |
| Provider definitions | Applications are data, not code ([docs/PROVIDER_DEFINITIONS.md](docs/PROVIDER_DEFINITIONS.md)), authored in the provider CMS with draft → review → publish, separation of duties, explicit confirmation of new API hosts, a one-click "make available / coming soon" switch and direct publishing for administrators (every application, seeded ones included, is edited as a new version), and Ed25519-signed published versions ([docs/CMS.md](docs/CMS.md)). The control plane and each webhook pull the catalog independently and accept only definitions that verify against the pinned CMS key; a provider published in the CMS is usable without a deploy. The console's Integration Catalog (tiles, categories, icons, "coming soon" entries, docs links) is entirely driven by these definitions. Each service keeps its last verified catalog and the highest accepted version per provider in its own database, re-verified on start-up, so a restart while the CMS is down keeps those providers and an old signed version cannot be replayed. The CMS signing key can be rotated without downtime: each published version carries a signature per key, and consumers may pin the old and new keys during the switch. The webhook builds each request from the definition, checks the host against its allow-list **before** attaching the credential, never follows redirects, and returns only allow-listed response fields. Templates cannot reference credentials | Signing key in a KMS/HSM |
| Upstream providers | **Simulated** by default. Set `PROVIDER_MODES=github=live` in `webhook/.env` to call the real GitHub API while other applications stay simulated (`UPSTREAM_MODE=live` makes every application live). In mock mode App JWTs are really signed and the simulated GitHub enforces minted-token scope. | A GitHub App installed on selected repositories of a dedicated test org (PATs remain available for demos) |

### Deviations from the specification

- **React + Vite instead of Next.js.** You asked for React with an Express backend, so the client is a Vite SPA with React Router. Same stack otherwise: TypeScript, Tailwind, Lucide.
- **Shadcn UI is not installed.** An equivalent component library was hand-written in `client/src/components/ui` in the same style. It has no CLI or codegen dependency.
- **TypeORM in the control plane, Drizzle in the webhook.** The control plane follows the service template in docs/fileStructure.md (TypeORM, class-validator, controllers and services). The customer webhook keeps Drizzle: it is a small, separately deployed runtime.
- **Text IDs instead of UUIDs.** Primary keys are prefixed random IDs (`agt_…`, `grt_…`), so they are recognizable in logs and audit records.
- **Integrations are soft-deleted** (`deleted_at`), so grants and audit records keep a valid reference.
- **One local Postgres server hosts both trust zones** for convenience, as separate databases with separate roles: the control plane's `token_vault` role cannot connect to the customer databases. In a real deployment the customer runs their own database server.
- **Shared-secret HMAC** signs every request. mTLS is available on top of it (wizard option *Mutual TLS + signed requests*) once both sides have certificates; `npm run dev` runs without them.
- **Redis is not used.** Rate limiting, the nonce cache and idempotency are in-process, so they reset on restart and are per instance.
- **Explicit DENY policies are evaluated before grant checks.** This makes "explicit deny takes precedence" observable: a destructive operation reports the matched deny policy instead of a generic scope error.

---

## Configuration

`server/.env` (control plane):

| Variable | Purpose |
| --- | --- |
| `PORT` | API port (4000) |
| `WEBHOOK_SIGNING_SECRET` | HMAC secret shared with the webhook (32+ bytes); signs every request |
| `WEBHOOK_PREVIOUS_SIGNING_SECRETS` | Optional, comma-separated: old secrets still accepted on webhook responses during a rotation |
| `DEFAULT_WEBHOOK_URL` | Pre-filled webhook URL and the seeded webhook endpoint |
| `DATABASE_URL` | PostgreSQL connection string (required) |
| `AUDIT_SIGNING_KEY` | HMAC key (32+ characters) for the audit chain signatures (required). Never stored in the database. Changing it makes existing signatures fail verification; key rotation is not supported in the POC |
| `SESSION_JWT_SECRET` | Signs console sessions (HS256 JWT, 32+ characters). Required in production; elsewhere derived from `AUDIT_SIGNING_KEY` when unset |
| `DATABASE_READ_URL` / `DATABASE_SSL` | Optional: a read replica for plain reads; `require` for TLS with certificate validation |
| `SEED_MODE` | `if-empty` (default): seed demo data into an empty database. `reset`: wipe and reseed on every start (used by the e2e suite) |
| `DB_POOL_MAX` | Connection pool size (default 10) |
| `HEARTBEAT_INTERVAL_MS` | Signed health-check interval (default 30000) |
| `CREDENTIAL_CHECK_INTERVAL_MS` | How often every stored credential is re-tested with its provider (default 21600000 = 6 h; `0` turns the schedule off). A credential the provider rejects (HTTP 401, a refused OAuth refresh, a rejected GitHub App key or installation) is marked **Invalid** and audited (`integration.credential_rejected`); one that works again is marked **Connected** (`integration.credential_recovered`). Outages (5xx, 429, timeouts) never change the status |
| `CONSOLE_PUBLIC_URL` | Where the console is served (default `http://localhost:5173`); OAuth providers redirect to `<this>/oauth/callback` |
| `API_PUBLIC_URL` | Where the control plane is reachable from the internet (default `http://localhost:4000`); Slack sends approval button clicks to `<this>/slack/interactions` |
| `DECISION_SIGNING_KEY` | Optional: seed for the Ed25519 key that signs decision tokens (integrations in decision-only or short-lived credential mode). Derived from `AUDIT_SIGNING_KEY` when unset; the public key is always at `/.well-known/jwks.json` |
| `DECISION_TOKEN_TTL_S` | How long a decision token is valid, 10–900 seconds (default 120) |
| `SETTINGS_ENCRYPTION_KEY` | Optional: encrypts secrets Token Vault stores for itself (the Slack bot token and signing secret). Derived from `AUDIT_SIGNING_KEY` when unset |
| `SLACK_API_URL` | Slack Web API base (default `https://slack.com/api`); tests point it at a stand-in |
| `CMS_CATALOG_URL` | Provider CMS catalog (`http://localhost:4200/catalog/v1`). Optional: without it only the bundled definitions are used |
| `CMS_PUBLIC_KEY` / `CMS_PUBLIC_KEY_FILE` | Pinned Ed25519 public key(s) of the CMS (PEM; `\n` escapes allowed; several concatenated during a key rotation). Required with `CMS_CATALOG_URL`; written by `npm run setup` |
| `CMS_POLL_INTERVAL_MS` | Catalog polling interval (default 30000) |
| `WEBHOOK_TLS_CA` / `_FILE` | CA bundle trusted for webhook server certificates (default: system CAs) |
| `CONTROL_PLANE_TLS_CERT` / `_FILE`, `CONTROL_PLANE_TLS_KEY` / `_FILE` | Client certificate presented to webhooks (mTLS) |
| `WEBHOOK_REQUIRE_TLS` | `true`: refuse `http://` webhook URLs (default `false`) |

`webhook/.env` (customer zone):

| Variable | Purpose |
| --- | --- |
| `PORT` | Webhook port (4100) |
| `WEBHOOK_SIGNING_SECRET` | Must match the control plane (except during a rotation) |
| `WEBHOOK_PREVIOUS_SIGNING_SECRETS` | Optional, comma-separated: old secrets still accepted during a rotation. Each response is signed with the secret its request used |
| `VAULT_ENCRYPTION_KEY` | Base64 of 32 random bytes. AES-256 key for the credential store: encrypts every new or changed credential |
| `VAULT_PREVIOUS_ENCRYPTION_KEYS` | Optional, comma-separated. Earlier keys, kept only to read credentials written before a rotation; at start-up the webhook re-encrypts those under the current key |
| `VAULT_KEY_PROVIDER` | `env` (default: `VAULT_ENCRYPTION_KEY` seals records), `aws-kms` or `vault-transit` (envelope encryption; `VAULT_ENCRYPTION_KEY` then only reads older records). See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#protecting-the-vault-key-with-a-kms) |
| `KMS_KEY_ID`, `AWS_REGION`, `KMS_ENDPOINT` | AWS KMS: key id, ARN or alias; region; optional endpoint (VPC endpoint, LocalStack). AWS credentials come from the default chain (IRSA, Pod Identity, task role, instance profile) |
| `VAULT_ADDR`, `VAULT_TRANSIT_KEY`, `VAULT_TRANSIT_MOUNT`, `VAULT_TOKEN` or `VAULT_K8S_ROLE` (+ `VAULT_K8S_MOUNT`, `VAULT_K8S_TOKEN_PATH`), `VAULT_NAMESPACE` | Vault Transit: address, key, mount (default `transit`), and a token or Kubernetes auth |
| `KMS_DATA_KEY_CACHE_SECONDS`, `KMS_TIMEOUT_MS` | How long unwrapped data keys stay in memory (default 300; `0` = never), and the per-call key-service timeout (default 2000) |
| `WEBHOOK_TLS_CERT` / `_FILE`, `WEBHOOK_TLS_KEY` / `_FILE` | Serve HTTPS with this certificate and key |
| `WEBHOOK_TLS_CLIENT_CA` / `_FILE`, `WEBHOOK_TLS_ALLOWED_CLIENTS` | Require a client certificate from this CA on `/internal/*`, optionally only these identities (`URI:…`, `DNS:…`, `CN=…`) |
| `WEBHOOK_INSTANCE_ID` | Identity pinned by the control plane (signature audience) |
| `WEBHOOK_DATABASE_URL` | Customer-side PostgreSQL connection string (required). Deliberately a different variable from the control plane's `DATABASE_URL` |
| `SEED_MODE` | `if-missing` (default): create the demo mock credentials where absent or unreadable. `reset`: wipe the credential store on start (used by the e2e suite) |
| `UPSTREAM_MODE` | `mock` (default) or `live`: the default for every application. `GITHUB_MODE` is still read when `UPSTREAM_MODE` is not set |
| `WEBHOOK_ALLOW_CREDENTIAL_ISSUE` | `true` lets this webhook hand a short-lived credential to the caller for integrations in short-lived credential mode: a GitHub App token for one repository and the operation's permissions, or the current OAuth access token. Stored keys and tokens are never handed out. Default `false` |
| `WEBHOOK_ALLOW_DESTRUCTIVE` | `true` lets this webhook run destructive operations (delete a repository, write a file), and then only for requests a human approved in Token Vault. Default `false`: the customer decides whether destructive actions can ever run |
| `PROVIDER_MODES` | Per-application override, e.g. `github=live,slack=mock`: go live with one provider at a time. Anything malformed stops the webhook at start-up rather than silently staying simulated (or going live) |
| `MOCK_OAUTH_TOKEN_TTL_S` | Lifetime of access tokens issued by the simulated OAuth server in mock mode (default 3600) |
| `GITHUB_APP_PRIVATE_KEY` | Optional. GitHub App private key (PEM; `\n` escapes allowed) for integrations created with "Already configured on the webhook". Inject it as a secret; never commit it |
| `GITHUB_APP_PRIVATE_KEY_FILE` | Optional. Path to the PEM file instead of the variable above (takes precedence) |
| `CMS_CATALOG_URL`, `CMS_PUBLIC_KEY` / `CMS_PUBLIC_KEY_FILE`, `CMS_POLL_INTERVAL_MS` | Same as the control plane. The webhook verifies the catalog itself, so the control plane cannot change where credentials are sent |

`cms/api/.env` (provider CMS):

| Variable | Purpose |
| --- | --- |
| `PORT` | CMS API port (4200) |
| `CMS_DATABASE_URL` | The CMS's own PostgreSQL database (`token_vault_cms`, separate role) |
| `CMS_SIGNING_PRIVATE_KEY` | Ed25519 private key (PEM; `\n` escapes allowed) that signs published definitions. Only the CMS holds it; consumers pin the public key from `/catalog/v1/public-key`. To rotate without downtime, see Key rotation in [docs/CMS.md](docs/CMS.md) (`npm run cms:rotate-key` locally) |
| `SEED_MODE` | `if-empty` (default): seed demo users and the GitHub definition into an empty database. `reset`: wipe and reseed on start (tests, e2e) |

### Rotating keys

**Moving to a KMS** (AWS KMS or Vault Transit, envelope encryption): keep `VAULT_ENCRYPTION_KEY`, set `VAULT_KEY_PROVIDER` and the KMS settings, restart the webhook (it re-encrypts every credential under the KMS), then remove `VAULT_ENCRYPTION_KEY`. Details and outage behaviour: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#protecting-the-vault-key-with-a-kms).

**Credential encryption key** (no credential is lost, no downtime beyond a webhook restart):

1. `npm run vault:rotate-key` writes a new `VAULT_ENCRYPTION_KEY` to `webhook/.env` and moves the old one to `VAULT_PREVIOUS_ENCRYPTION_KEYS`.
2. Restart the webhook. At start-up it re-encrypts every credential still on an older key, including records from versions before key ids (`#v1`). Each update only applies if the record is unchanged, so a concurrent OAuth refresh is never overwritten. Fingerprints and masked identifiers stay the same.
3. Check **Webhook Health**: the last check says which key encrypts the credentials, and how many are still on an older key.
4. When none are, `npm run vault:rotate-key -- --retire` removes the previous key; restart the webhook.

Elsewhere, do the same with your secret manager: new key in `VAULT_ENCRYPTION_KEY`, old key in `VAULT_PREVIOUS_ENCRYPTION_KEYS`, restart, then remove the old one. The scripts print key ids, never keys.

If a credential cannot be decrypted with any configured key (a key was removed too early, or replaced without keeping the old one), the webhook logs how many are affected but **never deletes them** (a misconfigured key must not destroy customer credentials). Requests that use them fail with `CREDENTIAL_UNREADABLE` until the key that encrypted them is added back as a previous key, or the credential is rotated. The seeded mock credentials are recreated automatically.

**Webhook signing secret** (no failed requests; restart the webhook first):

1. `npm run webhook:rotate-secret` gives the webhook a new secret and keeps accepting the old one (`WEBHOOK_PREVIOUS_SIGNING_SECRETS`). Restart the webhook. It answers each request with the secret that signed it, so the control plane keeps working on the old secret.
2. `npm run webhook:rotate-secret -- --switch` makes the control plane sign with the new secret, still accepting the old one on responses. Restart the control plane.
3. `npm run webhook:rotate-secret -- --retire` removes the old secret from both. Restart both.

The last health check on **Webhook Health** says which step is next ("the webhook has the new secret, Token Vault still signs with the old one", then "both sides use the new secret; the old one can be retired"). The script refuses steps out of order and never prints secrets. Elsewhere, do the same with your secret manager, in the same order.

**Rotation reminders:** on an integration's page, **Rotation reminder** sets how often its credential should be rotated (30 to 365 days; the API accepts 7 to 730). The due date counts from the last rotation, or from the connection. **Credential Status** shows it under *Rotate by*, and the dashboard reminds a week ahead (info) and once it is overdue (warning). Reminders never block agents: an overdue credential keeps working until it is rotated.

**Agent API keys:** **Agents → agent → Rotate API credential** issues a new key and can keep the old one working for 15 minutes to 24 hours. Requests with the old key succeed and carry a `Token-Vault-Key-Expires` header (the SDK exposes it as `tv.keyExpiresAt` and calls `onKeyExpiry`; the MCP server logs a warning). The agent page shows when the old key was last used, and **Revoke old key now** ends the grace period early. Rotating again ends any earlier grace period.

**Upgrading from the JSON store:** on first start, the webhook imports any records from `webhook/data/vault-store.json` that the current key can decrypt, then renames the file to `vault-store.json.imported`. For a Docker volume created before this change, run `npm run db:init` once to create the customer role and databases.

## Troubleshooting

- **`cannot use PostgreSQL at …` when starting or migrating:** the message names the address and says what to do. The common cases:
  - `ECONNREFUSED`: the database isn't running. Run `npm run db:up`.
  - `ECONNRESET` (often on Windows): the port accepted the connection and dropped it. Either the Docker database is still starting (`docker compose ps` should say healthy), or Node reached `localhost` over IPv6, which Docker Desktop forwards badly. `npm run setup` now writes `127.0.0.1` into the `.env` files and converts older files that say `localhost`.
  - `28P01` (password rejected), or `ECONNRESET` that persists with `127.0.0.1`: another program holds port 5432 (often a PostgreSQL installed on Windows: `Get-Service *postgres*`), or Docker's forward on that port is broken. Move the local database to another port: see *Database on another port* below.
  - `3D000` / `28000` (database or role missing): run `npm run db:init`.
  Then run `npm run db:migrate`, which applies every service's migrations and exits.
- **Database on another port:** when 5432 is taken, create a `.env` file at the repository root with one line, `POSTGRES_PORT=55432`. Docker Compose reads that file, and `npm run setup` points the three `…DATABASE_URL` values (and the e2e suite) at that port. Then recreate the container and migrate:
  ```bash
  npm run setup
  ```
  ```bash
  docker compose up -d --force-recreate --wait postgres
  ```
  ```bash
  npm run db:migrate
  ```
- **Webhook shows Unhealthy / verification fails:** make sure the webhook process is running on :4100 and that `WEBHOOK_SIGNING_SECRET` is identical in both `.env` files, or, during a rotation, that the webhook lists the control plane's secret in `WEBHOOK_PREVIOUS_SIGNING_SECRETS`. Delete both files and run `npm run setup` to regenerate them as a pair.
- **Playground says "Agent credential required":** click **Get a credential**. Keys live only in page memory and are cleared on reload.
- **"Agent credential is invalid, rotated or unknown":** the key was rotated, or the demo was reset. Issue a new one.
- **Webhook exits with "WEBHOOK_DATABASE_URL is missing" or "permission denied to connect":** run `npm run db:init` (existing Docker volume) and `npm run setup` (adds `WEBHOOK_DATABASE_URL` to an older `webhook/.env`).
- **API exits with "DATABASE_URL is missing" or a connection error:** start Postgres with `npm run db:up` (or point `DATABASE_URL` at your own PostgreSQL 16) and run `npm run setup` once to add `DATABASE_URL` to an older `server/.env`.
