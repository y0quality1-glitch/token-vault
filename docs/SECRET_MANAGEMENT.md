# Secret Management: implementation plan and status

This plan implements the requirements in [specs/4.9-secret-management.md](specs/4.9-secret-management.md) (section numbers below, e.g. §4.9.6, refer to it) across the four services: the provider CMS, the control plane, the customer webhook and the SDK. It is delivered in six phases, one pull request each.

## Design: where each piece lives

The spec asks for centralized secret management. Token Vault already separates *who may do what* from *where the credential is kept*, and secrets keep that split:

| Service | Owns | Never holds |
| --- | --- | --- |
| **Provider CMS** | The **secret type catalog**: each type's fields, which fields are sensitive, validation rules, metadata fields and the lifecycle operations it supports (§4.9.3). Types are drafted, reviewed, signed and published exactly like application definitions. | Any secret value |
| **Control plane** | Secret **metadata** (§4.9.5), version metadata, access grants, policies and approvals, lifecycle state, rotation and expiry schedules, the signed audit chain, notifications. All admin and application APIs. | Secret values at rest. Values pass through it in memory on create, update and retrieve (signed, over TLS or mTLS), and are never written to its database, logs, errors or audit (§4.9.5). |
| **Customer webhook** | Secret **values**: one encrypted record per version, under the key it already uses for credentials (env key, AWS KMS or Vault Transit). It validates each payload against the signed type, and later generates dynamic credentials (§4.9.3 J). | Policies, grants, metadata beyond what it needs to validate |
| **SDK** | `tv.secrets.get()` for applications and services | Nothing persistent; values are cached only in memory and only if the caller asks |

Requests the webhook receives are signed by the control plane and replay-protected, as for credentials today. An application identifies itself with its Token Vault key: agents of type `SERVICE` are the service accounts of §4.9.15 (workload identity login is a later option, see [ROADMAP.md](ROADMAP.md)).

The MCP server does **not** get a "read secret" tool. Handing raw secrets to a model is exactly what Token Vault exists to prevent; agents use brokered operations instead.

### Mapping to the spec's tables (§4.9.21)

| Spec table | Where |
| --- | --- |
| `secrets`, `secret_versions` (metadata), `secret_access_grants`, `rotation_jobs`, `leases` | Control plane, new tables |
| `secret_versions` (encrypted payload) | Webhook, `secret_values` |
| `policies`, `policy_assignments`, `approval_requests`, `audit_logs` | Control plane, existing `policies`, `operation_approvals`, `audit_events` (extended with secret events) |
| `providers`, `provider_configs` | CMS catalog and control plane `integrations` (existing) |
| `encryption_keys`, `key_versions` | Webhook keyring and KMS key references (existing); key ids recorded on every value |
| `environments` | Existing environment field (`development`, `staging`, `production`) |

**Phase 2 decisions.** Values live in their own webhook table, `secret_values` (not `credentials`), sealed with the same key and re-encrypted with it after a key rotation; the additional authenticated data binds each value to its organization, secret and version. Masked summaries never show any character of a sensitive field; versions are told apart by a keyed fingerprint. A value is stored on the webhook before the metadata is written; if the write fails, the value is destroyed again. Expiry is enforced on every retrieval even before the phase 4 job records it (`EXPIRED`). `secret:retrieve` is checked inside the service so refusals are audited.

**Phase 4 decisions.**
- *Rotation strategies.* `manual`: when rotation is due the secret becomes `ROTATION_PENDING`, people are notified (`secret.rotation_scheduled`), and storing the new value completes the rotation. `generated`: the webhook creates fresh random values for the type's fields marked `generate` (values the organization issues itself: API keys, HMAC, AES and JWT signing secrets, webhook secrets) and keeps the other fields; the value never leaves the webhook. Rotation through the provider that issued a credential (changing a database password at the database, for example) needs the same provider connections as dynamic secrets, so it moves to phase 5.
- *Validation.* A new value is validated against the signed type by the control plane and again by the webhook. Checking it against the provider (a database login) arrives with provider rotation in phase 5.
- *Grace period.* After a rotation the replaced version stays readable for `rotation_grace_hours` (default 24) by agents whose grant allows only the active version, so running applications can finish with it, and retention never destroys it during that time. A plain value update or a rollback opens no grace period.
- *Expiry.* The type's `expiryWarningDays` (default 14) or a policy decides when a secret becomes `EXPIRING`. A policy's or type's default lifetime is given to new secrets and renewed by each rotation; a `generated` secret that becomes `EXPIRING` rotates at once (expiration-based rotation).
- *Failures.* A generated rotation that fails because the webhook or its key service is unavailable is retried (after 15 minutes, then 1 hour), with a `secret.provider_failure` event each time; after the third attempt, or at once for any other error, it is `FAILED` (`secret.rotation_failed`) and tried again the next day. The previous version stays active throughout.
- *Retention.* An inactive version is destroyed when no rule keeps it: among the newest `keepVersions`, replaced less than `keepDays` ago, or inside the grace period. Without a retention policy nothing is destroyed automatically. Each destruction is audited (system actor).
- *Notifications.* Every secret event written to the audit log is matched against the organization's channels in the same transaction and queued (`notification_deliveries`); a delivery loop sends them with retries (30 s, 2 min, 10 min, 1 h). Payloads carry what the audit log says (names, versions, reason codes), never a value. Webhook deliveries are signed with a per-channel secret shown once. Generated rotations report their outcome (`secret.rotation_succeeded` or `secret.rotation_failed`); `secret.rotation_scheduled` is sent only when a person must act.
- *One runner.* The job takes a PostgreSQL advisory lock for each run; deliveries are claimed with `FOR UPDATE SKIP LOCKED`. Several control-plane instances are safe.

**Phase 5 decisions.**
- *Where providers are reached.* Only the customer webhook connects to a provider, with the credential it stores; the control plane never sees it. The webhook connects only to hosts in its `PROVIDER_ALLOWED_HOSTS` (default none): the host comes from the secret, so without this list a stored administrative login could be sent to any address. A host outside the list is "not monitored", not a failure.
- *Dynamic secrets.* The stored value is the administrative credential (never returned to applications, `SECRET_IS_DYNAMIC`). A lease is a PostgreSQL role created in one transaction with `LOGIN`, a random password, `VALID UNTIL` and the secret's grant statements (`{{name}}` is the quoted role), or AWS STS `AssumeRole` session credentials. The credential goes to the holder once and is never stored by Token Vault; the lease keeps the role or session name. Leases are limited by the secret's longest lease (metadata `maxTtlMinutes`), renewals included. Ending a lease drops the role (its sessions are terminated, its objects reassigned to the administrative login); AWS session credentials cannot be ended early, so their leases are short and only recorded as ended. Expired leases are ended by the lifecycle job; a failure is `REVOKE_FAILED` and retried, and a secret cannot be deleted while its leases cannot be ended. The role's own `VALID UNTIL` stops logins even if cleanup is late.
- *Provider rotation.* The login changes its own password (`ALTER ROLE CURRENT_USER`), the webhook logs in with the new one to check it, then stores it as a new version; if storing fails, the old password is put back. Connection details of static types come from the secret's metadata, still subject to the allow-list. There is no grace period at the provider: the old password stops working at once.
- *MySQL.* Left for later: there is no MySQL server in the development and test setup to verify it against, and shipping an untested engine for credentials is not worth it.
- *Custom types.* Same schema and checks as catalog types, key prefix `custom-`, category `custom`, never dynamic. They are not signed by the CMS, so the control plane sends the definition with each webhook request and the webhook validates it before use. Every field is still encrypted; sensitive fields are masked; grants, audit and lifecycle apply unchanged. Editing creates the next version; existing values are kept.
- *Import.* Each item goes through the normal create path (validated by the control plane and the webhook, encrypted, version 1, audited with `source: import`), so nothing is stored that could not have been created by hand. Duplicates: same name in the same scope (skip, new version, or fail) and same value as another live secret (keyed fingerprint), reported but not refused.
- *Export.* Off unless `SECRET_EXPORT_ENABLED=true`; then `secret:export` (owners) to ask, someone else with `secret:manage_access` to approve, and a passphrase only the requester knows to encrypt the file (scrypt N=2^15, AES-256-GCM, the export id as additional data). The file is kept encrypted for 10 minutes or one download, then deleted. Every exported secret is audited (`secret.exported`, critical).

**Projects and workspaces** (§4.9.2 objective 4) have no management module yet (§4.9.20 lists them as dependencies). Secrets get `project` and `workspace` fields now, as validated slugs that can be filtered on and restricted in grants and policies; a later project module can turn them into references without changing the secret APIs.

### Lifecycle (§4.9.10)

```
PENDING ──activate──▶ ACTIVE ──(expiry window)──▶ EXPIRING ──▶ EXPIRED
                        │  ▲                                     │
                  rotate│  │new version validated                │renew / new version
                        ▼  │                                     ▼
              ROTATION_PENDING ──▶ ROTATING                    ACTIVE
ACTIVE / EXPIRING / EXPIRED ──revoke──▶ REVOKED ──archive──▶ ARCHIVED ──delete──▶ DELETED
```

Only `ACTIVE`, `EXPIRING` and `ROTATION_PENDING` / `ROTATING` (previous version still valid) secrets can be retrieved. `DELETED` keeps the metadata row as a tombstone for audit; the webhook destroys the values.

### Permissions (§4.9.9)

New permissions `secret:create`, `secret:read_metadata`, `secret:retrieve`, `secret:update_metadata`, `secret:update_value`, `secret:delete`, `secret:rotate`, `secret:manage_versions`, `secret:manage_access`, `secret:export`, assigned to roles:

| Role | Secret permissions |
| --- | --- |
| Organization Owner | all |
| Vault Administrator | all except `secret:export` |
| Security Administrator | `read_metadata`, `manage_access`, `delete` (revoke) |
| Agent Developer | `read_metadata` |
| Auditor | `read_metadata` |

`secret:retrieve` for people is deliberately narrow (owners and vault administrators), every reveal is audited, and a policy can require approval for it. Applications never get role permissions; they need a secret access grant (default deny).

## Phases

### Phase 1: Secret types (CMS → control plane → webhook)

The classification model of §4.9.3 as signed, published data.

- **Shared** (`@token-vault/shared`): the `SecretTypeDefinition` schema and its validator: key, name, category (`api`, `database`, `auth`, `cloud`, `crypto`, `certificate`, `infrastructure`, `application`, `webhook`, `dynamic`, `custom`), fields (name, label, kind: text, multiline, number, url, email, pem, json, enum; `sensitive`, `required`, pattern, min/max length, enum values), metadata fields, supported lifecycle operations (`versioning`, `rotation`, `expiration`, `dynamic`), defaults (rotation interval, expiry). `validateSecretPayload()` checks a payload against a type. Signature verification is shared with provider definitions.
- **CMS**: catalog entries get a `kind` (`provider` or `secret_type`). Secret types use the same draft → review → sign → publish workflow, version history and audit. Public signed endpoint `GET /catalog/v1/secret-types`; the existing `/catalog/v1/definitions` stays provider-only, so deployed consumers are unaffected. Seed: the predefined types listed for categories A–I and J (e.g. `api_key`, `api_client_credentials`, `bearer_token`, `postgresql`, `mysql`, `mongodb`, `redis`, `mssql`, `oracle`, `db_connection_string`, `oauth_client`, `oauth_tokens`, `personal_access_token`, `jwt_signing_secret`, `aws_access_key`, `azure_service_principal`, `gcp_service_account`, `aes_key`, `rsa_private_key`, `hmac_secret`, `tls_certificate`, `pkcs12`, `ssh_private_key`, `kubeconfig`, `docker_registry`, `smtp`, `env_vars`, `webhook_signing_secret`). Console: a Secret types section.
- **Control plane**: syncs and verifies the secret type catalog (same pinned key, replay high-water mark, persisted state). `POST /api/v1/secretType/getall`, `GET /api/v1/secretType/getbyid/:key`.
- **Webhook**: syncs and verifies the same catalog, so it validates payloads against a type it verified itself, not one the control plane sent.
- **Tests**: schema validation, signature and tampering, sync, CMS workflow (e2e).

### Phase 2: Static secrets, versions and admin APIs

§4.9.4–4.9.8, 4.9.10 (manual states), 4.9.13, 4.9.17.

- **Webhook**: table `secret_values` (`value_ref`, `org_id`, `secret_id`, `version`, AES-256-GCM `iv`/`ciphertext`/`auth_tag` with `value_ref` as additional authenticated data, `encryption_key_ref`, `wrapped_key`, `fingerprint`, `created_at`, `destroyed_at`). Signed internal routes: store a version (validates against the type, encrypts, returns ref, fingerprint and a masked summary), read a version (decrypts; can return only selected fields), copy a version (rollback), destroy versions. Existing key rotation (`vault:rotate-key`) re-encrypts secret values too.
- **Control plane**: tables `secrets` (id, organization, project, workspace, environment, name, type key, description, tags, status, active version, provider / integration association, webhook, expiry, rotation settings, created and updated by and at, deleted at) and `secret_versions` (id, secret, number, value ref, fingerprint, masked fields, state `ACTIVE` / `PREVIOUS` / `DESTROYED`, created by and at, reason). `SecretService` and `SecretVersionService` on `BaseServices`. Unique name per organization, project, workspace and environment.
- **Admin APIs** (template routes, `/api/v1/secret`): `getall` (filters: type, category, project, workspace, environment, status, tags, provider, created, updated and expiry ranges; search by name and description; sort; never returns values), `getbyid/:id` (metadata, versions, grants), `save` (create with payload, or update metadata), `updateValue` (new version), `retrieve` (reveal for a person, `secret:retrieve`, audited, optionally held for approval), `versions`, `rollback` (new version copied from an older one), `destroyVersion`, `activate`, `revoke`, `archive`, `delete/:id`.
- **Audit**: `secret.created`, `secret.updated`, `secret.version_created`, `secret.retrieved`, `secret.version_retrieved`, `secret.revoked`, `secret.archived`, `secret.deleted`, `secret.access_denied`, with project, workspace, version, actor, outcome and reason code, never values.
- **Console**: Secrets list (filters and search), create form generated from the type (sensitive fields masked, never pre-filled), detail page (metadata, versions, reveal with confirmation, history).

### Phase 3: Application access

§4.9.6, 4.9.9, 4.9.15.

- **Control plane**: table `secret_access_grants` (secret or selector — by project, workspace, environment, type or tag — agent or service account, fields allowed, versions allowed `active` / `any`, valid from and until, source IP ranges, require approval, created, revoked, last used, use count).
- **Agent API**: `POST /agent/v1/secret/retrieve` (`{ secret_id | name + project / workspace / environment, version?, fields? }`): authenticates the key, default deny, checks the grant, lifecycle state, expiry, version, policies (new policy target "secret", conditions on type, project, environment and tags; decisions Allow, Deny, Require approval) and IP, then reads the value from the webhook and returns only the permitted fields. `POST /agent/v1/secret/getall`: metadata of the secrets the caller may read.
- **Admin APIs**: `/api/v1/secretAccess` `getall`, `save`, `revoke`; usage shown on the secret and agent pages. Audit `secret.access_granted`, `secret.access_revoked`.
- **SDK**: `tv.secrets.get(nameOrId, { fields, version })` and `tv.secrets.list()`; optional in-memory cache with a short time to live.
- **Kubernetes example**: inject a secret into the example application at start-up (§4.9.15, "secret injection").

### Phase 4: Expiration, rotation and notifications

§4.9.10–4.9.12, 4.9.18.

- Background job (single runner via a database lock, so several instances are safe): moves secrets to `EXPIRING` inside their warning window and to `EXPIRED` at expiry; expiry policies at organization, project, workspace and secret level (most specific wins).
- Rotation settings: enabled, interval or schedule, strategy (`manual`, `provider` for integrations that can rotate, `generated` for random values and keys the webhook can generate), grace period during which the previous version stays retrievable, retry policy. Table `rotation_jobs` with history and failures. Manual rotation from the console and API. A new version is validated (where the type has a check, e.g. database login) before it becomes active.
- Notifications: email (SMTP), outbound webhooks (signed) and the existing Slack integration, for created, updated, expiring, expired, rotation scheduled, succeeded and failed, access denied, revoked and provider failure. Per-organization settings.
- Version retention: keep the last *n* versions or *d* days; destruction is audited.

### Phase 5: Dynamic secrets, import and export, custom types

§4.9.3 J and K, 4.9.14, 4.9.16.

- **Dynamic secrets**: the webhook generates credentials on request: PostgreSQL and MySQL roles with `VALID UNTIL` and a configured grant template, AWS STS session credentials; table `leases` in the control plane (secret, holder, created, expires, renewed, revoked). Agent API `secret/lease`, `lease/renew`, `lease/revoke`; expired leases are revoked at the provider by the webhook and cleaned up. Leases are audited.
- **Custom secret types** per organization (§4.9.3 K), defined in the console, validated by the same schema (encryption, authorization and audit cannot be turned off).
- **Import**: JSON or `.env` file, validated per type, duplicate detection by name and fingerprint, audited.
- **Export**: off by default; `secret:export` plus approval; produces an encrypted file (age / password-based AES-GCM) behind a short-lived link; rate-limited; audited.

### Phase 6: Cryptographic keys and certificates

§4.9.3 E and F.

- Certificates: parse uploaded PEM / PKCS#12 to record subject, issuer, serial, validity and the matching private key; expiry drives `EXPIRING`. Renewal workflow (new version), later ACME or Vault PKI issuance.
- Keys held for operations: sign, verify, encrypt, decrypt and HMAC as agent API operations performed by the webhook (or by AWS KMS / Vault Transit), so the raw key never reaches the application; key usage policies, activation and deactivation per version.

## Acceptance (§4.9.19)

| # | Criterion | Phase |
| --- | --- | --- |
| 1 | Authorized users can create secrets | 2 |
| 2 | Defined secret categories supported | 1 |
| 3 | Payloads encrypted before storage | 2 |
| 4 | Metadata searchable without values | 2 |
| 5, 6 | Authorized applications can retrieve, unauthorized cannot | 3 |
| 7 | Updates create versions | 2 |
| 8 | Expiration enforced | 2 (checked on retrieval), 4 (scheduled) |
| 9 | Rotation configured and executed | 4 |
| 10 | Lifecycle states maintained | 2, 4 |
| 11 | Access restricted through policies | 3 |
| 12 | Access grants revocable | 3 |
| 13 | Retrieval audited | 2, 3 |
| 14 | Import and export controlled | 5 |
| 15 | External provider integration | 4 (provider rotation), 5 (dynamic) |
| 16 | Dynamic secrets with leases | 5 |
| 17 | Deletion follows retention and destruction | 2, 4 |
| 18 | Organization and project isolation | 2, 3 |

## Status

| Phase | Status |
| --- | --- |
| 1. Secret types | Done: schema and payload validation in `shared`, 51 predefined types, CMS workflow and signed `/catalog/v1/secret-types`, verified sync in the control plane (`/api/v1/secretType`) and the webhook, CMS console section ([CMS.md](CMS.md#secret-types)) |
| 2. Static secrets and versions | Done: webhook `secret_values` store and signed `/internal/v1/secrets/*`; control plane `secrets` and `secret_versions`, admin API `/api/v1/secret` ([API.md](API.md)), secret permissions per role, lifecycle (activate, revoke, archive, delete), expiry enforced on retrieval, renewal, audit of every change, retrieval and refusal; console Secrets pages |
| 3. Application access | Done: `secret_access_grants` (one secret or a selector; fields, versions, source IPs, validity, approval), held retrievals `secret_retrieval_approvals` (exact request, once, 15 minutes, not by the agent owner), agent API `/agent/v1/secret/getall` and `/retrieve` (default deny, every decision audited), admin API `/api/v1/secretAccess`, SDK `tv.secrets.get()` / `list()`, console Access card and Secret retrievals. Left for later: policies with conditions on secrets, and the Kubernetes injection example |
| 4. Expiration, rotation, notifications | Done: lifecycle job (expiry with warning window, scheduled and expiration-based rotation, retries, version retention; one instance at a time), rotation strategies `manual` and `generated` (fields with `generate` in nine predefined types, values created on the webhook), grace period, `rotation_jobs` history, expiry and retention policies by organization, project and workspace (`/api/v1/secretPolicy`), notification channels by email, signed webhook and Slack with a retried delivery queue (`/api/v1/notificationChannel`), console pages. Provider-based rotation moves to phase 5 (see the phase 4 decisions) |
| 5. Dynamic secrets, import/export, custom types | Done: dynamic secrets `postgresql-dynamic` and `aws-sts-dynamic` with leases (`secret_leases`; agent API `/agent/v1/secret/lease`, `/lease/renew`, `/lease/revoke`; admin `/api/v1/secretLease`; SDK `tv.secrets.lease()`), expired leases ended at the provider by the lifecycle job, rotation strategy `provider` (PostgreSQL logins changed at the database and checked), provider health checks, organization-defined types (`custom_secret_types`, `/api/v1/secretType/saveCustom`), import of JSON and `.env` with duplicate detection, export with approval and a passphrase-encrypted file (`/api/v1/secretExport`, `scripts/decrypt-export.mjs`). MySQL dynamic credentials are left for later (see the phase 5 decisions) |
| 6. Keys and certificates | Planned |
