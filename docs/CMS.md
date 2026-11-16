# Provider CMS

The provider CMS (`cms/`) is where the platform team defines the applications that Token Vault can broker, as [provider definitions](PROVIDER_DEFINITIONS.md). Nothing about an application is code: its API host, how credentials are attached, which resources grants are scoped to, and which operations exist are all data. Published definitions are **signed**, and consumers verify them before use.

| Service | URL | |
| --- | --- | --- |
| CMS UI (React) | http://localhost:5174 | Same component library as the console |
| CMS API (Express + TypeORM, see [fileStructure.md](fileStructure.md)) | http://localhost:4200 (API docs at `/api-docs/`) | Own database `token_vault_cms` and role `token_vault_cms` |

## Roles

| Account (password `TokenVault-Demo-2026`) | Role | Can |
| --- | --- | --- |
| `editor@cms.test` | Editor | Create applications, edit drafts, submit and withdraw |
| `publisher@cms.test` | Publisher | Approve and publish, or request changes |
| `admin@cms.test` | Administrator | Everything above, plus **publish directly**, one-click availability and archive applications |

**Separation of duties:** anyone who created, edited or submitted a version cannot *approve* it, whatever their role.

**Direct publishing (administrators):** an administrator can still take a draft (or a version in review) to published in one step with **Publish now**, without a second person. Validation, host confirmation and signing are the same as for an approval. The version's review note says "Published directly by an administrator", and the audit event carries `direct: true`. Set `CMS_ADMIN_DIRECT_PUBLISH=false` on the CMS API to turn this off and require two people for every publication, which is what you want in production.

## Workflow

```
New application ─► v1 DRAFT ──submit──► IN_REVIEW ──approve──► PUBLISHED ──(next publication)──► SUPERSEDED
                      ▲                    │
                      └──── withdraw / request changes (with note)
```

- **Editing any application:** every application, including the seeded ones (GitHub, Google Workspace, Slack, OpenAI), is edited the same way. A published version is signed and frozen, because consumers never accept a different definition under a version number they already have. **Edit** on a published version (or **Edit (new version)** on the application) therefore starts the next version as a draft copied from it; edit that draft and publish it. If a version is already open, Edit takes you there.
- **Draft:** edited with a **form** (the default) or as **JSON**. Both views change the same document, and the form keeps properties it does not show.
  - The form covers the general details, API (base URL, allowed hosts, static headers), the resource, auth methods (bearer, header, basic, OAuth 2.0), the credential test, and operations (add, duplicate, reorder, remove; request, query, body, inputs, response allow-list, mock response).
  - Request fields list the placeholders they may use.
  - The shared validator runs in the browser on every change. Each form section shows its own problems, and the side panel summarizes the unsaved document.
  - A draft can be saved while it is invalid, but it cannot be submitted until it is valid. The CMS owns `key` and `version`.
- **Submit:** the definition is normalized (defaults filled in), so the reviewer sees exactly what will be signed.
- **Review:** the *Changes* tab compares the version with the current publication (auth methods and operations, by id). The *Request preview* tab shows the exact request the webhook would build for any operation, including URL, headers and body. The credential header appears by name only.
- **Host confirmation:** if `api.baseUrl` or `api.allowedHosts` changed, or this is the first publication, the approver must explicitly confirm the hosts customer credentials will be sent to. The API refuses the approval otherwise (`HOST_CHANGE_UNACKNOWLEDGED`).
- **Approve:** signs the version and supersedes the previous publication in one transaction.
- Only one version per application can be open (draft or in review) at a time. Database constraints allow one open and one published version per application.
- **Archive** (administrator): the application leaves the catalog. Its versions are kept.

## Signing

On approval, the CMS computes:

```
digest    = sha256( canonicalJson(definition) )            // keys sorted recursively
signature = Ed25519( "token-vault/provider-definition/v1:" + digest )
```

The private key is `CMS_SIGNING_PRIVATE_KEY` and never leaves the CMS API. The key id is the first 16 hex characters of the sha256 of the public key (SPKI DER). A consumer accepts a definition only if all of these hold (`verifySignedDefinition` in `@token-vault/shared/signing`):

1. the digest recomputed from the definition matches `digest`;
2. at least one entry of `signatures` (or the primary `key_id` / `signature`) is by a pinned key and verifies;
3. the definition passes `validateProviderDefinition`.

## Key rotation

Published versions are immutable, so a rotation never re-signs them in place. Instead, a version carries **one signature per key** (`cms_version_signatures`, append-only):

- When the CMS starts with a key it has not used before, it records that key's public part (`cms_signing_keys`) and signs every published and superseded version with it. The old private key is not needed.
- The catalog serves every signature of a version, the active key's first (it is also the primary `key_id` / `signature`). `/catalog/v1/public-key` lists all keys that have signed, with the active one marked.
- Consumers may pin several keys: `CMS_PUBLIC_KEY` accepts concatenated PEM keys. A definition is accepted if any signature by a pinned key verifies.

Order of operations (locally, `npm run cms:rotate-key` does steps 1 and 2 in the `.env` files):

1. Add the new public key to every consumer's `CMS_PUBLIC_KEY`, next to the old one, and restart them. They now accept either key.
2. Give the CMS the new private key (`CMS_SIGNING_PRIVATE_KEY`) and restart it. It signs every published version with the new key, and new publications are signed with the new key only.
3. Once every consumer has synced (`/api/v1/providers` → `catalog.lastSuccessAt`, or the webhook health check), remove the old key from the consumers (`npm run cms:rotate-key -- --retire` locally) and restart them.

Doing step 2 before step 1 is safe for existing definitions (they still carry the old key's signature), but anything published in between would be refused by consumers that do not pin the new key yet.

Each step is audited (`signing.key_activated`, `signing.versions_signed`). A compromised key cannot be revoked by the CMS alone: remove it from every consumer's pins.

## Tamper resistance in the database

- A published or superseded version is **frozen** by a trigger: its definition, digest, signature and version number cannot change. The only allowed transition is PUBLISHED → SUPERSEDED, and such versions cannot be deleted.
- The CMS audit log (`cms_audit_events`) is append-only: UPDATE and DELETE are rejected.
- Even someone with database access who edits a definition cannot produce a valid signature without the private key, so consumers would reject the change.

## API

The CMS API follows the service template in [fileStructure.md](fileStructure.md): controllers and services built on a `BaseController` / `BaseServices` pair, TypeORM entities, class-validator DTOs, and one response envelope. Browse it at `http://localhost:4200/api-docs/` (OpenAPI at `/api-docs.json`).

**Response envelope** (every admin route):

```json
{ "status": "10000", "msg": "Application Fetched Successfully", "error": null, "details": [ … ], "totalRecords": 4 }
```

A failure has `status: "10001"`, the message in `error`, a stable `code` (`VALIDATION_ERROR`, `KEY_TAKEN`, `SEPARATION_OF_DUTIES`, `HOST_CHANGE_UNACKNOWLEDGED`, …) and extra data in `details` (`{ fields: { key: "…" } }` for field errors, `{ issues: [...] }` for definition problems). The HTTP status comes from the error catalogue in `cms/api/src/core/ErrorCodes.ts`. A known path with the wrong method answers 405.

**Signing in.** `POST /auth/login` sets the session token (a JWT, 8 hours) as an httpOnly, SameSite=Strict cookie; the token is never in a response body. Other clients may send the same token as `Authorization: Bearer <token>`. Only its SHA-256 is stored, so logging out ends the session even before the token expires. Five failed attempts lock an email for a minute.

Admin API (`/api/v1`):

| Method | Path | Role | Body / result |
| --- | --- | --- | --- |
| POST | `/auth/login` · `/auth/logout` · GET `/auth/me` | any | |
| GET | `/apiHealthCheck/apihealth` | none | liveness and a database check |
| POST | `/application/getall` | any | `{pageNumber?, pageSize? (max 200), search?}` → summaries, `totalRecords` |
| GET | `/application/getbyid/:key` | any | the application with every version |
| POST | `/application/save` | editor, admin | `{key, name, description?}` → creates v1 draft from a template (201) |
| POST | `/application/newversion` | editor, admin | `{key, from?}` new draft from the latest (or given) version (201) |
| POST | `/application/availability` | admin | `{key, availability, note?}` one-click availability |
| POST | `/application/archive` | admin | `{key, reason}` |
| POST | `/version/getdatabyid` | any | `{key, version}` → definition, validation issues, diff, allowed actions |
| POST | `/version/save` | editor, admin | `{key, version, definition}` (drafts only) |
| POST | `/version/submit` · `/version/withdraw` | editor, admin | `{key, version}` |
| POST | `/version/approve` | publisher, admin | `{key, version, note?, acknowledgeHostChange?}`; separation of duties |
| POST | `/version/publish` | admin | as approve; draft or in review → published in one step (`DIRECT_PUBLISH_DISABLED` when `CMS_ADMIN_DIRECT_PUBLISH=false`) |
| POST | `/version/reject` | publisher, admin | `{key, version, note}`; back to draft |
| POST | `/version/preview` | any | `{key, version, operation, resource, input}` → request preview + mock response |
| POST | `/audit/getall` | any | `{application?, search?, pageNumber?, pageSize?}`, newest first |

**Adding a module** (template, section 6): an entity in `src/entities/`, a model and DTO in `src/databases/repository/<module>/`, a service extending `BaseServices` in `src/services/<module>Service/`, a controller extending `BaseController` in `src/controllers/<module>Controller/`, a prefix in `APP_ROUTES`, and the controller in `src/controllers/index.ts`. Schema changes are TypeORM migrations in `src/databases/migrations/`, listed in `dataSource.ts`; they run at start-up (`npm run db:migrate -w cms/api` runs them alone). The first one, `Baseline`, creates the schema on an empty database and records itself on databases created before TypeORM.

Public catalog (`/catalog/v1`, no authentication: definitions are not secret, they are trusted because they are signed):

| Method | Path | |
| --- | --- | --- |
| GET | `/public-key` | `{algorithm: "Ed25519", key_id, public_key_pem}` |
| GET | `/definitions` | `{key_id, generated_at, definitions: SignedDefinition[]}`, with an `ETag` (send `If-None-Match` to get 304) |
| GET | `/definitions/:key` | one `SignedDefinition` |

`SignedDefinition` = `{definition, digest, signature, key_id, published_at, published_by, approved_by}`.

## The Integration Catalog is data

Everything in the console's **Integration Catalog** comes from definitions:
- the tiles themselves;
- each tile's category, icon, description, tags, auth methods and docs link;
- whether it can be connected (`catalog.availability`).

Nothing about the catalog is hard-coded in Token Vault:
- **Coming soon:** an application published with availability `coming_soon` is listed but cannot be connected. The console disables Connect, and the API answers `PROVIDER_NOT_AVAILABLE`.
- **Seeded entries:** the CMS seeds Google Workspace, Slack and OpenAI as coming soon. They are ordinary applications: edit them, publish them as available when ready, or archive them to remove the tile.
- **One-click availability (administrators):** on an application's page, **Make available** / **Mark as coming soon** publishes the next version straight away with *only* `catalog.availability` changed — same API hosts, auth and operations as the published version, so no review is needed. It is signed like any version, the previous one is superseded, and the audit log records `version.published` with `oneClick: true` and the optional note. Consoles pick it up on their next catalog poll (no reload). It is refused while a draft or review is open (set availability in that version, or withdraw it), before anything is published, and for archived applications. API: `POST /api/v1/applications/:key/availability` with `{ "availability": "available" | "coming_soon", "note"?: string }` (ADMIN only). Marking an application as coming soon blocks new connections; integrations already connected keep working.
- **Upgrading existing databases:** a CMS database from before this change gets any missing seeded entries on start-up (an archived one is never re-added). If GitHub's published version is still the untouched system seed, the CMS publishes the next version with only the catalog listing added. The upgrade is audited.
- **Live updates:** the console refreshes the catalog every 15 seconds and when the tab regains focus. A publication or archive shows up without a reload, after the control plane's next sync.

## How Token Vault consumes the catalog

The control plane and every customer webhook pull `/catalog/v1/definitions` **independently**. Each one pins the CMS public key (`CMS_PUBLIC_KEY`, written by `npm run setup`) and verifies every definition before using it. The webhook does not trust the control plane for definitions, so nothing the control plane sends can change where a webhook sends customer credentials.

- **Start-up and polling.** Each service syncs at start-up (without blocking it) and then polls every `CMS_POLL_INTERVAL_MS` (default 30 s), using the ETag so an unchanged catalog costs a 304. The webhook also refreshes once when asked to run an operation it does not know yet.
- **All or nothing.** If any entry in a catalog snapshot fails verification, the whole snapshot is rejected and the service keeps what it had.
- **No rollbacks.** A version lower than one already accepted is refused, so an old signed definition cannot be replayed. The highest accepted version per provider is persisted, so this holds across restarts.
- **Survives restarts.** Each service stores its last verified catalog in its own database (`provider_catalog_state`: the signed envelopes plus the version marks). On start-up it restores the marks first, then **re-verifies** every stored envelope against the pinned key. If the CMS is down, the restored definitions apply until it answers. A row edited in the database, or signed with a key that is no longer pinned, is ignored: only the bundled definitions apply until the next successful sync. `GET /api/v1/providers` reports `catalog.restoredFrom` when this happened. `SEED_MODE=reset` clears the stored catalog.
- **Bundled baseline.** Definitions shipped with the code (GitHub) are always available. A catalog version replaces the bundled one by key.
- **Archiving.** A provider that disappears from the catalog is removed, or falls back to its bundled version.

Once published, a provider is usable without a deploy:
- it appears in the **Integration Catalog** with a "CMS vN" badge;
- the **Connect** form is built from its auth methods (secret label, hint and format checks come from the definition);
- grants and access requests are scoped to its primary resource (for example a queue or project) and validated against its pattern;
- agents call its operations through the normal broker.

An operation can never run on an integration of another provider. This is enforced when the grant is created, by the broker, and by the webhook.

Without `CMS_CATALOG_URL`, a service uses the bundled definitions only.
