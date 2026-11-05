# Provider CMS

The provider CMS (`cms/`) is where the platform team defines the applications that Token Vault can broker, as [provider definitions](PROVIDER_DEFINITIONS.md). Nothing about an application is code: its API host, how credentials are attached, which resources grants are scoped to, and which operations exist are all data. Published definitions are **signed**, and consumers verify them before use.

| Service | URL | |
| --- | --- | --- |
| CMS UI (React) | http://localhost:5174 | Same component library as the console |
| CMS API (Express + Drizzle) | http://localhost:4200 | Own database `token_vault_cms` and role `token_vault_cms` |

## Roles

| Account (password `TokenVault-Demo-2026`) | Role | Can |
| --- | --- | --- |
| `editor@cms.test` | Editor | Create applications, edit drafts, submit and withdraw |
| `publisher@cms.test` | Publisher | Approve and publish, or request changes |
| `admin@cms.test` | Administrator | Everything above, plus archive applications |

**Separation of duties:** anyone who created, edited or submitted a version cannot approve it, whatever their role. An administrator who edits a draft therefore needs a publisher to approve it.

## Workflow

```
New application ─► v1 DRAFT ──submit──► IN_REVIEW ──approve──► PUBLISHED ──(next publication)──► SUPERSEDED
                      ▲                    │
                      └──── withdraw / request changes (with note)
```

- **Draft:** free-form JSON with live validation. A draft can be saved while it is invalid, but it cannot be submitted until it is valid. The CMS owns `key` and `version`.
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

1. `key_id` matches the pinned public key;
2. the digest recomputed from the definition matches `digest`;
3. the signature verifies;
4. the definition passes `validateProviderDefinition`.

## Tamper resistance in the database

- A published or superseded version is **frozen** by a trigger: its definition, digest, signature and version number cannot change. The only allowed transition is PUBLISHED → SUPERSEDED, and such versions cannot be deleted.
- The CMS audit log (`cms_audit_events`) is append-only: UPDATE and DELETE are rejected.
- Even someone with database access who edits a definition cannot produce a valid signature without the private key, so consumers would reject the change.

## API

Admin API (`/api/v1`, httpOnly session cookie):

| Method | Path | Role | |
| --- | --- | --- | --- |
| POST | `/auth/login` · `/auth/logout` · GET `/auth/me` | any | |
| GET | `/applications` | any | summaries |
| POST | `/applications` | editor, admin | `{key, name, description}` → creates v1 draft from a template |
| GET | `/applications/:key` | any | with versions |
| POST | `/applications/:key/versions` | editor, admin | `{from?}` new draft from the latest (or given) version |
| GET | `/applications/:key/versions/:v` | any | definition, validation issues, diff, allowed actions |
| PUT | `/applications/:key/versions/:v` | editor, admin | `{definition}` (drafts only) |
| POST | `…/submit` · `…/withdraw` | editor, admin | |
| POST | `…/approve` | publisher, admin | `{note?, acknowledgeHostChange?}`; separation of duties |
| POST | `…/reject` | publisher, admin | `{note}`; back to draft |
| POST | `…/preview` | any | `{operation, resource, input}` → request preview + mock response |
| POST | `/applications/:key/archive` | admin | `{reason}` |
| GET | `/audit?application=` | any | |

Public catalog (`/catalog/v1`, no authentication: definitions are not secret, they are trusted because they are signed):

| Method | Path | |
| --- | --- | --- |
| GET | `/public-key` | `{algorithm: "Ed25519", key_id, public_key_pem}` |
| GET | `/definitions` | `{key_id, generated_at, definitions: SignedDefinition[]}`, with an `ETag` (send `If-None-Match` to get 304) |
| GET | `/definitions/:key` | one `SignedDefinition` |

`SignedDefinition` = `{definition, digest, signature, key_id, published_at, published_by, approved_by}`.

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
