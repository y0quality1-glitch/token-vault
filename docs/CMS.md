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

## Next

Token Vault's control plane and the customer webhooks pull `/catalog/v1/definitions`, pin the public key and verify every definition, replacing the definitions bundled in `shared/`. The Connect form will be rendered from each definition's auth methods.
