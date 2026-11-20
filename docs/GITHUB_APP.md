# GitHub App connector

A GitHub App is the recommended way to connect GitHub. Compared with a personal access token:

| | Personal access token | GitHub App |
| --- | --- | --- |
| Long-lived secret | The token itself, with all its scopes, on every repository it can reach | Only the App private key, which cannot call the API by itself |
| What an upstream call uses | The same token every time | A token minted for **this request**: one repository, one permission, revoked after use, expires within an hour |
| Tied to a person | Yes (leaves with the employee) | No (installed on the organization) |
| Repository access | Whatever the token's owner can see | Only the repositories the App is installed on, further narrowed per request |

## How a request flows

1. The agent calls `POST /agent/v1/request/execute`. Token Vault evaluates grants and policies exactly as for a PAT.
2. If allowed, Token Vault sends a signed execution request to the customer webhook.
3. The webhook decrypts the App credential, signs a 9-minute App JWT (RS256) and calls `POST /app/installations/{id}/access_tokens` with `repositories: [<repo>]` and the operation's permission:

   | Operation | Minted permission |
   | --- | --- |
   | `github.repositories.read` | `metadata: read` |
   | `github.contents.read` | `contents: read` |
   | `github.issues.list` | `issues: read` |
   | `github.issues.create` | `issues: write` |

4. It makes the upstream call with that token, then revokes it (`DELETE /installation/token`).
5. Token Vault receives the sanitized result plus the token's scope (`execution.credential`), which is shown in the Playground and written to the audit log. The token never leaves the webhook.

If GitHub refuses to mint a token for the repository (the App is not installed on it), the request fails with that error. It never falls back to a broader token.

## Create the App (one-time, in a test organization)

1. GitHub → your **test organization** → Settings → Developer settings → GitHub Apps → **New GitHub App**.
2. Name it (e.g. `token-vault-poc-<org>`); any homepage URL; **uncheck Webhook → Active**.
3. Repository permissions: **Metadata: Read-only** (automatic), **Contents: Read-only**, **Issues: Read and write**. Nothing else.
4. "Where can this GitHub App be installed?": **Only on this account**. Create it.
5. Note the **App ID** on the App's page. Under **Private keys**, choose **Generate a private key**; a `.pem` file downloads.
6. **Install App** → choose **Only select repositories** → pick one test repository.

## Connect it in Token Vault

**Integrations → Catalog → GitHub → Connect**, choose **GitHub App**, enter the App ID and pick where the key lives:

- **Store it in the customer vault**: paste or load the `.pem`. It travels once, over the signed channel, to the webhook, which verifies it with GitHub and encrypts it (AES-256-GCM). It is never shown again.
- **Already configured on the webhook**: the key never passes through Token Vault. Provide it to the webhook process as a secret, either `GITHUB_APP_PRIVATE_KEY_FILE=/path/to/key.pem` or `GITHUB_APP_PRIVATE_KEY` (PEM, `\n` escapes allowed). In a hosted environment, add it as an environment secret; do not commit it or paste it into chat.

Leave **Installation ID** empty if the App is installed on exactly one account; the webhook finds it.

To call the real API, set `PROVIDER_MODES=github=live` (or `UPSTREAM_MODE=live` for every application) in `webhook/.env`, and make sure the webhook can reach `api.github.com`.

## Rotating the key

Generate a new key in the App settings, use **Rotate / replace** on the integration (the webhook verifies the new key before replacing the old one), then delete the old key on GitHub. For keys configured on the webhook, update the secret and restart the webhook.

## Mock mode

In mock mode (the default) no network access is needed. JWTs are still really signed with the key you provide, so an invalid key is rejected. The simulated GitHub has installation `1` on `demo-org`, and it enforces each minted token's scope: a read token cannot create issues (403), other repositories are invisible (404), and a revoked token is rejected (401).
