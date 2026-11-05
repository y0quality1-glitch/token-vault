# Provider definitions

An application (provider) that agents can call through Token Vault is described by a **provider definition**, a JSON document, not code. The customer webhook executes definitions with one generic executor. The control plane derives its catalog, operations, grantable scopes and resource validation from them.

GitHub is itself a definition: [`shared/src/providers/github.definition.ts`](../shared/src/providers/github.definition.ts), bundled with the build. Further providers are authored, reviewed and published in the [provider CMS](CMS.md). The control plane and each webhook pull the signed catalog at runtime and accept only definitions that verify against the pinned CMS key.

## Shape

```jsonc
{
  "key": "notes",                       // lower-case; prefixes every operation id
  "version": 1,
  "name": "Notes",
  "api": {
    "baseUrl": "https://api.notes.example.com/v2",
    "allowedHosts": ["*.notes.example.com"],   // credentials are never sent anywhere else
    "headers": { "Accept": "application/json" }, // static only; no credentials, no placeholders
    "timeoutMs": 10000
  },
  "resource": { "name": "project", "label": "Project", "pattern": "^[A-Z][A-Z0-9]{1,9}$" }, // what grants are scoped to
  "resourceFields": { },                // extra request fields, e.g. GitHub's file "path"
  "auth": [
    { "id": "API_KEY", "label": "API key", "kind": "header", "header": "X-Api-Key", "secretPattern": "^nk_[a-z0-9]{16,}$" }
  ],
  "credentialTest": { "request": { "method": "GET", "path": "/me" }, "response": { "fields": { "name": "name" } } },
  "operations": [
    {
      "id": "notes.notes.create",
      "label": "Create note",
      "risk": "write",                  // read | write | destructive (destructive: known to policies, never executed)
      "providerPermissions": {},        // used by token-minting auth plugins (GitHub App)
      "input": { "text": { "type": "string", "required": true, "maxLength": 100 } },
      "request": { "method": "POST", "path": "/projects/{resource.project}/notes", "body": { "text": "{input.text}" } },
      "response": { "fields": { "id": "id", "text": "text" } },
      "mock": { "status": 201, "body": { "id": "n_1", "text": "mocked" } }
    }
  ]
}
```

### Templates

- Placeholders are `{resource.<field>}` and `{input.<field>}`, optionally with a default: `{resource.path|README.md}`. No other namespace exists, so **a template can never reference a credential**.
- In paths, each value is URL-encoded per segment. Empty, `.` and `..` segments are refused.
- In bodies, a string that is exactly one placeholder keeps the value's type and is left out when the input is missing. Inputs that are not declared are never forwarded.

### Responses

`response.fields` is an allow-list. Each output field is a dot path (`"user.login"`) or an object `{ path, decode: "base64", pluck, maxLength }` / `{ const }`. Arrays are mapped element by element, up to `limit` elements. For non-2xx responses, only the upstream `message` is returned.

### Auth methods

| kind | Injection |
| --- | --- |
| `bearer` | `Authorization: Bearer <secret>` |
| `header` | `<header>: <prefix><secret>` |
| `basic` | `Authorization: Basic base64(<secret>)`, where the secret is `user:password` |
| `plugin` | Provider-specific code that produces a short-lived bearer token. Today the only plugin is `github_app`, which mints a token narrowed to the request's repository and the operation's `providerPermissions` |
| `oauth2` | OAuth 2.0 authorization code + PKCE (`oauth: {authorizeUrl, tokenUrl, scopes, …}`). The admin signs in at the provider; the webhook holds the client secret and tokens, and refreshes the access token. See [OAUTH.md](OAUTH.md) |

## Safety rules enforced

Validation (`validateProviderDefinition`) rejects a definition when any of these holds:
- `baseUrl` is not https, or its host is not in `allowedHosts`.
- `api.headers` contains Authorization, Cookie or other credential headers, or any placeholder.
- A template uses an unknown placeholder, or a path contains a scheme, `..`, a query string or a fragment.
- A resource pattern is not anchored, or is not a valid regex.
- Operation ids are duplicated, or are not prefixed with the provider key.
- A `GET` request has a body.

When executing, the webhook:
- checks the built URL is https and on an allowed host **before** attaching the credential;
- never follows redirects;
- rejects responses over 1 MB;
- checks request values against the resource patterns and declared input types;
- refuses `destructive` operations;
- refuses operations that belong to a different provider than the stored credential.

In mock mode (`GITHUB_MODE=mock`), a host with a simulator (today `api.github.com`) gets a simulated HTTP API, so mock and live mode run the same request-building code. Other hosts answer with the operation's `mock` response.

The webhook's signed health response lists the definitions it has loaded (`providers: [{key, version, digest}]`).
