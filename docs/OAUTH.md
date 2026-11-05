# OAuth 2.0 connections

A provider definition can offer an `oauth2` auth method. An administrator connects the integration by signing in at the provider, instead of pasting a secret. The flow is authorization code with **PKCE**. Everything secret stays in the customer webhook:

| Item | Where it lives |
| --- | --- |
| Client secret | Customer webhook, encrypted (sent once, over the signed channel) |
| PKCE verifier | Customer webhook, encrypted, until the code is redeemed |
| Access and refresh tokens | Customer webhook, encrypted; refreshed there |
| `state` | Only its hash: in the webhook (checked on completion) and in the control plane (`oauth_pending`, bound to the admin who started, single use, 10 minutes) |
| Authorization code | Passes through the browser and the control plane once; single use, and useless without the verifier and the client secret |

## Definition

```jsonc
{
  "id": "OAUTH",
  "label": "Sign in with CalendarX",
  "kind": "oauth2",
  "oauth": {
    "authorizeUrl": "https://login.calendarx.example.com/authorize",
    "tokenUrl": "https://api.calendarx.example.com/oauth/token",   // host must be in api.allowedHosts
    "scopes": ["events.read", "offline_access"],
    "scopeSeparator": " ",
    "clientAuth": "body",                 // or "basic"
    "authorizeParams": { "prompt": "consent" }   // e.g. Google: {"access_type": "offline", "prompt": "consent"}
  }
}
```

Both URLs must be https. The token endpoint receives the client secret and refresh tokens, so validation requires its host to be in `api.allowedHosts`. A change of hosts therefore goes through the CMS's host confirmation.

## Flow

1. **Connect** (console): the admin picks the OAuth method and enters the client ID and secret of an OAuth app registered at the provider. The redirect URI to register is shown: `<console>/oauth/callback` (`CONSOLE_PUBLIC_URL`, default `http://localhost:5173`).
2. **Start.** The control plane (`POST /api/v1/integrations/oauth/start`) forwards the client credentials to the webhook (`/internal/v1/oauth/start`). The webhook stores them encrypted with a fresh PKCE verifier and the state's hash, and returns the provider's authorize URL. The control plane records the pending connection for this admin and sends the browser there.
3. **Callback.** The provider redirects to `/oauth/callback?code&state`. The console page removes the code from the address bar. It then calls `POST /api/v1/integrations/oauth/complete` with a same-origin request, because the session cookie is `SameSite=Strict` and is not sent on the provider's cross-site redirect.
4. **Complete.** The control plane accepts the state only for the admin who started it, and only once. The webhook checks the state against its own hash, redeems the code with the verifier and client secret, and stores the tokens. The integration is then created and validated like any other.

If the provider returns an error (for example consent denied), the page cancels the pending connection (`/oauth/cancel`) and the webhook discards the stored client credentials.

## Using the tokens

- **Before each call:** the webhook refreshes the access token if it expires within 30 seconds.
- **Rejected token:** if the provider still answers 401 (for example the token was revoked early), the webhook refreshes once and retries.
- **One refresh at a time:** refreshes are single-flight per credential, and the webhook re-reads the stored credential first. Concurrent requests never spend a refresh token that has already been rotated.
- **Rotated refresh tokens:** a new refresh token returned by the provider replaces the old one.
- **What the agent sees:** the execution response and audit record show `credential: { type: "oauth2_access_token", refreshed, expires_at, scopes }`, never a token.
- **Renewing:** OAuth integrations are renewed by connecting again, so "Rotate / replace" is not offered.

## Mock mode

With `GITHUB_MODE=mock` (the default; the name predates other providers), a simulated authorization server stands in for the provider:
- it consents immediately;
- it enforces PKCE, the redirect URI and the client binding;
- codes are single use;
- access tokens expire after `MOCK_OAUTH_TOKEN_TTL_S` (default 3600; the e2e suite uses 2);
- refresh tokens rotate, and a used one is refused.

The simulated APIs reject expired access tokens, so the refresh path really runs.

## Not covered yet

- Client-credentials and device flows.
- Token revocation at the provider when an integration is deleted (the webhook crypto-shreds its copy).
- Provider-specific refresh quirks beyond the standard response fields.
