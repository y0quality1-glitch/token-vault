# Kubernetes example: a Node service with Token Vault

`orders-api` is a small Node service that runs on Kubernetes, gets its configuration as environment variables at boot from a secrets manager, and posts to Slack **only through Token Vault**. The pod never holds a Slack token.

```
 Secrets manager (Vault, AWS SM, …)        Kubernetes                          Pod: orders-api
┌──────────────────────────────┐  ESO   ┌───────────────────────────┐ envFrom ┌──────────────────────────────┐
│ secret/orders-api            │ ─────► │ ExternalSecret            │ ──────► │ DATABASE_URL                 │
│   DATABASE_URL               │ (pod's │   → Secret                │  boot   │ TOKEN_VAULT_API_KEY          │
│   TOKEN_VAULT_API_KEY        │  SA    │     orders-api-config     │         │ SLACK_INTEGRATION_ID, …      │
│   SLACK_INTEGRATION_ID, …    │ token) └───────────────────────────┘         └──────────────┬───────────────┘
└──────────────────────────────┘                                                             │ tv.execute(slack.messages.post)
                                                                                             ▼
                            Token Vault control plane ── checks the grant ──► customer webhook ──► Slack
                                                                              (adds the bot token)
```

## Which value lives where

| Value | Lives in | Reaches the pod? |
| --- | --- | --- |
| `DATABASE_URL`, other app config | Your secrets manager | Yes, at boot: the app needs it |
| `TOKEN_VAULT_API_KEY` | Your secrets manager | Yes, at boot: the app's only provider-facing key, limited by its grant |
| `SLACK_INTEGRATION_ID`, `SLACK_CHANNEL` | Your secrets manager (or a ConfigMap) | Yes; not secret |
| Slack bot token, Stripe key, GitHub token… | The Token Vault customer webhook, encrypted | **Never.** The app warns if one is set |

## What is here

| Path | Purpose |
| --- | --- |
| `orders-api/src/server.ts` | The service: fails fast on missing config, `/healthz` (liveness), `/readyz` (Token Vault reachable, cached 30 s), `POST /orders/:id/paid` (posts to Slack through Token Vault, idempotent per order), graceful `SIGTERM` |
| `orders-api/Dockerfile` | Bundles the service and the SDK into one file; non-root runtime image with no `node_modules` |
| `k8s/base` | Namespace, ServiceAccount, Deployment (non-root, read-only root filesystem, no capabilities, probes, `envFrom`), Service, PodDisruptionBudget, NetworkPolicy (egress only to DNS, Token Vault and the database) |
| `k8s/overlays/vault` | HashiCorp Vault through External Secrets Operator: `SecretStore` (Kubernetes auth as the pod's service account) and `ExternalSecret` (refreshed hourly) |
| `k8s/overlays/local` | Local cluster without a secrets manager: the Secret is generated from `config.env` |

## Run it on a local cluster

1. Start Token Vault on your machine (`npm run dev`). In the console:
   - connect Slack;
   - register an agent of type **Service**;
   - grant it **Post a message** on your channel.
2. Fill in the configuration:
   ```bash
   cp examples/kubernetes/k8s/overlays/local/config.env.example examples/kubernetes/k8s/overlays/local/config.env
   ```
   Put the agent key, the integration ID and the channel in `config.env`. It's git-ignored.
3. Build the image and load it into the cluster (kind shown):
   ```bash
   docker build -f examples/kubernetes/orders-api/Dockerfile -t orders-api:dev .
   ```
   ```bash
   kind load docker-image orders-api:dev
   ```
4. Deploy, then try it:
   ```bash
   kubectl apply -k examples/kubernetes/k8s/overlays/local
   ```
   ```bash
   kubectl -n orders port-forward svc/orders-api 8080:80
   ```
   ```bash
   curl -X POST localhost:8080/orders/A100/paid -H 'content-type: application/json' -d '{"amount":"EUR 42.00"}'
   ```

Behind a TLS-inspecting proxy, give the build its CA: `docker build --secret id=extra_ca,src=/path/to/ca.pem …`. The CA is used only during the build and is not stored in the image.

The local overlay points the pod at `http://host.docker.internal:4000`. On Linux with kind, use the Docker bridge address (usually `172.18.0.1`), or run Token Vault in the cluster.

## Production: HashiCorp Vault and External Secrets

1. In Vault, store `secret/orders-api` (KV v2) with `DATABASE_URL`, `TOKEN_VAULT_API_KEY`, `SLACK_INTEGRATION_ID` and `SLACK_CHANNEL`.
2. Enable Kubernetes auth with a role `orders-api`, bound to the `orders/orders-api` service account and allowed to read only that path.
3. Install External Secrets Operator. Optionally install Stakater Reloader, so pods restart when the Secret changes.
4. Set your image and the Vault address in `k8s/overlays/vault`, set `TOKEN_VAULT_URL` in the Deployment, and adjust the NetworkPolicy selectors to where Token Vault and the database run. Then apply:
   ```bash
   kubectl apply -k examples/kubernetes/k8s/overlays/vault
   ```

For AWS Secrets Manager, GCP Secret Manager or Azure Key Vault, change only the `SecretStore`.

## Rotations

- **The Slack token:** rotate it in the Token Vault console. The next call uses it. No redeploy, no pod restart, nothing to change in the secrets manager.
- **The app's Token Vault key:**
  1. In the console, **Agents → orders-api → Rotate API credential**, with a grace period (say 1 hour).
  2. Put the new key in Vault.
  3. External Secrets refreshes the Secret (within `refreshInterval`, or force a refresh), and Reloader rolls the pods.

  The old key works until the grace period ends, so no request fails. Meanwhile the service logs a warning (`this Token Vault key was rotated and stops working at …`), and the agent page shows when the old key was last used.
- **Revoking access:** revoke the grant in the console. The next request is denied (`GRANT_REVOKED`), the service answers `202 {"notified": false}`, and it keeps running.

## How this example is tested

`e2e/tests/18-kubernetes-example.spec.ts` starts the service with exactly the environment the Secret provides, against the running stack, and checks:
- readiness, a Slack post through Token Vault, and that no Slack token is anywhere in the pod's environment or output;
- a revoked grant;
- graceful shutdown;
- refusing to boot without its configuration.

`ORDERS_API_IMAGE=orders-api:dev` runs the same test against the built image. The manifests are rendered with kustomize and validated with kubeconform (Kubernetes 1.31 and the External Secrets CRD schemas).
