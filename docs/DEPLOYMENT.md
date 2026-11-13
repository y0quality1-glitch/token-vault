# Deploying Token Vault

Token Vault runs as five containers. They come in two trust zones, and only the customer webhook ever decrypts provider credentials.

| Image | What | Port | Zone |
| --- | --- | --- | --- |
| `token-vault/server` | Control plane (admin API `/api/v1`, agent API `/agent/v1`) | 4000 | Token Vault |
| `token-vault/console` | Admin console (nginx), proxying `/api` and `/agent/v1` to the control plane | 8080 | Token Vault |
| `token-vault/cms-api` | Provider CMS API and public catalog `/catalog/v1` | 4200 | Token Vault platform team |
| `token-vault/cms-ui` | CMS UI (nginx), proxying `/api` and `/catalog/v1` to the CMS API | 8080 | Token Vault platform team |
| `token-vault/webhook` | Customer webhook: encrypted credential store, calls the providers | 4100 | **Customer** |

Each Node service needs its own PostgreSQL database, with its own role. Each applies its migrations at start-up.

## The images

Build from the repository root:

```bash
docker build -f deploy/docker/service.Dockerfile --build-arg SERVICE=server  -t token-vault/server .
```
```bash
docker build -f deploy/docker/service.Dockerfile --build-arg SERVICE=webhook -t token-vault/webhook .
```
```bash
docker build -f deploy/docker/service.Dockerfile --build-arg SERVICE=cms/api -t token-vault/cms-api .
```
```bash
docker build -f deploy/docker/web.Dockerfile --build-arg APP=client     -t token-vault/console .
```
```bash
docker build -f deploy/docker/web.Dockerfile --build-arg APP=cms/client -t token-vault/cms-ui .
```

**Node services:**
- Each is bundled into a single file with its SQL migrations. There's no `node_modules` in the runtime image.
- They run as UID 1000, work with a read-only root filesystem, and read configuration from environment variables only.

**UIs:**
- Static builds on `nginx-unprivileged` (UID 101).
- Security headers on every response: Content-Security-Policy, X-Frame-Options, nosniff.
- Each proxies its API on the same origin, so session cookies (SameSite=Strict) work.

**Build options:**
- Behind a registry mirror, pass `--build-arg NODE_IMAGE=…` and `--build-arg NGINX_IMAGE=…`.
- Behind a TLS-inspecting proxy, pass `--secret id=extra_ca,src=/path/to/ca.pem`. The CA is used during the build only, never stored in the image.

## Docker Compose (one host: evaluation, demos, staging)

```bash
node deploy/compose/generate-env.mjs
```
```bash
docker compose -f deploy/compose/docker-compose.yml up -d --build --wait
```
```bash
node deploy/compose/smoke-test.mjs
```

- **Console:** http://localhost:8080. It's also the agent API, so agents use `TOKEN_VAULT_URL=http://localhost:8080`.
- **CMS:** http://localhost:8081.
- **`generate-env.mjs`:** writes `deploy/compose/.env` with random secrets (mode 600, git-ignored). It **refuses to overwrite** the file, because a new `VAULT_ENCRYPTION_KEY` would make every stored credential unreadable.
- **Networks mirror the trust zones:**
  - only the two UIs are published;
  - the APIs, the webhook and PostgreSQL sit on internal networks;
  - only the webhook can reach the internet, which live provider calls need.
- **Hardening:** every container runs with a read-only root filesystem, no capabilities and `no-new-privileges`.
- **Data:** lives in the `pgdata` volume. `docker compose down` keeps it; `down -v` deletes it. After deleting it, regenerate the secrets with `--force`.
- **Smoke test:** works against any deployment, given its console and CMS URLs. It signs in with the demo accounts, checks the CMS catalog sync, the signed webhook health challenge and one agent request end to end, then revokes what it created.

## Kubernetes

Kustomize manifests are in `deploy/k8s`.

- **Namespaces:**
  - `token-vault`: control plane, console, CMS API and CMS UI.
  - `token-vault-customer`: the webhook, which in a real split runs in the customer's cluster.
  - Both enforce the Pod Security **restricted** profile.
- **Workloads:**
  - Every pod runs with a numeric non-root UID, a read-only root filesystem, no capabilities, seccomp and probes.
  - The API services run one replica with the `Recreate` strategy: migrations run at start-up, and rate limits and OAuth refreshes are coordinated in-process (roadmap 1.5).
  - The UIs run two replicas, with PodDisruptionBudgets.
- **NetworkPolicies:** deny everything by default, then allow exactly the connections Token Vault makes:
  - ingress controller → UIs;
  - console → control plane, and CMS UI → CMS API;
  - control plane → webhook;
  - control plane and webhook → CMS API (catalog);
  - each service → its database;
  - webhook → port 443 (providers, live mode).

  This needs a CNI that enforces policies, such as Calico or Cilium.
- **Ingress:** publishes the console and the CMS UI only, with TLS (session cookies are `Secure`). The APIs and the webhook are never exposed directly.
- **Reloader:** each Deployment carries the Stakater Reloader annotation, so pods restart when their Secret changes, for example after a rotation.

### `overlays/external-secrets` (production pattern)

Each service's Secret comes from your secrets manager through External Secrets Operator, via a `ClusterSecretStore` named `token-vault`. The entries you need:

| Entry | Keys |
| --- | --- |
| `token-vault/server` | `DATABASE_URL`, `WEBHOOK_SIGNING_SECRET`, `WEBHOOK_PREVIOUS_SIGNING_SECRETS`, `AUDIT_SIGNING_KEY`, `SESSION_JWT_SECRET`, `CMS_PUBLIC_KEY` |
| `token-vault/webhook` | `WEBHOOK_DATABASE_URL`, `WEBHOOK_SIGNING_SECRET`, `WEBHOOK_PREVIOUS_SIGNING_SECRETS`, `VAULT_ENCRYPTION_KEY`, `VAULT_PREVIOUS_ENCRYPTION_KEYS`, `CMS_PUBLIC_KEY` |
| `token-vault/cms-api` | `CMS_DATABASE_URL`, `CMS_SIGNING_PRIVATE_KEY` |

`node deploy/compose/generate-env.mjs` produces suitable values. Only the webhook's Secret ever holds `VAULT_ENCRYPTION_KEY`, and only the CMS's holds its signing key; `check-manifests.py` enforces this. The webhook's ExternalSecret uses `deletionPolicy: Retain`, so deleting the resource never deletes the key to the stored credentials.

Set the image registry and tags, ingress hosts, TLS secrets and `CONSOLE_PUBLIC_URL` in the overlay, then apply:
```bash
kubectl apply -k deploy/k8s/overlays/external-secrets
```

### `overlays/local` (kind, minikube, k3d)

1. Generate the Secrets. They're written to `deploy/k8s/overlays/local/secrets/`, which is git-ignored:
   ```bash
   node deploy/k8s/overlays/local/generate-secrets.mjs
   ```
2. Build the five images (above) and load them into the cluster, for example:
   ```bash
   kind load docker-image token-vault/server:dev token-vault/webhook:dev token-vault/cms-api:dev token-vault/console:dev token-vault/cms-ui:dev
   ```
3. Deploy:
   ```bash
   kubectl apply -k deploy/k8s/overlays/local
   ```
4. Open the console and the CMS:
   ```bash
   kubectl -n token-vault port-forward svc/console 8080:80
   ```
   ```bash
   kubectl -n token-vault port-forward svc/cms-ui 8081:80
   ```
5. Check it:
   ```bash
   node deploy/compose/smoke-test.mjs
   ```

The local overlay runs PostgreSQL as a StatefulSet in `token-vault-data`, with the same bootstrap script as compose. It also replaces the Ingress with port-forwarding and allows the admin's direct publishing in the CMS.

### Checks

CI renders every overlay, including `examples/kubernetes`, and validates it with `kubeconform`: Kubernetes 1.31, plus the External Secrets CRD schemas. It then runs `deploy/k8s/check-manifests.py`, which catches what schemas don't:
- selectors that select nothing, and NetworkPolicy peers that match no pods;
- Secrets that are referenced but never created;
- keys held by the wrong service's Secret;
- Pod Security "restricted" violations;
- unpinned images.

Run the same locally:
```bash
kubectl kustomize deploy/k8s/overlays/local | python3 deploy/k8s/check-manifests.py
```

## Protecting the vault key with a KMS

By default the webhook seals credentials with `VAULT_ENCRYPTION_KEY`, an environment variable. With a KMS it uses **envelope encryption** instead:
- each credential is sealed with its own random 256-bit data key;
- the KMS wraps that data key, and only the wrapped key is stored next to the ciphertext;
- the master key never leaves the KMS, and every unwrap is logged there (CloudTrail, or Vault's audit device);
- each record names the key that protects it, so records keep opening when you switch keys.

| Setting | AWS KMS | HashiCorp Vault / OpenBao Transit |
| --- | --- | --- |
| `VAULT_KEY_PROVIDER` | `aws-kms` | `vault-transit` |
| Key | `KMS_KEY_ID` (id, ARN or `alias/…`), `AWS_REGION` | `VAULT_ADDR`, `VAULT_TRANSIT_KEY` (mount `VAULT_TRANSIT_MOUNT`, default `transit`) |
| Authentication | Default AWS chain: IRSA or EKS Pod Identity, task role, instance profile | `VAULT_K8S_ROLE` (Kubernetes auth; recommended) or `VAULT_TOKEN`; `VAULT_NAMESPACE` for Enterprise |
| Permissions | `kms:Encrypt`, `kms:Decrypt` on that key | `update` on `transit/encrypt/<key>` and `transit/decrypt/<key>` |
| Binding | The credential reference is the KMS encryption context (authenticated; visible in CloudTrail) | Records are bound by AES-GCM associated data |

**Moving an existing store to a KMS**
1. Keep `VAULT_ENCRYPTION_KEY` set, add the KMS settings, and restart the webhook.
2. At start-up, it checks the KMS (`key service … ok` in its log) and re-encrypts every credential under it.
3. Webhook Health confirms it: *Credentials encrypted with key aws-kms:…*, with none left on an older key.
4. Then remove `VAULT_ENCRYPTION_KEY`.

Fingerprints keep their values across the switch: the fingerprint key is itself stored wrapped by the KMS.

**Rotation:** AWS automatic key rotation and Vault's `transit/keys/<key>/rotate` need nothing from Token Vault, because old key versions keep decrypting. To move to a **different** key (a new ARN, or a new Transit key), change `KMS_KEY_ID` or `VAULT_TRANSIT_KEY` and restart. Records name their key, so they still open, and the webhook re-encrypts them under the new one.

**Outages:**
- Requests that need a credential fail with `KEY_SERVICE_UNAVAILABLE` (HTTP 503). That is never treated as a rejected credential, so nothing is marked Invalid, and the scheduled check reports them as "unknown".
- Webhook Health shows **KEY SERVICE UNAVAILABLE** until the KMS is back.
- Unwrapped data keys are cached for `KMS_DATA_KEY_CACHE_SECONDS` (default 300), which also bridges short outages. Set `0` to have every use logged in the KMS.
- Calls time out after `KMS_TIMEOUT_MS` (default 2000), well inside the control plane's webhook timeout.

**Try it:** Vault Transit with compose. This override adds a Vault *dev* server, which keeps everything in memory: restarting it loses the key. It's for trying the feature, not for data you keep.
```bash
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/vault-transit.yml up -d --build --wait
```

**Kubernetes:** add a component to your overlay, then fill in the placeholders it documents (key ARN and IAM role, or Vault address and role):
- `components: [../../components/aws-kms]` annotates the webhook's service account for IRSA.
- `components: [../../components/vault-transit]` mounts a short-lived service-account token for Vault only, and lets the webhook reach Vault.

## Mutual TLS between the control plane and webhooks

The control plane calls each customer webhook to use credentials. With mTLS, that link is authenticated in both directions at the TLS layer, in addition to the signed requests (HMAC, nonce, expiry, audience), which stay on:
- the webhook serves HTTPS and accepts `/internal/*` calls only from a client certificate issued by the CA it trusts, optionally only from listed identities (a SPIFFE ID, DNS name or CN);
- the control plane checks the webhook's server certificate against its own CA bundle and presents its client certificate;
- `/healthz` stays reachable without a client certificate, because Kubernetes probes have none.

| Side | Setting | Meaning |
| --- | --- | --- |
| Webhook | `WEBHOOK_TLS_CERT[_FILE]`, `WEBHOOK_TLS_KEY[_FILE]` | Serve HTTPS with this certificate and key |
| Webhook | `WEBHOOK_TLS_CLIENT_CA[_FILE]` | Require a client certificate from this CA on `/internal/*` |
| Webhook | `WEBHOOK_TLS_ALLOWED_CLIENTS` | Optional, comma-separated: `URI:spiffe://token-vault/control-plane`, `DNS:…` or `CN=…` |
| Control plane | `WEBHOOK_TLS_CA[_FILE]` | CA bundle for webhook server certificates (default: the system CAs) |
| Control plane | `CONTROL_PLANE_TLS_CERT[_FILE]`, `CONTROL_PLANE_TLS_KEY[_FILE]` | Client certificate presented to webhooks |
| Control plane | `WEBHOOK_REQUIRE_TLS` | `true`: refuse `http://` webhook URLs, both when registering and when calling |

**Per webhook:** a webhook set to **Mutual TLS + signed requests** (wizard step 2, or *Change URL or authentication* on its page) is never called without TLS and the client certificate. The console offers that option only when the control plane has a client certificate and the URL is `https://`.

**What operators see:**
- Webhook Health shows the transport: *mutual TLS, webhook certificate CN=… issued by CN=…, valid N more days*. Under 14 days it warns that the certificate expires soon.
- Failures name the cause: an untrusted CA, an expired certificate, a host the certificate doesn't name, a client certificate the webhook rejected (`CLIENT_CERTIFICATE_REJECTED`), or a refused plain-HTTP URL. They show as Unhealthy, never as invalid credentials.

**Renewal:** both sides re-read their certificate files every minute and use the new ones without a restart. The webhook ignores a half-written file and keeps its working certificate. That makes it fit cert-manager, Vault PKI agents or any tool that rewrites the files.

**Try it with compose:**
```bash
npm run tls:dev-certs
```
```bash
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/mtls.yml up -d --build --wait
```
`tls:dev-certs` writes a development CA and both certificates to `deploy/compose/tls/` (git-ignored; keys readable by the containers). Don't use them outside development. A stack that already ran over HTTP keeps its stored `http://` webhook URL: change it to `https://webhook:4100` on the webhook's page, or start from empty volumes (`down -v`).

**Kubernetes:** `components: [../../components/mtls]` needs cert-manager. It:
- issues the webhook's server certificate and the control plane's client certificate (ECDSA P-256, 90 days, renewed 15 days ahead) from a `ClusterIssuer` backed by your CA;
- mounts both, and switches the webhook's probes to HTTPS;
- points the control plane at `https://webhook.token-vault-customer.svc.cluster.local:4100` with `WEBHOOK_REQUIRE_TLS=true`.
In a real split, the customer issues the webhook's certificate from their own CA, and gives you that CA for `WEBHOOK_TLS_CA`.

## Staging checklist

- **TLS** at the ingress or load balancer, with `CONSOLE_PUBLIC_URL` set to the console's https URL (OAuth redirects use it).
- **mTLS** to the webhook (see above), with `WEBHOOK_REQUIRE_TLS=true`.
- **Databases:** managed PostgreSQL, one database and role per service. Give the webhook its own server, in the customer's environment. Keep backups of the webhook's database together with its `VAULT_ENCRYPTION_KEY`: one is useless without the other.
- **Secrets** come from your secrets manager (`overlays/external-secrets`). Rotate them with the documented steps in the README (*Rotating keys*), which need no downtime.
- **CMS:** set `CMS_ADMIN_DIRECT_PUBLISH=false` to require two people per publication. The Kubernetes base already does.
- **Providers:** start with `UPSTREAM_MODE=mock`. Switch applications to live one at a time with `PROVIDER_MODES=github=live,…`.
- **Destructive operations** (delete a repository, write a file) are refused by the webhook unless you set `WEBHOOK_ALLOW_DESTRUCTIVE=true`. Even then it runs them only for requests a human approved in Token Vault.
- **Not production-ready yet:**
  - sign-in uses the seeded demo accounts, until SSO arrives (roadmap 1.4);
  - the vault key is an environment variable unless you configure a KMS (see above);
  - API services run one replica (roadmap 1.5).

## What has been verified

- **All five images:** built; the stack ran with compose. The smoke test passed:
  - catalog sync;
  - a signed webhook health check;
  - an agent request through control plane → webhook → simulated GitHub;
  - CMS sign-in and catalog.
- **Restarts:** the smoke test passed again after `down`/`up`, with the stored credentials still decrypting.
- **UIs:** both sign in and render in a browser under their Content-Security-Policy.
- **Exposure:** only the UI ports were reachable from the host.
- **Kubernetes:** the manifests validate and pass the semantic checks. They have **not** yet been applied to a running cluster; kind can't start nested containers in the environment where this was built. Running `overlays/local` on your own cluster is the remaining check.
