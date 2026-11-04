# Screen Map and Application Flow

## Information architecture

```text
Token Vault
├── Overview                         /                         pages/OverviewPage.tsx
├── Integrations
│   ├── Integration Catalog          /integrations/catalog     pages/integrations/CatalogPage.tsx
│   ├── Connect GitHub               /integrations/connect/github   ConnectIntegrationPage.tsx
│   ├── Connected Integrations       /integrations/connected   ConnectedIntegrationsPage.tsx
│   ├── Integration Details          /integrations/:id         IntegrationDetailPage.tsx
│   └── Credential Status            /integrations/credentials CredentialStatusPage.tsx
├── Agents
│   ├── Agent Registry (+ Register)  /agents[?register=1]      pages/agents/AgentRegistryPage.tsx
│   └── Agent Details (4 tabs)       /agents/:id               AgentDetailPage.tsx
├── Access Management
│   ├── Access Grants                /access/grants            pages/access/GrantsPage.tsx
│   ├── Create Access Grant (5 steps)/access/grants/new        CreateGrantPage.tsx
│   ├── Grant Details                /access/grants/:id        GrantDetailPage.tsx
│   └── Policies                     /access/policies          PoliciesPage.tsx
├── Access Playground (Demo)         /playground               pages/PlaygroundPage.tsx
├── Webhook / Vault Agent
│   ├── Webhook Setup (4-step wizard)/webhook/setup            pages/webhook/WebhookSetupPage.tsx
│   └── Health & Connectivity        /webhook/health           WebhookHealthPage.tsx
├── Audit & Activity
│   ├── Access Logs (+ detail drawer)/audit/access-logs        pages/audit/AccessLogsPage.tsx
│   └── Security Events              /audit/security-events    SecurityEventsPage.tsx
├── Settings
│   ├── Organization                 /settings/organization    pages/settings/OrganizationSettingsPage.tsx
│   ├── Members & Roles              /settings/members         MembersPage.tsx
│   └── API Clients                  /settings/api-clients     ApiClientsPage.tsx
└── Demo guide                       /guide                    pages/DemoGuidePage.tsx

Public: Login /login · Organization selection /select-org
```

## Screen-to-screen navigation

```mermaid
flowchart TD
  Login[Login] -->|1 org| Overview
  Login -->|2+ orgs| SelectOrg[Select organization] --> Overview
  Overview -->|Configure Webhook| WH[Webhook Setup wizard]
  Overview -->|Connect Integration| Cat[Integration Catalog]
  Overview -->|Register Agent| AgReg[Agent Registry · Register dialog]
  Overview -->|Create Access Grant| GrNew[Create Grant wizard]
  Overview -->|stat cards| Lists[Integrations / Agents / Grants / Access Logs / Health]
  WH -->|Step 4: next action| Cat
  WH --> Health[Health & Connectivity]
  Cat -->|GitHub · Connect| Conn[Connect GitHub]
  Conn -->|success: next| AgReg
  Conn --> IntDet[Integration Details]
  IntDet -->|Create grant| GrNew
  AgReg -->|one-time secret · Use in Playground| PG[Access Playground]
  AgReg --> AgDet[Agent Details]
  AgDet -->|Create grant| GrNew
  AgDet -->|Rotate · Use in Playground| PG
  GrNew -->|Test in playground| PG
  GrNew --> GrDet[Grant Details]
  GrDet -->|View audit trail| Logs[Access Logs]
  GrDet -->|Revoke / Extend / New version / Expire now| GrDet
  PG -->|View audit record| Logs
  PG -->|Scenario hints| GrList[Access Grants] & IntDet & Health
  Logs -->|row| Drawer[Audit detail drawer] --> AgDet & GrDet
```

## Primary journeys

### Flow A: Initial organization setup

```mermaid
flowchart TD
    A[User Login] --> B[Select Organization]
    B --> C[Overview Dashboard · Get started checklist]
    C --> D[Webhook Setup · Step 1 Register endpoint]
    D --> D2[Step 2 Configure authentication · one-time challenge]
    D2 --> E[Step 3 Send signed health challenge]
    E -->|Success| F[Step 4 Complete → Integration Catalog]
    E -->|Failure| G[Actionable error + Retry]
    G --> E
    F --> H[Connect GitHub · secret input]
    H --> I[Webhook encrypts AES-256-GCM · returns cref_…]
    I --> J[Integration Connected · masked identifier]
    J --> K[Register Agent · one-time tvak_… credential]
    K --> L[Create Access Grant · 5 steps]
    L --> M[Active, or Pending Approval → Approve]
    M --> N[Ready for agent access · Playground]
```

### Flow B: Agent access request

```mermaid
sequenceDiagram
    participant A as AI Agent / Playground
    participant C as Control Plane
    participant P as Policy Engine
    participant W as Customer Webhook
    participant G as GitHub (mock)
    A->>C: POST /agent/v1/execute (Bearer tvak_…)
    C->>C: scrypt-verify credential → agent identity
    C->>P: evaluate(agent, integration, grants, policies)
    P-->>C: ALLOW / DENY + matched rule + decision trace
    alt ALLOW
        C->>W: HMAC-signed {request_id, iat, exp, nonce, aud, credential_ref, …}
        W->>W: verify signature, window, nonce, audience, org
        W->>W: decrypt credential (memory only)
        W->>G: call with injected token
        G-->>W: response
        W-->>C: sanitized + signed result
        C-->>A: result + request_id
    else DENY
        C-->>A: decision_code + reason + request_id
    end
    C->>C: append access request + audit event
```

### Flow C: Revocation

```mermaid
flowchart TD
    A[Grant Details] --> B[Revoke grant]
    B --> C[Confirmation dialog + reason]
    C -->|Confirm| D[storedStatus = REVOKED]
    D --> E[Audit: grant.revoked]
    E --> F[Next agent request]
    F --> G[Engine step 4: grant exists & active]
    G --> H[DENY · GRANT_REVOKED]
```

## UI states covered

| State | Where |
| --- | --- |
| Loading | Skeleton tables and page skeletons (`components/ui/feedback.tsx`), button spinners |
| Empty | Every list, with a call-to-action (e.g. "No agents registered → Register agent") |
| Validation errors | Inline field errors from client checks and server `fields` details (zod) |
| Error | `ErrorState` with retry; network failure message when the API is down |
| Success | Toasts plus success panels (integration connected, grant created, webhook connected) |
| Permission denied | Route-level `RequirePermission` (audit for Developer), action buttons hidden by role, server 403 surfaced |
| Confirmation | Revoke, disable, delete (typed confirmation), rotate, reset demo |
| One-time secret | `SecretOnceDialog` (acknowledgement checkbox, no re-display) |
| Status labels | Connected, Disconnected, Healthy, Unhealthy, Active, Revoked, Expired, Denied, Pending, Superseded, Scheduled |
