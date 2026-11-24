import type { SecretTypeDefinitionInput } from './schema';

/**
 * The predefined secret types of spec 4.9.3 A–I, as the CMS seeds them (published and signed).
 * They are ordinary catalog entries: the CMS can edit them through review, or add more.
 * Dynamic secrets (J) arrive with their generators; custom types (K) are defined per
 * organization. Fields with `generate` hold values the organization issues itself: the
 * webhook can create a new one, so such secrets can rotate on schedule without a person
 * (version 2 of those types added it).
 */

type Fields = SecretTypeDefinitionInput['fields'];
type Meta = NonNullable<SecretTypeDefinitionInput['metadata']>;

const secret = (label: string, extra: Partial<Fields[string]> = {}): Fields[string] => ({ label, required: true, sensitive: true, ...extra });
const plain = (label: string, extra: Partial<Fields[string]> = {}): Fields[string] => ({ label, sensitive: false, ...extra });
const meta = (label: string, extra: Partial<Meta[string]> = {}): Meta[string] => ({ label, ...extra });

const providerMeta: Meta = { provider: meta('Provider', { placeholder: 'e.g. Stripe' }), endpoint: meta('API endpoint', { kind: 'url' }), authMethod: meta('Authentication method', { placeholder: 'e.g. header X-API-Key' }) };
const dbMeta = (port: number): Meta => ({
  host: meta('Host', { kind: 'hostname', required: true }),
  port: meta('Port', { kind: 'port', placeholder: String(port) }),
  database: meta('Database name'),
  authMechanism: meta('Authentication mechanism', { placeholder: 'e.g. SCRAM-SHA-256' }),
  readReplica: meta('Read replica', { kind: 'boolean' }),
});
const tokenMeta: Meta = { scopes: meta('Scopes', { placeholder: 'space-separated' }), expiresAt: meta('Token expires at', { kind: 'datetime' }), issuer: meta('Issuer', { kind: 'url' }), subject: meta('Identity or application') };
const cloudMeta: Meta = { accountId: meta('Account, subscription or project'), region: meta('Region') };
const keyMeta: Meta = { algorithm: meta('Algorithm'), usage: meta('Usage', { kind: 'enum', values: ['encrypt', 'sign', 'mac', 'wrap', 'derive'] }), kmsKeyRef: meta('External KMS / HSM key reference') };
const certMeta: Meta = { commonName: meta('Common name'), issuer: meta('Issuer'), notAfter: meta('Valid until', { kind: 'datetime' }), serialNumber: meta('Serial number') };
const infraMeta: Meta = { resource: meta('Resource (server, cluster, registry)'), owner: meta('Owning team') };

const PEM_KEY = { kind: 'pem' as const, maxLength: 16_384 };

/** Numbers fields and metadata in the order they are written here (key order is not kept in storage). */
function ordered(t: SecretTypeDefinitionInput): SecretTypeDefinitionInput {
  const number = <F extends object>(rec: Record<string, F>) => Object.fromEntries(Object.entries(rec).map(([k, f], i) => [k, { ...f, order: (i + 1) * 10 }]));
  return { ...t, fields: number(t.fields), metadata: number(t.metadata ?? {}) };
}

const TYPES: SecretTypeDefinitionInput[] = [
  // ── A. API secrets ─────────────────────────────────────────────
  { key: 'api-key', version: 2, name: 'API key', category: 'api', description: 'A single API key for an external or internal API.', fields: { apiKey: secret('API key', { maxLength: 4096, generate: { encoding: 'base64url', bytes: 32 } }) }, metadata: providerMeta, defaults: { rotationIntervalDays: 90 }, tags: ['api'] },
  {
    key: 'api-client-credentials',
    version: 1,
    name: 'API client ID and secret',
    category: 'api',
    description: 'Client credentials: a public client ID and its secret.',
    fields: { clientId: plain('Client ID', { required: true, maxLength: 512 }), clientSecret: secret('Client secret', { maxLength: 4096 }) },
    identifiedBy: ['clientId'],
    metadata: providerMeta,
    defaults: { rotationIntervalDays: 180 },
    tags: ['api', 'oauth'],
  },
  { key: 'bearer-token', version: 2, name: 'Bearer token', category: 'api', description: 'A static bearer token sent in the Authorization header.', fields: { token: secret('Token', { maxLength: 8192, generate: { encoding: 'base64url', bytes: 32 } }) }, metadata: providerMeta, defaults: { rotationIntervalDays: 90 }, tags: ['api'] },
  {
    key: 'third-party-api',
    version: 1,
    name: 'Third-party API credentials',
    category: 'api',
    description: 'Several credential fields for one provider, e.g. an API key, an API secret and a webhook signing secret.',
    fields: { apiKey: secret('API key', { maxLength: 4096 }), apiSecret: secret('API secret', { required: false, maxLength: 4096 }), webhookSigningSecret: secret('Webhook signing secret', { required: false, maxLength: 4096 }), accountId: plain('Account ID', { maxLength: 200 }) },
    identifiedBy: ['accountId'],
    metadata: providerMeta,
    defaults: { rotationIntervalDays: 90 },
    tags: ['api', 'payments'],
  },
  {
    key: 'custom-api-auth',
    version: 1,
    name: 'Custom API authentication',
    category: 'api',
    description: 'Any API authentication made of named values (headers, keys, passwords).',
    fields: { values: secret('Values', { kind: 'keyvalue' }) },
    metadata: providerMeta,
    tags: ['api'],
  },

  // ── B. Database secrets ────────────────────────────────────────
  ...(
    [
      ['postgresql', 'PostgreSQL credentials', 5432, ['postgres']],
      ['mysql', 'MySQL credentials', 3306, ['mysql', 'mariadb']],
      ['mongodb', 'MongoDB credentials', 27017, ['mongo']],
      ['mssql', 'Microsoft SQL Server credentials', 1433, ['sqlserver']],
      ['oracle', 'Oracle Database credentials', 1521, ['oracle']],
    ] as const
  ).map(
    ([key, name, port, tags]): SecretTypeDefinitionInput => ({
      key,
      version: 1,
      name,
      category: 'database',
      description: `A database login for ${name.replace(' credentials', '')}.`,
      fields: { username: plain('Username', { required: true, maxLength: 128 }), password: secret('Password', { maxLength: 1024 }) },
      identifiedBy: ['username'],
      metadata: dbMeta(port),
      defaults: { rotationIntervalDays: 90 },
      tags: [...tags, 'database'],
    }),
  ),
  {
    key: 'redis',
    version: 1,
    name: 'Redis credentials',
    category: 'database',
    description: 'A Redis ACL user and password (username optional for the default user).',
    fields: { username: plain('Username', { maxLength: 128 }), password: secret('Password', { maxLength: 1024 }) },
    identifiedBy: ['username'],
    metadata: { ...dbMeta(6379), tls: meta('TLS', { kind: 'boolean' }) },
    defaults: { rotationIntervalDays: 90 },
    tags: ['redis', 'database'],
  },
  {
    key: 'db-connection-string',
    version: 1,
    name: 'Database connection string',
    category: 'database',
    description: 'A full connection string. It contains the credentials, so all of it is sensitive.',
    fields: { connectionString: secret('Connection string', { kind: 'url', maxLength: 4096 }) },
    metadata: dbMeta(5432),
    defaults: { rotationIntervalDays: 90 },
    tags: ['database'],
  },

  // ── C. Authentication and OAuth secrets ────────────────────────
  {
    key: 'oauth-client',
    version: 1,
    name: 'OAuth client secret',
    category: 'auth',
    description: 'The credentials of an OAuth or OIDC client registration.',
    fields: { clientId: plain('Client ID', { required: true, maxLength: 512 }), clientSecret: secret('Client secret', { maxLength: 4096 }) },
    identifiedBy: ['clientId'],
    metadata: { ...tokenMeta, tokenUrl: meta('Token endpoint', { kind: 'url' }), authorizeUrl: meta('Authorization endpoint', { kind: 'url' }) },
    defaults: { rotationIntervalDays: 365 },
    tags: ['oauth', 'oidc'],
  },
  {
    key: 'oauth-tokens',
    version: 1,
    name: 'OAuth access and refresh tokens',
    category: 'auth',
    description: 'Tokens issued by an OAuth provider: access, refresh and ID token.',
    fields: { accessToken: secret('Access token', { maxLength: 16_384 }), refreshToken: secret('Refresh token', { required: false, maxLength: 16_384 }), idToken: secret('ID token', { required: false, maxLength: 16_384 }), tokenType: plain('Token type', { placeholder: 'Bearer', maxLength: 40 }) },
    metadata: { ...tokenMeta, revokedAt: meta('Revoked at', { kind: 'datetime' }) },
    defaults: { expiresInDays: 30 },
    tags: ['oauth'],
  },
  { key: 'personal-access-token', version: 1, name: 'Personal access token', category: 'auth', description: 'A token issued to a person, e.g. a GitHub or GitLab PAT.', fields: { token: secret('Token', { maxLength: 4096 }) }, metadata: tokenMeta, defaults: { expiresInDays: 90, rotationIntervalDays: 90 }, tags: ['token'] },
  { key: 'service-account-token', version: 1, name: 'Service account token', category: 'auth', description: 'A token that authenticates a service account or workload.', fields: { token: secret('Token', { maxLength: 16_384 }) }, metadata: tokenMeta, defaults: { rotationIntervalDays: 90 }, tags: ['token', 'service-account'] },
  { key: 'jwt-signing-secret', version: 2, name: 'JWT signing secret', category: 'auth', description: 'A shared secret for HMAC-signed JWTs (HS256/384/512).', fields: { secret: secret('Secret', { minLength: 32, maxLength: 4096, generate: { encoding: 'base64url', bytes: 64 } }) }, metadata: { algorithm: meta('Algorithm', { kind: 'enum', values: ['HS256', 'HS384', 'HS512'] }), issuer: meta('Issuer') }, defaults: { rotationIntervalDays: 180 }, tags: ['jwt'] },
  { key: 'app-auth-secret', version: 2, name: 'Application authentication secret', category: 'auth', description: 'A secret an application uses to authenticate itself to another.', fields: { appId: plain('Application ID', { maxLength: 200 }), secret: secret('Secret', { maxLength: 4096, generate: { encoding: 'base64url', bytes: 32 } }) }, identifiedBy: ['appId'], metadata: tokenMeta, defaults: { rotationIntervalDays: 180 }, tags: ['application'] },

  // ── D. Cloud provider secrets ──────────────────────────────────
  {
    key: 'aws-access-key',
    version: 1,
    name: 'AWS access key',
    category: 'cloud',
    description: 'An IAM access key pair. Prefer short-lived credentials where possible.',
    fields: { accessKeyId: plain('Access key ID', { required: true, pattern: '^(AKIA|ASIA)[A-Z0-9]{16}$' }), secretAccessKey: secret('Secret access key', { minLength: 40, maxLength: 40 }) },
    identifiedBy: ['accessKeyId'],
    metadata: cloudMeta,
    defaults: { rotationIntervalDays: 90 },
    tags: ['aws'],
  },
  {
    key: 'aws-session-credentials',
    version: 1,
    name: 'AWS session credentials',
    category: 'cloud',
    description: 'Temporary STS credentials with a session token.',
    fields: { accessKeyId: plain('Access key ID', { required: true, pattern: '^ASIA[A-Z0-9]{16}$' }), secretAccessKey: secret('Secret access key', { minLength: 40, maxLength: 40 }), sessionToken: secret('Session token', { maxLength: 4096 }) },
    identifiedBy: ['accessKeyId'],
    metadata: { ...cloudMeta, roleArn: meta('Role ARN') },
    lifecycle: { rotation: false },
    defaults: { expiresInDays: 1 },
    tags: ['aws', 'sts'],
  },
  {
    key: 'azure-service-principal',
    version: 1,
    name: 'Azure service principal',
    category: 'cloud',
    description: 'An Entra ID application (service principal) and its client secret.',
    fields: { tenantId: plain('Tenant ID', { required: true, pattern: '^[0-9a-fA-F-]{36}$' }), clientId: plain('Client (application) ID', { required: true, pattern: '^[0-9a-fA-F-]{36}$' }), clientSecret: secret('Client secret', { maxLength: 1024 }) },
    identifiedBy: ['tenantId', 'clientId'],
    metadata: cloudMeta,
    defaults: { rotationIntervalDays: 180, expiresInDays: 365 },
    tags: ['azure'],
  },
  {
    key: 'gcp-service-account',
    version: 1,
    name: 'GCP service account key',
    category: 'cloud',
    description: 'A Google Cloud service account JSON key file.',
    fields: { clientEmail: plain('Service account email', { required: true, kind: 'email' }), keyJson: secret('Key file (JSON)', { kind: 'json', maxLength: 16_384 }) },
    identifiedBy: ['clientEmail'],
    metadata: cloudMeta,
    defaults: { rotationIntervalDays: 90 },
    tags: ['gcp'],
  },
  { key: 'cloud-api-token', version: 1, name: 'Cloud API token', category: 'cloud', description: 'An API token for a cloud platform (e.g. Cloudflare, DigitalOcean) or a deployment or provisioning pipeline.', fields: { token: secret('Token', { maxLength: 8192 }) }, metadata: { ...cloudMeta, provider: meta('Cloud provider'), purpose: meta('Purpose', { kind: 'enum', values: ['api', 'deployment', 'provisioning'] }) }, defaults: { rotationIntervalDays: 90 }, tags: ['cloud'] },

  // ── E. Cryptographic secrets ───────────────────────────────────
  { key: 'aes-key', version: 2, name: 'AES encryption key', category: 'crypto', description: 'A symmetric key, base64-encoded (128, 192 or 256 bits). Also used for data and key encryption keys.', fields: { key: secret('Key (base64)', { pattern: '^[A-Za-z0-9+/]{22,44}={0,2}$', generate: { encoding: 'base64', bytes: 32 } }) }, metadata: { ...keyMeta, role: meta('Role', { kind: 'enum', values: ['data-encryption-key', 'key-encryption-key', 'general'] }) }, defaults: { rotationIntervalDays: 365 }, tags: ['aes'] },
  { key: 'rsa-private-key', version: 1, name: 'RSA private key', category: 'crypto', description: 'An RSA private key in PEM.', fields: { privateKey: secret('Private key (PEM)', PEM_KEY), publicKey: plain('Public key (PEM)', PEM_KEY), passphrase: secret('Passphrase', { required: false, maxLength: 1024 }) }, metadata: keyMeta, defaults: { rotationIntervalDays: 365 }, tags: ['rsa'] },
  { key: 'ecc-private-key', version: 1, name: 'ECC private key', category: 'crypto', description: 'An elliptic-curve private key (P-256, P-384, Ed25519) in PEM.', fields: { privateKey: secret('Private key (PEM)', PEM_KEY), publicKey: plain('Public key (PEM)', PEM_KEY) }, metadata: { ...keyMeta, curve: meta('Curve', { kind: 'enum', values: ['P-256', 'P-384', 'P-521', 'Ed25519', 'secp256k1'] }) }, defaults: { rotationIntervalDays: 365 }, tags: ['ecc'] },
  { key: 'hmac-secret', version: 2, name: 'HMAC secret', category: 'crypto', description: 'A shared secret for message authentication codes.', fields: { secret: secret('Secret', { minLength: 32, maxLength: 4096, generate: { encoding: 'base64url', bytes: 32 } }) }, metadata: keyMeta, defaults: { rotationIntervalDays: 365 }, tags: ['hmac'] },
  { key: 'signing-key', version: 1, name: 'Signing key', category: 'crypto', description: 'A private key used to sign JWTs, releases or application artifacts.', fields: { privateKey: secret('Private key (PEM)', PEM_KEY), keyId: plain('Key ID (kid)', { maxLength: 200 }) }, identifiedBy: ['keyId'], metadata: keyMeta, defaults: { rotationIntervalDays: 365 }, tags: ['jwt', 'signing'] },

  // ── F. Certificates and PKI ────────────────────────────────────
  {
    key: 'tls-certificate',
    version: 1,
    name: 'TLS certificate and key',
    category: 'certificate',
    description: 'A server or client certificate (with chain) and its private key, in PEM.',
    fields: { certificate: plain('Certificate (PEM)', { required: true, kind: 'pem', maxLength: 65_536 }), privateKey: secret('Private key (PEM)', PEM_KEY), chain: plain('Chain (PEM)', { kind: 'pem', maxLength: 65_536 }) },
    metadata: { ...certMeta, usage: meta('Usage', { kind: 'enum', values: ['server', 'client', 'both'] }) },
    lifecycle: { rotation: false },
    defaults: { expiryWarningDays: 30 },
    tags: ['tls', 'x509'],
  },
  { key: 'ca-certificate', version: 1, name: 'Certificate authority', category: 'certificate', description: 'A CA certificate, with its private key when this CA issues certificates.', fields: { certificate: plain('CA certificate (PEM)', { required: true, kind: 'pem', maxLength: 65_536 }), privateKey: secret('CA private key (PEM)', { ...PEM_KEY, required: false }) }, metadata: certMeta, lifecycle: { rotation: false }, defaults: { expiryWarningDays: 60 }, tags: ['ca', 'x509'] },
  { key: 'pkcs12', version: 1, name: 'PKCS#12 / PFX file', category: 'certificate', description: 'A PKCS#12 (.p12 or .pfx) bundle, base64-encoded, and its passphrase.', fields: { bundle: secret('Bundle (base64)', { kind: 'multiline', maxLength: 65_536, pattern: '^[A-Za-z0-9+/=\\s]+$' }), passphrase: secret('Passphrase', { required: false, maxLength: 1024 }) }, metadata: certMeta, lifecycle: { rotation: false }, defaults: { expiryWarningDays: 30 }, tags: ['pkcs12', 'pfx'] },
  { key: 'certificate-passphrase', version: 1, name: 'Certificate passphrase', category: 'certificate', description: 'The passphrase protecting a key or bundle stored elsewhere.', fields: { passphrase: secret('Passphrase', { maxLength: 1024 }) }, metadata: certMeta, tags: ['passphrase'] },

  // ── G. Infrastructure and SSH secrets ──────────────────────────
  { key: 'ssh-private-key', version: 1, name: 'SSH private key', category: 'infrastructure', description: 'An SSH key pair, with an optional passphrase.', fields: { username: plain('Username', { maxLength: 128 }), privateKey: secret('Private key', { kind: 'pem', maxLength: 16_384, pattern: '^-----BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----[\\s\\S]+-----END (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----\\s*$' }), publicKey: plain('Public key', { maxLength: 4096 }), passphrase: secret('Passphrase', { required: false, maxLength: 1024 }) }, identifiedBy: ['username'], metadata: { ...infraMeta, host: meta('Host', { kind: 'hostname' }) }, defaults: { rotationIntervalDays: 365 }, tags: ['ssh'] },
  ...(
    [
      ['sftp', 'SFTP credentials', 'An SFTP login.', ['sftp']],
      ['vpn', 'VPN credentials', 'A VPN login.', ['vpn']],
      ['server-login', 'Server login', 'A login for a server or operational system.', ['server']],
      ['infra-automation', 'Infrastructure automation credentials', 'Credentials an automation tool (Ansible, Terraform runner) uses.', ['automation']],
    ] as const
  ).map(
    ([key, name, description, tags]): SecretTypeDefinitionInput => ({
      key,
      version: 1,
      name,
      category: 'infrastructure',
      description,
      fields: { username: plain('Username', { required: true, maxLength: 128 }), password: secret('Password', { maxLength: 1024 }) },
      identifiedBy: ['username'],
      metadata: { ...infraMeta, host: meta('Host', { kind: 'hostname' }), port: meta('Port', { kind: 'port' }) },
      defaults: { rotationIntervalDays: 90 },
      tags: [...tags],
    }),
  ),
  { key: 'kubeconfig', version: 1, name: 'Kubernetes kubeconfig', category: 'infrastructure', description: 'A kubeconfig file for a cluster.', fields: { kubeconfig: secret('Kubeconfig (YAML)', { kind: 'multiline', maxLength: 65_536 }) }, metadata: { ...infraMeta, cluster: meta('Cluster'), namespace: meta('Namespace') }, defaults: { rotationIntervalDays: 90 }, tags: ['kubernetes'] },
  { key: 'kubernetes-client', version: 1, name: 'Kubernetes client credentials', category: 'infrastructure', description: 'A service account token or client certificate for a cluster API.', fields: { server: plain('API server', { required: true, kind: 'url' }), token: secret('Token', { required: false, maxLength: 16_384 }), clientCertificate: plain('Client certificate (PEM)', { kind: 'pem', maxLength: 65_536 }), clientKey: secret('Client key (PEM)', { ...PEM_KEY, required: false }), caCertificate: plain('Cluster CA (PEM)', { kind: 'pem', maxLength: 65_536 }) }, identifiedBy: ['server'], metadata: { ...infraMeta, cluster: meta('Cluster'), namespace: meta('Namespace') }, defaults: { rotationIntervalDays: 90 }, tags: ['kubernetes'] },
  { key: 'docker-registry', version: 1, name: 'Container registry credentials', category: 'infrastructure', description: 'A login for a Docker or OCI registry.', fields: { registry: plain('Registry', { required: true, kind: 'hostname' }), username: plain('Username', { required: true, maxLength: 256 }), password: secret('Password or token', { maxLength: 4096 }) }, identifiedBy: ['registry', 'username'], metadata: infraMeta, defaults: { rotationIntervalDays: 90 }, tags: ['docker', 'oci'] },

  // ── H. Application secrets ─────────────────────────────────────
  { key: 'env-vars', version: 1, name: 'Environment variables', category: 'application', description: 'A set of environment variables for one application and environment.', fields: { variables: secret('Variables', { kind: 'keyvalue' }) }, metadata: { application: meta('Application') }, tags: ['env', 'config'] },
  { key: 'app-config', version: 1, name: 'Application configuration secret', category: 'application', description: 'A sensitive configuration document (JSON).', fields: { config: secret('Configuration (JSON)', { kind: 'json', maxLength: 65_536 }) }, metadata: { application: meta('Application') }, tags: ['config'] },
  { key: 'internal-service', version: 1, name: 'Internal service credentials', category: 'application', description: 'Credentials one internal service uses to call another (also internal API credentials).', fields: { clientId: plain('Client or user ID', { maxLength: 200 }), secret: secret('Secret', { maxLength: 4096 }) }, identifiedBy: ['clientId'], metadata: { application: meta('Application'), service: meta('Service called'), endpoint: meta('Endpoint', { kind: 'url' }) }, defaults: { rotationIntervalDays: 90 }, tags: ['internal'] },
  { key: 'session-signing-secret', version: 1, name: 'Session signing secret', category: 'application', description: 'The secret an application signs session cookies or tokens with.', fields: { secret: secret('Secret', { minLength: 32, maxLength: 4096 }) }, metadata: { application: meta('Application') }, defaults: { rotationIntervalDays: 180 }, tags: ['session'] },
  { key: 'smtp', version: 1, name: 'SMTP credentials', category: 'application', description: 'A mail server login.', fields: { username: plain('Username', { required: true, maxLength: 256 }), password: secret('Password', { maxLength: 1024 }) }, identifiedBy: ['username'], metadata: { host: meta('Host', { kind: 'hostname', required: true }), port: meta('Port', { kind: 'port', placeholder: '587' }), security: meta('Security', { kind: 'enum', values: ['starttls', 'tls', 'none'] }), from: meta('From address', { kind: 'email' }) }, defaults: { rotationIntervalDays: 180 }, tags: ['email'] },
  { key: 'encryption-passphrase', version: 1, name: 'Encryption passphrase', category: 'application', description: 'A passphrase an application derives encryption keys from.', fields: { passphrase: secret('Passphrase', { minLength: 12, maxLength: 1024 }) }, metadata: { application: meta('Application') }, tags: ['passphrase'] },
  { key: 'app-database', version: 1, name: 'Application database credentials', category: 'application', description: 'The database login of one application, with its connection details.', fields: { username: plain('Username', { required: true, maxLength: 128 }), password: secret('Password', { maxLength: 1024 }) }, identifiedBy: ['username'], metadata: { application: meta('Application'), ...dbMeta(5432) }, defaults: { rotationIntervalDays: 90 }, tags: ['database'] },

  // ── J. Dynamic secrets ─────────────────────────────────────────
  // The stored value is the credential the customer webhook uses to create short-lived ones
  // (leases); applications never read it. Lease lengths are metadata.
  {
    key: 'postgresql-dynamic',
    version: 1,
    name: 'PostgreSQL dynamic credentials',
    category: 'dynamic',
    description: 'Short-lived PostgreSQL logins created per lease (a role with VALID UNTIL and the grants below), dropped when the lease ends. Store an administrative login allowed to create roles.',
    fields: {
      host: plain('Host', { kind: 'hostname', required: true }),
      port: plain('Port', { kind: 'port', placeholder: '5432' }),
      database: plain('Database', { required: true, maxLength: 63 }),
      ssl: plain('Require TLS', { kind: 'boolean' }),
      username: plain('Administrative user', { required: true, maxLength: 63 }),
      password: secret('Password', { maxLength: 1024 }),
      creationStatements: plain('Grants for each lease', {
        kind: 'multiline',
        required: true,
        maxLength: 8192,
        description: 'SQL run after the role is created, one statement per line or separated by ";". {{name}} is the new role.',
        placeholder: 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};',
      }),
    },
    identifiedBy: ['host', 'database', 'username'],
    metadata: {
      defaultTtlMinutes: meta('Default lease (minutes)', { kind: 'integer', min: 1, max: 10_080, placeholder: '60' }),
      maxTtlMinutes: meta('Longest lease, with renewals (minutes)', { kind: 'integer', min: 1, max: 43_200, placeholder: '1440' }),
      owner: meta('Owning team'),
    },
    lifecycle: { dynamic: true, expiration: false },
    defaults: { rotationIntervalDays: 90 },
    tags: ['postgres', 'dynamic'],
  },
  {
    key: 'aws-sts-dynamic',
    version: 1,
    name: 'AWS temporary credentials (STS)',
    category: 'dynamic',
    description: 'Session credentials from sts:AssumeRole per lease. They cannot be revoked early: keep leases short. Store an access key allowed to assume the role.',
    fields: {
      accessKeyId: plain('Access key ID', { required: true, pattern: '^(AKIA|ASIA)[A-Z0-9]{16}$' }),
      secretAccessKey: secret('Secret access key', { minLength: 40, maxLength: 40 }),
      roleArn: plain('Role to assume (ARN)', { required: true, pattern: '^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$' }),
      region: plain('Region', { placeholder: 'us-east-1', pattern: '^[a-z]{2}(-[a-z]+)+-[0-9]$' }),
      externalId: secret('External ID', { required: false, maxLength: 1224 }),
    },
    identifiedBy: ['roleArn'],
    metadata: {
      defaultTtlMinutes: meta('Default lease (minutes)', { kind: 'integer', min: 15, max: 720, placeholder: '60' }),
      maxTtlMinutes: meta('Longest lease (minutes)', { kind: 'integer', min: 15, max: 720, placeholder: '60' }),
      accountId: meta('Account'),
    },
    lifecycle: { dynamic: true, expiration: false },
    defaults: { rotationIntervalDays: 90 },
    tags: ['aws', 'dynamic'],
  },

  // ── I. Webhook secrets ─────────────────────────────────────────
  { key: 'webhook-signing-secret', version: 2, name: 'Webhook signing secret', category: 'webhook', description: 'The secret webhook payloads are signed or verified with.', fields: { secret: secret('Secret', { minLength: 16, maxLength: 4096, generate: { encoding: 'hex', bytes: 32 } }) }, metadata: { provider: meta('Provider'), endpoint: meta('Webhook endpoint', { kind: 'url' }), algorithm: meta('Algorithm', { placeholder: 'e.g. HMAC-SHA256' }), direction: meta('Direction', { kind: 'enum', values: ['outgoing', 'incoming'] }) }, defaults: { rotationIntervalDays: 180 }, tags: ['webhook'] },
  { key: 'webhook-auth-token', version: 2, name: 'Webhook authentication token', category: 'webhook', description: 'A token a webhook sender presents, or a receiver expects.', fields: { token: secret('Token', { maxLength: 4096, generate: { encoding: 'base64url', bytes: 32 } }) }, metadata: { provider: meta('Provider'), endpoint: meta('Webhook endpoint', { kind: 'url' }), header: meta('Header name') }, defaults: { rotationIntervalDays: 180 }, tags: ['webhook'] },
  { key: 'webhook-api-credential', version: 1, name: 'Webhook API credential', category: 'webhook', description: 'A username and password or key a webhook endpoint requires.', fields: { username: plain('Username or key ID', { maxLength: 256 }), secret: secret('Password or key', { maxLength: 4096 }) }, identifiedBy: ['username'], metadata: { provider: meta('Provider'), endpoint: meta('Webhook endpoint', { kind: 'url' }) }, defaults: { rotationIntervalDays: 180 }, tags: ['webhook'] },
  { key: 'webhook-verification-secret', version: 2, name: 'Webhook verification secret', category: 'webhook', description: 'A secret used to answer a provider’s endpoint verification challenge.', fields: { secret: secret('Secret', { maxLength: 4096, generate: { encoding: 'base64url', bytes: 32 } }) }, metadata: { provider: meta('Provider'), endpoint: meta('Webhook endpoint', { kind: 'url' }) }, tags: ['webhook'] },
];

export const BUILTIN_SECRET_TYPES: SecretTypeDefinitionInput[] = TYPES.map(ordered);
