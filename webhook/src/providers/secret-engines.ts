import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { AssumeRoleCommand, GetCallerIdentityCommand, STSClient } from '@aws-sdk/client-sts';
import type { SecretPayload } from '@token-vault/shared';
import { config } from '../config';

/**
 * Provider engines for Secret Management (spec 4.9.3 J, 4.9.11, 4.9.16): what the customer
 * webhook does at a secret's provider with the credential it stores.
 *  - postgresql (static): rotate its own password, check the login works;
 *  - postgresql-dynamic: create a role per lease (LOGIN, VALID UNTIL, the configured grants),
 *    lengthen it, drop it; rotate the administrative password; check;
 *  - aws-sts-dynamic: AssumeRole per lease (session credentials expire on their own); check.
 * Nothing here logs a password or a key; provider errors are reduced to a code and a short
 * message without credentials.
 */

export class ProviderError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly retryable = false,
  ) {
    super(message);
  }
}

export interface Connection {
  host: string;
  port: number;
  database: string;
  ssl?: boolean;
}

export interface LeaseCredentials {
  username: string;
  credentials: Record<string, string>;
  expiresAt: string;
  renewable: boolean;
}

/** The host allow-list (PROVIDER_ALLOWED_HOSTS): a stored login is only ever sent to these. */
export function hostAllowed(host: string, port: number): boolean {
  const list = config.providerAllowedHosts;
  const h = host.toLowerCase();
  return list.includes('*') || list.includes(h) || list.includes(`${h}:${port}`);
}

function checkHost(c: Connection) {
  if (!hostAllowed(c.host, c.port)) throw new ProviderError('PROVIDER_HOST_NOT_ALLOWED', `This webhook may not connect to ${c.host}:${c.port} (add it to PROVIDER_ALLOWED_HOSTS)`);
}

const newPassword = () => randomBytes(32).toString('base64url');

/** A role name for a lease: lower-case, a fixed prefix, at most 63 characters. */
export function leaseRoleName(leaseId: string): string {
  return `tv_${leaseId.toLowerCase().replace(/[^a-z0-9_]/g, '_')}`.slice(0, 63);
}

// ── PostgreSQL ──────────────────────────────────────────────────────

function pgError(e: unknown, what: string): ProviderError {
  if (e instanceof ProviderError) return e;
  const err = e as { code?: string; message?: string };
  // Connection problems are worth retrying; SQL errors are not.
  if (['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNRESET', 'EHOSTUNREACH', '57P03'].includes(err.code ?? '') || /timeout/i.test(err.message ?? '')) return new ProviderError('PROVIDER_UNAVAILABLE', `The database could not be reached to ${what}`, true);
  if (err.code === '28P01' || err.code === '28000') return new ProviderError('PROVIDER_AUTH_FAILED', `The database refused the stored login (${what})`);
  if (err.code === '42501' && /for database/i.test(err.message ?? '')) return new ProviderError('PROVIDER_PERMISSION_DENIED', 'The stored login may not connect to that database');
  if (err.code === '42501') return new ProviderError('PROVIDER_PERMISSION_DENIED', `The stored login lacks the privilege to ${what}`);
  if (err.code && /^[0-9A-Z]{5}$/.test(err.code)) return new ProviderError('PROVIDER_SQL_ERROR', `The database refused a statement while trying to ${what} (SQLSTATE ${err.code})`);
  return new ProviderError('PROVIDER_ERROR', `The database could not ${what}`);
}

async function withPg<T>(c: Connection, user: string, password: string, what: string, fn: (client: pg.Client) => Promise<T>): Promise<T> {
  checkHost(c);
  const client = new pg.Client({ host: c.host, port: c.port, database: c.database, user, password, ssl: c.ssl ? { rejectUnauthorized: true } : undefined, connectionTimeoutMillis: 5_000, statement_timeout: 10_000, application_name: 'token-vault-webhook' });
  // Errors after connect (a dropped connection) must not crash the process.
  client.on('error', () => undefined);
  try {
    await client.connect();
    return await fn(client);
  } catch (e) {
    throw pgError(e, what);
  } finally {
    await client.end().catch(() => undefined);
  }
}

const pgConnection = (p: SecretPayload, fallback?: Partial<Connection>): Connection => ({
  host: String(p.host ?? fallback?.host ?? ''),
  port: Number(p.port ?? fallback?.port ?? 5432),
  database: String(p.database ?? fallback?.database ?? 'postgres'),
  ssl: p.ssl === true || fallback?.ssl === true,
});

/** Statements of a grant template, with {{name}} replaced by the quoted role name. */
export function grantStatements(template: string, quotedRole: string): string[] {
  return template
    .split(/;\s*(?:\r?\n|$)|\r?\n/)
    .map((s) => s.trim().replace(/;$/, ''))
    .filter((s) => s && !s.startsWith('--'))
    .map((s) => s.replaceAll('{{name}}', quotedRole));
}

const postgres = {
  async check(p: SecretPayload, conn: Connection): Promise<string> {
    return withPg(conn, String(p.username), String(p.password), 'check the login', async (c) => {
      const r = await c.query<{ who: string }>('SELECT current_user AS who');
      return `connected as ${r.rows[0]!.who}`;
    });
  },

  /** The login changes its own password; the new one is then checked by logging in with it. */
  async rotate(p: SecretPayload, conn: Connection): Promise<SecretPayload> {
    const password = newPassword();
    await withPg(conn, String(p.username), String(p.password), 'change the password', (c) => c.query(`ALTER ROLE CURRENT_USER PASSWORD ${c.escapeLiteral(password)}`));
    try {
      await withPg(conn, String(p.username), password, 'log in with the new password', (c) => c.query('SELECT 1'));
    } catch (e) {
      // Put the old password back so the stored version keeps working.
      await withPg(conn, String(p.username), password, 'restore the password', (c) => c.query(`ALTER ROLE CURRENT_USER PASSWORD ${c.escapeLiteral(String(p.password))}`)).catch(() => undefined);
      throw e;
    }
    return { ...p, password };
  },

  /** Puts a rotated password back (the new version could not be stored). */
  async restore(p: SecretPayload, rotated: SecretPayload, conn: Connection): Promise<void> {
    await withPg(conn, String(p.username), String(rotated.password), 'restore the password', (c) => c.query(`ALTER ROLE CURRENT_USER PASSWORD ${c.escapeLiteral(String(p.password))}`));
  },

  async lease(p: SecretPayload, leaseId: string, expiresAt: Date): Promise<LeaseCredentials> {
    const conn = pgConnection(p);
    const role = leaseRoleName(leaseId);
    const password = newPassword();
    await withPg(conn, String(p.username), String(p.password), 'create the lease role', async (c) => {
      const quoted = c.escapeIdentifier(role);
      await c.query('BEGIN');
      try {
        await c.query(`CREATE ROLE ${quoted} LOGIN PASSWORD ${c.escapeLiteral(password)} VALID UNTIL ${c.escapeLiteral(expiresAt.toISOString())}`);
        for (const stmt of grantStatements(String(p.creationStatements ?? ''), quoted)) await c.query(stmt);
        await c.query('COMMIT');
      } catch (e) {
        await c.query('ROLLBACK').catch(() => undefined);
        throw e;
      }
    });
    return { username: role, credentials: { username: role, password, host: conn.host, port: String(conn.port), database: conn.database }, expiresAt: expiresAt.toISOString(), renewable: true };
  },

  async renew(p: SecretPayload, username: string, expiresAt: Date): Promise<void> {
    await withPg(pgConnection(p), String(p.username), String(p.password), 'lengthen the lease', async (c) => {
      const r = await c.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [username]);
      if (!r.rowCount) throw new ProviderError('LEASE_NOT_FOUND', 'The lease role no longer exists at the database');
      await c.query(`ALTER ROLE ${c.escapeIdentifier(username)} VALID UNTIL ${c.escapeLiteral(expiresAt.toISOString())}`);
    });
  },

  /** Ends the role's sessions, hands its objects to the administrative login, and drops it. */
  async revoke(p: SecretPayload, username: string): Promise<void> {
    if (!username.startsWith('tv_')) throw new ProviderError('LEASE_NOT_FOUND', 'Not a lease role');
    await withPg(pgConnection(p), String(p.username), String(p.password), 'drop the lease role', async (c) => {
      const r = await c.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [username]);
      if (!r.rowCount) return; // already gone
      const quoted = c.escapeIdentifier(username);
      await c.query(`ALTER ROLE ${quoted} NOLOGIN`);
      await c.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1', [username]);
      await c.query(`REASSIGN OWNED BY ${quoted} TO CURRENT_USER`);
      await c.query(`DROP OWNED BY ${quoted}`);
      await c.query(`DROP ROLE ${quoted}`);
    });
  },
};

// ── AWS STS ─────────────────────────────────────────────────────────

function stsClient(p: SecretPayload) {
  return new STSClient({
    region: String(p.region || 'us-east-1'),
    endpoint: config.awsStsEndpoint,
    credentials: { accessKeyId: String(p.accessKeyId), secretAccessKey: String(p.secretAccessKey) },
    maxAttempts: 2,
    requestHandler: { connectionTimeout: 3_000, requestTimeout: 8_000 },
  });
}

function awsError(e: unknown, what: string): ProviderError {
  const err = e as { name?: string; $metadata?: { httpStatusCode?: number } };
  const status = err.$metadata?.httpStatusCode;
  if (!status || status >= 500 || err.name === 'TimeoutError') return new ProviderError('PROVIDER_UNAVAILABLE', `AWS STS could not be reached to ${what}`, true);
  if (status === 403 || err.name === 'AccessDenied' || err.name === 'InvalidClientTokenId' || err.name === 'SignatureDoesNotMatch') return new ProviderError('PROVIDER_AUTH_FAILED', `AWS refused the stored key (${what}: ${err.name})`);
  return new ProviderError('PROVIDER_ERROR', `AWS STS refused to ${what} (${err.name ?? `HTTP ${status}`})`);
}

const awsSts = {
  async check(p: SecretPayload): Promise<string> {
    try {
      const r = await stsClient(p).send(new GetCallerIdentityCommand({}));
      return `authenticated as ${r.Arn}`;
    } catch (e) {
      throw awsError(e, 'check the key');
    }
  },
  async lease(p: SecretPayload, leaseId: string, expiresAt: Date): Promise<LeaseCredentials> {
    const seconds = Math.max(900, Math.min(43_200, Math.round((expiresAt.getTime() - Date.now()) / 1000)));
    const session = `tv-${leaseId}`.slice(0, 64);
    try {
      const r = await stsClient(p).send(new AssumeRoleCommand({ RoleArn: String(p.roleArn), RoleSessionName: session, DurationSeconds: seconds, ...(p.externalId ? { ExternalId: String(p.externalId) } : {}) }));
      const c = r.Credentials;
      if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken) throw new ProviderError('PROVIDER_ERROR', 'AWS STS returned no credentials');
      return {
        username: session,
        credentials: { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken, region: String(p.region || 'us-east-1') },
        expiresAt: (c.Expiration ?? new Date(Date.now() + seconds * 1000)).toISOString(),
        renewable: false,
      };
    } catch (e) {
      throw e instanceof ProviderError ? e : awsError(e, 'assume the role');
    }
  },
};

// ── dispatch ────────────────────────────────────────────────────────

export const engines = {
  async check(typeKey: string, p: SecretPayload, connection?: Partial<Connection>): Promise<string> {
    if (typeKey === 'postgresql' || typeKey === 'postgresql-dynamic') return postgres.check(p, pgConnection(p, connection));
    if (typeKey === 'aws-sts-dynamic') return awsSts.check(p);
    throw new ProviderError('PROVIDER_NOT_SUPPORTED', 'This webhook cannot connect to the provider of this secret type');
  },
  async rotate(typeKey: string, p: SecretPayload, connection?: Partial<Connection>): Promise<{ next: SecretPayload; undo: () => Promise<void> }> {
    if (typeKey === 'postgresql' || typeKey === 'postgresql-dynamic') {
      const conn = pgConnection(p, connection);
      const next = await postgres.rotate(p, conn);
      return { next, undo: () => postgres.restore(p, next, conn) };
    }
    throw new ProviderError('PROVIDER_NOT_SUPPORTED', 'This secret type cannot be rotated at its provider');
  },
  async lease(typeKey: string, p: SecretPayload, leaseId: string, expiresAt: Date): Promise<LeaseCredentials> {
    if (typeKey === 'postgresql-dynamic') return postgres.lease(p, leaseId, expiresAt);
    if (typeKey === 'aws-sts-dynamic') return awsSts.lease(p, leaseId, expiresAt);
    throw new ProviderError('PROVIDER_NOT_SUPPORTED', 'This secret type does not issue leases');
  },
  async renew(typeKey: string, p: SecretPayload, username: string, expiresAt: Date): Promise<void> {
    if (typeKey === 'postgresql-dynamic') return postgres.renew(p, username, expiresAt);
    throw new ProviderError('LEASE_NOT_RENEWABLE', 'Leases of this type cannot be lengthened; ask for a new one');
  },
  /** False when the provider cannot end a credential early (it expires on its own). */
  async revoke(typeKey: string, p: SecretPayload, username: string): Promise<boolean> {
    if (typeKey === 'postgresql-dynamic') {
      await postgres.revoke(p, username);
      return true;
    }
    if (typeKey === 'aws-sts-dynamic') return false;
    throw new ProviderError('PROVIDER_NOT_SUPPORTED', 'This secret type does not issue leases');
  },
};
