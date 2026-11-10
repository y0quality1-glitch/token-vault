/**
 * Turns a failure to reach or use PostgreSQL into one actionable line: where it tried to
 * connect, what went wrong, and what usually fixes it. Never includes the password.
 */
const HINTS: Record<string, string> = {
  ECONNRESET:
    'The connection was opened and then dropped. Usually the Docker database is still starting (check "docker compose ps"), or another program owns the port: on Windows a local PostgreSQL service, or Docker forwarding "localhost" over IPv6 (use 127.0.0.1 in the URL; npm run setup does this)',
  ECONNREFUSED: 'Nothing is listening there. Start the database with "npm run db:up"',
  ETIMEDOUT: 'The database did not answer in time. Check the host, the port and any firewall',
  ENOTFOUND: 'The host name does not resolve',
  EAI_AGAIN: 'The host name could not be resolved right now',
  '28P01': 'The password was rejected. Another PostgreSQL may be answering on this port (on Windows: Get-Service *postgres*), or the URL holds the wrong password',
  '28000': 'The role is missing or not allowed. Create the roles and databases with "npm run db:init"',
  '3D000': 'The database does not exist. Create the roles and databases with "npm run db:init"',
  '42501': 'The role lacks a privilege it needs on this database. Run "npm run db:init", which sets the owners',
};

/** host:port, database and user from a connection string, without the password. */
export function describeDatabaseUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.hostname}:${u.port || '5432'} (database ${decodeURIComponent(u.pathname.slice(1)) || '?'}, user ${decodeURIComponent(u.username) || '?'})`;
  } catch {
    return 'the configured database';
  }
}

/** The driver's error code (pg puts it on the error or, under an ORM, on its cause). */
function codeOf(err: unknown): string | undefined {
  const e = err as { code?: string; cause?: { code?: string }; errors?: { code?: string }[] };
  return e?.cause?.code ?? e?.code ?? e?.errors?.[0]?.code;
}

/** An Error whose message says where the database is and how to fix the failure. */
export function databaseError(err: unknown, url: string): Error {
  const e = err as Error & { cause?: Error };
  const code = codeOf(err);
  const what = e?.cause?.message || (e instanceof AggregateError ? e.errors.map((x) => (x as Error).message).join('; ') : '') || (code ? '' : e?.message) || String(code ?? err);
  const hint = code ? HINTS[code] : undefined;
  const out = new Error(`cannot use PostgreSQL at ${describeDatabaseUrl(url)}: ${[code, what].filter(Boolean).join(' ').trim()}${hint ? `. ${hint}.` : ''}`);
  (out as Error & { code?: string }).code = code;
  return out;
}
