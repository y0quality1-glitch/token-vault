import { describe, expect, it } from 'vitest';
import pg from 'pg';
import { createServer } from 'node:net';
import { databaseError, describeDatabaseUrl } from '@token-vault/shared';

const URL = 'postgres://token_vault:super-secret-pw@127.0.0.1:5432/token_vault';

describe('database connection errors', () => {
  it('names host, port, database and user, never the password', () => {
    expect(describeDatabaseUrl(URL)).toBe('127.0.0.1:5432 (database token_vault, user token_vault)');
    expect(databaseError(new Error('x'), URL).message).not.toContain('super-secret-pw');
    expect(describeDatabaseUrl('not a url')).toBe('the configured database');
  });

  it('explains a connection that is accepted and then reset (the Windows/Docker case)', async () => {
    // A listener that drops every connection, like a broken port forward.
    const server = createServer((s) => s.resetAndDestroy());
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as { port: number }).port;
    const url = `postgres://token_vault:pw@127.0.0.1:${port}/token_vault`;
    const pool = new pg.Pool({ connectionString: url });
    try {
      const failure = await pool.query('select 1').catch((e) => e);
      // Under the ORM the driver error is the cause.
      const msg = databaseError(Object.assign(new Error('Failed query: CREATE SCHEMA IF NOT EXISTS "drizzle"'), { cause: failure }), url).message;
      expect(msg).toMatch(new RegExp(`^cannot use PostgreSQL at 127.0.0.1:${port} \\(database token_vault, user token_vault\\): ECONNRESET`));
      expect(msg).toContain('use 127.0.0.1 in the URL');
      expect(msg).not.toContain('Failed query');
    } finally {
      await pool.end();
      server.close();
    }
  });

  it('explains refused connections and PostgreSQL error codes', async () => {
    const pool = new pg.Pool({ connectionString: 'postgres://u:p@127.0.0.1:1/db' });
    const refused = await pool.query('select 1').catch((e) => e);
    await pool.end();
    expect(databaseError(refused, 'postgres://u:p@127.0.0.1:1/db').message).toContain('npm run db:up');
    expect(databaseError(Object.assign(new Error('password authentication failed for user "u"'), { code: '28P01' }), URL).message).toContain('Another PostgreSQL may be answering');
    expect(databaseError(Object.assign(new Error('database "x" does not exist'), { code: '3D000' }), URL).message).toContain('npm run db:init');
  });
});
