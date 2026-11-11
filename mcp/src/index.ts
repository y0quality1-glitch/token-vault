import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { TokenVault, TokenVaultError } from '@token-vault/sdk';
import { createServer } from './server';

/**
 * Token Vault MCP server (stdio).
 *
 * Configuration comes from the environment only (never command-line arguments, which
 * other users on the machine can see in the process list):
 *   TOKEN_VAULT_API_KEY  this agent's Token Vault credential (tvak_…), or a sub-agent's
 *                        delegation token (tvdt_…, created with the SDK's delegate()), required
 *   TOKEN_VAULT_URL      control plane URL (default http://localhost:4000)
 *   TOKEN_VAULT_ORG      optional organization slug (audit attribution of failed auth)
 *   TOKEN_VAULT_TOOLS_REFRESH_S  how often to re-read the catalog for new or changed
 *                        application tools (default 60, 0 = only at start-up)
 *   TOKEN_VAULT_USER_TOKEN_FILE  optional: act on behalf of a user. A file holding the user's
 *                        signed token (JWT), re-read on every call so another process can
 *                        keep it fresh. Takes precedence over TOKEN_VAULT_USER_TOKEN.
 *   TOKEN_VAULT_USER_TOKEN  optional: the user's signed token itself (expires; prefer the file)
 *   TOKEN_VAULT_SESSION_ID / TOKEN_VAULT_SESSION_LABEL  optional: the session every tool call
 *                        belongs to (Audit → Sessions). Default: one new session per server start,
 *                        with one W3C trace and a span per tool call.
 *
 * stdout carries the MCP protocol, so all diagnostics go to stderr.
 */
async function main() {
  let tv: TokenVault;
  const tokenFile = process.env.TOKEN_VAULT_USER_TOKEN_FILE || undefined;
  const userToken = tokenFile
    ? () => {
        try {
          return readFileSync(tokenFile, 'utf8').trim();
        } catch {
          console.error('[token-vault-mcp] warning: cannot read TOKEN_VAULT_USER_TOKEN_FILE; the request is sent without a user');
          return '';
        }
      }
    : process.env.TOKEN_VAULT_USER_TOKEN || undefined;
  // One session and one trace per MCP server process (= one client session); a span per tool call.
  const traceId = randomBytes(16).toString('hex');
  const sessionId = process.env.TOKEN_VAULT_SESSION_ID || `mcp-${traceId.slice(0, 16)}`;
  try {
    tv = new TokenVault({
      userToken,
      sessionId,
      sessionLabel: process.env.TOKEN_VAULT_SESSION_LABEL || 'MCP session',
      traceparent: () => `00-${traceId}-${randomBytes(8).toString('hex')}-01`,
      organization: process.env.TOKEN_VAULT_ORG || undefined,
      onKeyExpiry: (at) => console.error(`[token-vault-mcp] warning: this API key was rotated and stops working at ${at}. Set TOKEN_VAULT_API_KEY to the new key and restart.`),
    });
  } catch (e) {
    console.error(`[token-vault-mcp] ${(e as Error).message}`);
    process.exit(1);
  }
  const server = createServer(tv);
  const refresh = async (when: string) => {
    try {
      if (await server.refreshTools()) console.error(`[token-vault-mcp] application tools ${when}`);
    } catch (e) {
      console.error(`[token-vault-mcp] could not load application tools (${e instanceof TokenVaultError ? e.code : (e as Error).name}); GitHub tools remain available`);
    }
  };
  await refresh('loaded');
  await server.connect(new StdioServerTransport());
  console.error(`[token-vault-mcp] ready: ${tv.baseUrl} (${tv.isDelegated ? 'sub-agent delegation' : 'key'} ${tv.keyId})${tv.actsForUser ? ', acting on behalf of a user' : ''}, session ${sessionId}`);
  const every = Number(process.env.TOKEN_VAULT_TOOLS_REFRESH_S ?? 60);
  if (every > 0) setInterval(() => void refresh('updated'), every * 1000).unref();
}

main().catch((e) => {
  console.error(`[token-vault-mcp] failed to start: ${e instanceof TokenVaultError ? e.code : (e as Error).name}`);
  process.exit(1);
});
