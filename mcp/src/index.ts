import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { TokenVault, TokenVaultError } from '@token-vault/sdk';
import { createServer } from './server';

/**
 * Token Vault MCP server (stdio).
 *
 * Configuration comes from the environment only (never command-line arguments, which
 * other users on the machine can see in the process list):
 *   TOKEN_VAULT_API_KEY  this agent's Token Vault credential (tvak_…), required
 *   TOKEN_VAULT_URL      control plane URL (default http://localhost:4000)
 *   TOKEN_VAULT_ORG      optional organization slug (audit attribution of failed auth)
 *   TOKEN_VAULT_TOOLS_REFRESH_S  how often to re-read the catalog for new or changed
 *                        application tools (default 60, 0 = only at start-up)
 *
 * stdout carries the MCP protocol, so all diagnostics go to stderr.
 */
async function main() {
  let tv: TokenVault;
  try {
    tv = new TokenVault({ organization: process.env.TOKEN_VAULT_ORG || undefined });
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
  console.error(`[token-vault-mcp] ready: ${tv.baseUrl} (key ${tv.keyId})`);
  const every = Number(process.env.TOKEN_VAULT_TOOLS_REFRESH_S ?? 60);
  if (every > 0) setInterval(() => void refresh('updated'), every * 1000).unref();
}

main().catch((e) => {
  console.error(`[token-vault-mcp] failed to start: ${e instanceof TokenVaultError ? e.code : (e as Error).name}`);
  process.exit(1);
});
