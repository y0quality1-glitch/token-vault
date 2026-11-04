// Prints ready-to-use MCP client configuration for the Token Vault MCP server, with this
// checkout's absolute paths filled in. Never prints or stores a real API key.
//   npm run mcp:config               (control plane at http://localhost:4000)
//   npm run mcp:config -- --url https://tv.example.com
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const bin = resolve(root, 'mcp/bin/token-vault-mcp.mjs');
const urlArg = process.argv.indexOf('--url');
const url = urlArg > -1 ? process.argv[urlArg + 1] : 'http://localhost:4000';
const node = process.execPath;

const projectJson = {
  mcpServers: {
    'token-vault': {
      command: node,
      args: [bin],
      env: { TOKEN_VAULT_URL: url, TOKEN_VAULT_API_KEY: '${TOKEN_VAULT_API_KEY}' },
    },
  },
};
const desktopJson = {
  mcpServers: {
    'token-vault': {
      command: node,
      args: [bin],
      env: { TOKEN_VAULT_URL: url, TOKEN_VAULT_API_KEY: 'tvak_…paste this agent’s credential…' },
    },
  },
};

console.log(`Token Vault MCP server: ${bin}
Get an agent credential first: Agents → (agent) → Rotate API credential. It is shown once.

── Claude Code, project-scoped (.mcp.json; the key stays in your shell, not in the file) ──
${JSON.stringify(projectJson, null, 2)}

Then, in the shell you start Claude Code from:
  export TOKEN_VAULT_API_KEY='tvak_…'

── Claude Code, one command (stores the key in your Claude Code config) ──
claude mcp add token-vault -e TOKEN_VAULT_URL=${url} -e TOKEN_VAULT_API_KEY='tvak_…' -- ${node} ${bin}

── Claude Desktop (claude_desktop_config.json; the key is stored in that file) ──
${JSON.stringify(desktopJson, null, 2)}

Tools: token_vault_list_access, github_get_repository, github_read_file, github_list_issues, github_create_issue
Every call is authorized and audited by Token Vault; the GitHub credential never reaches the agent.`);
