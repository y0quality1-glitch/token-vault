// End-to-end smoke test of a running Token Vault deployment, through its public URLs only.
//
//   node deploy/compose/smoke-test.mjs [console-url] [cms-url]
//   (defaults: http://localhost:8080 http://localhost:8081, the docker compose ports)
//
// Signs in with the demo accounts, checks that the control plane has the signed CMS catalog,
// that the customer webhook answers a signed health challenge, and that an agent request goes
// through the whole path (control plane -> webhook -> provider, simulated by default). It creates
// one agent and grant, then revokes and disables them. Exits non-zero on the first failure.
const CONSOLE = (process.argv[2] ?? 'http://localhost:8080').replace(/\/$/, '');
const CMS = (process.argv[3] ?? 'http://localhost:8081').replace(/\/$/, '');
const PASSWORD = process.env.DEMO_PASSWORD ?? 'TokenVault-Demo-2026';

let failed = false;
const step = async (name, fn) => {
  try {
    const detail = await fn();
    console.log(`ok   ${name}${detail ? ` (${detail})` : ''}`);
  } catch (e) {
    failed = true;
    console.error(`FAIL ${name}: ${e.message}`);
    throw e;
  }
};
const expect = (cond, message) => {
  if (!cond) throw new Error(message);
};

/** Minimal cookie-keeping client for one origin. */
function session(base) {
  let cookie = '';
  return async (method, path, body, headers = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(20_000),
    });
    const set = res.headers.getSetCookie?.() ?? [];
    if (set.length) cookie = set.map((c) => c.split(';')[0]).join('; ');
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      /* not JSON */
    }
    return { status: res.status, json, text };
  };
}

const api = session(CONSOLE);
const cms = session(CMS);
let agentId = '';
let grantId = '';

try {
  await step('console and CMS are up', async () => {
    for (const base of [CONSOLE, CMS]) {
      const r = await fetch(base + '/healthz');
      expect(r.ok, `${base}/healthz answered ${r.status}`);
      const page = await (await fetch(base + '/')).text();
      expect(page.includes('<div id="root"'), `${base}/ does not serve the app`);
    }
  });

  await step('sign in to the console', async () => {
    const login = await api('POST', '/api/v1/auth/login', { email: 'owner@demo.test', password: PASSWORD });
    expect(login.status === 200, `login answered ${login.status}`);
    const org = await api('POST', '/api/v1/auth/select-organization', { organizationId: 'org_demo0000000001' });
    expect(org.status === 200, `organization selection answered ${org.status}`);
  });

  await step('control plane has the signed CMS catalog', async () => {
    let providers = [];
    for (let i = 0; i < 20; i++) {
      providers = (await api('GET', '/api/v1/providers')).json?.providers ?? [];
      if (providers.some((p) => p.source === 'catalog')) break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    const fromCatalog = providers.filter((p) => p.source === 'catalog').map((p) => p.key);
    expect(fromCatalog.length > 0, 'no provider came from the CMS catalog (check CMS_CATALOG_URL and CMS_PUBLIC_KEY)');
    return fromCatalog.join(', ');
  });

  await step('customer webhook answers a signed health challenge', async () => {
    const webhooks = (await api('GET', '/api/v1/webhooks')).json?.items ?? [];
    expect(webhooks.length > 0, 'no webhook registered');
    const r = await api('POST', `/api/v1/webhooks/${webhooks[0].id}/test`);
    expect(r.json?.result?.ok === true, `health check failed: ${r.json?.result?.detail ?? r.status}`);
    return r.json.result.detail;
  });

  await step('an agent request goes through the whole path', async () => {
    const integrations = (await api('GET', '/api/v1/integrations')).json?.items ?? [];
    const github = integrations.find((i) => i.provider === 'github' && i.credentialStatus === 'CONNECTED' && i.allowedResources.includes('demo-org/demo-repo'));
    expect(github, 'no connected GitHub integration for demo-org/demo-repo (demo data missing?)');
    const agent = await api('POST', '/api/v1/agents', { name: `smoke-test-${Date.now()}`, environment: github.environment, ownerTeam: 'Operations', agentType: 'SERVICE' });
    expect(agent.status === 201, `agent registration answered ${agent.status}`);
    agentId = agent.json.agent.id;
    const now = Date.now();
    const grant = await api('POST', '/api/v1/grants', { name: `Smoke test ${now}`, agentId, integrationId: github.id, environment: github.environment, scopes: ['github.repositories.read'], repositories: ['demo-org/demo-repo'], validFrom: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 3_600_000).toISOString(), rateLimitPerMinute: 10 });
    expect(grant.status === 201, `grant creation answered ${grant.status}: ${grant.text.slice(0, 200)}`);
    grantId = grant.json.id;
    const r = await fetch(CONSOLE + '/agent/v1/execute', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${agent.json.credential.apiKey}` },
      body: JSON.stringify({ integration_id: github.id, operation: 'github.repositories.read', resource: { repository: 'demo-org/demo-repo' }, idempotency_key: `smoke-${now}` }),
    });
    const body = await r.json();
    expect(r.status === 200 && body.decision === 'ALLOW', `execute answered ${r.status} ${body.decision_code}: ${body.reason}`);
    return `${body.decision_code}, upstream ${body.execution.upstream_status}${body.execution.simulated ? ' (simulated)' : ''}`;
  });

  await step('sign in to the CMS; its catalog is served', async () => {
    const login = await cms('POST', '/api/v1/auth/login', { email: 'admin@cms.test', password: PASSWORD });
    expect(login.status === 200, `CMS login answered ${login.status}`);
    const apps = (await cms('POST', '/api/v1/application/getall', { pageSize: 200 })).json?.details ?? [];
    expect(apps.length > 0, 'the CMS lists no applications');
    const catalog = await cms('GET', '/catalog/v1/definitions');
    expect(catalog.status === 200 && catalog.json?.definitions?.length > 0, `catalog answered ${catalog.status}`);
    return `${apps.length} applications, ${catalog.json.definitions.length} published`;
  });
} catch {
  /* reported by step() */
} finally {
  // Leave nothing usable behind.
  if (grantId) await api('POST', `/api/v1/grants/${grantId}/revoke`, { reason: 'smoke test finished' }).catch(() => {});
  if (agentId) await api('POST', `/api/v1/agents/${agentId}/disable`).catch(() => {});
}
if (failed) process.exit(1);
console.log('smoke test passed');
