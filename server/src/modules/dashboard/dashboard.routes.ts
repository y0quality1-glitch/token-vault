import { Router } from 'express';
import type { DashboardSummary } from '@token-vault/shared';
import { orgCtx } from '../../middleware/auth';
import { agentRepo, auditRepo, grantRepo, grantRequestRepo, integrationRepo, webhookRepo } from '../../store/repos';
import { effectiveStatus as requestStatus } from '../grant-requests/grant-requests.service';
import { effectiveGrantStatus, loadLookups, toGrant } from '../../store/views';

export const dashboardRouter = Router();

dashboardRouter.get('/dashboard', async (req, res) => {
  const { org } = orgCtx(req);
  const now = Date.now();
  const since = now - 86400e3;

  const [integrations, agents, grants, webhooks, recent, latest, anyRequests, lookups, grantRequests] = await Promise.all([
    integrationRepo.listIntegrations(org.id),
    agentRepo.listAgents(org.id),
    grantRepo.listGrants(org.id),
    webhookRepo.listWebhooks(org.id),
    auditRepo.accessRequestsSince(org.id, new Date(since).toISOString()),
    auditRepo.latestAccessRequests(org.id, 8),
    auditRepo.hasAccessRequests(org.id),
    loadLookups(org.id),
    grantRequestRepo.listGrantRequests(org.id),
  ]);

  const primary = webhooks.find((w) => w.status === 'CONNECTED') ?? webhooks[0];

  const hourly: DashboardSummary['hourly'] = [];
  for (let h = 23; h >= 0; h--) {
    const start = now - (h + 1) * 3600e3;
    const end = now - h * 3600e3;
    const bucket = recent.filter((r) => {
      const t = new Date(r.createdAt).getTime();
      return t > start && t <= end;
    });
    hourly.push({ hour: new Date(end).toISOString(), allowed: bucket.filter((r) => r.decision === 'ALLOW').length, denied: bucket.filter((r) => r.decision === 'DENY').length });
  }

  const alerts: DashboardSummary['alerts'] = [];
  for (const w of webhooks.filter((x) => x.status === 'UNHEALTHY' || x.status === 'DISCONNECTED')) {
    alerts.push({ id: `wh-${w.id}`, severity: 'critical', title: `Webhook "${w.name}" is unhealthy`, detail: w.lastError ?? 'Health check failing', link: '/webhook/health', at: w.healthHistory[0]?.at ?? new Date().toISOString() });
  }
  for (const i of integrations.filter((x) => x.credentialStatus === 'INVALID' || x.credentialStatus === 'DISABLED')) {
    alerts.push({ id: `int-${i.id}`, severity: 'warning', title: `Integration "${i.displayName}" is ${i.credentialStatus.toLowerCase()}`, detail: 'Agents cannot use this integration until it is re-enabled or rotated.', link: `/integrations/${i.id}`, at: i.updatedAt });
  }
  const pendingRequests = grantRequests.filter((r) => requestStatus(r) === 'PENDING');
  if (pendingRequests.length) {
    const names = [...new Set(pendingRequests.map((r) => lookups.agents.get(r.agentId) ?? 'An agent'))];
    alerts.push({
      id: 'grant-requests',
      severity: 'warning',
      title: `${pendingRequests.length} agent access request${pendingRequests.length > 1 ? 's' : ''} awaiting approval`,
      detail: `From ${names.join(', ')}. Requests lapse after 24 hours.`,
      link: '/access/requests',
      at: pendingRequests[0]!.createdAt,
    });
  }
  for (const g of grants.filter((x) => effectiveGrantStatus(x) === 'PENDING_APPROVAL')) {
    alerts.push({ id: `grt-${g.id}`, severity: 'info', title: `Grant "${g.name}" awaits approval`, detail: 'A Security Administrator must approve this grant before it becomes active.', link: `/access/grants/${g.id}`, at: g.createdAt });
  }
  const criticalDenials = recent.filter((r) => ['POLICY_DENIED', 'AGENT_UNAUTHENTICATED', 'GRANT_REVOKED', 'AGENT_DISABLED'].includes(r.decisionCode)).slice(0, 3);
  for (const r of criticalDenials) {
    alerts.push({ id: `req-${r.id}`, severity: 'warning', title: `${r.agentName}: ${r.decisionCode.replace(/_/g, ' ').toLowerCase()}`, detail: r.decisionReason, link: `/audit/access-logs?request=${r.id}`, at: r.createdAt });
  }

  const summary: DashboardSummary = {
    counts: {
      connectedIntegrations: integrations.filter((i) => i.credentialStatus === 'CONNECTED').length,
      registeredAgents: agents.length,
      activeGrants: grants.filter((g) => effectiveGrantStatus(g) === 'ACTIVE').length,
      requests24h: recent.length,
      denied24h: recent.filter((r) => r.decision === 'DENY').length,
    },
    webhook: { status: primary?.status ?? 'NOT_CONFIGURED', name: primary?.name ?? null, lastHeartbeatAt: primary?.lastHeartbeatAt ?? null, count: webhooks.length },
    hourly,
    recentActivity: latest,
    integrations: integrations.map((i) => ({ id: i.id, displayName: i.displayName, provider: i.provider, credentialStatus: i.credentialStatus, environment: i.environment, lastValidatedAt: i.lastValidatedAt })),
    agentActivity: agents.map((a) => {
      const mine = recent.filter((r) => r.agentId === a.id);
      return { agentId: a.id, agentName: a.name, status: a.status, requests24h: mine.length, denied24h: mine.filter((r) => r.decision === 'DENY').length, lastAccessAt: a.lastAccessAt };
    }),
    alerts: alerts.sort((a, b) => b.at.localeCompare(a.at)).slice(0, 6),
    expiringGrants: grants
      .map((g) => toGrant(g, lookups))
      .filter((g) => (g.status === 'ACTIVE' || g.status === 'PENDING_APPROVAL') && new Date(g.expiresAt).getTime() - now < 7 * 86400e3 + 3600e3)
      .sort((a, b) => a.expiresAt.localeCompare(b.expiresAt))
      .map((g) => ({ id: g.id, name: g.name, agentName: g.agentName, integrationName: g.integrationName, expiresAt: g.expiresAt, status: g.status })),
    setup: {
      webhook: webhooks.some((w) => w.verifiedAt),
      integration: integrations.length > 0,
      agent: agents.length > 0,
      grant: grants.length > 0,
      request: anyRequests,
    },
  };
  res.json(summary);
});
