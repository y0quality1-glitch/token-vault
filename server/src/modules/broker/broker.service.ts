import { z } from 'zod';
import {
  DECISION_CODES,
  getOperation,
  type AccessRequest,
  type DecisionCheck,
  type AgentCapabilitiesBody,
  type CredentialUseInfo,
  type ExecuteResponseBody,
  type MatchedRule,
} from '@token-vault/shared';
import { config } from '../../config';
import { parseAgentCredential, verifySecret } from '../../lib/crypto';
import { correlationId as newCorrelationId, nonce, requestId as newRequestId } from '../../lib/ids';
import { transaction } from '../../db/client';
import { agentRepo, auditRepo, grantRepo, integrationRepo, orgRepo, policyRepo, webhookRepo } from '../../store/repos';
import type { AgentRecord, GrantRecord, IntegrationRecord } from '../../store/types';
import { effectiveGrantStatus } from '../../store/views';
import { recordAccessRequest, recordEvent } from '../audit/audit.service';
import { CHECK_NAMES, evaluate, skippedChecks } from '../policy-engine/engine';
import { WebhookUnavailableError, callWebhook } from '../webhooks/webhook.client';

/**
 * Credential Broker. Authenticates the agent from its own credential, runs the
 * deterministic policy engine, and on ALLOW sends a signed short-lived execution
 * request to the customer webhook, which injects the credential upstream.
 * The control plane never sees the provider secret in this flow.
 */

const bodySchema = z.object({
  integration_id: z.string().min(1).max(64),
  operation: z.string().min(1).max(80),
  resource: z.object({ repository: z.string().max(140).optional(), path: z.string().max(240).optional() }).default({}),
  input: z.record(z.unknown()).default({}),
  idempotency_key: z.string().min(1).max(128).optional(),
});

// ---------------------------------------------------------------- rate limit + idempotency (in-memory)
const hits = new Map<string, number[]>();
function recentRequests(grantId: string, now = Date.now()): number {
  const list = (hits.get(grantId) ?? []).filter((t) => t > now - 60_000);
  hits.set(grantId, list);
  return list.length;
}
function recordHit(grantId: string) {
  hits.set(grantId, [...(hits.get(grantId) ?? []), Date.now()]);
}

const idempotency = new Map<string, { at: number; status: number; body: ExecuteResponseBody }>();
function idemKey(agentId: string, key: string) {
  return `${agentId}:${key}`;
}

export function resetBrokerState() {
  hits.clear();
  idempotency.clear();
}

// ---------------------------------------------------------------- main entry point
export interface ExecuteContext {
  authorization: string | undefined;
  orgHint: string | undefined;
  sourceIp: string;
  source: 'agent-api' | 'playground';
  body: unknown;
}

export async function executeAgentRequest(ctx: ExecuteContext): Promise<{ status: number; body: ExecuteResponseBody }> {
  const started = Date.now();
  const requestId = newRequestId();
  const correlationId = newCorrelationId();

  const respond = async (args: {
    status: number;
    orgId: string | null;
    agent: AgentRecord | null;
    integration: IntegrationRecord | null;
    grant: GrantRecord | null;
    operation: string;
    resource: Record<string, string>;
    decision: 'ALLOW' | 'DENY';
    code: string;
    reason: string;
    matchedRule: MatchedRule | null;
    checks: DecisionCheck[];
    executionStatus: AccessRequest['executionStatus'];
    webhookStatus: string;
    upstreamStatus: number | null;
    result: unknown;
    simulated?: boolean;
    credential?: CredentialUseInfo | null;
    idempotencyKey: string | null;
  }) => {
    const durationMs = Date.now() - started;
    const body: ExecuteResponseBody = {
      request_id: requestId,
      correlation_id: correlationId,
      decision: args.decision,
      decision_code: args.code,
      reason: args.reason,
      matched_rule: args.matchedRule,
      grant_id: args.grant?.id ?? null,
      execution: {
        status: args.executionStatus,
        webhook_status: args.webhookStatus,
        upstream_status: args.upstreamStatus,
        duration_ms: durationMs,
        simulated: args.simulated ?? true,
        idempotent_replay: false,
        credential: args.credential ?? null,
      },
      result: args.result,
      checks: args.checks,
    };
    // Every decision is audited (when the organization can be attributed).
    if (args.orgId) {
      const orgId = args.orgId;
      const failed = args.executionStatus === 'FAILED';
      // The access record and its audit event are committed together.
      await transaction(async (tx) => {
        await recordAccessRequest({
          id: requestId,
          organizationId: orgId,
          agentId: args.agent?.id ?? null,
          agentName: args.agent?.name ?? 'Unknown agent',
          integrationId: args.integration?.id ?? null,
          integrationName: args.integration?.displayName ?? '—',
          grantId: args.grant?.id ?? null,
          grantName: args.grant?.name ?? null,
          operation: args.operation,
          resource: args.resource,
          decision: args.decision,
          decisionCode: args.code,
          decisionReason: args.reason,
          matchedRule: args.matchedRule,
          executionStatus: args.executionStatus,
          upstreamStatusCode: args.upstreamStatus,
          webhookStatus: args.webhookStatus,
          durationMs,
          correlationId,
          sourceIp: ctx.sourceIp,
          source: ctx.source,
          idempotencyKey: args.idempotencyKey,
          checks: args.checks,
          createdAt: new Date().toISOString(),
        }, tx);
        await recordEvent({
          orgId,
          actor: args.agent ? { type: 'AGENT', id: args.agent.id, name: args.agent.name } : { type: 'AGENT', id: 'unknown', name: 'Unknown agent' },
          eventType: args.decision === 'DENY' ? 'access.denied' : failed ? 'access.execution_failed' : 'access.allowed',
          target: args.integration ? { type: 'integration', id: args.integration.id, name: args.integration.displayName } : { type: 'integration', id: 'unknown', name: '—' },
          outcome: args.decision === 'DENY' ? 'DENIED' : failed ? 'FAILURE' : 'SUCCESS',
          severity: args.decision === 'ALLOW' && !failed ? 'info' : ['AGENT_UNAUTHENTICATED', 'POLICY_DENIED', 'AGENT_DISABLED', 'GRANT_REVOKED'].includes(args.code) ? 'critical' : 'warning',
          metadata: { requestId, operation: args.operation, ...args.resource, decisionCode: args.code, grantId: args.grant?.id ?? null, upstreamStatus: args.upstreamStatus, ...(args.credential ? { credential: args.credential } : {}) },
          correlationId,
        }, tx);
      });
    }
    return { status: args.status, body };
  };

  const base = { grant: null, matchedRule: { type: 'default', name: 'Deny by default' } as MatchedRule, executionStatus: 'NOT_EXECUTED' as const, webhookStatus: 'NOT_CALLED', upstreamStatus: null, result: null, idempotencyKey: null };
  const rawBody = (ctx.body && typeof ctx.body === 'object' ? ctx.body : {}) as Record<string, any>;
  const opGuess = typeof rawBody.operation === 'string' ? rawBody.operation.slice(0, 80) : '(missing)';
  const resGuess: Record<string, string> = typeof rawBody.resource?.repository === 'string' ? { repository: rawBody.resource.repository.slice(0, 140) } : {};

  // ---- Step 1: authenticate the caller from its credential (never from a caller-supplied agent id)
  const token = /^Bearer\s+(\S+)$/i.exec(ctx.authorization ?? '')?.[1] ?? '';
  const parsed = parseAgentCredential(token);
  const agent = parsed ? await agentRepo.findAgentByKeyId(parsed.keyId) : null;
  const authenticated = !!agent && verifySecret(token, agent.credentialHash);
  if (!authenticated) {
    // Attribute to an org only for audit visibility: the key's org if the key id is known, else the non-authoritative hint.
    const orgId = agent?.organizationId ?? (ctx.orgHint ? (await orgRepo.findOrganizationBySlug(ctx.orgHint))?.id ?? null : null);
    const reason = !token ? 'Missing agent credential (Authorization: Bearer tvak_...).' : 'Agent credential is invalid, rotated or unknown.';
    return respond({
      ...base,
      status: 401,
      orgId,
      agent: null,
      integration: null,
      operation: opGuess,
      resource: resGuess,
      decision: 'DENY',
      code: DECISION_CODES.AGENT_UNAUTHENTICATED,
      reason,
      checks: [{ step: 1, name: CHECK_NAMES[0], passed: false, detail: reason }, ...skippedChecks(2)],
    });
  }
  await agentRepo.updateAgent(agent.id, { lastAccessAt: new Date().toISOString() });
  const orgId = agent.organizationId;
  const authCheck: DecisionCheck = { step: 1, name: CHECK_NAMES[0], passed: true, detail: `Authenticated as ${agent.name} (${agent.id}) from credential` };

  // ---- Request validation (malformed requests are denied and audited)
  const parsedBody = bodySchema.safeParse(ctx.body);
  if (!parsedBody.success) {
    const reason = 'Malformed request: ' + parsedBody.error.issues.map((i) => `${i.path.join('.') || 'body'} ${i.message.toLowerCase()}`).join('; ');
    return respond({ ...base, status: 400, orgId, agent, integration: null, operation: opGuess, resource: resGuess, decision: 'DENY', code: DECISION_CODES.MALFORMED_REQUEST, reason, checks: [authCheck, ...skippedChecks(2)] });
  }
  const req = parsedBody.data;
  const resource: Record<string, string> = {};
  if (req.resource.repository) resource.repository = req.resource.repository;
  if (req.resource.path) resource.path = req.resource.path;

  const operation = getOperation(req.operation);
  if (!operation) {
    return respond({ ...base, status: 400, orgId, agent, integration: null, operation: req.operation, resource, decision: 'DENY', code: DECISION_CODES.UNKNOWN_OPERATION, reason: `Unknown operation "${req.operation}".`, checks: [authCheck, ...skippedChecks(2)] });
  }
  if (operation.requiresRepository && !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(req.resource.repository ?? '')) {
    return respond({ ...base, status: 400, orgId, agent, integration: null, operation: req.operation, resource, decision: 'DENY', code: DECISION_CODES.MALFORMED_REQUEST, reason: 'Malformed request: resource.repository must be in owner/repository format.', checks: [authCheck, ...skippedChecks(2)] });
  }

  // Integration lookup is org-scoped: an agent can never address another organization's integration.
  const integration = await integrationRepo.getIntegration(orgId, req.integration_id);
  if (!integration) {
    return respond({ ...base, status: 404, orgId, agent, integration: null, operation: operation.id, resource, decision: 'DENY', code: DECISION_CODES.INTEGRATION_NOT_FOUND, reason: `Integration "${req.integration_id}" does not exist in this organization.`, checks: [authCheck, ...skippedChecks(2)] });
  }

  // ---- Steps 2-10: deterministic policy evaluation (current state, every request)
  // Fresh reads on every request: revocation, expiry and policy edits apply immediately.
  const [pairGrants, orgPolicies] = await Promise.all([grantRepo.grantsForPair(orgId, agent.id, integration.id), policyRepo.listPolicies(orgId)]);
  const evaluation = evaluate({
    agent,
    integration,
    grants: pairGrants,
    policies: orgPolicies,
    operation,
    resource: req.resource,
    sourceIp: ctx.sourceIp,
    now: Date.now(),
    recentRequests: (id) => recentRequests(id),
  });
  evaluation.checks[0] = authCheck;

  if (evaluation.decision === 'DENY') {
    const status = evaluation.code === DECISION_CODES.RATE_LIMITED ? 429 : 403;
    return respond({ ...base, status, orgId, agent, integration, grant: evaluation.grant, operation: operation.id, resource, decision: 'DENY', code: evaluation.code, reason: evaluation.reason, matchedRule: evaluation.matchedRule, checks: evaluation.checks, idempotencyKey: req.idempotency_key ?? null });
  }

  const grant = evaluation.grant!;
  recordHit(grant.id);
  await grantRepo.recordGrantUse(grant.id);

  // Idempotency is honoured only AFTER authorization, so a revoked grant cannot replay a cached success.
  if (req.idempotency_key) {
    const cached = idempotency.get(idemKey(agent.id, req.idempotency_key));
    if (cached && cached.at > Date.now() - 24 * 3600e3) {
      return { status: cached.status, body: { ...cached.body, execution: { ...cached.body.execution, idempotent_replay: true } } };
    }
  }

  const allowArgs = { orgId, agent, integration, grant, operation: operation.id, resource, decision: 'ALLOW' as const, matchedRule: evaluation.matchedRule, checks: evaluation.checks, idempotencyKey: req.idempotency_key ?? null };

  // ---- Broker: signed, short-lived execution request to the customer webhook
  const webhook = await webhookRepo.getWebhook(orgId, integration.webhookId);
  if (!webhook || !webhook.instanceId) {
    return respond({ ...allowArgs, status: 503, code: DECISION_CODES.WEBHOOK_UNAVAILABLE, reason: 'Authorized, but no verified customer webhook is configured for this integration. No credential was used.', executionStatus: 'FAILED', webhookStatus: 'NOT_CONFIGURED', upstreamStatus: null, result: null });
  }
  const iat = Date.now();
  const claims = {
    request_id: requestId,
    correlation_id: correlationId,
    iat,
    exp: iat + config.executionTtlMs,
    nonce: nonce(),
    aud: webhook.instanceId,
    org_id: orgId,
    credential_ref: integration.credentialReference,
    operation: operation.id,
    resource: req.resource,
    input: req.input,
  };

  let wh;
  try {
    wh = await callWebhook(webhook, 'POST', '/internal/v1/execute', claims);
  } catch (e) {
    const err = e as WebhookUnavailableError;
    const reasonCode = err instanceof WebhookUnavailableError ? err.reason : 'UNREACHABLE';
    return respond({ ...allowArgs, status: 503, code: DECISION_CODES.WEBHOOK_UNAVAILABLE, reason: `Authorized, but execution failed safely: ${err.message}. No credential was exposed.`, executionStatus: 'FAILED', webhookStatus: reasonCode, upstreamStatus: null, result: null });
  }

  if (wh.status !== 200) {
    return respond({ ...allowArgs, status: 502, code: DECISION_CODES.WEBHOOK_UNAVAILABLE, reason: `Authorized, but the webhook refused execution (${wh.body?.error?.code ?? wh.status}).`, executionStatus: 'FAILED', webhookStatus: wh.body?.error?.code ?? `HTTP_${wh.status}`, upstreamStatus: null, result: null });
  }

  const upstream = Number(wh.body.upstream_status);
  const ok = upstream >= 200 && upstream < 300;
  const out = await respond({
    ...allowArgs,
    status: ok ? 200 : 502,
    code: ok ? DECISION_CODES.ALLOWED : DECISION_CODES.UPSTREAM_ERROR,
    reason: ok ? evaluation.reason : `Authorized, but GitHub returned HTTP ${upstream}${wh.body.result?.message ? ` (${wh.body.result.message})` : ''}.`,
    executionStatus: ok ? 'SUCCEEDED' : 'FAILED',
    webhookStatus: 'OK',
    upstreamStatus: upstream,
    result: wh.body.result ?? null,
    simulated: wh.body.simulated !== false,
    credential: wh.body.credential ?? null,
  });
  if (req.idempotency_key && operation.mutating && ok) {
    idempotency.set(idemKey(agent.id, req.idempotency_key), { at: Date.now(), status: out.status, body: out.body });
  }
  return out;
}

/** Resolves the agent from its own credential (the only source of agent identity). */
export async function authenticate(authorization: string | undefined): Promise<AgentRecord | null> {
  const token = /^Bearer\s+(\S+)$/i.exec(authorization ?? '')?.[1] ?? '';
  const parsed = parseAgentCredential(token);
  const agent = parsed ? await agentRepo.findAgentByKeyId(parsed.keyId) : null;
  return agent && verifySecret(token, agent.credentialHash) ? agent : null;
}

/** Agents may look up only their own requests. */
export async function getOwnRequest(authorization: string | undefined, id: string) {
  const agent = await authenticate(authorization);
  if (!agent) return { status: 401 as const };
  const r = await auditRepo.getAccessRequestForAgent(agent.id, id);
  if (!r) return { status: 404 as const };
  return { status: 200 as const, body: r };
}

/**
 * The calling agent's own grants, with their current status (superseded versions omitted),
 * so agent tooling can tell a model which integrations, operations and repositories it
 * may use. Revoked and expired grants stay listed: tooling then still sends the request,
 * and /execute returns (and audits) the authoritative denial. Read-only; reveals nothing
 * about other agents.
 */
export async function getCapabilities(authorization: string | undefined): Promise<{ status: 200; body: AgentCapabilitiesBody } | { status: 401 }> {
  const agent = await authenticate(authorization);
  if (!agent) return { status: 401 };
  const [org, grants, integrations] = await Promise.all([
    orgRepo.getOrganization(agent.organizationId),
    grantRepo.listGrants(agent.organizationId, { agentId: agent.id }),
    integrationRepo.listIntegrations(agent.organizationId),
  ]);
  const byId = new Map(integrations.map((i) => [i.id, i]));
  const visible = grants.filter((g) => g.storedStatus !== 'SUPERSEDED' && byId.has(g.integrationId));
  return {
    status: 200,
    body: {
      agent: { id: agent.id, name: agent.name, status: agent.status, organization: org?.slug ?? '' },
      grants: visible.map((g) => {
        const i = byId.get(g.integrationId)!;
        return {
          grant_id: g.id,
          name: g.name,
          status: effectiveGrantStatus(g),
          integration_id: i.id,
          integration_name: i.displayName,
          provider: i.provider,
          integration_available: i.credentialStatus === 'CONNECTED',
          operations: g.scopes,
          repositories: g.resourceConstraints.repositories,
          rate_limit_per_minute: g.rateLimitPerMinute,
          valid_from: g.validFrom,
          expires_at: g.expiresAt,
        };
      }),
    },
  };
}
