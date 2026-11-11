import { z } from 'zod';
import {
  DECISION_CODES,
  type AccessRequest,
  type DecisionCheck,
  type AgentCapabilitiesBody,
  type AgentOperationsBody,
  type CredentialUseInfo,
  type ExecuteResponseBody,
  type MatchedRule,
} from '@token-vault/shared';
import { config } from '../../config';
import { getOperation, registry } from '../providers/registry';
import { isCredentialRejection, reportCredentialRejected } from '../integrations/credential-health';
import { parseAgentCredential, verifySecret } from '../../lib/crypto';
import { correlationId as newCorrelationId, nonce, requestId as newRequestId } from '../../lib/ids';
import { transaction } from '../../db/client';
import { agentRepo, approvalRepo, auditRepo, grantRepo, integrationRepo, orgRepo, policyRepo, webhookRepo } from '../../store/repos';
import { APPROVAL_LIMITS, approvalSummary, createPending, lookupApproval, requestDigest } from '../approvals/approvals.service';
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
  // Field names come from the provider definition (e.g. repository + path for GitHub).
  resource: z
    .record(z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]{0,39}$/), z.string().max(500))
    .refine((r) => Object.keys(r).length <= 10, 'too many resource fields')
    .default({}),
  input: z.record(z.unknown()).default({}),
  idempotency_key: z.string().min(1).max(128).optional(),
  approval_id: z.string().min(1).max(64).optional(),
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
  /** Called with the expiry when the caller used a rotated key during its grace period. */
  onPreviousKey?: (expiresAt: string) => void;
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
    approval?: ExecuteResponseBody['approval'];
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
      ...(args.approval ? { approval: args.approval } : {}),
    };
    const waiting = args.code === DECISION_CODES.APPROVAL_REQUIRED;
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
          eventType: waiting ? 'access.approval_required' : args.decision === 'DENY' ? 'access.denied' : failed ? 'access.execution_failed' : 'access.allowed',
          target: args.integration ? { type: 'integration', id: args.integration.id, name: args.integration.displayName } : { type: 'integration', id: 'unknown', name: '—' },
          outcome: args.decision === 'DENY' ? 'DENIED' : failed ? 'FAILURE' : 'SUCCESS',
          severity: (args.decision === 'ALLOW' && !failed) || waiting ? 'info' : ['AGENT_UNAUTHENTICATED', 'POLICY_DENIED', 'AGENT_DISABLED', 'GRANT_REVOKED', 'EMERGENCY_STOP'].includes(args.code) ? 'critical' : 'warning',
          metadata: { requestId, operation: args.operation, ...args.resource, decisionCode: args.code, grantId: args.grant?.id ?? null, upstreamStatus: args.upstreamStatus, ...(args.credential ? { credential: args.credential } : {}), ...(args.approval ? { approvalId: args.approval.approval_id } : {}) },
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
  const verified = await verifyAgentKey(token);
  const agent = verified.agent;
  if (!verified.ok || !agent) {
    // Attribute to an org only for audit visibility: the key's org if the key id is known, else the non-authoritative hint.
    const orgId = agent?.organizationId ?? (ctx.orgHint ? (await orgRepo.findOrganizationBySlug(ctx.orgHint))?.id ?? null : null);
    const reason = !token ? 'Missing agent credential (Authorization: Bearer tvak_...).' : (verified.reason ?? 'Agent credential is invalid, rotated or unknown.');
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
  if (verified.previousKeyExpiresAt) ctx.onPreviousKey?.(verified.previousKeyExpiresAt);
  const orgId = agent.organizationId;
  const authCheck: DecisionCheck = {
    step: 1,
    name: CHECK_NAMES[0],
    passed: true,
    detail: `Authenticated as ${agent.name} (${agent.id}) from credential${verified.previousKeyExpiresAt ? `; this key was rotated and stops working at ${verified.previousKeyExpiresAt}` : ''}`,
  };

  // ---- Request validation (malformed requests are denied and audited)
  const parsedBody = bodySchema.safeParse(ctx.body);
  if (!parsedBody.success) {
    const reason = 'Malformed request: ' + parsedBody.error.issues.map((i) => `${i.path.join('.') || 'body'} ${i.message.toLowerCase()}`).join('; ');
    return respond({ ...base, status: 400, orgId, agent, integration: null, operation: opGuess, resource: resGuess, decision: 'DENY', code: DECISION_CODES.MALFORMED_REQUEST, reason, checks: [authCheck, ...skippedChecks(2)] });
  }
  const req = parsedBody.data;
  const resource: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.resource)) if (v) resource[k] = v;

  const operation = getOperation(req.operation);
  if (!operation) {
    return respond({ ...base, status: 400, orgId, agent, integration: null, operation: req.operation, resource, decision: 'DENY', code: DECISION_CODES.UNKNOWN_OPERATION, reason: `Unknown operation "${req.operation}".`, checks: [authCheck, ...skippedChecks(2)] });
  }
  // The primary resource (what grants are scoped to) is named by the provider definition.
  const primary = resource[operation.resourceName] ?? '';
  if (operation.requiresRepository && !new RegExp(operation.resourcePattern).test(primary)) {
    const example = operation.resourceName === 'repository' ? ' in owner/repository format' : ` matching ${operation.resourcePattern}`;
    return respond({ ...base, status: 400, orgId, agent, integration: null, operation: req.operation, resource, decision: 'DENY', code: DECISION_CODES.MALFORMED_REQUEST, reason: `Malformed request: resource.${operation.resourceName} must be${example}.`, checks: [authCheck, ...skippedChecks(2)] });
  }

  // Integration lookup is org-scoped: an agent can never address another organization's integration.
  const integration = await integrationRepo.getIntegration(orgId, req.integration_id);
  if (!integration) {
    return respond({ ...base, status: 404, orgId, agent, integration: null, operation: operation.id, resource, decision: 'DENY', code: DECISION_CODES.INTEGRATION_NOT_FOUND, reason: `Integration "${req.integration_id}" does not exist in this organization.`, checks: [authCheck, ...skippedChecks(2)] });
  }
  if (integration.provider !== operation.provider) {
    return respond({ ...base, status: 400, orgId, agent, integration, operation: operation.id, resource, decision: 'DENY', code: DECISION_CODES.UNKNOWN_OPERATION, reason: `Operation "${operation.id}" belongs to ${operation.provider}, but integration "${integration.displayName}" is ${integration.provider}.`, checks: [authCheck, ...skippedChecks(2)] });
  }

  // ---- Human approval (REQUIRE_APPROVAL policies): find the approval for exactly this request.
  const shape = { integrationId: integration.id, operation: operation.id, resource, input: req.input };
  const digest = requestDigest(shape);
  const approval = await lookupApproval(agent, digest, req.approval_id);
  if (approval.kind === 'invalid') {
    return respond({ ...base, status: 409, orgId, agent, integration, operation: operation.id, resource, decision: 'DENY', code: DECISION_CODES.APPROVAL_INVALID, reason: approval.reason, checks: [authCheck, ...skippedChecks(2)], idempotencyKey: req.idempotency_key ?? null, approval: approval.record ? approvalSummary(approval.record) : null });
  }

  // ---- Steps 2-11: deterministic policy evaluation (current state, every request)
  // Fresh reads on every request: revocation, expiry and policy edits apply immediately.
  const [pairGrants, orgPolicies, org] = await Promise.all([grantRepo.grantsForPair(orgId, agent.id, integration.id), policyRepo.listPolicies(orgId), orgRepo.getOrganization(orgId)]);
  const usage = await budgetUsageFor(pairGrants);
  const evaluation = evaluate({
    agent,
    integration,
    grants: pairGrants,
    policies: orgPolicies,
    operation,
    resource: { repository: primary || undefined },
    sourceIp: ctx.sourceIp,
    now: Date.now(),
    recentRequests: (id) => recentRequests(id),
    approval: approval.kind === 'approved' ? { id: approval.record.id, approvedBy: approval.approvedBy } : null,
    request: { resource, input: req.input },
    organization: org,
    budgetUsage: (id) => usage.get(id) ?? { requestsLast24h: 0, writesLastHour: 0 },
  });
  evaluation.checks[0] = authCheck;

  // Every other check allows the request, but a human must approve it first.
  if (evaluation.code === DECISION_CODES.APPROVAL_REQUIRED && evaluation.approvalPolicy) {
    const held = { ...base, orgId, agent, integration, grant: evaluation.grant, operation: operation.id, resource, decision: 'DENY' as const, matchedRule: evaluation.matchedRule, checks: evaluation.checks, idempotencyKey: req.idempotency_key ?? null };
    if (approval.kind === 'rejected') {
      const note = approval.record.decisionNote ? ` Note: "${approval.record.decisionNote}"` : '';
      return respond({ ...held, status: 403, code: DECISION_CODES.APPROVAL_REJECTED, reason: `A human rejected this request (approval ${approval.record.id}).${note}`, approval: approvalSummary(approval.record) });
    }
    const pending = approval.kind === 'pending' ? approval.record : await createPending({ agent, integration, policy: evaluation.approvalPolicy, request: shape, digest, requestId, correlationId });
    if (!pending) {
      return respond({ ...held, status: 429, code: DECISION_CODES.RATE_LIMITED, reason: `This agent already has ${APPROVAL_LIMITS.MAX_PENDING} requests waiting for approval; wait for decisions before sending more.` });
    }
    return respond({ ...held, status: 202, code: DECISION_CODES.APPROVAL_REQUIRED, reason: `${evaluation.reason} Approval ${pending.id} is waiting for a human (until ${pending.expiresAt}); once approved, send the same request again.`, approval: approvalSummary(pending) });
  }

  if (evaluation.decision === 'DENY') {
    const status = evaluation.code === DECISION_CODES.RATE_LIMITED || evaluation.code === DECISION_CODES.BUDGET_EXCEEDED ? 429 : 403;
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

  // An approval runs exactly one request: claim it before any credential is used.
  let usedApproval: ExecuteResponseBody['approval'] = null;
  if (approval.kind === 'approved') {
    const consumed = await approvalRepo.consumeApproval(approval.record.id, requestId, new Date().toISOString());
    if (!consumed) {
      return respond({ ...base, status: 409, orgId, agent, integration, grant, operation: operation.id, resource, decision: 'DENY', code: DECISION_CODES.APPROVAL_INVALID, reason: `Approval ${approval.record.id} was used by another request at the same time. Each approval runs one request.`, matchedRule: evaluation.matchedRule, checks: evaluation.checks, idempotencyKey: req.idempotency_key ?? null });
    }
    usedApproval = approvalSummary(consumed);
  }

  const allowArgs = { orgId, agent, integration, grant, operation: operation.id, resource, decision: 'ALLOW' as const, matchedRule: evaluation.matchedRule, checks: evaluation.checks, idempotencyKey: req.idempotency_key ?? null, approval: usedApproval };

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
    // The webhook runs a destructive operation only for a request a human approved (and only if its operator allows them).
    ...(usedApproval ? { approval_id: usedApproval.approval_id } : {}),
  };

  let wh;
  try {
    wh = await callWebhook(webhook, 'POST', '/internal/v1/execute', claims);
  } catch (e) {
    const err = e as WebhookUnavailableError;
    const reasonCode = err instanceof WebhookUnavailableError ? err.reason : 'UNREACHABLE';
    return respond({ ...allowArgs, status: 503, code: DECISION_CODES.WEBHOOK_UNAVAILABLE, reason: `Authorized, but execution failed safely: ${err.message}. No credential was exposed.`, executionStatus: 'FAILED', webhookStatus: reasonCode, upstreamStatus: null, result: null });
  }

  const providerName = registry.get(integration.provider)?.name ?? integration.provider;
  // The provider no longer accepts the stored credential: mark the integration invalid
  // (later requests are denied until a test passes) and say so in this response.
  const rejection = { upstreamStatus: wh.status === 200 ? Number(wh.body.upstream_status) : null, errorCode: wh.status === 200 ? null : (wh.body?.error?.code ?? null), errorUpstreamStatus: wh.status === 200 ? null : (wh.body?.error?.upstream_status ?? null) };
  const rejected = isCredentialRejection(rejection) ? await reportCredentialRejected(integration, 'agent_request', { ...rejection, requestId }).then(() => true) : false;
  const rejectedNote = rejected ? ` ${providerName} rejected the stored credential; the integration "${integration.displayName}" is now marked invalid until an administrator rotates or re-tests it.` : '';

  if (wh.status !== 200) {
    const destructiveNote = operation.destructive && wh.body?.error?.code === 'UNSUPPORTED_OPERATION' ? ' The customer webhook does not run destructive operations; its operator can allow them with WEBHOOK_ALLOW_DESTRUCTIVE=true.' : '';
    return respond({ ...allowArgs, status: 502, code: DECISION_CODES.WEBHOOK_UNAVAILABLE, reason: `Authorized, but the webhook refused execution (${wh.body?.error?.code ?? wh.status}).${destructiveNote}${rejectedNote}`, executionStatus: 'FAILED', webhookStatus: wh.body?.error?.code ?? `HTTP_${wh.status}`, upstreamStatus: null, result: null });
  }

  const upstream = Number(wh.body.upstream_status);
  const ok = upstream >= 200 && upstream < 300;
  const out = await respond({
    ...allowArgs,
    status: ok ? 200 : 502,
    code: ok ? DECISION_CODES.ALLOWED : DECISION_CODES.UPSTREAM_ERROR,
    reason: ok ? evaluation.reason : `Authorized, but ${providerName} returned HTTP ${upstream}${wh.body.result?.message ? ` (${wh.body.result.message})` : ''}.${rejectedNote}`,
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

/** Budget usage of the grants that have budgets (two small grouped queries each; none without budgets). */
export async function budgetUsageFor(grants: GrantRecord[]): Promise<Map<string, { requestsLast24h: number; writesLastHour: number }>> {
  const now = Date.now();
  const withBudgets = grants.filter((g) => g.storedStatus === 'ACTIVE' && (g.maxRequestsPerDay || g.maxWritesPerHour));
  const entries = await Promise.all(
    withBudgets.map(async (g) => {
      const [day, hour] = await Promise.all([
        g.maxRequestsPerDay ? auditRepo.authorizedByOperationSince(g.id, new Date(now - 24 * 3600e3).toISOString()) : Promise.resolve([]),
        g.maxWritesPerHour ? auditRepo.authorizedByOperationSince(g.id, new Date(now - 3600e3).toISOString()) : Promise.resolve([]),
      ]);
      const requestsLast24h = day.reduce((s, r) => s + Number(r.n), 0);
      // Anything that is not a read counts as a write (unknown operations included: fail closed).
      const writesLastHour = hour.filter((r) => getOperation(r.operation)?.mutating ?? true).reduce((s, r) => s + Number(r.n), 0);
      return [g.id, { requestsLast24h, writesLastHour }] as const;
    }),
  );
  return new Map(entries);
}

/**
 * Checks an agent API key: the agent's current key, or the key replaced by its last
 * rotation while that rotation's grace period lasts (one hash verification either way).
 * `agent` is set whenever the key id is known, for audit attribution, even if the key fails.
 */
export async function verifyAgentKey(token: string): Promise<{ agent: AgentRecord | null; ok: boolean; previousKeyExpiresAt: string | null; reason?: string }> {
  const parsed = parseAgentCredential(token);
  const agent = parsed ? await agentRepo.findAgentByKeyId(parsed.keyId) : null;
  if (!parsed || !agent) return { agent: null, ok: false, previousKeyExpiresAt: null };
  if (agent.credentialKeyId === parsed.keyId) return { agent, ok: verifySecret(token, agent.credentialHash), previousKeyExpiresAt: null };
  const until = agent.previousCredentialExpiresAt;
  if (!agent.previousCredentialHash || !until || Date.parse(until) <= Date.now()) {
    return { agent, ok: false, previousKeyExpiresAt: null, reason: `Agent credential was rotated${until ? ` and its grace period ended at ${until}` : ''}; use the new key.` };
  }
  if (!verifySecret(token, agent.previousCredentialHash)) return { agent, ok: false, previousKeyExpiresAt: null };
  await agentRepo.updateAgent(agent.id, { previousCredentialLastUsedAt: new Date().toISOString() });
  return { agent, ok: true, previousKeyExpiresAt: until };
}

/**
 * Resolves the agent from its own credential (the only source of agent identity).
 * `onPreviousKey` is called with the expiry when the caller used a rotated key in its grace period.
 */
export async function authenticate(authorization: string | undefined, onPreviousKey?: (expiresAt: string) => void): Promise<AgentRecord | null> {
  const token = /^Bearer\s+(\S+)$/i.exec(authorization ?? '')?.[1] ?? '';
  const v = await verifyAgentKey(token);
  if (!v.ok || !v.agent) return null;
  if (v.previousKeyExpiresAt) onPreviousKey?.(v.previousKeyExpiresAt);
  return v.agent;
}

/** Agents may look up only their own requests. */
export async function getOwnRequest(authorization: string | undefined, id: string, onPreviousKey?: (expiresAt: string) => void) {
  const agent = await authenticate(authorization, onPreviousKey);
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
/** Operation shapes for the providers of the agent's grants (for typed agent tools). */
export async function getAgentOperations(authorization: string | undefined, onPreviousKey?: (expiresAt: string) => void): Promise<{ status: 200; body: AgentOperationsBody } | { status: 401 }> {
  const agent = await authenticate(authorization, onPreviousKey);
  if (!agent) return { status: 401 };
  const [grants, integrations] = await Promise.all([grantRepo.listGrants(agent.organizationId, { agentId: agent.id }), integrationRepo.listIntegrations(agent.organizationId)]);
  const byId = new Map(integrations.map((i) => [i.id, i]));
  const keys = [...new Set(grants.filter((g) => g.storedStatus !== 'SUPERSEDED' && byId.has(g.integrationId)).map((g) => byId.get(g.integrationId)!.provider))].sort();
  const entries = keys.flatMap((k) => registry.entry(k) ?? []);
  const field = (name: string, f: { label: string; pattern: string; caseInsensitive: boolean; example?: string }) => ({ name, label: f.label, pattern: f.pattern, case_insensitive: f.caseInsensitive, example: f.example ?? null });
  return {
    status: 200,
    body: {
      version: entries.map((e) => `${e.definition.key}@${e.definition.version}:${e.digest ?? 'bundled'}`).join(','),
      providers: entries.map(({ definition: d }) => ({
        key: d.key,
        name: d.name,
        description: d.description,
        version: d.version,
        resource: field(d.resource.name, d.resource),
        resource_fields: Object.entries(d.resourceFields).map(([n, f]) => field(n, f)),
        operations: d.operations.map((o) => ({
          id: o.id,
          label: o.label,
          description: o.description,
          risk: o.risk,
          requires_resource: o.requiresResource,
          input: Object.entries(o.input).map(([n, f]) => ({ name: n, type: f.type, label: f.label ?? null, required: f.required, max_length: f.maxLength ?? null })),
        })),
      })),
    },
  };
}

export async function getCapabilities(authorization: string | undefined, onPreviousKey?: (expiresAt: string) => void): Promise<{ status: 200; body: AgentCapabilitiesBody } | { status: 401 }> {
  const agent = await authenticate(authorization, onPreviousKey);
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
          max_requests_per_day: g.maxRequestsPerDay ?? null,
          max_writes_per_hour: g.maxWritesPerHour ?? null,
          valid_from: g.validFrom,
          expires_at: g.expiresAt,
        };
      }),
    },
  };
}
