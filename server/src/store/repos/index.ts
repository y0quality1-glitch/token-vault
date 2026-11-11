/**
 * Repository layer: the only code that talks to PostgreSQL. Every org-scoped
 * function takes the organization ID and filters on it (organization isolation).
 * Each function accepts an optional Executor so callers can compose a transaction.
 */
export * as orgRepo from './organizations';
export * as sessionRepo from './sessions';
export * as webhookRepo from './webhooks';
export * as integrationRepo from './integrations';
export * as agentRepo from './agents';
export * as grantRepo from './grants';
export * as policyRepo from './policies';
export * as auditRepo from './audit';
export * as grantRequestRepo from './grant-requests';
export * as approvalRepo from './operation-approvals';
export * as userIssuerRepo from './user-issuers';
export * as delegationRepo from './delegations';
