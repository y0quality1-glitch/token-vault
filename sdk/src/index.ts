export { TokenVault, type AccessRequestResult, type DelegateOptions, type DelegationResult, type ExecuteOptions, type ExecuteResult, type GitHubOperation, type RequestAccessOptions, type TokenVaultOptions, type UserTokenSource, type WaitForApprovalOptions } from './client';
export { AccessDeniedError, ApprovalRequiredError, AuthenticationError, ExecutionFailedError, ResponseWithheldError, TokenVaultError } from './errors';
export type { AgentAccessRequestBody, AgentApprovalBody, AgentCapabilitiesBody, AgentDelegationBody, DecisionTokenClaims, ExecuteResponseBody, HandedOffCredential } from '@token-vault/shared';
export { DecisionTokenError, verifyDecisionToken, type VerifyDecisionOptions } from './decision';
