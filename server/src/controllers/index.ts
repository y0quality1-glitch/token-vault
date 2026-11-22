import { AccessRequestController } from './accessRequestController/accessRequestController.controller';
import { AccessReviewController } from './accessReviewController/accessReviewController.controller';
import { AgentController } from './agentController/agentController.controller';
import { agentControllers } from './agentApi/agentApi.controller';
import { APIHealthCheckController } from './apiHealthController/apiHealthController.controller';
import { ApiClientController } from './apiClientController/apiClientController.controller';
import { ApprovalController } from './approvalController/approvalController.controller';
import { AuditEventController } from './auditEventController/auditEventController.controller';
import { AuthController } from './authController/authController.controller';
import type { BaseController } from './baseController';
import { DashboardController } from './dashboardController/dashboardController.controller';
import { DelegationController } from './delegationController/delegationController.controller';
import { DemoController } from './demoController/demoController.controller';
import { GrantController } from './grantController/grantController.controller';
import { GrantRequestController } from './grantRequestController/grantRequestController.controller';
import { IntegrationController } from './integrationController/integrationController.controller';
import { MemberController } from './memberController/memberController.controller';
import { OrganizationController } from './organizationController/organizationController.controller';
import { PolicyController } from './policyController/policyController.controller';
import { ProviderController } from './providerController/providerController.controller';
import { SessionController } from './sessionController/sessionController.controller';
import { SlackSettingsController } from './slackSettingsController/slackSettingsController.controller';
import { UserIssuerController } from './userIssuerController/userIssuerController.controller';
import { WebhookController } from './webhookController/webhookController.controller';

/** Admin API controllers, mounted under PATH (/api/v1). Register new modules here and in APP_ROUTES. */
export const adminControllers = (): BaseController[] => [
  new APIHealthCheckController(),
  new AuthController(),
  new OrganizationController(),
  new MemberController(),
  new DashboardController(),
  new WebhookController(),
  new ProviderController(),
  new IntegrationController(),
  new AgentController(),
  new ApiClientController(),
  new GrantController(),
  new GrantRequestController(),
  new ApprovalController(),
  new AccessReviewController(),
  new PolicyController(),
  new UserIssuerController(),
  new DelegationController(),
  new SessionController(),
  new SlackSettingsController(),
  new AccessRequestController(),
  new AuditEventController(),
  new DemoController(),
];

/** Agent API controllers, mounted under AGENT_PATH (/agent/v1). */
export { agentControllers };
