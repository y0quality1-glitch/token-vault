/** Every entity of the control plane, registered explicitly in the DataSource (template fix B-04). */
import { OrganizationEntity } from './organizationEntity';
import { UserEntity } from './userEntity';
import { OrganizationMemberEntity } from './organizationMemberEntity';
import { UserLoginsEntity } from './userLoginsEntity';
import { WebhookEntity } from './webhookEntity';
import { IntegrationEntity } from './integrationEntity';
import { AgentEntity } from './agentEntity';
import { GrantEntity } from './grantEntity';
import { PolicyEntity } from './policyEntity';
import { AccessRequestEntity } from './accessRequestEntity';
import { AuditEventEntity } from './auditEventEntity';
import { GrantRequestEntity } from './grantRequestEntity';
import { OperationApprovalEntity } from './operationApprovalEntity';
import { ProviderCatalogStateEntity } from './providerCatalogStateEntity';
import { OauthPendingEntity } from './oauthPendingEntity';
import { UserIssuerEntity } from './userIssuerEntity';
import { DelegationEntity } from './delegationEntity';
import { SlackSettingsEntity } from './slackSettingsEntity';

export const ENTITIES = [OrganizationEntity, UserEntity, OrganizationMemberEntity, UserLoginsEntity, WebhookEntity, IntegrationEntity, AgentEntity, GrantEntity, PolicyEntity, AccessRequestEntity, AuditEventEntity, GrantRequestEntity, OperationApprovalEntity, ProviderCatalogStateEntity, OauthPendingEntity, UserIssuerEntity, DelegationEntity, SlackSettingsEntity];

export { OrganizationEntity, UserEntity, OrganizationMemberEntity, UserLoginsEntity, WebhookEntity, IntegrationEntity, AgentEntity, GrantEntity, PolicyEntity, AccessRequestEntity, AuditEventEntity, GrantRequestEntity, OperationApprovalEntity, ProviderCatalogStateEntity, OauthPendingEntity, UserIssuerEntity, DelegationEntity, SlackSettingsEntity };
