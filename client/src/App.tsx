import { Route, Routes } from 'react-router-dom';
import { PERMISSIONS } from '@token-vault/shared';
import { AppShell } from '@/components/layout/AppShell';
import { RequireAuth, RequirePermission } from '@/components/guards';
import { LoginPage } from '@/pages/LoginPage';
import { SelectOrgPage } from '@/pages/SelectOrgPage';
import { OverviewPage } from '@/pages/OverviewPage';
import { DemoGuidePage } from '@/pages/DemoGuidePage';
import { NotFoundPage } from '@/pages/NotFoundPage';
import { CatalogPage } from '@/pages/integrations/CatalogPage';
import { ConnectedIntegrationsPage } from '@/pages/integrations/ConnectedIntegrationsPage';
import { CredentialStatusPage } from '@/pages/integrations/CredentialStatusPage';
import { ConnectIntegrationPage } from '@/pages/integrations/ConnectIntegrationPage';
import { IntegrationDetailPage } from '@/pages/integrations/IntegrationDetailPage';
import { AgentRegistryPage } from '@/pages/agents/AgentRegistryPage';
import { AgentDetailPage } from '@/pages/agents/AgentDetailPage';
import { GrantsPage } from '@/pages/access/GrantsPage';
import { CreateGrantPage } from '@/pages/access/CreateGrantPage';
import { GrantDetailPage } from '@/pages/access/GrantDetailPage';
import { PoliciesPage } from '@/pages/access/PoliciesPage';
import { AccessRequestsPage } from '@/pages/access/AccessRequestsPage';
import { ApprovalsPage } from '@/pages/access/ApprovalsPage';
import { AccessReviewsPage } from '@/pages/access/AccessReviewsPage';
import { WebhookSetupPage } from '@/pages/webhook/WebhookSetupPage';
import { WebhookHealthPage } from '@/pages/webhook/WebhookHealthPage';
import { PlaygroundPage } from '@/pages/PlaygroundPage';
import { AccessLogsPage } from '@/pages/audit/AccessLogsPage';
import { SecurityEventsPage } from '@/pages/audit/SecurityEventsPage';
import { OrganizationSettingsPage } from '@/pages/settings/OrganizationSettingsPage';
import { MembersPage } from '@/pages/settings/MembersPage';
import { UserIdentityPage } from '@/pages/settings/UserIdentityPage';
import { ApiClientsPage } from '@/pages/settings/ApiClientsPage';
import { OAuthCallbackPage } from '@/pages/integrations/OAuthCallbackPage';

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/select-org" element={<SelectOrgPage />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<OverviewPage />} />
        <Route path="guide" element={<DemoGuidePage />} />

        <Route path="integrations/catalog" element={<CatalogPage />} />
        <Route path="integrations/connected" element={<ConnectedIntegrationsPage />} />
        <Route path="integrations/credentials" element={<CredentialStatusPage />} />
        <Route path="integrations/connect/:provider" element={<ConnectIntegrationPage />} />
        <Route path="integrations/:id" element={<IntegrationDetailPage />} />
        <Route path="oauth/callback" element={<OAuthCallbackPage />} />

        <Route path="agents" element={<AgentRegistryPage />} />
        <Route path="agents/:id" element={<AgentDetailPage />} />

        <Route path="access/grants" element={<GrantsPage />} />
        <Route path="access/grants/new" element={<CreateGrantPage />} />
        <Route path="access/grants/:id" element={<GrantDetailPage />} />
        <Route path="access/requests" element={<AccessRequestsPage />} />
        <Route path="access/approvals" element={<ApprovalsPage />} />
        <Route path="access/reviews" element={<AccessReviewsPage />} />
        <Route path="access/policies" element={<PoliciesPage />} />

        <Route path="webhook/setup" element={<WebhookSetupPage />} />
        <Route path="webhook/health" element={<WebhookHealthPage />} />

        <Route path="playground" element={<PlaygroundPage />} />

        <Route
          path="audit/access-logs"
          element={
            <RequirePermission permission={PERMISSIONS.AUDIT_READ}>
              <AccessLogsPage />
            </RequirePermission>
          }
        />
        <Route
          path="audit/security-events"
          element={
            <RequirePermission permission={PERMISSIONS.AUDIT_READ}>
              <SecurityEventsPage />
            </RequirePermission>
          }
        />

        <Route path="settings/organization" element={<OrganizationSettingsPage />} />
        <Route path="settings/members" element={<MembersPage />} />
        <Route path="settings/api-clients" element={<ApiClientsPage />} />
        <Route path="settings/user-identity" element={<UserIdentityPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
