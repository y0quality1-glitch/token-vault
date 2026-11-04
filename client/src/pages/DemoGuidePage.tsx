import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, RotateCcw } from 'lucide-react';
import { PERMISSIONS } from '@token-vault/shared';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader } from '@/components/ui/card';
import { Callout } from '@/components/ui/feedback';
import { ConfirmDialog } from '@/components/ui/dialog';
import { PageHeader } from '@/components/ui/navigation';
import { useToast } from '@/components/ui/toast';
import { TrustBoundary } from '@/components/TrustBoundary';

const SCRIPT: { step: string; to?: string; tip?: string }[] = [
  { step: 'Sign in as Organization Owner (owner@demo.test).', to: '/login', tip: 'The owner belongs to two organizations, so organization selection is shown.' },
  { step: 'Open Overview in Sandbox Organization to show the empty / initial state.', to: '/', tip: 'Use the organization switcher in the header.' },
  { step: 'Register and test the customer webhook (http://localhost:4100).', to: '/webhook/setup' },
  { step: 'Open the Integration Catalog and connect the GitHub demo credential.', to: '/integrations/catalog', tip: 'Any mock token works, e.g. mock_ghp_ followed by 20+ characters. Never use a real token in demos.' },
  { step: 'Show the integration is connected; only the credential reference and a masked identifier are displayed.', to: '/integrations/connected' },
  { step: 'Register the "GitHub Assistant" agent and copy its one-time API credential.', to: '/agents?register=1' },
  { step: 'Create a grant: read repository metadata + create issues, only in demo-org/demo-repo.', to: '/access/grants/new' },
  { step: 'Open the Agent Access Playground.', to: '/playground' },
  { step: 'Submit a permitted operation (Scenario A) and show the successful result.', to: '/playground' },
  { step: 'Submit an operation outside the allowed scope (Scenario B) and show Access Denied.', to: '/playground' },
  { step: 'Open Audit & Activity and show both decisions.', to: '/audit/access-logs' },
  { step: 'Revoke the grant.', to: '/access/grants' },
  { step: 'Retry the previously permitted operation (Scenario D) and show Access Denied.', to: '/playground' },
  { step: 'Open the grant and audit details to demonstrate traceability.', to: '/audit/security-events' },
];

const SCENARIOS = [
  { id: 'A', name: 'Successful access', how: 'GitHub Assistant → Demo GitHub → Create issue in demo-org/demo-repo.', expect: 'ALLOW · upstream 201 (simulated)' },
  { id: 'B', name: 'Scope violation', how: 'Request "Delete repository" (explicit deny policy) or "Read repository contents" (not granted).', expect: 'DENY · POLICY_DENIED / SCOPE_DENIED' },
  { id: 'C', name: 'Resource restriction', how: 'Create issue in demo-org/other-repo.', expect: 'DENY · RESOURCE_DENIED' },
  { id: 'D', name: 'Revoked grant', how: 'Revoke "GitHub Issue Creation", then repeat Scenario A.', expect: 'DENY · GRANT_REVOKED' },
  { id: 'E', name: 'Expired grant', how: 'Use integration "GitHub Staging" (seeded grant expired yesterday), or click "Expire now" on any grant.', expect: 'DENY · GRANT_EXPIRED' },
  { id: 'F', name: 'Webhook unavailable', how: 'Enable "Simulate outage" on Health & Connectivity (or stop the webhook process), then repeat Scenario A.', expect: 'ALLOW decision, execution FAILED safely · WEBHOOK_UNAVAILABLE' },
];

export function DemoGuidePage() {
  const { can } = useAuth();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const [pending, setPending] = useState(false);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Demo guide"
        description="A 5–8 minute walkthrough of the Token Vault proof of concept."
        breadcrumbs={[{ label: 'Overview', to: '/' }, { label: 'Demo guide' }]}
        actions={
          can(PERMISSIONS.DEMO_RESET) && (
            <Button variant="outline" onClick={() => setConfirm(true)}>
              <RotateCcw className="h-4 w-4" /> Reset demo data
            </Button>
          )
        }
      />

      <Card>
        <CardHeader title="Where is the credential handled?" description="The central principle this POC demonstrates." />
        <CardBody>
          <TrustBoundary />
        </CardBody>
      </Card>

      <div className="grid gap-6 xl:grid-cols-[1.3fr_1fr]">
        <Card>
          <CardHeader title="Demo script" />
          <CardBody>
            <ol className="space-y-3">
              {SCRIPT.map((s, i) => (
                <li key={i} className="flex gap-3">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-50 text-xs font-semibold text-brand-700">{i + 1}</span>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-slate-800">{s.step}</p>
                    {s.tip && <p className="mt-0.5 text-xs text-slate-500">{s.tip}</p>}
                  </div>
                  {s.to && (
                    <Link to={s.to} className="flex shrink-0 items-center gap-1 self-start text-xs font-medium text-brand-700 hover:underline">
                      Open <ArrowRight className="h-3 w-3" />
                    </Link>
                  )}
                </li>
              ))}
            </ol>
          </CardBody>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader title="Functional scenarios" description="All are available as presets in the Access Playground." />
            <CardBody className="space-y-3">
              {SCENARIOS.map((s) => (
                <div key={s.id} className="rounded-lg border border-slate-200 p-3">
                  <p className="text-sm font-medium text-slate-900">
                    <span className="mr-2 rounded bg-slate-900 px-1.5 py-0.5 text-[11px] font-semibold text-white">{s.id}</span>
                    {s.name}
                  </p>
                  <p className="mt-1 text-xs text-slate-600">{s.how}</p>
                  <p className="mt-1 font-mono text-[11px] text-slate-500">{s.expect}</p>
                </div>
              ))}
            </CardBody>
          </Card>
          <Callout tone="warning" title="What is simulated">
            GitHub API responses are simulated by the customer webhook (GITHUB_MODE=mock). Request signing, AES-256-GCM encryption, scrypt hashing and the policy engine run as real code, but this POC is not production-hardened and makes no production-security claims.
          </Callout>
          <Callout tone="info" title="Seeded agents have no known credential">
            Seeded agents are created with random API keys that are discarded. Use "Get a credential" in the playground (or Rotate on the agent) to issue one; it is shown exactly once.
          </Callout>
        </div>
      </div>

      <ConfirmDialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Reset demo data?"
        description="All organizations, agents, grants, policies and audit records in the control plane return to the seeded state. Issued agent credentials become invalid."
        confirmLabel="Reset"
        loading={pending}
        onConfirm={async () => {
          setPending(true);
          try {
            await api.post('/demo/reset');
            toast.success('Demo data reset');
            setConfirm(false);
          } catch (e) {
            toast.error('Reset failed', (e as Error).message);
          } finally {
            setPending(false);
          }
        }}
      />
    </div>
  );
}
