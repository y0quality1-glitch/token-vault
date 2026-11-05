import type { SignedDefinition } from '@token-vault/shared';
import { Card, CardBody, CardHeader, DetailList } from '@ui/card';
import { Callout, ErrorState, PageSkeleton } from '@ui/feedback';
import { PageHeader } from '@ui/navigation';
import { CopyButton } from '@ui/secret';
import { DataTable } from '@ui/table';
import { useApi } from '@tv-hooks/useApi';
import { formatDateTime } from '@/lib/utils';
import { Badge } from '@ui/badge';

interface PublicKey {
  algorithm: string;
  key_id: string;
  public_key_pem: string;
  keys: { key_id: string; public_key_pem: string | null; active: boolean; first_used_at: string }[];
}

export function CatalogPage() {
  const key = useApi<PublicKey>('/catalog/v1/public-key');
  const catalog = useApi<{ definitions: SignedDefinition[] }>('/catalog/v1/definitions');
  if (key.error) return <ErrorState error={key.error} onRetry={key.reload} />;
  if (!key.data) return <PageSkeleton />;
  const defs = catalog.data?.definitions ?? [];
  return (
    <>
      <PageHeader title="Catalog & signing key" description="What Token Vault and customer webhooks pull from this CMS. Every published definition is signed with the CMS key; consumers pin the public key below and refuse anything that does not verify." />
      <div className="space-y-6">
        <Card>
          <CardHeader title="Signing key" description="Ed25519. The private key never leaves the CMS API's environment (CMS_SIGNING_PRIVATE_KEY)." actions={<CopyButton value={key.data.public_key_pem} label="Copy public key" />} />
          <CardBody className="space-y-4">
            <DetailList
              items={[
                { label: 'Algorithm', value: key.data.algorithm },
                { label: 'Key ID', value: key.data.key_id, mono: true },
              ]}
            />
            <pre className="overflow-x-auto rounded-lg bg-slate-900 p-4 font-mono text-xs text-slate-100">{key.data.public_key_pem}</pre>
            {key.data.keys.length > 1 && (
              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Keys that have signed published versions</p>
                <ul className="space-y-1 text-sm" data-testid="signing-keys">
                  {key.data.keys.map((k) => (
                    <li key={k.key_id} className="flex items-center gap-2">
                      <span className="font-mono text-xs">{k.key_id}</span>
                      {k.active ? <Badge tone="green">active</Badge> : <Badge>previous</Badge>}
                      <span className="text-xs text-slate-500">since {formatDateTime(k.first_used_at)}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-2 text-xs text-slate-500">Every published version carries a signature by each of these keys, so consumers still pinning a previous key keep working until they switch. See docs/CMS.md, Key rotation.</p>
              </div>
            )}
            <Callout tone="security">
              A consumer accepts a definition only if sha256(canonical JSON) equals its digest, the signature over <span className="font-mono">token-vault/provider-definition/v1:&lt;digest&gt;</span> verifies with this key, and the definition passes validation.
            </Callout>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Published definitions" description="GET /catalog/v1/definitions (ETag-cached)" />
          <DataTable
            loading={catalog.loading}
            rows={defs}
            rowKey={(d) => d.digest}
            empty="Nothing is published."
            columns={[
              { key: 'key', header: 'Application', cell: (d) => <span className="font-mono text-sm">{(d.definition as { key: string }).key}</span> },
              { key: 'v', header: 'Version', cell: (d) => <span className="text-sm">v{(d.definition as { version: number }).version}</span> },
              { key: 'digest', header: 'Digest', cell: (d) => <span className="font-mono text-xs text-slate-500">{d.digest.slice(0, 16)}…</span> },
              { key: 'approved', header: 'Approved by', cell: (d) => <span className="text-sm">{d.approved_by}</span>, hideBelow: 'md' },
              { key: 'at', header: 'Published', cell: (d) => <span className="text-sm text-slate-500">{formatDateTime(d.published_at)}</span>, hideBelow: 'lg' },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
