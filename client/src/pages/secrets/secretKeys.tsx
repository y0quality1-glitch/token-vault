import { useState } from 'react';
import { BadgeCheck, Ban, Download, FileBadge, KeyRound, PlayCircle, RefreshCw, Upload, XCircle } from 'lucide-react';
import {
  CERTIFICATE_KEY_ALGORITHMS,
  SECRET_CERTIFICATE_TYPES,
  type CertificateInfo,
  type CertificateRequestStatus,
  type CertificateRequestView,
  type KeyOperation,
  type SecretDetail,
  type SecretRetrievalApprovalView,
  type SecretVersionView,
  type SecretView,
} from '@token-vault/shared';
import { useMutation, usePost } from '@/hooks/useApi';
import { api } from '@/lib/api';
import { formatDateTime, relativeTime } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, DetailList } from '@/components/ui/card';
import { Checkbox, Field, Input, Select, Textarea } from '@/components/ui/form';
import { Callout } from '@/components/ui/feedback';
import { Dialog } from '@/components/ui/dialog';
import { DataTable, type Column } from '@/components/ui/table';
import { CopyButton, Mono } from '@/components/ui/secret';
import { useToast } from '@/components/ui/toast';
import { ApiErrorCallout } from './secretUi';

/**
 * Keys and certificates (spec 4.9.3 E, F): the key card (what the key can do and what it may be used
 * for), key version activation, the certificate card and certificate renewal. Private keys are never
 * shown: renewal keys stay on the customer webhook, only their CSR is.
 */

// ── labels ───────────────────────────────────────────────────────

export const KEY_OPERATION_LABELS: Record<KeyOperation, { label: string; description: string }> = {
  sign: { label: 'Sign', description: 'Sign data with the key' },
  verify: { label: 'Verify', description: 'Check a signature or MAC' },
  encrypt: { label: 'Encrypt', description: 'Encrypt data with the key' },
  decrypt: { label: 'Decrypt', description: 'Decrypt what the key encrypted' },
  mac: { label: 'MAC', description: 'Compute a MAC with the key' },
};

export const KEY_EXTERNAL_LABELS: Record<'vault-transit' | 'aws-kms', string> = { 'vault-transit': 'Vault Transit', 'aws-kms': 'AWS KMS' };

export function keyOperationLabel(op: string): string {
  return KEY_OPERATION_LABELS[op as KeyOperation]?.label ?? op;
}

/** Key operations as small badges. */
export function KeyOperationBadges({ operations, testId }: { operations: string[]; testId?: string }) {
  return (
    <span className="inline-flex flex-wrap gap-1" data-testid={testId} data-operations={operations.join(',')}>
      {operations.map((o) => (
        <Badge key={o} tone="violet">
          {keyOperationLabel(o)}
        </Badge>
      ))}
    </span>
  );
}

/** What a held request asks for: a retrieval, a lease, or a key operation (with a short digest of its input). */
export function ApprovalOperation({ approval: r }: { approval: Pick<SecretRetrievalApprovalView, 'operation' | 'inputDigest'> }) {
  const label = r.operation === 'retrieve' ? 'Retrieve' : r.operation === 'lease' ? 'Lease' : keyOperationLabel(r.operation);
  return (
    <span className="block" data-testid="secret-approval-operation" data-operation={r.operation}>
      <Badge tone={r.operation === 'retrieve' ? 'blue' : r.operation === 'lease' ? 'violet' : 'amber'}>{label}</Badge>
      {r.inputDigest && (
        <span className="mt-0.5 block whitespace-nowrap font-mono text-[11px] text-slate-500" title={`SHA-256 of the input: ${r.inputDigest}`}>
          Input SHA-256: {r.inputDigest.slice(0, 16)}…
        </span>
      )}
    </span>
  );
}

// ── certificates: helpers ────────────────────────────────────────

/** Whole days until `iso` (negative once past). */
export function daysLeft(iso: string): number {
  return Math.floor((Date.parse(iso) - Date.now()) / 86_400_000);
}

export function daysLeftText(days: number): string {
  if (days < 0) return `expired ${-days} day${days === -1 ? '' : 's'} ago`;
  if (days === 0) return 'expires today';
  return `${days} day${days === 1 ? '' : 's'} left`;
}

export function daysLeftClass(days: number): string {
  return days < 0 ? 'text-red-700' : days <= 30 ? 'text-amber-700' : 'text-slate-500';
}

/** Short certificate hint for lists: common name and days left. */
export function CertificateHint({ certificate: c }: { certificate: CertificateInfo }) {
  const d = daysLeft(c.notAfter);
  return (
    <span className="block text-xs" data-testid="secret-row-certificate" data-days-left={d} title={`Valid until ${formatDateTime(c.notAfter)}`}>
      {c.commonName && <span className="text-slate-600">{c.commonName} · </span>}
      <span className={daysLeftClass(d)}>{daysLeftText(d)}</span>
    </span>
  );
}

function downloadText(filename: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

const REQUEST_STATUS: Record<CertificateRequestStatus, { label: string; tone: 'amber' | 'green' | 'gray' }> = {
  PENDING: { label: 'Waiting for certificate', tone: 'amber' },
  COMPLETED: { label: 'Completed', tone: 'green' },
  CANCELLED: { label: 'Cancelled', tone: 'gray' },
  EXPIRED: { label: 'Expired', tone: 'gray' },
};

function RequestStatusBadge({ status }: { status: CertificateRequestStatus }) {
  const m = REQUEST_STATUS[status] ?? { label: status, tone: 'gray' as const };
  return (
    <Badge tone={m.tone} dot>
      {m.label}
    </Badge>
  );
}

const CLOSED_STATUSES = ['REVOKED', 'ARCHIVED', 'DELETED'];

// ── certificate card ─────────────────────────────────────────────

/** The active version's certificate, its chain, and renewal requests (renewable types). */
export function CertificateCard({ secret: s, onChanged }: { secret: SecretDetail; onChanged: () => Promise<void> }) {
  const [renewing, setRenewing] = useState(false);
  const c = s.certificate;
  const renewable = !!SECRET_CERTIFICATE_TYPES[s.typeKey]?.renewable;
  const pending = s.certificateRequests.find((r) => r.status === 'PENDING') ?? null;
  const canAct = renewable && s.can.updateValue && !CLOSED_STATUSES.includes(s.status);
  const days = c ? daysLeft(c.notAfter) : null;

  const columns: Column<CertificateRequestView>[] = [
    {
      key: 'when',
      header: 'Requested',
      cell: (r) => (
        <div className="whitespace-nowrap" data-testid="secret-cert-request" data-status={r.status} data-request-id={r.id}>
          <span className="block text-slate-700" title={formatDateTime(r.createdAt)}>
            {relativeTime(r.createdAt)}
          </span>
          <span className="block text-xs text-slate-500">by {r.createdBy.name}</span>
        </div>
      ),
    },
    { key: 'algorithm', header: 'New key', cell: (r) => <span className="whitespace-nowrap font-mono text-[12px] text-slate-600">{r.keyAlgorithm}</span>, hideBelow: 'md' },
    { key: 'status', header: 'Status', cell: (r) => <RequestStatusBadge status={r.status} /> },
    {
      key: 'outcome',
      header: 'Outcome',
      cell: (r) => (
        <span className="block max-w-xs break-words text-xs text-slate-600">
          {r.status === 'COMPLETED' && (
            <span className="block">
              Stored as v{r.completedVersion ?? '?'}
              {r.issuer ? `, issued by ${r.issuer.name}` : ', uploaded'}
              {r.completedAt ? ` ${relativeTime(r.completedAt)}` : ''}
            </span>
          )}
          {r.status === 'PENDING' && <span className="block" title={formatDateTime(r.expiresAt)}>lapses {relativeTime(r.expiresAt)}</span>}
          {r.status === 'EXPIRED' && <span className="block">Lapsed {relativeTime(r.expiresAt)}</span>}
          {r.cancelledReason && <span className="block text-slate-500">{r.cancelledReason}</span>}
        </span>
      ),
      hideBelow: 'md',
    },
  ];

  return (
    <Card data-testid="secret-certificate-card" data-days-left={days ?? undefined}>
      <CardHeader
        title="Certificate"
        description={c ? 'Read from the active version by the customer webhook.' : 'The active version has no certificate to show.'}
        icon={<FileBadge className="h-4 w-4" />}
        actions={
          canAct && (
            <Button size="sm" onClick={() => setRenewing(true)} disabled={!!pending} title={pending ? 'A renewal request is waiting for its certificate' : undefined} data-testid="secret-cert-renew">
              <RefreshCw className="h-3.5 w-3.5" /> Renew certificate
            </Button>
          )
        }
      />
      {c && days !== null && (
        <CardBody className="space-y-4">
          <DetailList
            columns={3}
            items={[
              { label: 'Common name', value: <span data-testid="secret-certificate-cn">{c.commonName ?? '—'}</span> },
              {
                label: 'Valid until',
                value: (
                  <span data-testid="secret-certificate-not-after" data-days-left={days}>
                    {formatDateTime(c.notAfter)}
                    <span className={`block text-xs ${daysLeftClass(days)}`}>{daysLeftText(days)}</span>
                  </span>
                ),
              },
              { label: 'Valid from', value: formatDateTime(c.notBefore) },
              { label: 'Subject', value: <span className="font-mono text-[12px]">{c.subject}</span> },
              { label: 'Issuer', value: <span className="font-mono text-[12px]">{c.issuer}</span> },
              { label: 'Serial number', value: <Mono className="break-all">{c.serialNumber}</Mono> },
              {
                label: 'Subject alternative names',
                value: c.subjectAltNames.length ? (
                  <span className="flex flex-wrap gap-1" data-testid="secret-certificate-sans">
                    {c.subjectAltNames.map((n) => (
                      <Badge key={n}>{n}</Badge>
                    ))}
                  </span>
                ) : (
                  '—'
                ),
              },
              { label: 'Public key', value: c.publicKey },
              {
                label: 'Properties',
                value: (
                  <span className="flex flex-wrap gap-1" data-testid="secret-certificate-badges">
                    {c.isCA && (
                      <span data-testid="secret-certificate-ca">
                        <Badge tone="violet">CA</Badge>
                      </span>
                    )}
                    {c.selfSigned && (
                      <span data-testid="secret-certificate-self-signed">
                        <Badge tone="amber">Self-signed</Badge>
                      </span>
                    )}
                    <span data-testid="secret-certificate-private-key" data-private-key={c.privateKey}>
                      {c.privateKey === 'matches' ? <Badge tone="green">Private key matches</Badge> : <Badge>No private key</Badge>}
                    </span>
                  </span>
                ),
              },
            ]}
          />
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Fingerprint (SHA-256)</dt>
            <dd className="mt-1">
              <Mono className="break-all">{c.fingerprintSha256}</Mono>
            </dd>
          </div>
          <CertificateChain certificate={c} />
        </CardBody>
      )}
      {(renewable || s.certificateRequests.length > 0) && (
        <div className="border-t border-slate-100" data-testid="secret-cert-requests">
          <div className="px-5 pt-4">
            <p className="text-sm font-medium text-slate-700">Renewal requests</p>
            <p className="text-xs text-slate-500">A renewal makes a new key on the customer webhook (never shown) and a CSR for it. The new certificate becomes the next version.</p>
          </div>
          <DataTable rows={s.certificateRequests} rowKey={(r) => r.id} columns={columns} dense empty={<p className="px-5 py-6 text-sm text-slate-500">No renewal requests yet.</p>} />
          {pending && <PendingRequest key={pending.id} secret={s} request={pending} canAct={canAct} onChanged={onChanged} />}
        </div>
      )}
      {renewing && (
        <RenewDialog
          secret={s}
          onClose={() => setRenewing(false)}
          onDone={async () => {
            setRenewing(false);
            await onChanged();
          }}
        />
      )}
    </Card>
  );
}

function CertificateChain({ certificate: c }: { certificate: CertificateInfo }) {
  const valid = c.chainValid === null ? 'none' : c.chainValid ? 'true' : 'false';
  return (
    <div className="border-t border-slate-100 pt-4" data-testid="secret-certificate-chain" data-valid={valid}>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-medium text-slate-700">Chain</p>
        {c.chainValid === true && (
          <Badge tone="green">
            <BadgeCheck className="h-3 w-3" /> Each certificate signed the one before it
          </Badge>
        )}
        {c.chainValid === false && (
          <Badge tone="red">
            <XCircle className="h-3 w-3" /> Broken: a certificate did not sign the one before it
          </Badge>
        )}
      </div>
      {c.chain.length === 0 ? (
        <p className="text-sm text-slate-500">No chain stored with this certificate.</p>
      ) : (
        <ol className="space-y-2">
          {c.chain.map((x, i) => (
            <li key={i} className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs" data-testid="secret-certificate-chain-entry">
              <span className="block font-mono text-[12px] text-slate-800">{x.subject}</span>
              <span className="block text-slate-500">
                issued by <span className="font-mono">{x.issuer}</span>
              </span>
              <span className={`block ${daysLeftClass(daysLeft(x.notAfter))}`}>valid until {formatDateTime(x.notAfter)}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function RenewDialog({ secret, onClose, onDone }: { secret: SecretDetail; onClose: () => void; onDone: () => Promise<void> }) {
  const toast = useToast();
  const [algorithm, setAlgorithm] = useState('');
  const request = useMutation((body: unknown) => api.post<CertificateRequestView>('/secret/certificate/request', body));

  async function submit() {
    const r = await request.run({ id: secret.id, ...(algorithm ? { keyAlgorithm: algorithm } : {}) });
    if (!r) return;
    toast.success('Renewal requested', 'Give the CSR to your certificate authority, or issue it with a CA secret.');
    await onDone();
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Renew ${secret.name}`}
      description="The customer webhook makes a new key pair and a CSR with the current subject and names. The current certificate keeps working until the new one is stored."
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={request.pending} onClick={() => void submit()} data-testid="secret-cert-renew-confirm">
            <RefreshCw className="h-4 w-4" /> Make CSR
          </Button>
        </>
      }
    >
      <div className="space-y-4" data-testid="secret-cert-renew-dialog">
        <Field label="New key" htmlFor="secret-cert-renew-algorithm" error={request.fieldErrors.keyAlgorithm}>
          <Select id="secret-cert-renew-algorithm" value={algorithm} onChange={(e) => setAlgorithm(e.target.value)} data-testid="secret-cert-renew-algorithm">
            <option value="">Same as now{secret.certificate ? ` (${secret.certificate.publicKey})` : ''}</option>
            {CERTIFICATE_KEY_ALGORITHMS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </Select>
        </Field>
        <ApiErrorCallout error={request.error} shownFields={['keyAlgorithm']} />
      </div>
    </Dialog>
  );
}

/** The waiting request: its CSR, and the two ways to complete it (upload, or issue with a CA secret). */
function PendingRequest({ secret: s, request: r, canAct, onChanged }: { secret: SecretDetail; request: CertificateRequestView; canAct: boolean; onChanged: () => Promise<void> }) {
  const toast = useToast();
  const [certificate, setCertificate] = useState('');
  const [chain, setChain] = useState('');
  const [issuerId, setIssuerId] = useState('');
  const [days, setDays] = useState('90');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [cancelling, setCancelling] = useState(false);
  const upload = useMutation((body: unknown) => api.post<SecretDetail>('/secret/certificate/complete', body));
  const issue = useMutation((body: unknown) => api.post<SecretDetail>('/secret/certificate/complete', body));
  const cas = usePost<{ items: SecretView[]; total: number }>(canAct ? '/secret/getall' : null, { typeKey: 'ca-certificate', pageSize: 100, sortBy: 'name', sortOrder: 'asc' });
  const issuers = (cas.data?.items ?? []).filter((x) => x.id !== s.id);
  const uploadErrors: Record<string, string> = { ...upload.fieldErrors, ...errors };
  const issueErrors: Record<string, string> = { ...issue.fieldErrors, ...errors };
  const certificateError = uploadErrors['payload.certificate'] ?? uploadErrors.certificate ?? uploadErrors.payload;
  const chainError = uploadErrors['payload.chain'] ?? uploadErrors.chain;

  async function doUpload() {
    const e: Record<string, string> = {};
    if (!certificate.trim()) e.certificate = 'Paste the certificate the CA issued (PEM)';
    setErrors(e);
    if (Object.keys(e).length) return;
    issue.setError(null);
    const res = await upload.run({ requestId: r.id, certificate: certificate.trim(), ...(chain.trim() ? { chain: chain.trim() } : {}) });
    if (!res) return;
    setCertificate('');
    setChain('');
    toast.success('Certificate stored', `Version ${res.activeVersion ?? ''} is the new certificate.`);
    await onChanged();
  }

  async function doIssue() {
    const e: Record<string, string> = {};
    if (!issuerId) e.issuerSecretId = 'Choose a CA secret';
    const n = Number(days);
    if (!/^\d+$/.test(days.trim()) || n < 1 || n > 825) e.validityDays = 'A whole number of days, 1 to 825';
    setErrors(e);
    if (Object.keys(e).length) return;
    upload.setError(null);
    const res = await issue.run({ requestId: r.id, issuerSecretId: issuerId, validityDays: n });
    if (!res) return;
    toast.success('Certificate issued', `Version ${res.activeVersion ?? ''} is the new certificate.`);
    await onChanged();
  }

  return (
    <div className="space-y-4 border-t border-slate-100 px-5 py-4" data-testid="secret-cert-pending" data-request-id={r.id}>
      <div>
        <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm font-medium text-slate-700">
            Certificate signing request <span className="font-normal text-slate-500">· {r.keyAlgorithm}</span>
          </p>
          <div className="flex gap-2">
            <CopyButton value={r.csr} />
            <Button variant="outline" size="sm" onClick={() => downloadText(`${s.name.replace(/[^A-Za-z0-9._-]+/g, '-')}.csr`, r.csr, 'application/pkcs10')} data-testid="secret-cert-csr-download">
              <Download className="h-3.5 w-3.5" /> Download .csr
            </Button>
          </div>
        </div>
        <Textarea readOnly rows={6} value={r.csr} spellCheck={false} className="font-mono text-[12px]" aria-label="Certificate signing request" data-testid="secret-cert-csr" />
        <p className="mt-1 text-xs text-slate-500">
          Subject <span className="font-mono">{r.subject}</span>
          {r.subjectAltNames.length > 0 && <> · {r.subjectAltNames.join(', ')}</>} · lapses {relativeTime(r.expiresAt)}
        </p>
      </div>

      {canAct ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <form
            className="space-y-3 rounded-lg border border-slate-200 p-4"
            data-testid="secret-cert-upload-form"
            onSubmit={(e) => {
              e.preventDefault();
              void doUpload();
            }}
          >
            <div>
              <p className="text-sm font-medium text-slate-800">Upload the certificate</p>
              <p className="text-xs text-slate-500">The certificate your CA issued for this CSR. It must belong to the new key.</p>
            </div>
            <Field label="Certificate (PEM)" htmlFor="secret-cert-complete-certificate" required error={certificateError}>
              <Textarea id="secret-cert-complete-certificate" rows={5} value={certificate} onChange={(e) => setCertificate(e.target.value)} spellCheck={false} className="font-mono text-[12px]" placeholder="-----BEGIN CERTIFICATE-----" invalid={!!certificateError} data-testid="secret-cert-complete-certificate" />
            </Field>
            <Field label="Chain (optional)" htmlFor="secret-cert-complete-chain" error={chainError} hint="Intermediate certificates, in order.">
              <Textarea id="secret-cert-complete-chain" rows={3} value={chain} onChange={(e) => setChain(e.target.value)} spellCheck={false} className="font-mono text-[12px]" invalid={!!chainError} data-testid="secret-cert-complete-chain" />
            </Field>
            <ApiErrorCallout error={upload.error} shownFields={['certificate', 'chain', 'payload']} />
            <div className="flex justify-end">
              <Button type="submit" loading={upload.pending} data-testid="secret-cert-complete-upload">
                <Upload className="h-4 w-4" /> Store certificate
              </Button>
            </div>
          </form>

          <form
            className="space-y-3 rounded-lg border border-slate-200 p-4"
            data-testid="secret-cert-issue-form"
            onSubmit={(e) => {
              e.preventDefault();
              void doIssue();
            }}
          >
            <div>
              <p className="text-sm font-medium text-slate-800">Issue with a CA secret</p>
              <p className="text-xs text-slate-500">A CA certificate stored in this organization signs the CSR on the customer webhook. You also need secret:retrieve on the CA secret.</p>
            </div>
            <Field label="CA secret" htmlFor="secret-cert-issuer-select" required error={issueErrors.issuerSecretId} hint={cas.error ? `CA secrets could not be loaded: ${cas.error.message}` : undefined}>
              <Select id="secret-cert-issuer-select" value={issuerId} onChange={(e) => setIssuerId(e.target.value)} invalid={!!issueErrors.issuerSecretId} data-testid="secret-cert-issuer-select">
                <option value="">{cas.loading && !cas.data ? 'Loading CA secrets…' : issuers.length ? 'Choose a CA secret…' : 'No CA secrets in this organization'}</option>
                {issuers.map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.name} · {x.project}/{x.environment}
                    {x.status !== 'ACTIVE' ? ` (${x.status.toLowerCase()})` : ''}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Valid for (days)" htmlFor="secret-cert-issuer-days" error={issueErrors.validityDays} hint="1 to 825 days.">
              <Input id="secret-cert-issuer-days" type="number" min={1} max={825} step={1} value={days} onChange={(e) => setDays(e.target.value)} invalid={!!issueErrors.validityDays} data-testid="secret-cert-issuer-days" />
            </Field>
            <ApiErrorCallout error={issue.error} shownFields={['issuerSecretId', 'validityDays']} />
            <div className="flex justify-end">
              <Button type="submit" loading={issue.pending} disabled={!issuers.length} data-testid="secret-cert-complete-issue">
                <BadgeCheck className="h-4 w-4" /> Issue certificate
              </Button>
            </div>
          </form>
        </div>
      ) : (
        <p className="text-xs text-slate-500">Members who can store new values of this secret complete the request.</p>
      )}

      {canAct && (
        <div className="flex justify-end">
          <Button variant="danger-outline" size="sm" onClick={() => setCancelling(true)} data-testid="secret-cert-cancel">
            <Ban className="h-3.5 w-3.5" /> Cancel request
          </Button>
        </div>
      )}
      {cancelling && (
        <CancelRequestDialog
          request={r}
          onClose={() => setCancelling(false)}
          onDone={async () => {
            setCancelling(false);
            await onChanged();
          }}
        />
      )}
    </div>
  );
}

function CancelRequestDialog({ request, onClose, onDone }: { request: CertificateRequestView; onClose: () => void; onDone: () => Promise<void> }) {
  const toast = useToast();
  const [reason, setReason] = useState('');
  const cancel = useMutation((body: unknown) => api.post<CertificateRequestView>('/secret/certificate/cancel', body));
  async function confirm() {
    const r = await cancel.run({ requestId: request.id, ...(reason.trim() ? { reason: reason.trim() } : {}) });
    if (!r) return;
    toast.success('Renewal cancelled', 'The waiting key was destroyed.');
    await onDone();
  }
  return (
    <Dialog
      open
      onClose={onClose}
      size="sm"
      title="Cancel renewal request"
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={cancel.pending}>
            Keep it
          </Button>
          <Button variant="danger" loading={cancel.pending} onClick={() => void confirm()} data-testid="secret-cert-cancel-confirm">
            Cancel request
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-sm text-slate-600" data-testid="secret-cert-cancel-dialog">
        <p>The new key made for this request is destroyed, and a certificate issued for its CSR can no longer be stored. The current certificate is not changed.</p>
        <Field label="Reason (optional)" htmlFor="secret-cert-cancel-reason" hint="Recorded in the audit log.">
          <Textarea id="secret-cert-cancel-reason" rows={2} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} data-testid="secret-cert-cancel-reason" />
        </Field>
        <ApiErrorCallout error={cancel.error} />
      </div>
    </Dialog>
  );
}

// ── key card ─────────────────────────────────────────────────────

/** What the key type can do, where the key is held, and what applications may use it for. */
export function KeyCard({ secret: s, onChanged }: { secret: SecretDetail; onChanged: () => Promise<void> }) {
  const toast = useToast();
  const key = s.key!;
  const [ops, setOps] = useState<KeyOperation[]>(key.operations);
  const save = useMutation((body: unknown) => api.post<SecretDetail>('/secret/save', body));
  const canEdit = s.can.updateMetadata && s.status !== 'DELETED';
  const changed = key.supported.some((o) => ops.includes(o) !== key.operations.includes(o));
  const external = key.external ? KEY_EXTERNAL_LABELS[key.external] : null;

  async function submit() {
    const selected = key.supported.filter((o) => ops.includes(o));
    // Everything the type supports: no limit (null).
    const r = await save.run({ id: s.id, name: s.name, keyOperations: selected.length === key.supported.length ? null : selected });
    if (!r) return;
    toast.success('Key usage updated');
    await onChanged();
  }

  return (
    <Card data-testid="secret-key-card" data-external={key.external ?? 'none'}>
      <CardHeader
        title="Key"
        description="Applications can use this key without ever reading it: the customer webhook performs each operation."
        icon={<KeyRound className="h-4 w-4" />}
        actions={
          canEdit &&
          changed && (
            <Button size="sm" loading={save.pending} onClick={() => void submit()} data-testid="secret-key-ops-save">
              Save
            </Button>
          )
        }
      />
      <CardBody className="space-y-4">
        <DetailList
          columns={2}
          items={[
            { label: 'The key type can', value: <KeyOperationBadges operations={key.supported} testId="secret-key-supported" /> },
            {
              label: 'Held by',
              value: (
                <span data-testid="secret-key-held-by">
                  {external ? (
                    <>
                      {external}
                      <span className="block text-xs text-slate-500">The key never leaves {external}. The stored value is how the customer webhook reaches it.</span>
                    </>
                  ) : (
                    <>
                      Your customer webhook
                      <span className="block text-xs text-slate-500">Stored encrypted with the other versions; applications never receive it.</span>
                    </>
                  )}
                </span>
              ),
            },
          ]}
        />
        <div className="space-y-2" data-testid="secret-key-ops">
          <p className="text-sm font-medium text-slate-700">Allowed uses</p>
          <p className="text-xs text-slate-500">What applications may ask for. Unticked operations are refused for every grant.</p>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {key.supported.map((o) => (
              <Checkbox
                key={o}
                id={`secret-key-op-${o}`}
                testId={`secret-key-op-${o}`}
                checked={ops.includes(o)}
                disabled={!canEdit}
                onChange={(c) => setOps((xs) => (c ? [...xs, o] : xs.filter((x) => x !== o)))}
                label={KEY_OPERATION_LABELS[o].label}
                description={KEY_OPERATION_LABELS[o].description}
              />
            ))}
          </div>
          <ApiErrorCallout error={save.error} />
          {save.fieldErrors.keyOperations && <p className="text-xs text-red-600">{save.fieldErrors.keyOperations}</p>}
        </div>
        <Callout tone="info">
          Applications use the key with <code className="font-mono text-[12px]">tv.keys.sign()</code> and friends, or <code className="font-mono text-[12px]">POST /agent/v1/secret/key/{'{operation}'}</code>, through an access grant that lists those key operations.
        </Callout>
      </CardBody>
    </Card>
  );
}

// ── key versions ─────────────────────────────────────────────────

export function KeyVersionBadge({ version: v }: { version: SecretVersionView }) {
  if (v.keyEnabled === null) return null;
  return (
    <span data-testid="secret-key-version-state" data-key-enabled={v.keyEnabled ? 'true' : 'false'}>
      {v.keyEnabled ? (
        <Badge tone="green" dot>
          Active
        </Badge>
      ) : (
        <Badge tone="gray" dot>
          Deactivated
        </Badge>
      )}
    </span>
  );
}

/** The certificate a version holds: valid until, and serial. */
export function VersionCertificate({ version: v }: { version: SecretVersionView }) {
  const c = v.certificate;
  if (!c) return <span className="text-slate-400">—</span>;
  const d = daysLeft(c.notAfter);
  return (
    <span className="block text-xs" data-testid="secret-version-certificate" data-days-left={d}>
      <span className={`block whitespace-nowrap ${daysLeftClass(d)}`} title={formatDateTime(c.notAfter)}>
        until {formatDateTime(c.notAfter)}
      </span>
      <span className="block max-w-[12rem] truncate font-mono text-slate-500" title={c.serialNumber}>
        {c.serialNumber}
      </span>
    </span>
  );
}

/** Deactivates or activates a key version (with an optional reason). */
export function KeyVersionDialog({ secret, version, enable, onClose, onDone }: { secret: SecretDetail; version: number; enable: boolean; onClose: () => void; onDone: () => Promise<void> }) {
  const toast = useToast();
  const [reason, setReason] = useState('');
  const submit = useMutation((body: unknown) => api.post<SecretDetail>(`/secret/keyVersion/${enable ? 'enable' : 'disable'}`, body));
  async function confirm() {
    const r = await submit.run({ id: secret.id, version, ...(reason.trim() ? { reason: reason.trim() } : {}) });
    if (!r) return;
    toast.success(enable ? `Version ${version} activated` : `Version ${version} deactivated`);
    await onDone();
  }
  return (
    <Dialog
      open
      onClose={onClose}
      size="sm"
      title={enable ? `Activate key version ${version}` : `Deactivate key version ${version}`}
      footer={
        <>
          <Button variant="outline" onClick={onClose} disabled={submit.pending}>
            Cancel
          </Button>
          <Button variant={enable ? 'primary' : 'danger'} loading={submit.pending} onClick={() => void confirm()} data-testid="secret-key-version-confirm">
            {enable ? (
              <>
                <PlayCircle className="h-4 w-4" /> Activate
              </>
            ) : (
              <>
                <Ban className="h-4 w-4" /> Deactivate
              </>
            )}
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-sm text-slate-600" data-testid="secret-key-version-dialog">
        <p>
          {enable
            ? `Key operations with v${version} of ${secret.name} are allowed again.`
            : `Key operations with v${version} of ${secret.name} are refused, including verifying and decrypting what it made. The version is kept and can be activated again.`}
        </p>
        <Field label="Reason (optional)" htmlFor="secret-key-version-reason" hint="Recorded in the audit log.">
          <Textarea id="secret-key-version-reason" rows={2} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} data-testid="secret-key-version-reason" />
        </Field>
        <ApiErrorCallout error={submit.error} />
      </div>
    </Dialog>
  );
}
