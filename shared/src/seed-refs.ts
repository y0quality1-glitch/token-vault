/**
 * Non-secret credential references that both the control plane seed and the
 * customer webhook seed agree on, so the demo works immediately after start-up.
 * The webhook generates random MOCK secret values for these refs at runtime;
 * no secret value appears anywhere in source control.
 */
export const SEED_CREDENTIAL_REFS = {
  demoGithub: { ref: 'cref_6f1d2a9c4b7e4e31', orgId: 'org_demo0000000001', label: 'Demo GitHub' },
  stagingGithub: { ref: 'cref_a83b55e0c2d94f7a', orgId: 'org_demo0000000001', label: 'GitHub Staging' },
  partnerGithub: { ref: 'cref_0c9e7d4410ab4b22', orgId: 'org_demo0000000001', label: 'Partner GitHub' },
} as const;

export const DEFAULT_WEBHOOK_INSTANCE_ID = 'whi_local_customer_vault';
