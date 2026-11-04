import { customType, index, jsonb, pgTable, text } from 'drizzle-orm/pg-core';

/**
 * Customer-side store (spec section 9, "Customer webhook credential store").
 * This database belongs to the CUSTOMER trust zone: it is separate from the control
 * plane's database and is reached with a different role. Only ciphertext is stored;
 * the AES-256-GCM key comes from the environment and is never written here.
 */
const ts = customType<{ data: string; driverData: string | Date }>({
  dataType: () => 'timestamp(3) with time zone',
  fromDriver: (v) => (v instanceof Date ? v : new Date(v)).toISOString(),
  toDriver: (v) => v,
});

export const credentials = pgTable(
  'credentials',
  {
    credentialRef: text('credential_ref').primaryKey(),
    /** Organization that owns the credential; every lookup is scoped to it. */
    orgId: text('org_id').notNull(),
    provider: text('provider').notNull(),
    /** AES-256-GCM output (base64). The credential ref is bound as additional authenticated data. */
    iv: text('iv').notNull(),
    ciphertext: text('ciphertext').notNull(),
    authTag: text('auth_tag').notNull(),
    /** Which key encrypted this row (e.g. env:VAULT_ENCRYPTION_KEY#v1). Never the key itself. */
    encryptionKeyRef: text('encryption_key_ref').notNull(),
    maskedIdentifier: text('masked_identifier').notNull(),
    fingerprint: text('fingerprint').notNull(),
    metadata: jsonb('metadata').$type<Record<string, string>>().notNull().default({}),
    status: text('status').$type<'ACTIVE' | 'DISABLED'>().notNull(),
    createdAt: ts('created_at').notNull(),
    rotatedAt: ts('rotated_at'),
  },
  (t) => [index('credentials_org_idx').on(t.orgId)],
);

/**
 * Replay protection shared by every webhook instance: a signed request's nonce is
 * accepted once within its validity window, whichever instance receives it.
 */
export const usedNonces = pgTable(
  'used_nonces',
  {
    nonce: text('nonce').primaryKey(),
    expiresAt: ts('expires_at').notNull(),
  },
  (t) => [index('used_nonces_expires_at_idx').on(t.expiresAt)],
);
