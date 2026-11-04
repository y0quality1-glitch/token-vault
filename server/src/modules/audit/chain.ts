import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { ChainVerification, IntegrityProblemKind } from '@token-vault/shared';

/**
 * Tamper-evident audit chain (pure functions; no database or config access).
 *
 * Each organization has one chain per audit table. Record n stores:
 *   seq       n (1, 2, 3, …)
 *   prev_hash hash of record n-1 (GENESIS for n = 1)
 *   hash      SHA-256( prev_hash "\n" canonical(record) )
 *   mac       HMAC-SHA256( key, table "|" org "|" seq "|" hash ), key held outside the database
 *
 * Verification catches a modified record (hash mismatch), a removed or reordered record
 * (broken link / sequence gap), and a forged or re-hashed record (invalid MAC: forging
 * needs the key). Not detectable without an external copy of the head: deleting the
 * newest records. Exporting the head (seq + hash) periodically closes that gap.
 */
export type ChainTable = 'audit_events' | 'access_requests';
export const GENESIS = '0'.repeat(64);
export const CHAIN_FIELDS = ['seq', 'prevHash', 'hash', 'mac'] as const;

/** Deterministic JSON: sorted keys, undefined dropped (matches what JSONB round-trips). */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? 'null' : canonical(v))).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
}

/** The record's own content, without chain fields. */
export function content<T extends Record<string, unknown>>(record: T): Record<string, unknown> {
  const out: Record<string, unknown> = { ...record };
  for (const f of CHAIN_FIELDS) delete out[f];
  return out;
}

export function hashRecord(prevHash: string, record: Record<string, unknown>): string {
  return createHash('sha256').update(`${prevHash}\n${canonical(content(record))}`).digest('hex');
}

export function macOf(key: string, table: ChainTable, orgId: string, seq: number, hash: string): string {
  return createHmac('sha256', key).update(`${table}|${orgId}|${seq}|${hash}`).digest('hex');
}

export interface ChainFields {
  seq: number;
  prevHash: string;
  hash: string;
  mac: string;
}

export function link(key: string, table: ChainTable, orgId: string, prev: { seq: number; hash: string } | null, record: Record<string, unknown>): ChainFields {
  const seq = (prev?.seq ?? 0) + 1;
  const prevHash = prev?.hash ?? GENESIS;
  const hash = hashRecord(prevHash, record);
  return { seq, prevHash, hash, mac: macOf(key, table, orgId, seq, hash) };
}

/** Chains a batch for an empty table (seeding), oldest first, per organization. */
export function chainBatch<T extends { organizationId: string; createdAt: string }>(key: string, table: ChainTable, records: T[]): (T & ChainFields)[] {
  const heads = new Map<string, { seq: number; hash: string }>();
  return [...records]
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
    .map((r) => {
      const fields = link(key, table, r.organizationId, heads.get(r.organizationId) ?? null, r as unknown as Record<string, unknown>);
      heads.set(r.organizationId, { seq: fields.seq, hash: fields.hash });
      return { ...r, ...fields };
    });
}

const safeEqual = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** Verifies an organization's chain. `rows` must be the chained rows ordered by seq. */
export function verify(
  key: string,
  table: ChainTable,
  orgId: string,
  rows: ReadonlyArray<{ id: string; seq: number; prevHash: string | null; hash: string | null; mac: string | null }>,
  legacyRecords: number,
): ChainVerification {
  const problems: ChainVerification['problems'] = [];
  const report = (seq: number | null, id: string, kind: IntegrityProblemKind, detail: string) => {
    if (problems.length < 25) problems.push({ seq, id, kind, detail });
  };
  let prev: { seq: number; hash: string } | null = null;
  for (const row of rows) {
    const last: { seq: number; hash: string } | null = prev;
    const expectedSeq: number = (last?.seq ?? 0) + 1;
    const expectedPrev: string = last?.hash ?? GENESIS;
    if (row.seq !== expectedSeq) report(row.seq, row.id, 'sequence_gap', `Expected record #${expectedSeq}, found #${row.seq}: records are missing or reordered`);
    else if (row.prevHash !== expectedPrev) report(row.seq, row.id, 'broken_link', `Record #${row.seq} does not link to the previous record's hash`);
    const recomputed = hashRecord(row.prevHash ?? '', row as unknown as Record<string, unknown>);
    if (!row.hash || !safeEqual(recomputed, row.hash)) report(row.seq, row.id, 'hash_mismatch', `Record #${row.seq}'s content no longer matches its hash: it was modified after being written`);
    else if (!row.mac || !safeEqual(macOf(key, table, orgId, row.seq, row.hash), row.mac)) report(row.seq, row.id, 'mac_invalid', `Record #${row.seq}'s signature is invalid: it was not written by Token Vault (or the signing key changed)`);
    prev = { seq: row.seq, hash: row.hash ?? '' };
  }
  const head = rows.at(-1);
  return {
    table,
    ok: problems.length === 0,
    totalRecords: rows.length + legacyRecords,
    chainedRecords: rows.length,
    legacyRecords,
    headSeq: head?.seq ?? null,
    headHash: head?.hash ?? null,
    problems,
  };
}
