import { describe, expect, it } from 'vitest';
import { GENESIS, canonical, chainBatch, hashRecord, link, verify } from '../src/services/auditService/chain';

const KEY = 'k'.repeat(40);

describe('audit hash chain (pure)', () => {
  it('canonical JSON is independent of key order and drops undefined (like JSONB)', () => {
    expect(canonical({ b: 1, a: { d: [1, { y: 2, x: undefined }], c: null } })).toBe('{"a":{"c":null,"d":[1,{"y":2}]},"b":1}');
    expect(hashRecord(GENESIS, { a: 1, b: { c: 2, d: 3 } })).toBe(hashRecord(GENESIS, { b: { d: 3, c: 2 }, a: 1 }));
  });

  it('links records and verifies an intact chain', () => {
    const rows = chainBatch(KEY, 'audit_events', [
      { id: 'e2', organizationId: 'o', createdAt: '2026-11-04T10:00:01.000Z', note: 'second' },
      { id: 'e1', organizationId: 'o', createdAt: '2026-11-04T10:00:00.000Z', note: 'first' },
    ]);
    expect(rows.map((r) => [r.id, r.seq])).toEqual([['e1', 1], ['e2', 2]]);
    expect(rows[0]!.prevHash).toBe(GENESIS);
    expect(rows[1]!.prevHash).toBe(rows[0]!.hash);
    expect(verify(KEY, 'audit_events', 'o', rows, 0)).toMatchObject({ ok: true, chainedRecords: 2, headSeq: 2 });
  });

  it('detects modification, removal and forgery', () => {
    const base = chainBatch(KEY, 'audit_events', [1, 2, 3].map((n) => ({ id: `e${n}`, organizationId: 'o', createdAt: `2026-11-04T10:00:0${n}.000Z`, note: `n${n}` })));
    const modified = base.map((r) => (r.seq === 2 ? { ...r, note: 'changed' } : r));
    expect(verify(KEY, 'audit_events', 'o', modified, 0).problems[0]).toMatchObject({ seq: 2, kind: 'hash_mismatch' });
    const removed = base.filter((r) => r.seq !== 2);
    expect(verify(KEY, 'audit_events', 'o', removed, 0).problems[0]).toMatchObject({ seq: 3, kind: 'sequence_gap' });
    // An attacker who recomputes hashes still cannot produce valid signatures without the key.
    const forged = { id: 'e4', organizationId: 'o', createdAt: '2026-11-04T10:00:04.000Z', note: 'forged' };
    const fields = link('attacker-key-'.padEnd(40, 'x'), 'audit_events', 'o', { seq: 3, hash: base[2]!.hash }, forged);
    expect(verify(KEY, 'audit_events', 'o', [...base, { ...forged, ...fields }], 0).problems[0]).toMatchObject({ seq: 4, kind: 'mac_invalid' });
  });
});
