import { describe, expect, it } from 'vitest';

import {
  MLDSA_Q,
  reconstructByteShares,
  splitByteShares,
} from '../src/mldsa-primitives';
import {
  reconstructPolynomial,
  reconstructVector,
  sharedInfinityNormLessThan,
  sharedLessThan,
  splitPolynomial,
} from '../src/sharing';

describe('additive byte sharing (the real 2-of-2 custody primitive)', () => {
  it('recombines exactly to the original secret', () => {
    const secret = new Uint8Array([0, 1, 2, 42, 128, 200, 255, 7, 99]);
    const { serverShare, phoneShare } = splitByteShares(secret);
    const recombined = reconstructByteShares(serverShare, phoneShare);
    expect(Array.from(recombined)).toEqual(Array.from(secret));
  });

  it('gives shares of equal length to the secret', () => {
    const secret = new Uint8Array(64).map((_, i) => (i * 7) % 256);
    const { serverShare, phoneShare } = splitByteShares(secret);
    expect(serverShare.length).toBe(secret.length);
    expect(phoneShare.length).toBe(secret.length);
  });

  it('produces different shares on each split (fresh randomness)', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const a = splitByteShares(secret);
    const b = splitByteShares(secret);
    // With a real CSPRNG the phone shares should essentially never coincide.
    expect(Array.from(a.phoneShare)).not.toEqual(Array.from(b.phoneShare));
    // But both still recombine to the same secret.
    expect(Array.from(reconstructByteShares(a.serverShare, a.phoneShare))).toEqual(Array.from(secret));
    expect(Array.from(reconstructByteShares(b.serverShare, b.phoneShare))).toEqual(Array.from(secret));
  });

  it('a single share alone reveals nothing usable — it is NOT the secret', () => {
    const secret = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
    const { serverShare, phoneShare } = splitByteShares(secret);
    // Neither share equals the secret (except with negligible probability).
    expect(Array.from(serverShare)).not.toEqual(Array.from(secret));
    expect(Array.from(phoneShare)).not.toEqual(Array.from(secret));
  });

  it('rejects mismatched share lengths on reconstruction', () => {
    expect(() => reconstructByteShares(new Uint8Array(4), new Uint8Array(5))).toThrow();
  });
});

describe('additive polynomial sharing', () => {
  it('reconstructs a polynomial from two shares', () => {
    const poly = Array.from({ length: 32 }, (_, i) => ((i * 131) % MLDSA_Q));
    const { shareServer, sharePhone } = splitPolynomial(poly, MLDSA_Q);
    expect(reconstructPolynomial(shareServer, sharePhone, MLDSA_Q)).toEqual(poly);
  });

  it('reconstructs a vector of polynomials', () => {
    const v = [
      [1, 2, 3],
      [4, 5, 6],
    ];
    const split = v.map((p) => splitPolynomial(p, MLDSA_Q));
    const rec = reconstructVector(
      split.map((s) => s.shareServer),
      split.map((s) => s.sharePhone),
      MLDSA_Q,
    );
    expect(rec).toEqual(v);
  });
});

describe('shared comparison gadgets', () => {
  it('sharedLessThan compares the reconstructed (centered) value', () => {
    expect(sharedLessThan(5, MLDSA_Q - 3, 10, MLDSA_Q).result).toBe(true); // combined = 2
    expect(sharedLessThan(500, 0, 100, MLDSA_Q).result).toBe(false);
  });

  it('sharedInfinityNormLessThan fails when any coefficient exceeds the bound', () => {
    expect(sharedInfinityNormLessThan([2, 3], [1, 1], 10, MLDSA_Q).result).toBe(true);
    expect(sharedInfinityNormLessThan([2, 900], [1, 1], 10, MLDSA_Q).result).toBe(false);
  });
});
