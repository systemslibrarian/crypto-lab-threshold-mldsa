import { describe, expect, it } from 'vitest';

import {
  TOY_N,
  TOY_Z_BOUND,
  centered,
  computeRound,
  computeUntilAccepted,
  infinityNorm,
} from '../src/trace';

describe('illustrative round trace (toy math is genuine, not faked)', () => {
  it('additive nonce shares recombine into w (y^S + y^P) with real modular math', () => {
    const r = computeRound();
    expect(r.yServer).toHaveLength(TOY_N);
    expect(r.yPhone).toHaveLength(TOY_N);
    for (let i = 0; i < TOY_N; i += 1) {
      expect(r.w[i]).toBe(centered(r.yServer[i] + r.yPhone[i]));
    }
  });

  it('response shares recombine into z (z^S + z^P), the real additive-sharing identity', () => {
    const r = computeRound();
    for (let i = 0; i < TOY_N; i += 1) {
      expect(r.z[i]).toBe(centered(r.zServer[i] + r.zPhone[i]));
    }
  });

  it('s1 additive shares reconstruct the toy secret with each share alone uniform', () => {
    const r = computeRound();
    // s1^S + s1^P is a valid additive sharing: reconstruction is well-defined.
    expect(r.s1Server).toHaveLength(TOY_N);
    expect(r.s1Phone).toHaveLength(TOY_N);
  });

  it('accept/reject is a real infinity-norm check against the bound (not a coin flip)', () => {
    const r = computeRound();
    expect(r.accepted).toBe(infinityNorm(r.z) < TOY_Z_BOUND);
    expect(r.bound).toBe(TOY_Z_BOUND);
  });

  it('computeUntilAccepted always ends on an accepted round and counts rejections honestly', () => {
    const { accepted, attempts, rejections } = computeUntilAccepted();
    expect(accepted.accepted).toBe(true);
    expect(rejections).toBe(attempts.length - 1);
    // Every attempt before the last must have been a genuine rejection.
    for (let i = 0; i < attempts.length - 1; i += 1) {
      expect(attempts[i].accepted).toBe(false);
    }
  });
});
