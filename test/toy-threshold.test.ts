/**
 * Guards on the toy never-combine threshold protocol.
 *
 * These run the protocol rather than inspecting it. Margin: a 300-cycle sweep
 * (each cycle = one DKG plus an honest sign, an over-bound tamper, a one-unit
 * tamper and a single-party forgery attempt) was clean, with a mean of 2.52
 * signing attempts and a worst case of 12 against a 60-attempt budget. The
 * suite below re-runs a smaller version of that sweep on every test run.
 */
import { describe, expect, it } from 'vitest';

import { encodeText } from '../src/mldsa-primitives';
import {
  TOY_ETA,
  TOY_K,
  TOY_L,
  TOY_MAX_ATTEMPTS,
  TOY_N,
  TOY_PER_PARTY_BOUND,
  TOY_TAU,
  TOY_Z_BOUND,
  addVec,
  centered,
  challenge,
  createParty,
  expandA,
  infinityNorm,
  matVecMul,
  mulPoly,
  sampleInBall,
  subPoly,
  toyDkg,
  toySinglePartyAttempt,
  toyThresholdSign,
  toyVerify,
  zeroPoly,
} from '../src/toy-threshold';

const message = encodeText('Transfer $1000 to Alice');

describe('ring arithmetic', () => {
  it('multiplies negacyclically: X^(n-1) · X = −1', () => {
    const a = zeroPoly();
    a[TOY_N - 1] = 1;
    const b = zeroPoly();
    b[1] = 1;
    const product = mulPoly(a, b);
    expect(centered(product[0])).toBe(-1);
    for (let i = 1; i < TOY_N; i += 1) expect(product[i]).toBe(0);
  });

  it('multiplication is commutative and distributes over addition', () => {
    const setup = toyDkg();
    const [f, g] = setup.publicKey.t;
    expect(Array.from(mulPoly(f, g))).toEqual(Array.from(mulPoly(g, f)));
    const c = sampleInBall(new Uint8Array([1, 2, 3]));
    const left = mulPoly(c, subPoly(f, g));
    const right = subPoly(mulPoly(c, f), mulPoly(c, g));
    expect(Array.from(left)).toEqual(Array.from(right));
  });

  it('the ∞-norm reads centered representatives, not raw residues', () => {
    const poly = zeroPoly();
    poly[0] = 1; // +1
    poly[1] = 8380416; // −1 centered
    expect(infinityNorm([poly])).toBe(1);
  });
});

describe('public parameter expansion', () => {
  it('is deterministic in rho and produces a k×l matrix', () => {
    const rho = Uint8Array.from({ length: 32 }, (_, i) => i);
    const first = expandA(rho);
    const second = expandA(rho);
    expect(first.length).toBe(TOY_K);
    expect(first[0].length).toBe(TOY_L);
    for (let r = 0; r < TOY_K; r += 1) {
      for (let c = 0; c < TOY_L; c += 1) {
        expect(Array.from(second[r][c])).toEqual(Array.from(first[r][c]));
      }
    }
  });

  it('a different seed gives a different matrix', () => {
    const a = expandA(new Uint8Array(32));
    const b = expandA(Uint8Array.from({ length: 32 }, () => 1));
    expect(Array.from(a[0][0])).not.toEqual(Array.from(b[0][0]));
  });

  it('rejects a wrong-length seed rather than padding it', () => {
    expect(() => expandA(new Uint8Array(31))).toThrow();
  });
});

describe('the challenge polynomial', () => {
  it('has exactly tau coefficients in {−1, +1}', () => {
    for (let trial = 0; trial < 25; trial += 1) {
      const c = sampleInBall(encodeText(`seed-${trial}`));
      const nonzero = Array.from(c).map(centered).filter((v) => v !== 0);
      expect(nonzero.length).toBe(TOY_TAU);
      for (const v of nonzero) expect(Math.abs(v)).toBe(1);
    }
  });

  it('is a deterministic function of the message and the commitment', () => {
    const setup = toyDkg();
    const w = setup.server.commit();
    expect(Array.from(challenge(message, w))).toEqual(Array.from(challenge(message, w)));
    expect(Array.from(challenge(message, w))).not.toEqual(
      Array.from(challenge(encodeText('a different message'), w)),
    );
  });
});

describe('key setup never forms the whole secret', () => {
  it('exposes no secret share on the party object', () => {
    const setup = toyDkg();
    // The share lives in a closure. If a future refactor hangs it off the
    // object, this fails — which is the point: the guarantee is structural.
    const keys = Object.keys(setup.server);
    expect(keys).toEqual(expect.arrayContaining(['name', 'publicShare']));
    for (const key of keys) {
      expect(['name', 'publicShare', 'commit', 'respond']).toContain(key);
    }
    expect(JSON.stringify(setup.server)).not.toMatch(/secret|s1|share":\s*\[\[/i);
  });

  it('publishes t = A·s^S + A·s^P, and each party only ever knew its own half', () => {
    const setup = toyDkg();
    const sum = addVec(setup.server.publicShare, setup.phone.publicShare);
    for (let i = 0; i < sum.length; i += 1) {
      expect(Array.from(setup.publicKey.t[i])).toEqual(Array.from(sum[i]));
    }
  });

  it("a party's own secret share is genuinely small", () => {
    const A = expandA(new Uint8Array(32));
    const party = createParty('server', A);
    // s is not readable, but t^i = A·s^i must be a real product of the matrix
    // with SOME vector, and the response path proves the share is η-bounded:
    // ‖z − y‖∞ = ‖c·s‖∞ ≤ tau·eta.
    party.commit();
    const c = sampleInBall(new Uint8Array(32));
    const { norm } = party.respond(c);
    expect(norm).toBeLessThanOrEqual(4095 + TOY_TAU * TOY_ETA);
  });

  it('refuses to reuse a nonce across two challenges', () => {
    const A = expandA(new Uint8Array(32));
    const party = createParty('phone', A);
    party.commit();
    party.respond(sampleInBall(new Uint8Array(32)));
    expect(() => party.respond(sampleInBall(new Uint8Array(32)))).toThrow(/nonce reuse/i);
  });
});

describe('the honest two-party signing path', () => {
  it('produces a signature its own verifier accepts, 20 times running', () => {
    for (let trial = 0; trial < 20; trial += 1) {
      const setup = toyDkg();
      const outcome = toyThresholdSign(encodeText(`msg-${trial}`), setup);
      expect(outcome.status).toBe('signed');
      expect(outcome.signature).not.toBeNull();
      expect(outcome.verification?.accepted).toBe(true);
      expect(outcome.verification?.failedCheck).toBe('none');
      expect(outcome.attempts.length).toBeLessThan(TOY_MAX_ATTEMPTS);
      // The combined response really is inside the verifier's bound.
      expect(outcome.verification!.zNorm).toBeLessThan(TOY_Z_BOUND);
      expect(outcome.verification!.zBound).toBe(TOY_Z_BOUND);
    }
  });

  it('records a real rejection-sampling trace, with restarts counted', () => {
    let sawARestart = false;
    let totalAttempts = 0;
    for (let trial = 0; trial < 25; trial += 1) {
      const outcome = toyThresholdSign(encodeText(`trace-${trial}`), toyDkg());
      totalAttempts += outcome.attempts.length;
      expect(outcome.restarts).toBe(outcome.attempts.length - 1);
      // Only the last attempt may be the accepted one.
      outcome.attempts.forEach((attempt, index) => {
        const isLast = index === outcome.attempts.length - 1;
        expect(attempt.accepted).toBe(isLast);
        expect(attempt.accepted).toBe(attempt.serverAccepted && attempt.phoneAccepted);
        expect(attempt.bound).toBe(TOY_PER_PARTY_BOUND);
        if (attempt.serverAccepted) expect(attempt.serverNorm).toBeLessThan(TOY_PER_PARTY_BOUND);
        else expect(attempt.serverNorm).toBeGreaterThanOrEqual(TOY_PER_PARTY_BOUND);
      });
      if (outcome.restarts > 0) sawARestart = true;
    }
    // With both parties accepting ≈37% of rounds, 25 trials without a single
    // abort has probability ≈ 0.37^25 ≈ 6e−11.
    expect(sawARestart).toBe(true);
    expect(totalAttempts).toBeGreaterThan(25);
  });

  it('binds the signature to the message it was made for', () => {
    const setup = toyDkg();
    const outcome = toyThresholdSign(message, setup);
    expect(outcome.verification?.accepted).toBe(true);
    const wrong = toyVerify(encodeText('Transfer $1000 to Mallory'), outcome.signature!, setup.publicKey);
    expect(wrong.accepted).toBe(false);
    expect(wrong.failedCheck).toBe('challenge');
  });

  it('binds the signature to the public key it was made under', () => {
    const outcome = toyThresholdSign(message, toyDkg());
    const other = toyDkg();
    expect(toyVerify(message, outcome.signature!, other.publicKey).accepted).toBe(false);
  });
});

describe('the learner-caused failures', () => {
  it('an over-bound z-share is stopped by the norm check, and no signature is emitted', () => {
    for (let trial = 0; trial < 10; trial += 1) {
      const setup = toyDkg();
      const outcome = toyThresholdSign(encodeText(`inflate-${trial}`), setup, 'inflate');
      expect(outcome.status).toBe('rejected-by-norm-check');
      expect(outcome.rejectedShare).toBe('phone');
      expect(outcome.rejectedNorm).toBeGreaterThanOrEqual(TOY_PER_PARTY_BOUND);
      expect(outcome.signature).toBeNull();
      expect(outcome.verification).toBeNull();
      expect(outcome.tamperDetail).toMatch(/over the per-share bound/);
    }
  });

  it('a one-unit change slips past the norm check and is caught by the verifier', () => {
    for (let trial = 0; trial < 10; trial += 1) {
      const setup = toyDkg();
      const outcome = toyThresholdSign(encodeText(`nudge-${trial}`), setup, 'nudge');
      expect(outcome.status).toBe('signed');
      // The norm check genuinely passed — that is the lesson.
      expect(outcome.verification?.normOk).toBe(true);
      expect(outcome.verification?.challengeOk).toBe(false);
      expect(outcome.verification?.accepted).toBe(false);
      expect(outcome.verification?.failedCheck).toBe('challenge');
      expect(outcome.tamperDetail).toMatch(/single unit/);
    }
  });

  it('one party alone cannot make a signature the verifier accepts', () => {
    for (let trial = 0; trial < 10; trial += 1) {
      const setup = toyDkg();
      const solo = toySinglePartyAttempt(encodeText(`solo-${trial}`), setup);
      // The server really did produce a well-formed (c, z) pair…
      expect(solo.signature.z.length).toBe(TOY_L);
      expect(solo.verification.normOk).toBe(true);
      // …and it is rejected, because t commits to BOTH shares.
      expect(solo.verification.accepted).toBe(false);
      expect(solo.verification.failedCheck).toBe('challenge');
    }
  });
});

describe('the verifier itself', () => {
  it('rejects a z that is inside the ring but over the norm bound', () => {
    const setup = toyDkg();
    const outcome = toyThresholdSign(message, setup);
    const z = outcome.signature!.z.map((poly) => Int32Array.from(poly));
    z[0][0] = TOY_Z_BOUND + 1;
    const verdict = toyVerify(message, { c: outcome.signature!.c, z }, setup.publicKey);
    expect(verdict.normOk).toBe(false);
    expect(verdict.failedCheck).toBe('norm');
    expect(verdict.accepted).toBe(false);
    expect(verdict.zNorm).toBeGreaterThan(TOY_Z_BOUND);
  });

  it('rejects a swapped challenge', () => {
    const setup = toyDkg();
    const outcome = toyThresholdSign(message, setup);
    const verdict = toyVerify(
      message,
      { c: sampleInBall(encodeText('not the real challenge')), z: outcome.signature!.z },
      setup.publicKey,
    );
    expect(verdict.accepted).toBe(false);
    expect(verdict.challengeOk).toBe(false);
  });

  it('recomputes w = A·z − c·t exactly, which is why there is no hint', () => {
    const setup = toyDkg();
    const outcome = toyThresholdSign(message, setup);
    const A = expandA(setup.publicKey.rho);
    const Az = matVecMul(A, outcome.signature!.z);
    const ct = setup.publicKey.t.map((poly) => mulPoly(outcome.signature!.c, poly));
    const w = Az.map((poly, i) => subPoly(poly, ct[i]));
    expect(Array.from(challenge(message, w))).toEqual(Array.from(outcome.signature!.c));
  });
});
