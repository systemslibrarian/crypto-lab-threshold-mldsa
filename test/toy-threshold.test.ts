/**
 * Guards on the toy never-combine threshold protocol.
 *
 * These run the protocol rather than inspecting it. Margin: a 300-cycle sweep
 * (each cycle = one DKG plus an honest sign, an over-bound tamper, a one-unit
 * tamper and a single-party forgery attempt) was clean, with a worst case of 12
 * against a 60-attempt budget. A 20,000-signature re-measurement on 15 November
 * 2026 put the mean at 2.72 attempts (worst case 21, none exhausting the
 * budget); the 2.52 previously recorded here was a small-sample artefact of that
 * 300-cycle run, and 2.72 is what the parameters predict — see the mean-attempt
 * test below. The suite re-runs a smaller version of the sweep on every run.
 */
import { describe, expect, it } from 'vitest';

import { encodeText } from '../src/mldsa-primitives';
import {
  TOY_BETA,
  TOY_ETA,
  TOY_GAMMA1,
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

describe('the rejection bound is the one FIPS 204 states', () => {
  it('is γ₁ − β, with β = τ·η — not β', () => {
    // FIPS 204 Algorithm 7, line 23: reject while ‖z‖∞ ≥ γ₁ − β, with β = τ·η
    // from Table 1. The page used to print the check as "‖z‖∞ < β", which is a
    // much tighter bound than the standard's and is not what this code does.
    expect(TOY_BETA).toBe(TOY_TAU * TOY_ETA);
    expect(TOY_PER_PARTY_BOUND).toBe(TOY_GAMMA1 - TOY_BETA);
    expect(TOY_PER_PARTY_BOUND).toBeGreaterThan(TOY_BETA);
    // The verifier's bound is the two parties' bounds added, not β either.
    expect(TOY_Z_BOUND).toBe(2 * (TOY_GAMMA1 - TOY_BETA));
  });

  it('accepts a response that β alone would have rejected', () => {
    // A z-share whose norm sits between β and γ₁ − β is valid under the
    // standard's check and would have been thrown away under the printed one.
    const setup = toyDkg();
    let sawOne = false;
    for (let trial = 0; trial < 40 && !sawOne; trial += 1) {
      const outcome = toyThresholdSign(encodeText(`bound-${trial}`), setup);
      for (const attempt of outcome.attempts) {
        if (attempt.serverAccepted && attempt.serverNorm > TOY_BETA) sawOne = true;
      }
    }
    expect(sawOne).toBe(true);
  });
});

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

  it('aborts at the rate the parameters predict: a mean of 2.72 attempts', () => {
    // The README and the two margin notes in this suite quote this figure, so
    // it is pinned here rather than left to a reader's memory of one sample.
    //
    // y is uniform over 2·γ₁ − 1 values per coefficient and c·s shifts it by a
    // fixed amount, so a party accepts a coefficient with probability
    // (2(γ₁ − β) − 1)/(2γ₁ − 1) exactly, independently across n·l coefficients;
    // both parties must accept, and attempts are geometric in that.
    const perCoefficient = (2 * TOY_PER_PARTY_BOUND - 1) / (2 * TOY_GAMMA1 - 1);
    const bothAccept = perCoefficient ** (2 * TOY_N * TOY_L);
    expect(bothAccept).toBeCloseTo(0.3671, 4);
    // 2.72, the figure the documentation states. 2.52 came from a 300-cycle
    // sample and is outside this band.
    expect(1 / bothAccept).toBeCloseTo(2.72, 2);

    // ...and the harness really does behave that way. 240 runs put the standard
    // error near 0.14, so a ±0.75 band is ~5 SE: wide enough never to flake,
    // narrow enough to catch a protocol change that moved the abort rate.
    const RUNS = 240;
    let attempts = 0;
    let worst = 0;
    for (let trial = 0; trial < RUNS; trial += 1) {
      const outcome = toyThresholdSign(encodeText(`rate-${trial}`), toyDkg());
      expect(outcome.status).toBe('signed');
      attempts += outcome.attempts.length;
      worst = Math.max(worst, outcome.attempts.length);
    }
    expect(attempts / RUNS).toBeGreaterThan(1 / bothAccept - 0.75);
    expect(attempts / RUNS).toBeLessThan(1 / bothAccept + 0.75);
    expect(worst).toBeLessThan(TOY_MAX_ATTEMPTS);
    // 240 signatures at these dimensions run past the 5 s default.
  }, 60_000);

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
