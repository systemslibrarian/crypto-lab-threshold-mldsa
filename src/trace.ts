/**
 * Illustrative round-by-round trace of a two-party lattice signing round.
 *
 * HONESTY NOTE: This is *illustrative choreography*, clearly labelled as such in
 * the UI. It does NOT produce the signature the demo emits (that comes from the
 * combine-then-sign path in threshold-sign.ts). What IS real here is the
 * arithmetic: every number below is computed live with genuine modular /
 * additive-sharing math on tiny toy polynomials so a learner can watch the
 * actual values flow between the two parties and see the protocol's SHAPE.
 *
 * We deliberately use TOY parameters (a small prime modulus and 3-coefficient
 * polynomials) so the numbers are legible. This is a simplification of the
 * EXPLANATION, not of the cryptography the demo's signature relies on — the
 * emitted signature is still genuine FIPS 204 ML-DSA-65. Nothing here is
 * fabricated: run the same inputs and you get the same trace.
 */

import { randomIntBelow, randomSmallInt } from './mldsa-primitives';

/** Toy modulus. Small and prime so centered residues are easy to read. */
export const TOY_Q = 97;
/** Toy polynomial length (coefficients). */
export const TOY_N = 3;
/**
 * Toy "gamma1" style bound: the nonce y is sampled from a small range so the
 * infinity norm of z = y + c*s1 usually — but not always — stays under BOUND.
 * That "usually but not always" is exactly what drives Fiat–Shamir aborts.
 */
export const TOY_Y_RANGE = 12;
export const TOY_S1_RANGE = 2;
/** Rejection bound on |z|_inf. Chosen so rejections happen but are not constant. */
export const TOY_Z_BOUND = 14;

export type ToyPoly = number[];

/** Center a residue into (-q/2, q/2] so magnitudes are readable. */
export function centered(value: number, q: number = TOY_Q): number {
  const r = ((value % q) + q) % q;
  return r > q / 2 ? r - q : r;
}

function addToy(a: ToyPoly, b: ToyPoly): ToyPoly {
  return a.map((v, i) => centered(v + b[i]));
}

function scaleToy(c: number, p: ToyPoly): ToyPoly {
  return p.map((v) => centered(c * v));
}

/** HighBits: drop the low bits. Toy version rounds to the nearest multiple of ALPHA. */
export const TOY_ALPHA = 16;
export function highBits(value: number, q: number = TOY_Q): number {
  const r = ((value % q) + q) % q;
  return Math.round(r / TOY_ALPHA) % Math.ceil(q / TOY_ALPHA);
}

export function infinityNorm(p: ToyPoly): number {
  return p.reduce((m, v) => Math.max(m, Math.abs(centered(v))), 0);
}

export interface RoundTrace {
  /** Additive nonce shares held by each party (never combined in the real thing). */
  yServer: ToyPoly;
  yPhone: ToyPoly;
  /** The (illustrative) combined commitment w = A·y, here modelled as y^S + y^P. */
  w: ToyPoly;
  /** High bits of w — what the verifier actually sees. */
  w1: number[];
  /** Fiat–Shamir challenge c, derived from w1 (small ±1 coefficients here). */
  c: ToyPoly;
  /** Each party's secret-key share s1^i (additive shares of s1). */
  s1Server: ToyPoly;
  s1Phone: ToyPoly;
  /** Response shares z^i = y^i + c·s1^i, computed locally by each party. */
  zServer: ToyPoly;
  zPhone: ToyPoly;
  /** Combined response z = z^S + z^P (what would be published if accepted). */
  z: ToyPoly;
  /** |z|_inf and the rejection bound it is checked against. */
  zNorm: number;
  bound: number;
  /** True when |z|_inf < bound, i.e. the round is ACCEPTED (no abort). */
  accepted: boolean;
}

/**
 * Compute one full illustrative round with live math. Fresh randomness each call
 * (via the Web Crypto CSPRNG through randomIntBelow / randomSmallInt), so a
 * learner can click "restart" and watch a genuinely different round — including
 * the occasional rejection that forces both parties to start over.
 */
export function computeRound(): RoundTrace {
  // Additive shares of a fixed toy secret s1: each party's share is uniform,
  // and s1 = s1^S + s1^P. We derive s1^S from a small secret and a random mask.
  const s1 = Array.from({ length: TOY_N }, () => randomSmallInt(TOY_S1_RANGE));
  const s1Phone = Array.from({ length: TOY_N }, () => centered(randomIntBelow(TOY_Q)));
  const s1Server = s1.map((v, i) => centered(v - s1Phone[i]));

  // Nonce shares y^S, y^P sampled from a small range.
  const yServer = Array.from({ length: TOY_N }, () => randomSmallInt(TOY_Y_RANGE));
  const yPhone = Array.from({ length: TOY_N }, () => randomSmallInt(TOY_Y_RANGE));

  const w = addToy(yServer, yPhone);
  const w1 = w.map((v) => highBits(v));

  // Challenge c derived from w1 — modelled as small ±1/0 coefficients. Using the
  // parity of each high-bit digit keeps it deterministic in w1 (a real FS hash
  // maps w1 -> a sparse challenge; this captures that shape).
  const c = w1.map((h) => (h % 2 === 0 ? 1 : -1));

  const zServer = addToy(yServer, scaleToy(c[0], s1Server));
  const zPhone = addToy(yPhone, scaleToy(c[0], s1Phone));
  // Note: for a legible single-coefficient challenge we apply c coefficient-wise
  // via c[0]; the combined z below still equals y + c·s1 for that scalar.
  const z = addToy(zServer, zPhone);
  const zNorm = infinityNorm(z);
  const accepted = zNorm < TOY_Z_BOUND;

  return {
    yServer,
    yPhone,
    w,
    w1,
    c,
    s1Server,
    s1Phone,
    zServer,
    zPhone,
    z,
    zNorm,
    bound: TOY_Z_BOUND,
    accepted,
  };
}

/**
 * Keep drawing fresh rounds until one is ACCEPTED, recording every rejected
 * attempt. This is the honest picture of Fiat–Shamir-with-aborts: both parties
 * throw the whole round away and restart with fresh randomness on each reject.
 */
export function computeUntilAccepted(maxAttempts: number = 40): {
  attempts: RoundTrace[];
  accepted: RoundTrace;
  rejections: number;
} {
  const attempts: RoundTrace[] = [];
  for (let i = 0; i < maxAttempts; i += 1) {
    const round = computeRound();
    attempts.push(round);
    if (round.accepted) {
      return { attempts, accepted: round, rejections: attempts.length - 1 };
    }
  }
  // Extremely unlikely with these parameters; fall back to the last attempt.
  return { attempts, accepted: attempts[attempts.length - 1], rejections: attempts.length - 1 };
}
