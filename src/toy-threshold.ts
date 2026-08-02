/**
 * toy-threshold.ts — a REAL two-party lattice signature in which the secret key
 * is never combined, at deliberately toy parameters, with its own verifier.
 *
 * WHY THIS MODULE EXISTS
 * ----------------------
 * The rest of this lab is honest about a hard limit: to emit a genuine FIPS 204
 * ML-DSA-65 signature it reconstructs the secret key in one place. That is
 * split custody, not threshold signing, and the page says so plainly.
 *
 * This module is the missing half. It gives up standard-compatibility and real
 * parameters in exchange for the property the headline scheme cannot reach:
 * **the full signing secret is never assembled anywhere, at any point.** Each
 * party samples its own secret share, publishes only A·s^i, and every signing
 * round is executed — nonces, commitment, Fiat–Shamir challenge, per-party
 * rejection sampling, response shares — with a verifier written here that
 * checks the emitted signature.
 *
 * WHAT THE SCHEME IS
 * ------------------
 * Lyubashevsky-style "Fiat–Shamir with aborts" over a module lattice, in the
 * SIS setting (t = A·s exactly, no LWE error term). This is the shape ML-DSA
 * grew out of, minus the high/low-bit decomposition and hint that make ML-DSA
 * compress well and make it painful to split.
 *
 *   KeyGen (distributed, no dealer):
 *     A ← expandA(rho)                       public, k×l over R_q
 *     each party i samples s^i with ‖s^i‖∞ ≤ eta        (LOCAL, never sent)
 *     each party publishes t^i = A·s^i;  t = t^S + t^P
 *     The full s = s^S + s^P is never formed by anyone.
 *
 *   Sign(mu), one attempt:
 *     each party samples y^i uniform with ‖y^i‖∞ < gamma1
 *     each publishes w^i = A·y^i;  w = w^S + w^P
 *     c = SampleInBall(SHAKE256(mu ‖ encode(w)))
 *     each computes z^i = y^i + c·s^i  and checks ‖z^i‖∞ < gamma1 − beta
 *       — if either party rejects, BOTH restart with fresh randomness
 *     signature = (c, z) with z = z^S + z^P
 *
 *   Verify(mu, (c, z)):
 *     ‖z‖∞ < 2(gamma1 − beta)                          and
 *     SampleInBall(SHAKE256(mu ‖ encode(A·z − c·t))) == c
 *
 *   Correctness: A·z − c·t = A·y + c·A·s − c·A·s = A·y = w. Exact, no hint.
 *
 * TOY SCALE — SAID PLAINLY
 * ------------------------
 * n = 64 (ML-DSA uses 256), k = l = 2 (ML-DSA-65 uses 6×5), eta = 2, tau = 8.
 * The underlying module-SIS instance at these dimensions carries NO security
 * and should be assumed breakable. Nothing here is FIPS 204 and no standard
 * verifier will accept its output. What is real is the PROTOCOL: the secret is
 * genuinely never combined, the rejection sampling genuinely runs and genuinely
 * aborts, and the verifier genuinely recomputes the challenge.
 *
 * Randomness is Web Crypto only — never Math.random.
 */

import { shake256 } from '@noble/hashes/sha3.js';

import { randomBytes, randomIntBelow } from './mldsa-primitives';

/* ------------------------------------------------------------------ params */

/** Ring degree: R_q = Z_q[X]/(X^n + 1). ML-DSA uses 256. */
export const TOY_N = 64;
/** Modulus. Same prime ML-DSA uses, so the arithmetic looks familiar. */
export const TOY_Q = 8380417;
/** Rows of the public matrix A. */
export const TOY_K = 2;
/** Columns of A / length of the secret vector. */
export const TOY_L = 2;
/** Per-party secret coefficient bound: ‖s^i‖∞ ≤ eta. */
export const TOY_ETA = 2;
/** Challenge weight: c has exactly tau coefficients in {−1, +1}. */
export const TOY_TAU = 8;
/** Nonce bound: y^i coefficients are uniform in (−gamma1, gamma1). */
export const TOY_GAMMA1 = 4096;
/** Worst case ‖c·s^i‖∞ ≤ tau·eta. The rejection-sampling margin. */
export const TOY_BETA = TOY_TAU * TOY_ETA;
/** A party accepts its own response iff ‖z^i‖∞ < this. */
export const TOY_PER_PARTY_BOUND = TOY_GAMMA1 - TOY_BETA;
/** The verifier's bound on the combined z (two parties, so twice the above). */
export const TOY_Z_BOUND = 2 * TOY_PER_PARTY_BOUND;
/**
 * Attempts before the protocol gives up. Per-party acceptance is about
 * ((2(gamma1−beta)−1)/(2·gamma1−1))^(n·l) ≈ 0.61, so both parties accept with
 * probability ≈ 0.37 and the chance of 60 consecutive failures is ≈ 6e−12.
 */
export const TOY_MAX_ATTEMPTS = 60;

/** A polynomial in R_q, coefficients normalized to [0, q). */
export type ToyPoly = Int32Array;
/** A vector of polynomials. */
export type ToyVec = ToyPoly[];

/* -------------------------------------------------------------- arithmetic */

function mod(value: number): number {
  const r = value % TOY_Q;
  return r < 0 ? r + TOY_Q : r;
}

/** Centered representative in (−q/2, q/2]. */
export function centered(value: number): number {
  const r = mod(value);
  return r > TOY_Q >> 1 ? r - TOY_Q : r;
}

export function zeroPoly(): ToyPoly {
  return new Int32Array(TOY_N);
}

export function addPoly(a: ToyPoly, b: ToyPoly): ToyPoly {
  const out = zeroPoly();
  for (let i = 0; i < TOY_N; i += 1) out[i] = mod(a[i] + b[i]);
  return out;
}

export function subPoly(a: ToyPoly, b: ToyPoly): ToyPoly {
  const out = zeroPoly();
  for (let i = 0; i < TOY_N; i += 1) out[i] = mod(a[i] - b[i]);
  return out;
}

/**
 * Negacyclic product in Z_q[X]/(X^n + 1): wrapping past degree n flips sign.
 * Schoolbook, because n = 64 makes an NTT pointless here and the direct loop is
 * the one a reader can check against the definition.
 */
export function mulPoly(a: ToyPoly, b: ToyPoly): ToyPoly {
  const out = zeroPoly();
  for (let i = 0; i < TOY_N; i += 1) {
    const ai = a[i];
    if (ai === 0) continue;
    for (let j = 0; j < TOY_N; j += 1) {
      const bj = b[j];
      if (bj === 0) continue;
      const k = i + j;
      const product = ai * bj; // < 2^46, exact in a double
      if (k < TOY_N) out[k] = mod(out[k] + product);
      else out[k - TOY_N] = mod(out[k - TOY_N] - product);
    }
  }
  return out;
}

export function addVec(a: ToyVec, b: ToyVec): ToyVec {
  if (a.length !== b.length) throw new Error('vector length mismatch');
  return a.map((poly, i) => addPoly(poly, b[i]));
}

/** Matrix-vector product A·v, where A is k×l and v has length l. */
export function matVecMul(A: ToyVec[], v: ToyVec): ToyVec {
  if (A.length !== TOY_K) throw new Error('matrix has the wrong number of rows');
  if (v.length !== TOY_L) throw new Error('vector has the wrong length');
  return A.map((row) => {
    if (row.length !== TOY_L) throw new Error('matrix row has the wrong length');
    let acc = zeroPoly();
    for (let j = 0; j < TOY_L; j += 1) acc = addPoly(acc, mulPoly(row[j], v[j]));
    return acc;
  });
}

/** Largest centered absolute coefficient across a vector — the ∞-norm. */
export function infinityNorm(v: ToyVec): number {
  let max = 0;
  for (const poly of v) {
    for (let i = 0; i < TOY_N; i += 1) {
      const abs = Math.abs(centered(poly[i]));
      if (abs > max) max = abs;
    }
  }
  return max;
}

/* ---------------------------------------------------------------- sampling */

/**
 * Expand the public matrix A from a 32-byte seed with SHAKE256, rejecting
 * 23-bit draws that land outside [0, q). Deterministic in rho, so both parties
 * derive the identical A — the point of publishing a seed instead of a matrix.
 */
export function expandA(rho: Uint8Array): ToyVec[] {
  if (rho.length !== 32) throw new Error('rho must be 32 bytes');
  const xof = shake256.create({ dkLen: 32 }).update(rho);
  const buffer = new Uint8Array(3);
  const draw = (): number => {
    for (;;) {
      xof.xofInto(buffer);
      const value = (buffer[0] | (buffer[1] << 8) | (buffer[2] << 16)) & 0x7fffff;
      if (value < TOY_Q) return value;
    }
  };
  const A: ToyVec[] = [];
  for (let row = 0; row < TOY_K; row += 1) {
    const cols: ToyVec = [];
    for (let col = 0; col < TOY_L; col += 1) {
      const poly = zeroPoly();
      for (let i = 0; i < TOY_N; i += 1) poly[i] = draw();
      cols.push(poly);
    }
    A.push(cols);
  }
  return A;
}

/** A vector of l polynomials with coefficients uniform in [−bound, bound]. */
function sampleSmallVec(bound: number, length: number): ToyVec {
  return Array.from({ length }, () => {
    const poly = zeroPoly();
    for (let i = 0; i < TOY_N; i += 1) poly[i] = mod(randomIntBelow(2 * bound + 1) - bound);
    return poly;
  });
}

/** A nonce vector: coefficients uniform in (−gamma1, gamma1). */
function sampleNonce(): ToyVec {
  return sampleSmallVec(TOY_GAMMA1 - 1, TOY_L);
}

/**
 * SampleInBall: a polynomial with exactly tau coefficients in {−1, +1} and the
 * rest zero, derived from a seed. This is ML-DSA's own construction (FIPS 204
 * Algorithm 29): take tau sign bits, then Fisher–Yates the nonzero positions
 * into place using rejection-sampled bytes.
 */
export function sampleInBall(seed: Uint8Array): ToyPoly {
  const xof = shake256.create({ dkLen: 32 }).update(seed);
  const signBytes = new Uint8Array(8);
  xof.xofInto(signBytes);
  let signs = 0n;
  for (let i = 7; i >= 0; i -= 1) signs = (signs << 8n) | BigInt(signBytes[i]);

  const c = zeroPoly();
  const byte = new Uint8Array(1);
  for (let i = TOY_N - TOY_TAU; i < TOY_N; i += 1) {
    let j: number;
    do {
      xof.xofInto(byte);
      j = byte[0];
    } while (j > i);
    c[i] = c[j];
    c[j] = mod((signs & 1n) === 1n ? -1 : 1);
    signs >>= 1n;
  }
  return c;
}

/** Serialize a vector as 4-byte little-endian coefficients, for hashing. */
export function encodeVec(v: ToyVec): Uint8Array {
  const out = new Uint8Array(v.length * TOY_N * 4);
  let offset = 0;
  for (const poly of v) {
    for (let i = 0; i < TOY_N; i += 1) {
      const value = mod(poly[i]);
      out[offset] = value & 0xff;
      out[offset + 1] = (value >>> 8) & 0xff;
      out[offset + 2] = (value >>> 16) & 0xff;
      out[offset + 3] = (value >>> 24) & 0xff;
      offset += 4;
    }
  }
  return out;
}

/** The Fiat–Shamir challenge: c = SampleInBall(SHAKE256(mu ‖ encode(w))). */
export function challenge(message: Uint8Array, w: ToyVec): ToyPoly {
  const encoded = encodeVec(w);
  const seed = new Uint8Array(message.length + encoded.length);
  seed.set(message, 0);
  seed.set(encoded, message.length);
  return sampleInBall(seed);
}

/* ------------------------------------------------------------- key material */

export interface ToyPublicKey {
  /** Seed the public matrix A is expanded from. */
  rho: Uint8Array;
  /** t = A·s^S + A·s^P. The only thing derived from the secrets that is public. */
  t: ToyVec;
}

/**
 * One signing party. The secret share lives in a closure and is NOT a property
 * of this object: there is no field for anything else to read, so "the shares
 * are never combined" is a structural fact about this type rather than a
 * promise in a comment. The only ways out are the two protocol methods, and
 * neither returns s.
 */
export interface ToyParty {
  readonly name: 'server' | 'phone';
  /** t^i = A·s^i — this party's public contribution. Safe to publish. */
  readonly publicShare: ToyVec;
  /** Sample a fresh nonce and return the commitment w^i = A·y^i. */
  commit(): ToyVec;
  /**
   * Compute z^i = y^i + c·s^i for the nonce from the last commit(), and report
   * whether it passes this party's own rejection-sampling bound. Consumes the
   * nonce: calling it twice for one commitment throws, because reusing a nonce
   * across two challenges is exactly how a lattice signature leaks its key.
   */
  respond(c: ToyPoly): { z: ToyVec; norm: number; accepted: boolean };
}

/** Create a party holding a freshly sampled secret share. */
export function createParty(name: 'server' | 'phone', A: ToyVec[]): ToyParty {
  const s = sampleSmallVec(TOY_ETA, TOY_L);
  const publicShare = matVecMul(A, s);
  let nonce: ToyVec | null = null;

  return {
    name,
    publicShare,
    commit(): ToyVec {
      nonce = sampleNonce();
      return matVecMul(A, nonce);
    },
    respond(c: ToyPoly): { z: ToyVec; norm: number; accepted: boolean } {
      if (nonce === null) {
        throw new Error(`${name}: respond() called without a fresh commit() — nonce reuse refused.`);
      }
      const y = nonce;
      nonce = null; // one nonce, one challenge. Never twice.
      const z = y.map((poly, i) => addPoly(poly, mulPoly(c, s[i])));
      const norm = infinityNorm(z);
      return { z, norm, accepted: norm < TOY_PER_PARTY_BOUND };
    },
  };
}

export interface ToySetup {
  publicKey: ToyPublicKey;
  A: ToyVec[];
  server: ToyParty;
  phone: ToyParty;
}

/**
 * Distributed key generation with no dealer and no combination step. Each party
 * samples its own s^i and publishes A·s^i; the public key is the sum. Nothing
 * in this function ever sees both secret shares — it cannot, because neither
 * party exposes one.
 */
export function toyDkg(): ToySetup {
  const rho = randomBytes(32);
  const A = expandA(rho);
  const server = createParty('server', A);
  const phone = createParty('phone', A);
  return {
    A,
    server,
    phone,
    publicKey: { rho, t: addVec(server.publicShare, phone.publicShare) },
  };
}

/* ------------------------------------------------------------- the protocol */

export interface ToySignature {
  c: ToyPoly;
  z: ToyVec;
}

export interface ToyVerification {
  accepted: boolean;
  /** ‖z‖∞ measured from the signature under test. */
  zNorm: number;
  zBound: number;
  normOk: boolean;
  /** Whether the recomputed Fiat–Shamir challenge equals the one in the signature. */
  challengeOk: boolean;
  /** Which check failed first, for a verdict that says only what was learned. */
  failedCheck: 'none' | 'norm' | 'challenge';
}

/**
 * The toy verifier. Recomputes w' = A·z − c·t and re-derives the challenge from
 * it; both the norm bound and the challenge equality must hold. This is the
 * whole verification algorithm — there is nothing else to trust.
 */
export function toyVerify(
  message: Uint8Array,
  signature: ToySignature,
  publicKey: ToyPublicKey,
): ToyVerification {
  const A = expandA(publicKey.rho);
  const zNorm = infinityNorm(signature.z);
  const normOk = zNorm < TOY_Z_BOUND;

  const Az = matVecMul(A, signature.z);
  const ct = publicKey.t.map((poly) => mulPoly(signature.c, poly));
  const wPrime = Az.map((poly, i) => subPoly(poly, ct[i]));
  const recomputed = challenge(message, wPrime);
  let challengeOk = true;
  for (let i = 0; i < TOY_N; i += 1) {
    if (recomputed[i] !== signature.c[i]) {
      challengeOk = false;
      break;
    }
  }

  return {
    accepted: normOk && challengeOk,
    zNorm,
    zBound: TOY_Z_BOUND,
    normOk,
    challengeOk,
    failedCheck: !normOk ? 'norm' : !challengeOk ? 'challenge' : 'none',
  };
}

/** How the learner may corrupt the phone's response share. */
export type ToyTamper = 'none' | 'inflate' | 'nudge';

export interface ToyAttemptTrace {
  attempt: number;
  serverNorm: number;
  phoneNorm: number;
  bound: number;
  serverAccepted: boolean;
  phoneAccepted: boolean;
  accepted: boolean;
}

export interface ToySignOutcome {
  /**
   * 'signed'                — a signature was produced (verify it to judge it)
   * 'rejected-by-norm-check'— a partner's z-share failed the bound, so the
   *                           protocol refused to combine and emitted nothing
   * 'out-of-attempts'       — rejection sampling never converged in the budget
   */
  status: 'signed' | 'rejected-by-norm-check' | 'out-of-attempts';
  attempts: ToyAttemptTrace[];
  /** Rounds thrown away before one was accepted. */
  restarts: number;
  signature: ToySignature | null;
  /** The toy verifier's own verdict on the emitted signature, if any. */
  verification: ToyVerification | null;
  tamper: ToyTamper;
  /** Human-readable statement of what the tamper did, if anything. */
  tamperDetail: string | null;
  /** Which party's share the norm check rejected, when it did. */
  rejectedShare: 'server' | 'phone' | null;
  /** The ∞-norm the norm check measured on the rejected share. */
  rejectedNorm: number | null;
  elapsedMs: number;
  /** Small slices of the real values, for display. Never fabricated. */
  sample: {
    serverZ: number[];
    phoneZ: number[];
    combinedZ: number[];
    challengeSupport: Array<{ index: number; value: number }>;
  } | null;
}

function firstCoeffs(v: ToyVec, count = 3): number[] {
  return Array.from({ length: count }, (_, i) => centered(v[0][i]));
}

function challengeSupport(c: ToyPoly): Array<{ index: number; value: number }> {
  const out: Array<{ index: number; value: number }> = [];
  for (let i = 0; i < TOY_N && out.length < 6; i += 1) {
    const value = centered(c[i]);
    if (value !== 0) out.push({ index: i, value });
  }
  return out;
}

/**
 * Run the two-party protocol for real.
 *
 * `tamper` corrupts the PHONE's response share after it computes it, so the
 * learner can watch a specific defence fire:
 *   'inflate' adds gamma1 to one coefficient — far over the per-share bound, so
 *             the server's check on the incoming share rejects it and NO
 *             signature is emitted.
 *   'nudge'   adds 1 to one coefficient — small enough to slip past the norm
 *             check, so a signature IS emitted and the verifier's Fiat–Shamir
 *             recomputation is what catches it.
 * Which check fired is reported from the run, not assumed.
 */
export function toyThresholdSign(
  message: Uint8Array,
  setup: ToySetup,
  tamper: ToyTamper = 'none',
): ToySignOutcome {
  const startedAt = performance.now();
  const attempts: ToyAttemptTrace[] = [];

  for (let attempt = 1; attempt <= TOY_MAX_ATTEMPTS; attempt += 1) {
    const wServer = setup.server.commit();
    const wPhone = setup.phone.commit();
    const w = addVec(wServer, wPhone);
    const c = challenge(message, w);

    const server = setup.server.respond(c);
    const phone = setup.phone.respond(c);

    attempts.push({
      attempt,
      serverNorm: server.norm,
      phoneNorm: phone.norm,
      bound: TOY_PER_PARTY_BOUND,
      serverAccepted: server.accepted,
      phoneAccepted: phone.accepted,
      accepted: server.accepted && phone.accepted,
    });

    if (!server.accepted || !phone.accepted) continue;

    // Both parties accepted their own share. Now apply the learner's tamper to
    // the phone's share as it crosses the channel.
    let phoneZ = phone.z;
    let tamperDetail: string | null = null;
    if (tamper === 'inflate') {
      // Overwrite one coefficient with a value that is unambiguously over the
      // bound. (Merely ADDING a large delta is not enough: modular wrap-around
      // can land a big offset back inside the bound, which would make the
      // exhibit's outcome a coin flip instead of a demonstration.)
      const forced = TOY_PER_PARTY_BOUND + 512;
      phoneZ = phoneZ.map((poly, index) => {
        if (index !== 0) return poly;
        const copy = Int32Array.from(poly);
        copy[0] = mod(forced);
        return copy;
      });
      tamperDetail =
        `Coefficient 0 of the phone's z-share was overwritten with ${forced.toLocaleString()}, ` +
        `which is ${(forced - TOY_PER_PARTY_BOUND).toLocaleString()} over the per-share bound of ` +
        `${TOY_PER_PARTY_BOUND.toLocaleString()}.`;
    } else if (tamper === 'nudge') {
      // Add 1 to the SMALLEST coefficient, so the ∞-norm provably cannot cross
      // the bound and the norm check is guaranteed to wave this one through.
      let smallest = 0;
      for (let i = 1; i < TOY_N; i += 1) {
        if (Math.abs(centered(phoneZ[0][i])) < Math.abs(centered(phoneZ[0][smallest]))) smallest = i;
      }
      const before = centered(phoneZ[0][smallest]);
      phoneZ = phoneZ.map((poly, index) => {
        if (index !== 0) return poly;
        const copy = Int32Array.from(poly);
        copy[smallest] = mod(copy[smallest] + 1);
        return copy;
      });
      tamperDetail =
        `Coefficient ${smallest} of the phone's z-share was changed from ${before} to ${before + 1} — ` +
        `a single unit, deliberately on the smallest coefficient so the norm check cannot catch it.`;
    }

    // Each party checks the share it RECEIVES against the same bound it applied
    // to its own. This is the norm check the choreography used to only narrate.
    const receivedNorm = infinityNorm(phoneZ);
    if (receivedNorm >= TOY_PER_PARTY_BOUND) {
      return {
        status: 'rejected-by-norm-check',
        attempts,
        restarts: attempts.length - 1,
        signature: null,
        verification: null,
        tamper,
        tamperDetail,
        rejectedShare: 'phone',
        rejectedNorm: receivedNorm,
        elapsedMs: performance.now() - startedAt,
        sample: null,
      };
    }

    const z = addVec(server.z, phoneZ);
    const signature: ToySignature = { c, z };
    const verification = toyVerify(message, signature, setup.publicKey);

    return {
      status: 'signed',
      attempts,
      restarts: attempts.length - 1,
      signature,
      verification,
      tamper,
      tamperDetail,
      rejectedShare: null,
      rejectedNorm: null,
      elapsedMs: performance.now() - startedAt,
      sample: {
        serverZ: firstCoeffs(server.z),
        phoneZ: firstCoeffs(phoneZ),
        combinedZ: firstCoeffs(z),
        challengeSupport: challengeSupport(c),
      },
    };
  }

  return {
    status: 'out-of-attempts',
    attempts,
    restarts: attempts.length,
    signature: null,
    verification: null,
    tamper,
    tamperDetail: null,
    rejectedShare: null,
    rejectedNorm: null,
    elapsedMs: performance.now() - startedAt,
    sample: null,
  };
}

/**
 * The custody check, executed rather than asserted: the server runs the whole
 * protocol on its own, treating the phone's contribution as absent. It gets a
 * well-formed (c, z) pair — and the verifier rejects it, because the public key
 * commits to BOTH secret shares. Returns the verifier's actual verdict.
 */
export function toySinglePartyAttempt(
  message: Uint8Array,
  setup: ToySetup,
): { signature: ToySignature; verification: ToyVerification } {
  for (let attempt = 0; attempt < TOY_MAX_ATTEMPTS; attempt += 1) {
    const w = setup.server.commit();
    const c = challenge(message, w);
    const response = setup.server.respond(c);
    if (!response.accepted) continue;
    const signature: ToySignature = { c, z: response.z };
    return { signature, verification: toyVerify(message, signature, setup.publicKey) };
  }
  throw new Error('single-party attempt never cleared its own norm bound');
}
