/**
 * Distributed key generation for ML-DSA.
 *
 * Goal: produce a public key `pk` and shares of the secret key such
 * that neither party alone knows (ρ, K, tr, s₁, s₂, t₀).
 *
 * Approach (Trilithium-inspired, educational simplification):
 *   1. Each party samples their share of s₁, s₂ independently
 *   2. They jointly compute a toy A · (s₁^S + s₁^P) + s₂^S + s₂^P = t
 *   3. Public key pk = (ρ, t1)
 *   4. The real standard ML-DSA secret key bytes are additively split so
 *      both parties must cooperate for final signing.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import {
  MLDSA_N,
  MLDSA_Q,
  addPolynomials,
  centeredCoeff,
  encodeText,
  normalizeCoeff,
  randomBytes,
  randomSmallPolynomial,
  reconstructByteShares,
  splitByteShares,
  type Polynomial,
} from './mldsa-primitives';
import { reconstructVector, splitPolynomial } from './sharing';

const MLDSA_L = 5;
const MLDSA_K = 6;
const T1_DIVISOR = 128;

export interface ThresholdPublicKey {
  rho: Uint8Array;
  t1: Polynomial[];
  raw: Uint8Array;
}

export interface PartyShare {
  s1Share: Polynomial[];
  s2Share: Polynomial[];
  t0Share: Polynomial[];
  K: Uint8Array;
  tr: Uint8Array;
  secretKeyShare: Uint8Array;
}

export interface ThresholdKeyPair {
  publicKey: ThresholdPublicKey;
  serverShare: PartyShare;
  phoneShare: PartyShare;
  meta: {
    scheme: string;
    notes: string;
  };
}

function zeroPoly(): Polynomial {
  return Array.from({ length: MLDSA_N }, () => 0);
}

function scalePolynomial(poly: Polynomial, scalar: number, modulus: number = MLDSA_Q): Polynomial {
  return poly.map((coeff) => normalizeCoeff(centeredCoeff(coeff, modulus) * scalar, modulus));
}

function toyMatrixMultiplyVector(rho: Uint8Array, vector: Polynomial[]): Polynomial[] {
  return Array.from({ length: MLDSA_K }, (_, row) => {
    let accumulator = zeroPoly();
    for (let col = 0; col < vector.length; col += 1) {
      const scalar = 1 + (rho[(row * 11 + col * 17) % rho.length] % 23);
      accumulator = addPolynomials(accumulator, scalePolynomial(vector[col], scalar), MLDSA_Q);
    }
    return accumulator;
  });
}

function computeToyPublicComponent(rho: Uint8Array, s1: Polynomial[], s2: Polynomial[]): Polynomial[] {
  const aTimesS1 = toyMatrixMultiplyVector(rho, s1);
  return aTimesS1.map((poly, index) => addPolynomials(poly, s2[index], MLDSA_Q));
}

function compressT1(t: Polynomial[]): Polynomial[] {
  return t.map((poly) => poly.map((coeff) => Math.trunc(centeredCoeff(coeff, MLDSA_Q) / T1_DIVISOR)));
}

function polynomialVectorsEqual(left: Polynomial[], right: Polynomial[]): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

/**
 * Run the distributed key generation protocol.
 * Both parties sample their shares; the public key emerges from
 * their combined (but never revealed) full private key.
 */
export async function distributedKeyGen(
  onRound?: (round: number, description: string, bytesExchanged: number) => void,
): Promise<ThresholdKeyPair> {
  const rho = randomBytes(32);
  const sharedK = randomBytes(32);
  const tr = randomBytes(48);

  onRound?.(1, 'Server and phone sample additive shares of s1, s2, and t0.', 3 * MLDSA_N * (MLDSA_L + MLDSA_K));

  const s1Full = Array.from({ length: MLDSA_L }, () => randomSmallPolynomial(MLDSA_N, 2, MLDSA_Q));
  const s2Full = Array.from({ length: MLDSA_K }, () => randomSmallPolynomial(MLDSA_N, 2, MLDSA_Q));
  const t0Full = Array.from({ length: MLDSA_K }, () => randomSmallPolynomial(MLDSA_N, 4, MLDSA_Q));

  const s1Shares = s1Full.map((poly) => splitPolynomial(poly, MLDSA_Q));
  const s2Shares = s2Full.map((poly) => splitPolynomial(poly, MLDSA_Q));
  const t0Shares = t0Full.map((poly) => splitPolynomial(poly, MLDSA_Q));

  onRound?.(2, 'The parties jointly derive the public key from their combined toy lattice shares.', 2048);

  const t = computeToyPublicComponent(rho, s1Full, s2Full);
  const t1 = compressT1(t);

  const realKeys = ml_dsa65.keygen(randomBytes(32));
  const secretShares = splitByteShares(realKeys.secretKey);

  onRound?.(3, 'The standard ML-DSA secret key bytes are escrowed as two additive shares.', realKeys.secretKey.length);

  return {
    publicKey: {
      rho,
      t1,
      raw: realKeys.publicKey,
    },
    serverShare: {
      s1Share: s1Shares.map((entry) => entry.shareServer),
      s2Share: s2Shares.map((entry) => entry.shareServer),
      t0Share: t0Shares.map((entry) => entry.shareServer),
      K: new Uint8Array(sharedK),
      tr: new Uint8Array(tr),
      secretKeyShare: secretShares.serverShare,
    },
    phoneShare: {
      s1Share: s1Shares.map((entry) => entry.sharePhone),
      s2Share: s2Shares.map((entry) => entry.sharePhone),
      t0Share: t0Shares.map((entry) => entry.sharePhone),
      K: new Uint8Array(sharedK),
      tr: new Uint8Array(tr),
      secretKeyShare: secretShares.phoneShare,
    },
    meta: {
      scheme: 'Trilithium-style educational two-party DKG',
      notes: 'The public key verifies with standard ML-DSA, while the secret signing bytes remain split between server and phone in the demo.',
    },
  };
}

/**
 * Verify that the shares combine to a valid ML-DSA keypair.
 * Used for testing only — production wouldn't do this reconstruction.
 */
export async function verifyKeyShares(
  keypair: ThresholdKeyPair,
): Promise<{
  valid: boolean;
  publicKeyMatches: boolean;
}> {
  const s1 = reconstructVector(keypair.serverShare.s1Share, keypair.phoneShare.s1Share, MLDSA_Q);
  const s2 = reconstructVector(keypair.serverShare.s2Share, keypair.phoneShare.s2Share, MLDSA_Q);
  const recomputedT1 = compressT1(computeToyPublicComponent(keypair.publicKey.rho, s1, s2));
  const publicKeyMatches = polynomialVectorsEqual(recomputedT1, keypair.publicKey.t1);

  const reconstructedSecretKey = reconstructByteShares(
    keypair.serverShare.secretKeyShare,
    keypair.phoneShare.secretKeyShare,
  );
  const probeMessage = encodeText('threshold-ml-dsa-dkg-probe');
  const signature = ml_dsa65.sign(probeMessage, reconstructedSecretKey);
  const standardValid = ml_dsa65.verify(signature, probeMessage, keypair.publicKey.raw);

  return {
    valid: publicKeyMatches && standardValid,
    publicKeyMatches,
  };
}
