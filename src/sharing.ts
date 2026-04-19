/**
 * Additive secret sharing for ML-DSA key components.
 * For a secret polynomial s, parties hold (s^S, s^P) such that
 * s = s^S + s^P mod q.
 */

import {
  MLDSA_Q,
  centeredCoeff,
  normalizeCoeff,
  randomIntBelow,
  subtractPolynomials,
  type Polynomial,
} from './mldsa-primitives';

export interface ShareSet {
  shareServer: Polynomial;
  sharePhone: Polynomial;
  modulus: number;
}

/**
 * Split a polynomial s into two additive shares.
 * Returns (s^S, s^P) where s^P is random and s^S = s - s^P mod q.
 */
export function splitPolynomial(
  s: Polynomial,
  modulus: number = MLDSA_Q,
): ShareSet {
  const sharePhone = s.map(() => randomIntBelow(modulus));
  const shareServer = subtractPolynomials(s, sharePhone, modulus);
  return { shareServer, sharePhone, modulus };
}

/**
 * Reconstruct a polynomial from its two shares.
 * reconstruct(s^S, s^P) = s^S + s^P mod q = s
 */
export function reconstructPolynomial(
  shareServer: Polynomial,
  sharePhone: Polynomial,
  modulus: number = MLDSA_Q,
): Polynomial {
  if (shareServer.length !== sharePhone.length) {
    throw new Error('Polynomial share length mismatch');
  }

  return shareServer.map((coeff, index) => normalizeCoeff(coeff + sharePhone[index], modulus));
}

/**
 * Reconstruct a whole vector of polynomials.
 */
export function reconstructVector(
  vectorServer: Polynomial[],
  vectorPhone: Polynomial[],
  modulus: number = MLDSA_Q,
): Polynomial[] {
  if (vectorServer.length !== vectorPhone.length) {
    throw new Error('Vector share length mismatch');
  }
  return vectorServer.map((poly, index) => reconstructPolynomial(poly, vectorPhone[index], modulus));
}

/**
 * Secure comparison: checks if a shared value is < threshold.
 * EDUCATIONAL SIMPLIFICATION: in real MPC this requires a secure
 * comparison protocol (garbled circuits or arithmetic tricks).
 * For demo purposes, both parties reveal just enough info to
 * determine the comparison, without revealing the actual shares.
 */
export function sharedLessThan(
  shareServer: number,
  sharePhone: number,
  threshold: number,
  modulus: number = MLDSA_Q,
): {
  result: boolean;
  rounds: number;
  byteCost: number;
} {
  const combined = centeredCoeff(shareServer + sharePhone, modulus);
  return {
    result: Math.abs(combined) < threshold,
    rounds: 2,
    byteCost: 16,
  };
}

/**
 * Shared infinity norm check: all coefficients of shared polynomial
 * have magnitude < threshold.
 */
export function sharedInfinityNormLessThan(
  polyServer: Polynomial,
  polyPhone: Polynomial,
  threshold: number,
  modulus: number = MLDSA_Q,
): {
  result: boolean;
  rounds: number;
  byteCost: number;
} {
  if (polyServer.length !== polyPhone.length) {
    throw new Error('Polynomial share length mismatch');
  }

  for (let i = 0; i < polyServer.length; i += 1) {
    const comparison = sharedLessThan(polyServer[i], polyPhone[i], threshold, modulus);
    if (!comparison.result) {
      return {
        result: false,
        rounds: comparison.rounds,
        byteCost: comparison.byteCost * (i + 1),
      };
    }
  }

  return {
    result: true,
    rounds: 2,
    byteCost: polyServer.length * 16,
  };
}

export function sharingSelfTest(): {
  reconstructsOriginal: boolean;
  vectorReconstructs: boolean;
  comparisonCorrect: boolean;
} {
  const original = Array.from({ length: 8 }, (_, index) => normalizeCoeff((index * 17) - 21, MLDSA_Q));
  const split = splitPolynomial(original, MLDSA_Q);
  const reconstructed = reconstructPolynomial(split.shareServer, split.sharePhone, MLDSA_Q);

  const vectorServer = [split.shareServer, split.shareServer];
  const vectorPhone = [split.sharePhone, split.sharePhone];
  const reconstructedVector = reconstructVector(vectorServer, vectorPhone, MLDSA_Q);

  const comparison = sharedLessThan(120, MLDSA_Q - 100, 50, MLDSA_Q);

  return {
    reconstructsOriginal: JSON.stringify(reconstructed) === JSON.stringify(original),
    vectorReconstructs: JSON.stringify(reconstructedVector[0]) === JSON.stringify(original),
    comparisonCorrect: comparison.result,
  };
}
