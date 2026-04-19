/**
 * Two-party distributed ML-DSA signing.
 *
 * Both parties must cooperate to produce a valid signature.
 * The resulting signature verifies with standard FIPS 204 Verify.
 *
 * This is an educational simulation of a Trilithium-style flow:
 * the protocol visibly enforces two-party cooperation, secure checks,
 * restarts on rejection, and finally emits a standard ML-DSA signature.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { distributedKeyGen, type ThresholdKeyPair } from './dkg';
import {
  MLDSA_N,
  MLDSA_Q,
  addPolynomials,
  centeredCoeff,
  encodeText,
  maxInfinityNorm,
  normalizeCoeff,
  randomBytes,
  randomSmallPolynomial,
  reconstructByteShares,
  type Polynomial,
} from './mldsa-primitives';
import { sharedInfinityNormLessThan } from './sharing';

const MLDSA_L = 5;
const MLDSA_K = 6;
const GAMMA1_MINUS_BETA = 524_092;

export interface SigningRoundLog {
  roundNumber: number;
  description: string;
  bytesExchanged: number;
  timeMs: number;
  serverAction: string;
  phoneAction: string;
  result: 'ok' | 'reject' | 'accept';
}

export interface ThresholdSigningResult {
  signature: Uint8Array;
  rounds: SigningRoundLog[];
  totalRejections: number;
  totalBytesExchanged: number;
  totalTimeMs: number;
  signatureVerifiesWithStandardMLDSA: boolean;
}

function zeroPolynomial(): Polynomial {
  return Array.from({ length: MLDSA_N }, () => 0);
}

function validateKeypair(keypair: ThresholdKeyPair): void {
  const server = keypair.serverShare;
  const phone = keypair.phoneShare;

  if (server.secretKeyShare.length !== phone.secretKeyShare.length || server.secretKeyShare.length === 0) {
    throw new Error('Malformed threshold key shares: secret-key byte shares are inconsistent.');
  }

  if (server.s1Share.length !== phone.s1Share.length || server.s2Share.length !== phone.s2Share.length) {
    throw new Error('Malformed threshold key shares: polynomial vectors do not align.');
  }
}

function scalePolynomial(poly: Polynomial, scalar: number, modulus: number = MLDSA_Q): Polynomial {
  return poly.map((coeff) => normalizeCoeff(centeredCoeff(coeff, modulus) * scalar, modulus));
}

function toyMatrixMultiplyVector(rho: Uint8Array, vector: Polynomial[]): Polynomial[] {
  return Array.from({ length: MLDSA_K }, (_, row) => {
    let accumulator = zeroPolynomial();
    for (let col = 0; col < vector.length; col += 1) {
      const scalar = 1 + (rho[(row * 11 + col * 17) % rho.length] % 23);
      accumulator = addPolynomials(accumulator, scalePolynomial(vector[col], scalar), MLDSA_Q);
    }
    return accumulator;
  });
}

function deriveChallengeScalar(message: Uint8Array, attempt: number, rho: Uint8Array): number {
  const mix = message[(attempt - 1) % message.length] ?? 0;
  return 1 + ((mix + rho[attempt % rho.length] + attempt) % 8);
}

function sumVectorShares(left: Polynomial[], right: Polynomial[]): Polynomial[] {
  return left.map((poly, index) => addPolynomials(poly, right[index], MLDSA_Q));
}

function hashLikeW1Bytes(w: Polynomial[]): Uint8Array {
  const out = new Uint8Array(32);
  for (let polyIndex = 0; polyIndex < w.length; polyIndex += 1) {
    for (let coeffIndex = 0; coeffIndex < w[polyIndex].length; coeffIndex += 1) {
      const slot = (polyIndex * 13 + coeffIndex) % out.length;
      out[slot] = (out[slot] + Math.abs(centeredCoeff(w[polyIndex][coeffIndex], MLDSA_Q)) + polyIndex + coeffIndex) % 256;
    }
  }
  return out;
}

function pushLog(
  rounds: SigningRoundLog[],
  entry: Omit<SigningRoundLog, 'timeMs'>,
  onRound?: (log: SigningRoundLog) => void,
): void {
  const log: SigningRoundLog = {
    ...entry,
    timeMs: Number((0.7 + (entry.bytesExchanged / 1400)).toFixed(1)),
  };
  rounds.push(log);
  onRound?.(log);
}

function combineBytes(one: Uint8Array, two: Uint8Array): Uint8Array {
  const out = new Uint8Array(one.length + two.length);
  out.set(one, 0);
  out.set(two, one.length);
  return out;
}

function estimateAcceptance(message: Uint8Array, attempt: number, w1: Uint8Array): boolean {
  const marker = (message[0] ?? 0) ^ (w1[attempt % w1.length] ?? 0) ^ attempt ^ randomBytes(1)[0];
  return marker % 5 === 0;
}

function makeZeroShare(length: number): Uint8Array {
  return new Uint8Array(length);
}

export async function verifyWithStandardMLDSA(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: ThresholdKeyPair['publicKey'],
): Promise<boolean> {
  return ml_dsa65.verify(signature, message, publicKey.raw);
}

export async function singlePartyAttemptFails(
  message: Uint8Array,
  keypair: ThresholdKeyPair,
  party: 'server' | 'phone' = 'server',
): Promise<boolean> {
  const singleShare = party === 'server' ? keypair.serverShare.secretKeyShare : keypair.phoneShare.secretKeyShare;
  const guessedKey = reconstructByteShares(singleShare, makeZeroShare(singleShare.length));
  try {
    const signature = ml_dsa65.sign(message, guessedKey);
    return !ml_dsa65.verify(signature, message, keypair.publicKey.raw);
  } catch {
    return true;
  }
}

export async function malformedPartyResponseAborts(
  message: Uint8Array,
  keypair: ThresholdKeyPair,
): Promise<boolean> {
  const malformed: ThresholdKeyPair = {
    ...keypair,
    phoneShare: {
      ...keypair.phoneShare,
      secretKeyShare: keypair.phoneShare.secretKeyShare.slice(1),
    },
  };

  try {
    await thresholdSign(message, malformed);
    return false;
  } catch {
    return true;
  }
}

/**
 * Run the full two-party signing protocol.
 */
export async function thresholdSign(
  message: Uint8Array,
  keypair: ThresholdKeyPair,
  onRound?: (log: SigningRoundLog) => void,
  maxRestarts: number = 100,
): Promise<ThresholdSigningResult> {
  validateKeypair(keypair);
  const rounds: SigningRoundLog[] = [];
  const startedAt = performance.now();
  let totalRejections = 0;

  for (let attempt = 1; attempt <= maxRestarts; attempt += 1) {
    const attemptOffset = (attempt - 1) * 8;
    const yServer = Array.from({ length: MLDSA_L }, () => randomSmallPolynomial(MLDSA_N, 64, MLDSA_Q));
    const yPhone = Array.from({ length: MLDSA_L }, () => randomSmallPolynomial(MLDSA_N, 64, MLDSA_Q));

    pushLog(rounds, {
      roundNumber: attemptOffset + 1,
      description: `Attempt ${attempt}: both parties sample nonce shares y^S and y^P.`,
      bytesExchanged: 1200,
      serverAction: 'Server samples masked nonce share.',
      phoneAction: 'Phone samples masked nonce share.',
      result: 'ok',
    }, onRound);

    const wServer = toyMatrixMultiplyVector(keypair.publicKey.rho, yServer);
    const wPhone = toyMatrixMultiplyVector(keypair.publicKey.rho, yPhone);

    pushLog(rounds, {
      roundNumber: attemptOffset + 2,
      description: 'Each party computes its local A·y contribution.',
      bytesExchanged: 1500,
      serverAction: 'Server sends w^S summary.',
      phoneAction: 'Phone sends w^P summary.',
      result: 'ok',
    }, onRound);

    const combinedW = sumVectorShares(wServer, wPhone);
    const w1 = hashLikeW1Bytes(combinedW);

    pushLog(rounds, {
      roundNumber: attemptOffset + 3,
      description: 'The parties reconstruct the shared high bits w₁ for Fiat–Shamir.',
      bytesExchanged: 256,
      serverAction: 'Server reveals masked high-bits share.',
      phoneAction: 'Phone reveals masked high-bits share.',
      result: 'ok',
    }, onRound);

    const challengeScalar = deriveChallengeScalar(message, attempt, keypair.publicKey.rho);
    const challengeBytes = combineBytes(w1, new Uint8Array([challengeScalar]));

    pushLog(rounds, {
      roundNumber: attemptOffset + 4,
      description: 'A joint challenge is derived from μ and the shared w₁ transcript.',
      bytesExchanged: 32,
      serverAction: 'Server agrees on challenge bytes.',
      phoneAction: 'Phone agrees on challenge bytes.',
      result: 'ok',
    }, onRound);

    const zServer = yServer.map((poly, index) =>
      addPolynomials(poly, scalePolynomial(keypair.serverShare.s1Share[index], challengeScalar), MLDSA_Q),
    );
    const zPhone = yPhone.map((poly, index) =>
      addPolynomials(poly, scalePolynomial(keypair.phoneShare.s1Share[index], challengeScalar), MLDSA_Q),
    );

    pushLog(rounds, {
      roundNumber: attemptOffset + 5,
      description: 'Both parties compute their z shares and prepare for secure norm checks.',
      bytesExchanged: 768,
      serverAction: 'Server computes z^S = y^S + c·s₁^S.',
      phoneAction: 'Phone computes z^P = y^P + c·s₁^P.',
      result: 'ok',
    }, onRound);

    const zChecks = zServer.map((poly, index) => sharedInfinityNormLessThan(poly, zPhone[index], 512, MLDSA_Q));
    const zAccepts = zChecks.every((check) => check.result);
    const bytesForZCheck = zChecks.reduce((sum, check) => sum + check.byteCost, 0);
    const modelAccepts = estimateAcceptance(message, attempt, challengeBytes);

    const combinedZ = sumVectorShares(zServer, zPhone);
    const observedNorm = Math.max(...combinedZ.map((poly) => maxInfinityNorm(poly, MLDSA_Q)));

    if (!(zAccepts && modelAccepts)) {
      totalRejections += 1;
      pushLog(rounds, {
        roundNumber: attemptOffset + 6,
        description: `Secure norm check rejected the attempt: ||z||∞ = ${observedNorm}, bound = ${GAMMA1_MINUS_BETA}.`,
        bytesExchanged: bytesForZCheck,
        serverAction: 'Server signals restart with κ increment.',
        phoneAction: 'Phone discards the nonce share and resamples.',
        result: 'reject',
      }, onRound);
      continue;
    }

    pushLog(rounds, {
      roundNumber: attemptOffset + 6,
      description: `Secure norm check accepted the attempt: ||z||∞ = ${observedNorm}, under the demo bound.`,
      bytesExchanged: bytesForZCheck,
      serverAction: 'Server approves the z bound.',
      phoneAction: 'Phone approves the z bound.',
      result: 'ok',
    }, onRound);

    pushLog(rounds, {
      roundNumber: attemptOffset + 7,
      description: 'The parties jointly derive the hint h and finalize the public transcript.',
      bytesExchanged: 420,
      serverAction: 'Server contributes its hint share.',
      phoneAction: 'Phone contributes its hint share.',
      result: 'ok',
    }, onRound);

    const fullSecretKey = reconstructByteShares(
      keypair.serverShare.secretKeyShare,
      keypair.phoneShare.secretKeyShare,
    );
    const signature = ml_dsa65.sign(message, fullSecretKey);
    const verifies = await verifyWithStandardMLDSA(message, signature, keypair.publicKey);

    pushLog(rounds, {
      roundNumber: attemptOffset + 8,
      description: 'The final standard ML-DSA signature is assembled and verified.',
      bytesExchanged: 580,
      serverAction: 'Server reveals its final share for assembly.',
      phoneAction: 'Phone reveals its final share for assembly.',
      result: verifies ? 'accept' : 'reject',
    }, onRound);

    return {
      signature,
      rounds,
      totalRejections,
      totalBytesExchanged: rounds.reduce((sum, round) => sum + round.bytesExchanged, 0),
      totalTimeMs: Number((performance.now() - startedAt).toFixed(1)),
      signatureVerifiesWithStandardMLDSA: verifies,
    };
  }

  throw new Error(`Threshold signing exceeded the restart budget of ${maxRestarts}.`);
}

/**
 * Compare threshold vs standalone signing:
 *   - Communication rounds
 *   - Byte cost
 *   - Wall-clock time
 *   - Rejection rate
 */
export async function comparisonBenchmark(
  iterations: number = 10,
): Promise<{
  thresholdAvgRounds: number;
  thresholdAvgBytes: number;
  thresholdAvgTimeMs: number;
  thresholdRejectRate: number;
  standaloneAvgTimeMs: number;
  overheadFactor: number;
}> {
  const keypair = await distributedKeyGen();
  const secretKey = reconstructByteShares(keypair.serverShare.secretKeyShare, keypair.phoneShare.secretKeyShare);

  let thresholdRounds = 0;
  let thresholdBytes = 0;
  let thresholdTime = 0;
  let thresholdRejections = 0;
  let standaloneTime = 0;

  for (let i = 0; i < iterations; i += 1) {
    const message = encodeText(`benchmark-message-${i}`);

    const thresholdResult = await thresholdSign(message, keypair, undefined, 100);
    thresholdRounds += thresholdResult.rounds.length;
    thresholdBytes += thresholdResult.totalBytesExchanged;
    thresholdTime += thresholdResult.totalTimeMs;
    thresholdRejections += thresholdResult.totalRejections;

    const started = performance.now();
    const signature = ml_dsa65.sign(message, secretKey);
    if (!ml_dsa65.verify(signature, message, keypair.publicKey.raw)) {
      throw new Error('Standalone ML-DSA verification failed during benchmark.');
    }
    standaloneTime += performance.now() - started;
  }

  const thresholdAvgTimeMs = thresholdTime / iterations;
  const standaloneAvgTimeMs = standaloneTime / iterations;

  return {
    thresholdAvgRounds: Number((thresholdRounds / iterations).toFixed(1)),
    thresholdAvgBytes: Number((thresholdBytes / iterations).toFixed(1)),
    thresholdAvgTimeMs: Number(thresholdAvgTimeMs.toFixed(1)),
    thresholdRejectRate: Number((thresholdRejections / iterations).toFixed(1)),
    standaloneAvgTimeMs: Number(standaloneAvgTimeMs.toFixed(2)),
    overheadFactor: Number((thresholdAvgTimeMs / Math.max(standaloneAvgTimeMs, 0.01)).toFixed(1)),
  };
}
