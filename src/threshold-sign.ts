/**
 * Two-party ML-DSA signing for the teaching lab.
 *
 * HONEST SUMMARY OF WHAT THIS DOES:
 *   - The genuine ML-DSA-65 secret key is held as two additive byte shares.
 *   - To sign, the two shares are COMBINED in one place and the standard
 *     `ml_dsa65.sign` is called. The result is a genuine FIPS 204 signature
 *     that the unmodified standard verifier accepts.
 *   - This delivers 2-of-2 CUSTODY (neither party alone can sign or recover the
 *     key), but NOT key-non-reconstruction. A production threshold scheme must
 *     never combine the key; doing that is the open research problem this lab
 *     explains (Trilithium / Quorus / TOPCOAT — see the README).
 *
 * The round-by-round narrative (`walkthroughSteps`) is an explicitly-labelled
 * illustration of a Trilithium-style protocol's SHAPE. It does not compute the
 * emitted signature and it carries no fabricated "measured" byte/time figures.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { distributedKeyGen, type ThresholdKeyPair } from './dkg';
import {
  encodeText,
  reconstructByteShares,
} from './mldsa-primitives';

export interface WalkthroughStep {
  stepNumber: number;
  description: string;
  serverAction: string;
  phoneAction: string;
  kind: 'illustrative' | 'real';
}

export interface ThresholdSigningResult {
  signature: Uint8Array;
  /** Illustrative protocol steps (shape only — see module docstring). */
  steps: WalkthroughStep[];
  /** Wall-clock time actually measured for reconstruct + standard sign. */
  signTimeMs: number;
  signatureVerifiesWithStandardMLDSA: boolean;
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

function makeZeroShare(length: number): Uint8Array {
  return new Uint8Array(length);
}

/**
 * The illustrative Trilithium-style protocol walkthrough. These steps describe
 * the SHAPE of a real two-party lattice signing round; they do not compute the
 * signature this demo emits. Marked `illustrative` vs `real` so nothing is
 * presented as measured MPC traffic.
 */
export function walkthroughSteps(): WalkthroughStep[] {
  return [
    {
      stepNumber: 1,
      description: 'Both parties sample additive nonce shares y^S and y^P.',
      serverAction: 'Server samples y^S.',
      phoneAction: 'Phone samples y^P.',
      kind: 'illustrative',
    },
    {
      stepNumber: 2,
      description: 'Each party computes a local A·y contribution and exchanges masked summaries.',
      serverAction: 'Server sends w^S.',
      phoneAction: 'Phone sends w^P.',
      kind: 'illustrative',
    },
    {
      stepNumber: 3,
      description: 'The parties derive the shared high bits w₁ and the Fiat–Shamir challenge c.',
      serverAction: 'Server agrees on c.',
      phoneAction: 'Phone agrees on c.',
      kind: 'illustrative',
    },
    {
      stepNumber: 4,
      description: 'Each computes z^i = y^i + c·s₁^i and a secure norm check runs; on failure both restart.',
      serverAction: 'Server computes z^S.',
      phoneAction: 'Phone computes z^P.',
      kind: 'illustrative',
    },
    {
      stepNumber: 5,
      description: 'In this teaching build the two secret-key byte shares are combined in one place and the STANDARD ML-DSA signer produces the actual signature.',
      serverAction: 'Server reveals its byte share.',
      phoneAction: 'Phone reveals its byte share.',
      kind: 'real',
    },
    {
      stepNumber: 6,
      description: 'The emitted signature verifies with the unmodified standard FIPS 204 verifier.',
      serverAction: 'Server checks the verifier accepts.',
      phoneAction: 'Phone checks the verifier accepts.',
      kind: 'real',
    },
  ];
}

export async function verifyWithStandardMLDSA(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: ThresholdKeyPair['publicKey'],
): Promise<boolean> {
  return ml_dsa65.verify(signature, message, publicKey.raw);
}

/**
 * A single party (holding only its own byte share) cannot forge a signature
 * this public key accepts. Returns true when the single-party attempt fails,
 * as it must.
 */
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

/**
 * A malformed (truncated) partner share must abort signing rather than silently
 * producing garbage.
 */
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
 * Combine the two additive byte shares and produce a genuine ML-DSA-65
 * signature. Requires BOTH shares to be present and well-formed.
 */
export async function thresholdSign(
  message: Uint8Array,
  keypair: ThresholdKeyPair,
): Promise<ThresholdSigningResult> {
  validateKeypair(keypair);

  const startedAt = performance.now();
  const fullSecretKey = reconstructByteShares(
    keypair.serverShare.secretKeyShare,
    keypair.phoneShare.secretKeyShare,
  );
  const signature = ml_dsa65.sign(message, fullSecretKey);
  const signTimeMs = Number((performance.now() - startedAt).toFixed(2));

  const verifies = await verifyWithStandardMLDSA(message, signature, keypair.publicKey);

  return {
    signature,
    steps: walkthroughSteps(),
    signTimeMs,
    signatureVerifiesWithStandardMLDSA: verifies,
  };
}

/**
 * A HONEST timing comparison: standalone standard signing vs the
 * reconstruct-then-sign path used by this two-party custody demo. Only
 * genuinely-measured wall-clock time is reported — there are no fabricated
 * "bytes exchanged" figures, because this build does not run real MPC traffic.
 */
export async function comparisonBenchmark(
  iterations: number = 10,
): Promise<{
  iterations: number;
  standaloneAvgTimeMs: number;
  reconstructThenSignAvgTimeMs: number;
  overheadFactor: number;
}> {
  const keypair = await distributedKeyGen();
  const secretKey = reconstructByteShares(keypair.serverShare.secretKeyShare, keypair.phoneShare.secretKeyShare);

  let standaloneTime = 0;
  let thresholdTime = 0;

  for (let i = 0; i < iterations; i += 1) {
    const message = encodeText(`benchmark-message-${i}`);

    const t0 = performance.now();
    const result = await thresholdSign(message, keypair);
    thresholdTime += performance.now() - t0;
    if (!result.signatureVerifiesWithStandardMLDSA) {
      throw new Error('Two-party signing produced a signature the standard verifier rejected.');
    }

    const started = performance.now();
    const signature = ml_dsa65.sign(message, secretKey);
    if (!ml_dsa65.verify(signature, message, keypair.publicKey.raw)) {
      throw new Error('Standalone ML-DSA verification failed during benchmark.');
    }
    standaloneTime += performance.now() - started;
  }

  const standaloneAvgTimeMs = standaloneTime / iterations;
  const reconstructThenSignAvgTimeMs = thresholdTime / iterations;

  return {
    iterations,
    standaloneAvgTimeMs: Number(standaloneAvgTimeMs.toFixed(2)),
    reconstructThenSignAvgTimeMs: Number(reconstructThenSignAvgTimeMs.toFixed(2)),
    overheadFactor: Number((reconstructThenSignAvgTimeMs / Math.max(standaloneAvgTimeMs, 0.01)).toFixed(2)),
  };
}
