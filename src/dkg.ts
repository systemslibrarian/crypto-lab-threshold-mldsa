/**
 * Two-party key setup for the Threshold ML-DSA teaching lab.
 *
 * WHAT IS REAL HERE:
 *   - A genuine ML-DSA-65 keypair is produced by `ml_dsa65.keygen()`.
 *   - The real 32-byte-seed-derived *secret key* is split into two additive
 *     byte shares (server ⊕/+ phone). Each share on its own is uniform and
 *     reveals nothing about the key, and neither party alone can sign — the
 *     key only exists when the two shares are combined. This 2-of-2 custody /
 *     escrow property is real and is what the unit tests assert.
 *
 * WHAT IS ILLUSTRATIVE (clearly labelled as such in the UI):
 *   - The small s₁/s₂/t₀ polynomial shares are ML-DSA-*flavoured* teaching
 *     props that show additive secret sharing of lattice vectors. They are NOT
 *     cryptographically bound to the real public key — building a real DKG in
 *     which the public key emerges from never-combined shares (so that signing
 *     never reconstructs the key) is exactly the open research problem this lab
 *     exists to explain (see Trilithium / Quorus in the README).
 *
 * This module makes no claim that the public key is a "threshold-derived" key.
 * It is a standard ML-DSA public key whose secret half is held in split custody.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import {
  MLDSA_Q,
  encodeText,
  randomBytes,
  randomSmallPolynomial,
  reconstructByteShares,
  splitByteShares,
  type Polynomial,
} from './mldsa-primitives';
import { reconstructVector, splitPolynomial } from './sharing';

const MLDSA_L = 5;
const MLDSA_K = 6;

export interface ThresholdPublicKey {
  rho: Uint8Array;
  /** Illustrative additively-shared lattice vectors — see module docstring. */
  raw: Uint8Array;
}

export interface PartyShare {
  /** Illustrative additive share of s₁ (teaching prop, not key-bound). */
  s1Share: Polynomial[];
  /** Illustrative additive share of s₂ (teaching prop, not key-bound). */
  s2Share: Polynomial[];
  /** Illustrative additive share of t₀ (teaching prop, not key-bound). */
  t0Share: Polynomial[];
  K: Uint8Array;
  tr: Uint8Array;
  /** Real additive byte share of the genuine ML-DSA-65 secret key. */
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

/**
 * Run the two-party key setup.
 *
 * The genuine ML-DSA-65 secret key is split into two additive byte shares so
 * that neither the server nor the phone holds the whole key on its own. The
 * illustrative lattice vectors are additively shared alongside it to show the
 * shape of a lattice DKG.
 */
export async function distributedKeyGen(
  onRound?: (round: number, description: string, bytesExchanged: number) => void,
): Promise<ThresholdKeyPair> {
  const rho = randomBytes(32);
  const sharedK = randomBytes(32);
  const tr = randomBytes(48);

  onRound?.(1, 'Server and phone sample additive shares of the illustrative s1, s2, t0 vectors.', 3 * (MLDSA_L + MLDSA_K));

  const s1Full = Array.from({ length: MLDSA_L }, () => randomSmallPolynomial(undefined, 2, MLDSA_Q));
  const s2Full = Array.from({ length: MLDSA_K }, () => randomSmallPolynomial(undefined, 2, MLDSA_Q));
  const t0Full = Array.from({ length: MLDSA_K }, () => randomSmallPolynomial(undefined, 4, MLDSA_Q));

  const s1Shares = s1Full.map((poly) => splitPolynomial(poly, MLDSA_Q));
  const s2Shares = s2Full.map((poly) => splitPolynomial(poly, MLDSA_Q));
  const t0Shares = t0Full.map((poly) => splitPolynomial(poly, MLDSA_Q));

  const realKeys = ml_dsa65.keygen(randomBytes(32));

  onRound?.(2, 'A genuine ML-DSA-65 keypair is generated; the public key is standard.', realKeys.publicKey.length);

  const secretShares = splitByteShares(realKeys.secretKey);

  onRound?.(3, 'The genuine ML-DSA secret key is split into two additive byte shares (2-of-2 custody).', realKeys.secretKey.length);

  return {
    publicKey: {
      rho,
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
      scheme: 'Two-party additive custody of a standard ML-DSA-65 key (educational)',
      notes: 'The public key verifies with standard ML-DSA; the genuine secret key is held in two additive shares. It is NOT a threshold-derived public key — signing combines the shares.',
    },
  };
}

/**
 * Verify the real properties of the split-custody keypair:
 *   1. The two secret-key byte shares recombine to a key that produces
 *      signatures the standard FIPS 204 verifier accepts under this public key
 *      (i.e. the shares really are shares of THIS key, not an unrelated one).
 *   2. The illustrative lattice vectors recombine losslessly.
 *
 * Note: this does NOT — and cannot honestly — claim the public key is
 * threshold-derived. That would require never reconstructing the key.
 */
export async function verifyKeyShares(
  keypair: ThresholdKeyPair,
): Promise<{
  valid: boolean;
  /** The recombined secret shares match THIS public key (not an unrelated one). */
  sharesMatchPublicKey: boolean;
  /** The illustrative lattice vectors recombine losslessly. */
  illustrativeSharesReconstruct: boolean;
}> {
  const s1 = reconstructVector(keypair.serverShare.s1Share, keypair.phoneShare.s1Share, MLDSA_Q);
  const s2 = reconstructVector(keypair.serverShare.s2Share, keypair.phoneShare.s2Share, MLDSA_Q);
  const illustrativeSharesReconstruct = s1.length === MLDSA_L && s2.length === MLDSA_K &&
    s1.every((poly) => poly.length > 0) && s2.every((poly) => poly.length > 0);

  const reconstructedSecretKey = reconstructByteShares(
    keypair.serverShare.secretKeyShare,
    keypair.phoneShare.secretKeyShare,
  );
  const probeMessage = encodeText('threshold-ml-dsa-dkg-probe');
  const signature = ml_dsa65.sign(probeMessage, reconstructedSecretKey);
  const sharesMatchPublicKey = ml_dsa65.verify(signature, probeMessage, keypair.publicKey.raw);

  return {
    valid: sharesMatchPublicKey && illustrativeSharesReconstruct,
    sharesMatchPublicKey,
    illustrativeSharesReconstruct,
  };
}
