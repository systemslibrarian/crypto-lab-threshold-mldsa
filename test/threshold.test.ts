import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { describe, expect, it } from 'vitest';

import { distributedKeyGen, verifyKeyShares } from '../src/dkg';
import { encodeText, reconstructByteShares } from '../src/mldsa-primitives';
import {
  comparisonBenchmark,
  malformedPartyResponseAborts,
  singlePartyAttemptFails,
  thresholdSign,
  verifyWithStandardMLDSA,
  walkthroughSteps,
} from '../src/threshold-sign';

describe('distributed key setup', () => {
  it('splits a GENUINE ml_dsa65 secret key: the two byte shares recombine to a key bound to THIS public key', async () => {
    const kp = await distributedKeyGen();
    const recombined = reconstructByteShares(
      kp.serverShare.secretKeyShare,
      kp.phoneShare.secretKeyShare,
    );
    // The recombined secret key must sign under THIS public key.
    const msg = encodeText('bind-check');
    const sig = ml_dsa65.sign(msg, recombined);
    expect(ml_dsa65.verify(sig, msg, kp.publicKey.raw)).toBe(true);
  });

  it('verifyKeyShares confirms the shares match the public key (guards against the old disconnect)', async () => {
    const kp = await distributedKeyGen();
    const check = await verifyKeyShares(kp);
    expect(check.sharesMatchPublicKey).toBe(true);
    expect(check.valid).toBe(true);
  });

  it('REGRESSION: shares from a DIFFERENT keypair must NOT verify under this public key', async () => {
    // The original bug: verify checked the toy lattice against itself and the
    // real key against itself, so a public key unrelated to the shares still
    // "passed". Swap in a foreign public key and require the check to FAIL.
    const kp = await distributedKeyGen();
    const other = await distributedKeyGen();
    const frankenstein = {
      ...kp,
      publicKey: other.publicKey, // shares of kp, public key of other
    };
    const check = await verifyKeyShares(frankenstein);
    expect(check.sharesMatchPublicKey).toBe(false);
    expect(check.valid).toBe(false);
  });

  it('the public key is a standard ML-DSA-65 public key (1952 bytes)', async () => {
    const kp = await distributedKeyGen();
    expect(kp.publicKey.raw.length).toBe(1952);
  });
});

describe('two-party signing (combine-then-sign)', () => {
  it('produces a signature the UNMODIFIED standard verifier accepts (round-trip)', async () => {
    const kp = await distributedKeyGen();
    const msg = encodeText('Transfer $1000 to Alice');
    const result = await thresholdSign(msg, kp);
    expect(result.signatureVerifiesWithStandardMLDSA).toBe(true);
    // Independent verification with the raw noble verifier.
    expect(ml_dsa65.verify(result.signature, msg, kp.publicKey.raw)).toBe(true);
  });

  it('a single party alone cannot forge an accepted signature', async () => {
    const kp = await distributedKeyGen();
    const msg = encodeText('forge attempt');
    expect(await singlePartyAttemptFails(msg, kp, 'server')).toBe(true);
    expect(await singlePartyAttemptFails(msg, kp, 'phone')).toBe(true);
  });

  it('aborts when a partner share is malformed (truncated)', async () => {
    const kp = await distributedKeyGen();
    const msg = encodeText('malformed partner');
    expect(await malformedPartyResponseAborts(msg, kp)).toBe(true);
  });

  it('the standard verifier rejects a tampered signature (forgery rejection)', async () => {
    const kp = await distributedKeyGen();
    const msg = encodeText('tamper the signature');
    const result = await thresholdSign(msg, kp);
    const tampered = result.signature.slice();
    tampered[0] ^= 0xff;
    expect(await verifyWithStandardMLDSA(msg, tampered, kp.publicKey)).toBe(false);
  });

  it('the standard verifier rejects the signature on a different message', async () => {
    const kp = await distributedKeyGen();
    const msg = encodeText('the real message');
    const result = await thresholdSign(msg, kp);
    const otherMsg = encodeText('a different message');
    expect(await verifyWithStandardMLDSA(otherMsg, result.signature, kp.publicKey)).toBe(false);
  });
});

describe('honesty of the walkthrough and benchmark', () => {
  it('walkthrough steps are explicitly labelled illustrative vs real', () => {
    const steps = walkthroughSteps();
    expect(steps.length).toBeGreaterThan(0);
    expect(steps.some((s) => s.kind === 'illustrative')).toBe(true);
    // The step that actually produces the signature must be flagged as real and
    // must disclose that the key is combined in one place.
    const realSteps = steps.filter((s) => s.kind === 'real');
    expect(realSteps.length).toBeGreaterThan(0);
    expect(realSteps.some((s) => /combined|standard ML-DSA signer/i.test(s.description))).toBe(true);
  });

  it('the signing result carries NO fabricated MPC byte counts', async () => {
    const kp = await distributedKeyGen();
    const result = await thresholdSign(encodeText('x'), kp);
    // The result surface must not resurrect the old fabricated fields.
    expect('totalBytesExchanged' in result).toBe(false);
    expect('rounds' in result).toBe(false);
    // Only a genuinely measured time is present.
    expect(typeof result.signTimeMs).toBe('number');
    expect(result.signTimeMs).toBeGreaterThanOrEqual(0);
  });

  it('benchmark reports only measured wall-clock time, not fabricated bytes', async () => {
    const bench = await comparisonBenchmark(3);
    expect(bench.iterations).toBe(3);
    expect(bench.standaloneAvgTimeMs).toBeGreaterThan(0);
    expect(bench.reconstructThenSignAvgTimeMs).toBeGreaterThan(0);
    expect(Number.isFinite(bench.overheadFactor)).toBe(true);
    // No fabricated communication figures leak into the benchmark surface.
    expect('thresholdAvgBytes' in bench).toBe(false);
    expect('bytesExchanged' in bench).toBe(false);
  });
});
