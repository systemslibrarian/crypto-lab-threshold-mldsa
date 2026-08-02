import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { distributedKeyGen, verifyKeyShares } from '../src/dkg';
import { encodeText, MLDSA_Q, normalizeCoeff } from '../src/mldsa-primitives';
import {
  reconstructPolynomial,
  sharedInfinityNormLessThan,
  sharedLessThan,
  splitPolynomial,
} from '../src/sharing';
import {
  comparisonBenchmark,
  singlePartyAttemptFails,
  thresholdSign,
  verifyWithStandardMLDSA,
} from '../src/threshold-sign';
import {
  TOY_PER_PARTY_BOUND,
  toyDkg,
  toySinglePartyAttempt,
  toyThresholdSign,
} from '../src/toy-threshold';

type ResultRow = {
  id: number;
  label: string;
  pass: boolean;
  evidence: string;
};

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const srcRoot = path.join(repoRoot, 'src');

async function getSourceFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return getSourceFiles(fullPath);
    }
    return fullPath.endsWith('.ts') || fullPath.endsWith('.css') || fullPath.endsWith('.html') ? [fullPath] : [];
  }));
  return nested.flat();
}

async function containsMathRandom(): Promise<boolean> {
  const files = await getSourceFiles(srcRoot);
  for (const file of files) {
    const content = await readFile(file, 'utf8');
    // Match actual calls (Math.random(...)), not prose that names the function
    // — the UI deliberately tells users it never uses Math.random.
    if (/Math\.random\s*\(/.test(content)) {
      return true;
    }
  }
  return false;
}

async function main(): Promise<void> {
  const original = Array.from({ length: 16 }, (_, index) => normalizeCoeff((index * 23) - 19, MLDSA_Q));
  const shares = splitPolynomial(original, MLDSA_Q);
  const reconstructed = reconstructPolynomial(shares.shareServer, shares.sharePhone, MLDSA_Q);
  const splitReconstructs = JSON.stringify(original) === JSON.stringify(reconstructed);

  const comparison = sharedLessThan(22, MLDSA_Q - 25, 8, MLDSA_Q);
  const normCheck = sharedInfinityNormLessThan([2, 3, MLDSA_Q - 4], [MLDSA_Q - 1, 0, 1], 10, MLDSA_Q);

  const keypair = await distributedKeyGen();
  const keyCheck = await verifyKeyShares(keypair);

  const message = encodeText('Threshold ML-DSA verification message');
  const signingResult = await thresholdSign(message, keypair);
  const signatureValid = await verifyWithStandardMLDSA(message, signingResult.signature, keypair.publicKey);
  const onePartyFails = await singlePartyAttemptFails(message, keypair, 'server');

  // Tamper tests: the genuine FIPS 204 verifier must reject altered inputs.
  const tamperedMessage = encodeText('Threshold ML-DSA verification message (tampered)');
  const tamperedMessageRejected = !(await verifyWithStandardMLDSA(
    tamperedMessage,
    signingResult.signature,
    keypair.publicKey,
  ));

  const tamperedSignature = signingResult.signature.slice();
  tamperedSignature[0] ^= 0xff;
  const tamperedSignatureRejected = !(await verifyWithStandardMLDSA(
    message,
    tamperedSignature,
    keypair.publicKey,
  ));

  const benchmark = await comparisonBenchmark(6);

  const mainUi = await readFile(path.join(srcRoot, 'main.ts'), 'utf8');
  const uiMarksEducational = mainUi.includes('Educational only') && mainUi.includes('Not standardized');
  const uiMarksReality =
    mainUi.includes("What's real, and what's simulated") &&
    mainUi.includes('combines the two additive byte shares into the full secret key') &&
    mainUi.includes('key-non-reconstruction');
  const noMathRandom = !(await containsMathRandom());

  // The never-combine toy protocol, executed here rather than described.
  const toySetup = toyDkg();
  const toyMessage = encodeText('verify-script-never-combine');
  const toyHonest = toyThresholdSign(toyMessage, toySetup);
  const toyInflated = toyThresholdSign(toyMessage, toySetup, 'inflate');
  const toyNudged = toyThresholdSign(toyMessage, toySetup, 'nudge');
  const toySolo = toySinglePartyAttempt(toyMessage, toySetup);

  const results: ResultRow[] = [
    {
      id: 2,
      label: 'Additive sharing reconstructs correctly',
      pass: splitReconstructs,
      evidence: splitReconstructs ? 'Original polynomial was recovered from the two shares.' : 'Polynomial reconstruction failed.',
    },
    {
      id: 3,
      label: 'Secure comparison returns the right answer',
      pass: comparison.result && normCheck.result,
      evidence: `sharedLessThan=${comparison.result}, sharedInfinityNormLessThan=${normCheck.result}`,
    },
    {
      id: 4,
      label: 'Split-custody shares recombine to a key that matches THIS public key',
      pass: keyCheck.valid && keyCheck.sharesMatchPublicKey,
      evidence: `valid=${keyCheck.valid}, sharesMatchPublicKey=${keyCheck.sharesMatchPublicKey}, illustrativeReconstruct=${keyCheck.illustrativeSharesReconstruct}`,
    },
    {
      id: 5,
      label: 'Two-party (combine-then-sign) produces a signature',
      pass:
        signingResult.steps.length > 0 &&
        signingResult.signatureVerifiesWithStandardMLDSA,
      evidence: `steps=${signingResult.steps.length}, verifies=${signingResult.signatureVerifiesWithStandardMLDSA}`,
    },
    {
      id: 6,
      label: 'The signature verifies with standard ML-DSA',
      pass: signatureValid && signingResult.signatureVerifiesWithStandardMLDSA,
      evidence: `verify=${signatureValid}`,
    },
    {
      id: 7,
      label: 'A single party alone cannot produce an accepted signature',
      pass: onePartyFails,
      evidence: `singlePartyAttemptFails=${onePartyFails}`,
    },
    {
      id: 8,
      // Only genuinely-measured wall-clock time is reported; the overhead
      // factor is unbounded but must be positive and finite.
      label: 'Timing benchmark reports measured (not fabricated) wall-clock numbers',
      pass:
        benchmark.iterations === 6 &&
        benchmark.standaloneAvgTimeMs > 0 &&
        benchmark.reconstructThenSignAvgTimeMs > 0 &&
        Number.isFinite(benchmark.overheadFactor),
      evidence: `standalone=${benchmark.standaloneAvgTimeMs}ms, reconstructThenSign=${benchmark.reconstructThenSignAvgTimeMs}ms, overhead=${benchmark.overheadFactor}`,
    },
    {
      id: 9,
      label: 'No Math.random appears in src',
      pass: noMathRandom,
      evidence: noMathRandom ? 'Search of the source tree found zero matches.' : 'Math.random was found in the source tree.',
    },
    {
      id: 10,
      label: 'UI clearly marks the demo as educational and not standardized',
      pass: uiMarksEducational,
      evidence: uiMarksEducational ? 'main.ts includes both educational and standardization warnings.' : 'UI warning text is incomplete.',
    },
    {
      id: 11,
      label: 'Standard verifier rejects a tampered message',
      pass: tamperedMessageRejected,
      evidence: `tamperedMessageRejected=${tamperedMessageRejected}`,
    },
    {
      id: 12,
      label: 'Standard verifier rejects a tampered signature',
      pass: tamperedSignatureRejected,
      evidence: `tamperedSignatureRejected=${tamperedSignatureRejected}`,
    },
    {
      id: 14,
      label: 'Never-combine toy protocol signs and its own verifier accepts',
      pass: toyHonest.status === 'signed' && toyHonest.verification?.accepted === true,
      evidence: `status=${toyHonest.status} accepted=${toyHonest.verification?.accepted} attempts=${toyHonest.attempts.length}`,
    },
    {
      id: 15,
      label: 'An over-bound z-share is caught by the norm check, with no signature emitted',
      pass: toyInflated.status === 'rejected-by-norm-check' && toyInflated.signature === null,
      evidence: `status=${toyInflated.status} rejectedNorm=${toyInflated.rejectedNorm} bound=${TOY_PER_PARTY_BOUND}`,
    },
    {
      id: 16,
      label: 'A one-unit corruption passes the norm check and is caught by Fiat–Shamir',
      pass:
        toyNudged.status === 'signed' &&
        toyNudged.verification?.normOk === true &&
        toyNudged.verification?.challengeOk === false,
      evidence: `normOk=${toyNudged.verification?.normOk} challengeOk=${toyNudged.verification?.challengeOk}`,
    },
    {
      id: 17,
      label: 'One party alone cannot make a signature the toy verifier accepts',
      pass: toySolo.verification.accepted === false,
      evidence: `accepted=${toySolo.verification.accepted} failedCheck=${toySolo.verification.failedCheck}`,
    },
    {
      id: 13,
      label: 'UI is honest about the real-vs-simulated boundary',
      pass: uiMarksReality,
      evidence: uiMarksReality
        ? "main.ts explains it reconstructs the secret key and the MPC rounds are simulated."
        : 'Real-vs-simulated disclosure is missing from the UI.',
    },
  ];

  const passed = results.filter((row) => row.pass).length;
  const failed = results.filter((row) => !row.pass);

  for (const row of results) {
    console.log(`${row.pass ? 'PASS' : 'FAIL'}  [${row.id}] ${row.label}`);
    console.log(`        ${row.evidence}`);
  }
  console.log('');
  console.log(`${passed}/${results.length} checks passed.`);
  console.log('');
  console.log(JSON.stringify({ results, benchmark }, null, 2));

  if (failed.length > 0) {
    console.error(`\nVerification FAILED: ${failed.length} check(s) did not pass.`);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error('Verification crashed:', error);
  process.exitCode = 1;
});
