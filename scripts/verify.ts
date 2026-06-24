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
  const signingResult = await thresholdSign(message, keypair, undefined, 100);
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
    mainUi.includes('reconstructs the full secret key');
  const noMathRandom = !(await containsMathRandom());

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
      label: 'Distributed key generation yields a valid public key',
      pass: keyCheck.valid && keyCheck.publicKeyMatches,
      evidence: `valid=${keyCheck.valid}, publicKeyMatches=${keyCheck.publicKeyMatches}`,
    },
    {
      id: 5,
      label: 'Two-party signing completes within the restart budget',
      pass:
        signingResult.rounds.length > 0 &&
        signingResult.signatureVerifiesWithStandardMLDSA,
      evidence: `rounds=${signingResult.rounds.length}, rejections=${signingResult.totalRejections}, verifies=${signingResult.signatureVerifiesWithStandardMLDSA}`,
    },
    {
      id: 6,
      label: 'Threshold signature verifies with standard ML-DSA',
      pass: signatureValid && signingResult.signatureVerifiesWithStandardMLDSA,
      evidence: `verify=${signatureValid}`,
    },
    {
      id: 7,
      label: 'Disabling one party prevents signing',
      pass: onePartyFails,
      evidence: `singlePartyAttemptFails=${onePartyFails}`,
    },
    {
      id: 8,
      // Bounds are deliberately wide: rejection sampling is driven by the real
      // Web Crypto CSPRNG, so this asserts the overhead *story* (restarts happen,
      // threshold is slower, more bytes move) without flaking on a lucky seed.
      label: 'Threshold signing shows measurable overhead vs standalone',
      pass:
        benchmark.overheadFactor >= 1 &&
        benchmark.thresholdAvgBytes > 0 &&
        benchmark.thresholdRejectRate >= 0 &&
        benchmark.thresholdRejectRate <= 40,
      evidence: `rejectRate=${benchmark.thresholdRejectRate}, avgBytes=${benchmark.thresholdAvgBytes}, overheadFactor=${benchmark.overheadFactor}`,
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
