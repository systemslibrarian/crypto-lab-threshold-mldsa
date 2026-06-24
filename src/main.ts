import './style.css';

import { distributedKeyGen, verifyKeyShares, type ThresholdKeyPair } from './dkg';
import { bytesToHex, encodeText } from './mldsa-primitives';
import {
  comparisonBenchmark,
  malformedPartyResponseAborts,
  singlePartyAttemptFails,
  thresholdSign,
  type SigningRoundLog,
} from './threshold-sign';

type StatusTone = 'idle' | 'working' | 'success' | 'warning' | 'danger';

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App container was not found.');
}

app.innerHTML = `
  <a class="skip-link" href="#live-demo">Skip to live demo</a>
  <div class="shell">
    <header class="hero-section panel">
      <div class="hero-copy">
        <div class="eyebrow">Threshold ML-DSA • FIPS 204 compatibility demo</div>
        <h1>Two parties. One standard ML-DSA signature.</h1>
        <p class="lead">
          A browser-based educational simulation of threshold signing for ML-DSA-65 inspired by
          Trilithium, Quorus, TOPCOAT, and related 2024–2026 research.
        </p>
        <div class="badge-row">
          <span class="badge badge-gold">Educational only</span>
          <span class="badge badge-green">Standard verifier compatible</span>
          <span class="badge badge-purple">No backend</span>
        </div>
      </div>
      <div class="hero-side">
        <blockquote>
          “Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God.”
          <span>— 1 Corinthians 10:31</span>
        </blockquote>
      </div>
    </header>

    <section class="notice-row" aria-label="Protocol status">
      <div id="status-banner" class="status-banner tone-idle" role="status" aria-live="polite" aria-atomic="true">Initializing the two-party ML-DSA-65 demo…</div>
    </section>

    <section class="protocol-stage panel" aria-label="Two-party signing stage">
      <div class="party-panel server-panel">
        <div class="party-head">
          <h2>SERVER</h2>
          <span class="dot server-dot"></span>
        </div>
        <p>Holds additive shares of s₁, s₂, t₀ and half of the real signing key bytes.</p>
        <div id="server-share-box" class="masked-box">Waiting for distributed key generation…</div>
      </div>

      <div class="shared-lane" aria-label="Shared communication channel">
        <div class="lane-label">Shared channel</div>
        <div class="arrow arrow-right">ρ, w, challenge, hints</div>
        <div class="joint-artifact">
          <div class="joint-title">Joint artifact</div>
          <div id="joint-artifact-text">No signature yet</div>
        </div>
        <div class="arrow arrow-left">z shares, accept/restart</div>
      </div>

      <div class="party-panel phone-panel">
        <div class="party-head">
          <h2>PHONE</h2>
          <span id="phone-indicator" class="dot phone-dot"></span>
        </div>
        <p>Must participate for 2-of-2 signing. Disabling the phone blocks the protocol.</p>
        <div id="phone-share-box" class="masked-box">Waiting for distributed key generation…</div>
      </div>
    </section>

    <section class="panel reality-panel" aria-labelledby="reality-heading">
      <h3 id="reality-heading">What's real, and what's simulated</h3>
      <p class="small-note">
        Honesty matters more than spectacle in a crypto demo. Here is exactly where the
        genuine cryptography stops and the teaching simulation begins.
      </p>
      <div class="reality-grid">
        <div class="reality-card reality-real">
          <div class="reality-tag">Real — standard FIPS 204</div>
          <ul>
            <li>Key generation, signing, and verification all use <code>@noble/post-quantum</code>'s ML-DSA-65.</li>
            <li>The public key and every emitted signature are genuine and verify under the unmodified standard verifier.</li>
            <li>All randomness comes from the Web Crypto CSPRNG — never <code>Math.random</code>.</li>
            <li>Additive secret sharing is real: each share alone is uniform and reveals nothing.</li>
          </ul>
        </div>
        <div class="reality-card reality-sim">
          <div class="reality-tag">Simulated — for teaching</div>
          <ul>
            <li>The round-by-round nonce, w₁, challenge, and z exchanges are <strong>choreography</strong>: they illustrate protocol shape but do not produce the signature.</li>
            <li>The "secure norm check" reveals the combined value in the clear instead of running real MPC.</li>
            <li>Rejections are injected to demonstrate restart-on-reject behavior.</li>
            <li><strong>To actually sign, the demo reconstructs the full secret key in one place</strong> — so it does <em>not</em> achieve real key-non-reconstruction. A production threshold scheme never does this.</li>
          </ul>
        </div>
      </div>
      <p class="small-note">
        In short: the ML-DSA math is real and the output is a valid FIPS 204 signature; the
        <em>distributed-trust</em> property is illustrated, not enforced. Building the real thing is
        the open research problem this lab is about — see the landscape table below.
      </p>
    </section>

    <section class="exhibits-grid">
      <article class="panel exhibit">
        <h3>Exhibit 1 — Why threshold ML-DSA is hard</h3>
        <div class="comparison-stack">
          <div class="mini-card bls-card">
            <strong>Threshold BLS</strong>
            <p>Linear group law. Partial signatures combine directly with Lagrange interpolation.</p>
          </div>
          <div class="mini-card schnorr-card">
            <strong>Threshold Schnorr</strong>
            <p>Mostly linear: each party contributes a nonce share and a response share.</p>
          </div>
          <div class="mini-card mldsa-card">
            <strong>Threshold ML-DSA</strong>
            <ul>
              <li>Fiat–Shamir with aborts means full restarts on rejection.</li>
              <li>HighBits, LowBits, and MakeHint are non-linear MPC steps.</li>
              <li>Secure norm checks must happen before revealing too much.</li>
            </ul>
          </div>
        </div>
      </article>

      <article class="panel exhibit">
        <h3>Exhibit 2 — Trilithium-style protocol walkthrough</h3>
        <ol class="steps-list">
          <li>Server and phone sample additive nonce shares y^S and y^P.</li>
          <li>Each computes a local A·y contribution and exchanges masked summaries.</li>
          <li>Both derive the shared high bits w₁ and challenge c.</li>
          <li>Each computes z^i = y^i + c·s₁^i.</li>
          <li>A secure comparison checks the hidden norm bound.</li>
          <li>If rejected, both restart with fresh randomness.</li>
          <li>If accepted, the final signature verifies with the standard ML-DSA verifier.</li>
        </ol>
      </article>

      <article id="live-demo" class="panel exhibit live-exhibit" tabindex="-1">
        <h3>Exhibit 3 — Live two-party signing</h3>
        <label class="field-label" for="message-input">Message</label>
        <p id="message-help" class="small-note">Enter the message both parties will jointly authorize with ML-DSA-65.</p>
        <textarea id="message-input" rows="3" aria-describedby="message-help">Transfer $1000 to Alice</textarea>
        <div class="button-row">
          <button id="sign-button" class="primary-button" type="button" aria-controls="protocol-log sign-stats">Start threshold signing</button>
          <button id="phone-toggle" class="secondary-button" type="button" aria-controls="protocol-log" aria-pressed="false">Disable phone</button>
          <button id="benchmark-button" class="secondary-button" type="button" aria-controls="protocol-log sign-stats">Run quick benchmark</button>
        </div>
        <div id="sign-stats" class="stats-grid">
          <div class="stat-card"><span>Scenario</span><strong>2-of-2</strong></div>
          <div class="stat-card"><span>Attempts</span><strong>—</strong></div>
          <div class="stat-card"><span>Rounds</span><strong>—</strong></div>
          <div class="stat-card"><span>Bytes</span><strong>—</strong></div>
          <div class="stat-card"><span>Time</span><strong>—</strong></div>
          <div class="stat-card"><span>Verifier</span><strong>—</strong></div>
        </div>
        <div id="protocol-log" class="log-panel" role="log" aria-live="polite" aria-relevant="additions text">Awaiting the first signing run…</div>
      </article>

      <article class="panel exhibit">
        <h3>Exhibit 4 — Published threshold ML-DSA landscape</h3>
        <div class="table-wrap">
          <table>
            <caption class="sr-only">Comparison of threshold ML-DSA research schemes and their properties.</caption>
            <thead>
              <tr>
                <th scope="col">Scheme</th>
                <th scope="col">Parties</th>
                <th scope="col">Security</th>
                <th scope="col">Rounds</th>
                <th scope="col">Std compat</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>Trilithium (2025/675)</td><td>2</td><td>UC, malicious</td><td>5–8</td><td>Yes</td></tr>
              <tr><td>Quorus (2025/1163)</td><td>n ≤ 6+</td><td>MPC malicious</td><td>6–10</td><td>Yes</td></tr>
              <tr><td>TOPCOAT (2024)</td><td>2</td><td>sim. malicious</td><td>3</td><td>Yes</td></tr>
              <tr><td>Dufka–Kravtsenko (2025/871)</td><td>up to 6</td><td>Identifiable aborts</td><td>Varies</td><td>Yes</td></tr>
              <tr><td>THED (2026/638)</td><td>Any t-of-n</td><td>FHE-based</td><td>2+</td><td>Yes</td></tr>
              <tr><td>Threshold Raccoon</td><td>Any t-of-n</td><td>Standard lattice</td><td>2–3</td><td>No</td></tr>
            </tbody>
          </table>
        </div>
        <p class="small-note">
          No threshold ML-DSA construction is NIST-standardized as of 2026. This lab models the signing-side protocol only.
        </p>
      </article>

      <article class="panel exhibit applications-exhibit">
        <h3>Exhibit 5 — Why it matters</h3>
        <ul class="app-list">
          <li><strong>Root CAs:</strong> no single HSM can forge a post-quantum root signature.</li>
          <li><strong>Blockchains:</strong> validators can require multiple nodes to authorize signatures.</li>
          <li><strong>Government and enterprise:</strong> t-of-n approval over high-value signing actions.</li>
          <li><strong>Emergency recovery:</strong> social recovery with designated approvers.</li>
          <li><strong>PrayerWarriors.Mobi:</strong> future multi-person authorization for recovery and attestations.</li>
        </ul>
        <div class="chip-row">
          <span class="chip">crypto-lab-dilithium-seal</span>
          <span class="chip">crypto-lab-dilithium-reject</span>
          <span class="chip">crypto-lab-frost-threshold</span>
          <span class="chip">crypto-lab-shamir-gate</span>
          <span class="chip">crypto-lab-mpc-arena</span>
        </div>
      </article>
    </section>

    <section class="panel footer-panel">
      <h3>Research anchors</h3>
      <p>
        Trilithium: Dufka, Kravtsenko, Laud, Snetkov (ePrint 2025/675). Quorus: Borin et al. (ePrint 2025/1163). TOPCOAT: 2024 two-party HighBits compression. Dufka–Kravtsenko identifiable aborts: ePrint 2025/871. del Pino–Prest unmasking TRaccoon: ePrint 2025/849.
      </p>
    </section>
  </div>
`;

let keypair: ThresholdKeyPair | null = null;
let phoneEnabled = true;

const statusBanner = getElement<HTMLDivElement>('#status-banner');
const serverShareBox = getElement<HTMLDivElement>('#server-share-box');
const phoneShareBox = getElement<HTMLDivElement>('#phone-share-box');
const phoneIndicator = getElement<HTMLSpanElement>('#phone-indicator');
const jointArtifactText = getElement<HTMLDivElement>('#joint-artifact-text');
const protocolLog = getElement<HTMLDivElement>('#protocol-log');
const signStats = getElement<HTMLDivElement>('#sign-stats');
const messageInput = getElement<HTMLTextAreaElement>('#message-input');
const signButton = getElement<HTMLButtonElement>('#sign-button');
const phoneToggleButton = getElement<HTMLButtonElement>('#phone-toggle');
const benchmarkButton = getElement<HTMLButtonElement>('#benchmark-button');

function getElement<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) {
    throw new Error(`Missing required element: ${selector}`);
  }
  return element;
}

function updatePhoneToggleButton(): void {
  phoneToggleButton.textContent = phoneEnabled ? 'Disable phone' : 'Enable phone';
  phoneToggleButton.setAttribute('aria-pressed', String(!phoneEnabled));
  phoneToggleButton.setAttribute(
    'aria-label',
    phoneEnabled ? 'Disable the phone party to test 2 of 2 enforcement' : 'Enable the phone party to restore 2 of 2 signing',
  );
}

function setBusyState(isBusy: boolean): void {
  signButton.disabled = isBusy;
  benchmarkButton.disabled = isBusy;
  phoneToggleButton.disabled = isBusy;
  messageInput.disabled = isBusy;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function setStatus(tone: StatusTone, message: string): void {
  statusBanner.className = `status-banner tone-${tone}`;
  statusBanner.textContent = message;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${bytes} B`;
}

function formatTime(ms: number): string {
  return `${ms.toFixed(1)} ms`;
}

function maskedRow(label: string): string {
  // The block glyphs are decorative; screen readers get a real word instead of
  // a run of "black square" announcements.
  return `<div class="masked-row"><span>${label}</span><strong aria-hidden="true">████████</strong><span class="sr-only">value hidden</span></div>`;
}

function renderMaskedShares(currentKeypair: ThresholdKeyPair): void {
  const rows = `${maskedRow('s₁ share')}${maskedRow('s₂ share')}${maskedRow('t₀ share')}`;
  serverShareBox.innerHTML = `
    ${rows}
    <div class="masked-row"><span>Signing bytes</span><strong>${currentKeypair.serverShare.secretKeyShare.length} hidden bytes</strong></div>
  `;
  phoneShareBox.innerHTML = `
    ${rows}
    <div class="masked-row"><span>Signing bytes</span><strong>${currentKeypair.phoneShare.secretKeyShare.length} hidden bytes</strong></div>
  `;
}

function renderStats(entries: Array<{ label: string; value: string }>): void {
  signStats.innerHTML = entries
    .map((entry) => `<div class="stat-card"><span>${escapeHtml(entry.label)}</span><strong>${escapeHtml(entry.value)}</strong></div>`)
    .join('');
}

function renderLogs(logs: SigningRoundLog[]): void {
  protocolLog.innerHTML = logs
    .map((log) => `
      <div class="log-row log-${log.result}">
        <div class="log-top">
          <strong>Round ${log.roundNumber}</strong>
          <span>${formatBytes(log.bytesExchanged)} • ${formatTime(log.timeMs)}</span>
        </div>
        <div>${escapeHtml(log.description)}</div>
        <div class="log-actions">
          <span>Server: ${escapeHtml(log.serverAction)}</span>
          <span>Phone: ${escapeHtml(log.phoneAction)}</span>
        </div>
      </div>
    `)
    .join('');
}

async function ensureKeypair(): Promise<ThresholdKeyPair> {
  if (keypair) {
    return keypair;
  }

  const dkgLogs: string[] = [];
  keypair = await distributedKeyGen((round, description, bytesExchanged) => {
    dkgLogs.push(`Round ${round}: ${description} (${formatBytes(bytesExchanged)})`);
  });
  renderMaskedShares(keypair);

  const check = await verifyKeyShares(keypair);
  protocolLog.innerHTML = dkgLogs.map((entry) => `<div class="log-row"><div>${escapeHtml(entry)}</div></div>`).join('');

  if (check.valid) {
    jointArtifactText.textContent = `Public key ready • ρ = ${bytesToHex(keypair.publicKey.rho, 12)}…`;
    setStatus('success', 'Distributed key generation succeeded. Both parties now hold only their own additive shares.');
  } else {
    setStatus('danger', 'Distributed key generation failed verification.');
  }

  renderStats([
    { label: 'Scenario', value: '2-of-2' },
    { label: 'Key status', value: check.valid ? 'Ready' : 'Failed' },
    { label: 'Verifier', value: 'Standard ML-DSA-65' },
    { label: 'Public key', value: `${keypair.publicKey.raw.length} bytes` },
    { label: 'Research status', value: 'Not standardized' },
    { label: 'Backend', value: 'None' },
  ]);

  return keypair;
}

async function runSigningDemo(): Promise<void> {
  setBusyState(true);
  try {
    const currentKeypair = await ensureKeypair();
    const message = encodeText(messageInput.value.trim() || 'Transfer $1000 to Alice');

    if (!phoneEnabled) {
      const blocked = await singlePartyAttemptFails(message, currentKeypair, 'server');
      jointArtifactText.textContent = blocked ? 'Signing blocked: phone share missing.' : 'Unexpected single-party success.';
      setStatus('warning', 'The phone is disabled, so the 2-of-2 protocol cannot complete.');
      renderStats([
        { label: 'Scenario', value: '2-of-2' },
        { label: 'Attempts', value: '0' },
        { label: 'Rounds', value: '0' },
        { label: 'Bytes', value: '0 B' },
        { label: 'Time', value: '0 ms' },
        { label: 'Verifier', value: blocked ? 'Sign blocked' : 'Unexpected' },
      ]);
      protocolLog.innerHTML = `
        <div class="log-row log-reject">
          <div class="log-top"><strong>Drop-one test</strong><span>2-of-2 enforced</span></div>
          <div>Server alone cannot reconstruct the real ML-DSA signing key, so the protocol aborts.</div>
        </div>
      `;
      return;
    }

    setStatus('working', 'Both parties are participating. Running the threshold signing rounds…');
    const liveLogs: SigningRoundLog[] = [];
    const result = await thresholdSign(message, currentKeypair, (log) => {
      liveLogs.push(log);
      renderLogs(liveLogs);
    });

    jointArtifactText.textContent = `σ = ${bytesToHex(result.signature, 20)}…`;
    setStatus(
      result.signatureVerifiesWithStandardMLDSA ? 'success' : 'danger',
      result.signatureVerifiesWithStandardMLDSA
        ? 'Success: the joint signature verifies with the standard ML-DSA verifier.'
        : 'The signature failed standard verification.',
    );

    renderStats([
      { label: 'Scenario', value: '2-of-2' },
      { label: 'Attempts', value: String(result.totalRejections + 1) },
      { label: 'Rounds', value: String(result.rounds.length) },
      { label: 'Bytes', value: formatBytes(result.totalBytesExchanged) },
      { label: 'Time', value: formatTime(result.totalTimeMs) },
      { label: 'Verifier', value: result.signatureVerifiesWithStandardMLDSA ? 'PASS' : 'FAIL' },
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unexpected error';
    setStatus('danger', `Signing aborted: ${message}`);
    protocolLog.innerHTML = `<div class="log-row log-reject">${escapeHtml(message)}</div>`;
  } finally {
    setBusyState(false);
  }
}

async function runBenchmarkDemo(): Promise<void> {
  setBusyState(true);
  try {
    await ensureKeypair();
    setStatus('working', 'Benchmarking threshold signing overhead versus standalone ML-DSA…');
    const stats = await comparisonBenchmark(6);
    renderStats([
      { label: 'Scenario', value: '2-of-2' },
      { label: 'Avg rounds', value: String(stats.thresholdAvgRounds) },
      { label: 'Avg bytes', value: formatBytes(stats.thresholdAvgBytes) },
      { label: 'Threshold time', value: formatTime(stats.thresholdAvgTimeMs) },
      { label: 'Standalone time', value: formatTime(stats.standaloneAvgTimeMs) },
      { label: 'Rejects / sig', value: String(stats.thresholdRejectRate) },
    ]);
    protocolLog.innerHTML = `
      <div class="log-row log-ok">
        <div class="log-top"><strong>Benchmark result</strong><span>Overhead ×${stats.overheadFactor}</span></div>
        <div>Threshold ML-DSA signing is slower because every restart requires both parties to resample and coordinate.</div>
      </div>
    `;
    setStatus('success', 'Benchmark completed. The demo shows the expected multi-round overhead of threshold ML-DSA.');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unexpected error';
    setStatus('danger', `Benchmark failed: ${message}`);
  } finally {
    setBusyState(false);
  }
}

function togglePhoneState(): void {
  phoneEnabled = !phoneEnabled;
  phoneIndicator.className = `dot ${phoneEnabled ? 'phone-dot' : 'off-dot'}`;
  updatePhoneToggleButton();
  setStatus(
    phoneEnabled ? 'idle' : 'warning',
    phoneEnabled
      ? 'Phone restored. Two-party signing is available again.'
      : 'Phone disabled. Any 2-of-2 signing attempt should now fail cleanly.',
  );
}

async function runInitialChecks(): Promise<void> {
  try {
    const currentKeypair = await ensureKeypair();
    const probeMessage = encodeText('drop-one-probe');
    const onePartyFails = await singlePartyAttemptFails(probeMessage, currentKeypair);
    const malformedAborts = await malformedPartyResponseAborts(probeMessage, currentKeypair);
    if (!onePartyFails || !malformedAborts) {
      setStatus('warning', 'The demo loaded, but one of the threshold safety checks needs attention.');
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unexpected error';
    setStatus('danger', `Initialization failed: ${message}`);
  }
}

updatePhoneToggleButton();

signButton.addEventListener('click', () => {
  void runSigningDemo();
});

benchmarkButton.addEventListener('click', () => {
  void runBenchmarkDemo();
});

phoneToggleButton.addEventListener('click', () => {
  togglePhoneState();
});

void runInitialChecks();
