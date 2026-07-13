import './style.css';

import { distributedKeyGen, verifyKeyShares, type ThresholdKeyPair } from './dkg';
import { bytesToHex, encodeText } from './mldsa-primitives';
import {
  comparisonBenchmark,
  malformedPartyResponseAborts,
  singlePartyAttemptFails,
  thresholdSign,
  type WalkthroughStep,
} from './threshold-sign';
import {
  TOY_Q,
  TOY_Z_BOUND,
  computeRound,
  computeUntilAccepted,
  type RoundTrace,
} from './trace';

type StatusTone = 'idle' | 'working' | 'success' | 'warning' | 'danger';

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App container was not found.');
}

app.innerHTML = `
  <a class="skip-link" href="#live-demo">Skip to live demo</a>
  <div class="shell">
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">Threshold ML-DSA</h1>
        <p class="cl-hero-sub">FIPS 204 · Lattice threshold signing</p>
        <p class="cl-hero-desc">Split an ML-DSA-65 signing key across a server and a phone, then watch both parties jointly produce one signature that verifies under the standard FIPS 204 verifier.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">Post-quantum signatures will guard root CAs, ledgers, and firmware — targets too valuable to trust to one key holder. But ML-DSA's Fiat–Shamir-with-aborts and non-linear rounding make it far harder to split than classical Schnorr or BLS.</p>
      </aside>
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

    <section class="panel share-demo-panel" aria-labelledby="share-demo-heading">
      <h3 id="share-demo-heading">The one real idea you can hold: additive secret sharing</h3>
      <p class="small-note">
        This is the primitive the whole scheme rests on, and it is <strong>genuinely real here</strong> —
        not illustrative. The real ML-DSA-65 secret key is stored as two byte arrays. For each key byte,
        <code>server + phone (mod 256) = the real key byte</code>. Each share on its own is uniform random
        and reveals nothing. Below is one live byte pair from the actual split key. Click combine to sum them.
      </p>
      <div class="share-combine" aria-live="polite">
        <div class="share-cell share-cell-server">
          <span class="share-cell-label">SERVER share byte</span>
          <strong id="share-server-byte" class="share-byte">—</strong>
        </div>
        <span class="share-op" aria-hidden="true">+</span>
        <div class="share-cell share-cell-phone">
          <span class="share-cell-label">PHONE share byte</span>
          <strong id="share-phone-byte" class="share-byte">—</strong>
        </div>
        <span class="share-op" aria-hidden="true">= (mod 256)</span>
        <div class="share-cell share-cell-result">
          <span class="share-cell-label">Real key byte</span>
          <strong id="share-result-byte" class="share-byte">?</strong>
        </div>
      </div>
      <div class="button-row">
        <button id="share-combine-btn" class="secondary-button" type="button" aria-controls="share-result-byte">Combine shares (sum mod 256)</button>
        <button id="share-reroll-btn" class="secondary-button" type="button" aria-controls="share-server-byte">Show a different byte</button>
      </div>
      <p id="share-combine-note" class="small-note share-combine-note">Each share is uniform on 0–255, so neither byte alone tells you anything. Only their sum mod 256 recovers the secret byte.</p>
    </section>

    <section class="panel reality-panel" aria-labelledby="reality-heading">
      <h3 id="reality-heading">What's real, and what's simulated</h3>
      <p class="small-note">
        <strong>Educational only.</strong> Honesty matters more than spectacle in a crypto demo.
        Here is exactly where the genuine cryptography stops and the teaching simulation begins.
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
            <li>The round-by-round nonce, w₁, challenge, and z exchanges are <strong>choreography</strong>: they illustrate protocol shape but do not produce the signature. Each step is labelled real or illustrative.</li>
            <li>The "secure norm check" is described, not executed — this build runs no real MPC and reports no fabricated "bytes exchanged" traffic.</li>
            <li><strong>To actually sign, the demo combines the two additive byte shares into the full secret key in one place</strong> — so it does <em>not</em> achieve real key-non-reconstruction. A production threshold scheme never does this.</li>
          </ul>
        </div>
      </div>
      <p class="small-note">
        In short: the ML-DSA math is real and the output is a valid FIPS 204 signature; the
        <em>distributed-trust</em> property is illustrated, not enforced. Building the real thing is
        the open research problem this lab is about — see the landscape table below.
      </p>

      <div class="contrast-experiment">
        <h4 id="contrast-heading">Feel the difference: escrow vs. a real threshold scheme</h4>
        <p class="small-note">
          Both paths start from the same two byte shares. Watch what happens to the full secret key
          buffer. Toggle to compare.
        </p>
        <div class="button-row" role="group" aria-labelledby="contrast-heading">
          <button id="contrast-escrow" class="secondary-button" type="button" aria-pressed="true" aria-controls="contrast-view">This build: combine then sign (escrow)</button>
          <button id="contrast-ideal" class="secondary-button" type="button" aria-pressed="false" aria-controls="contrast-view">Real threshold: never combine</button>
        </div>
        <div id="contrast-view" class="contrast-view" aria-live="polite"></div>
      </div>
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

        <div class="aborts-demo">
          <h4 id="aborts-heading">Why aborts make it expensive</h4>
          <p class="small-note">
            A single-signer ML-DSA just retries a rejected round by itself. In a <em>threshold</em> scheme
            every rejection makes <strong>all</strong> parties throw away their work and restart together
            with fresh randomness — a fully coordinated do-over. Press sign and watch the restart counter.
          </p>
          <button id="aborts-run" class="secondary-button" type="button" aria-controls="aborts-view">Sign until accepted (may take restarts)</button>
          <div id="aborts-view" class="aborts-view" role="region" aria-label="Rejection restart trace" aria-live="polite">
            <p class="small-note">No round run yet. Because each round is fresh randomness, some are rejected by the norm check.</p>
          </div>
        </div>
      </article>

      <article class="panel exhibit trace-exhibit">
        <h3>Exhibit 2 — Walk a signing round, one step at a time</h3>
        <p class="small-note">
          <strong>Illustrative choreography</strong> — this shows the <em>shape</em> of a real two-party
          lattice signing round. The tiny numbers below are computed live with genuine modular /
          additive-sharing math on toy 3-coefficient polynomials (mod ${TOY_Q}), so you can watch the
          actual values flow between the two parties. It does <em>not</em> produce the signature the live
          demo emits — that still comes from the honest combine-then-sign path. Simplified numbers, real math.
        </p>
        <div class="button-row trace-controls">
          <button id="trace-next" class="primary-button" type="button" aria-controls="trace-stage">Reveal round 1: sample nonces</button>
          <button id="trace-reset" class="secondary-button" type="button" aria-controls="trace-stage">Fresh randomness (restart)</button>
        </div>
        <div id="trace-stage" class="trace-stage" tabindex="0" role="region" aria-label="Round-by-round signing trace" aria-live="polite">
          <p class="small-note trace-placeholder">Press <strong>Reveal round 1</strong> to begin. Each press advances one step of the protocol and animates the numbers moving between the SERVER and PHONE columns.</p>
        </div>
        <details class="glossary">
          <summary>Glossary — what these terms mean (and why the step exists)</summary>
          <dl class="glossary-list">
            <dt>Nonce share (y^S, y^P)</dt>
            <dd>A one-time random value each party samples. Masks the secret so the response leaks nothing. <em>Why:</em> without a fresh nonce, two signatures would expose the key.</dd>
            <dt>Commitment w = A·y</dt>
            <dd>A public "photo" of the combined nonce. <em>Why:</em> it binds the parties to their nonces before the challenge is chosen.</dd>
            <dt>High bits w₁ (HighBits)</dt>
            <dd>Only the top bits of w — the low bits are dropped as noise. <em>Why:</em> ML-DSA rounds w to shrink signatures; this rounding is <strong>non-linear</strong>, which is exactly what makes it hard to split.</dd>
            <dt>Fiat–Shamir challenge c</dt>
            <dd>A small pseudo-random polynomial derived by hashing w₁ and the message. <em>Why:</em> it replaces an interactive verifier with a hash, turning identification into a signature.</dd>
            <dt>Response z = y + c·s₁</dt>
            <dd>Each party's masked reply. The nonce hides the secret term c·s₁. <em>Why:</em> z is what the verifier checks, without ever seeing s₁.</dd>
            <dt>Infinity-norm bound (|z|∞ &lt; β)</dt>
            <dd>The largest coefficient of z must stay small. <em>Why:</em> if z is too big it leaks information about s₁, so the round is rejected.</dd>
            <dt>Rejection / abort</dt>
            <dd>When the norm check fails, the whole round is thrown away and restarted with fresh randomness. <em>Why:</em> this "Fiat–Shamir with aborts" is the core reason threshold ML-DSA is harder than Schnorr — every abort is a coordinated restart.</dd>
            <dt>Secure comparison</dt>
            <dd>An MPC protocol that checks |z|∞ &lt; β <em>without</em> revealing z. <em>Why:</em> the parties must decide accept/reject before publishing z, but must not leak it if rejected.</dd>
          </dl>
        </details>
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
          <div class="stat-card"><span>Scenario</span><strong>2-of-2 custody</strong></div>
          <div class="stat-card"><span>Signature</span><strong>—</strong></div>
          <div class="stat-card"><span>Sign time</span><strong>—</strong></div>
          <div class="stat-card"><span>Verifier</span><strong>—</strong></div>
        </div>
        <div id="sign-verdict" class="verdict-grid" aria-live="polite">
          <div class="verdict-card verdict-idle" id="verdict-sig">
            <span class="verdict-icon" aria-hidden="true">•</span>
            <span class="verdict-body"><span class="verdict-label">Signature valid</span><span class="verdict-state">awaiting run</span></span>
          </div>
          <div class="verdict-card verdict-idle" id="verdict-trust">
            <span class="verdict-icon" aria-hidden="true">•</span>
            <span class="verdict-body"><span class="verdict-label">Distributed-trust enforced</span><span class="verdict-state">awaiting run</span></span>
          </div>
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
        <details class="glossary">
          <summary>Glossary — reading the security column</summary>
          <dl class="glossary-list">
            <dt>Parties / t-of-n</dt>
            <dd>How many key-holders exist (n) and how many must cooperate to sign (t). "2" means both of two must join; "t-of-n" means any t of n suffice.</dd>
            <dt>Rounds</dt>
            <dd>Back-and-forth messaging passes needed per signature. More rounds = more network latency and coordination cost.</dd>
            <dt>UC (Universally Composable)</dt>
            <dd>The strongest security proof style: the scheme stays secure even when run alongside arbitrary other protocols.</dd>
            <dt>Malicious security</dt>
            <dd>Safe even if some parties actively cheat (not just passively observe). Weaker "semi-honest" proofs assume everyone follows the rules.</dd>
            <dt>Identifiable aborts</dt>
            <dd>If the protocol fails, it can name <em>which</em> party misbehaved — so a cheater can be removed rather than just stalling everyone.</dd>
            <dt>FHE-based</dt>
            <dd>Uses Fully Homomorphic Encryption to compute on encrypted shares. Very flexible (any t-of-n) but currently expensive.</dd>
            <dt>Std compat (standard-compatible)</dt>
            <dd>"Yes" means the output is a normal FIPS 204 signature the unmodified verifier accepts — no special verifier needed.</dd>
          </dl>
        </details>
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
      <p class="related-demos">
        Related demos:
        <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/">crypto-lab-dilithium-seal</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-frost-threshold/">crypto-lab-frost-threshold</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/">crypto-lab-threshold-decrypt</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-vss-gate/">crypto-lab-vss-gate</a> ·
        <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-sign/">crypto-lab-hybrid-sign</a>
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
const verdictSig = getElement<HTMLDivElement>('#verdict-sig');
const verdictTrust = getElement<HTMLDivElement>('#verdict-trust');
const traceStage = getElement<HTMLDivElement>('#trace-stage');
const traceNextButton = getElement<HTMLButtonElement>('#trace-next');
const traceResetButton = getElement<HTMLButtonElement>('#trace-reset');
const contrastEscrowButton = getElement<HTMLButtonElement>('#contrast-escrow');
const contrastIdealButton = getElement<HTMLButtonElement>('#contrast-ideal');
const contrastView = getElement<HTMLDivElement>('#contrast-view');
const abortsRunButton = getElement<HTMLButtonElement>('#aborts-run');
const abortsView = getElement<HTMLDivElement>('#aborts-view');
const shareServerByte = getElement<HTMLElement>('#share-server-byte');
const sharePhoneByte = getElement<HTMLElement>('#share-phone-byte');
const shareResultByte = getElement<HTMLElement>('#share-result-byte');
const shareCombineButton = getElement<HTMLButtonElement>('#share-combine-btn');
const shareRerollButton = getElement<HTMLButtonElement>('#share-reroll-btn');
const shareCombineNote = getElement<HTMLParagraphElement>('#share-combine-note');

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

type VerdictTone = 'idle' | 'good' | 'bad';

// State via icon + text + color (never color alone), per the a11y rules.
const VERDICT_ICON: Record<VerdictTone, string> = { idle: '•', good: '✓', bad: '✕' };

function setVerdict(card: HTMLDivElement, tone: VerdictTone, label: string, state: string): void {
  card.className = `verdict-card verdict-${tone}`;
  const icon = card.querySelector<HTMLElement>('.verdict-icon');
  const labelEl = card.querySelector<HTMLElement>('.verdict-label');
  const stateEl = card.querySelector<HTMLElement>('.verdict-state');
  if (icon) icon.textContent = VERDICT_ICON[tone];
  if (labelEl) labelEl.textContent = label;
  if (stateEl) stateEl.textContent = state;
}

function resetVerdicts(): void {
  setVerdict(verdictSig, 'idle', 'Signature valid', 'awaiting run');
  setVerdict(verdictTrust, 'idle', 'Distributed-trust enforced', 'awaiting run');
}

function renderSteps(steps: WalkthroughStep[]): void {
  protocolLog.innerHTML = steps
    .map((step) => `
      <div class="log-row log-${step.kind === 'real' ? 'ok' : 'reject'}">
        <div class="log-top">
          <strong>Step ${step.stepNumber}</strong>
          <span>${step.kind === 'real' ? 'Real cryptography' : 'Illustrative (protocol shape)'}</span>
        </div>
        <div>${escapeHtml(step.description)}</div>
        <div class="log-actions">
          <span>Server: ${escapeHtml(step.serverAction)}</span>
          <span>Phone: ${escapeHtml(step.phoneAction)}</span>
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
  renderShareDemo();

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
        { label: 'Scenario', value: '2-of-2 custody' },
        { label: 'Signature', value: '—' },
        { label: 'Sign time', value: '—' },
        { label: 'Verifier', value: blocked ? 'Sign blocked' : 'Unexpected' },
      ]);
      setVerdict(verdictSig, 'bad', 'Signature valid', 'No signature — phone share missing');
      setVerdict(verdictTrust, 'good', 'Custody enforced', 'One party alone cannot sign');
      protocolLog.innerHTML = `
        <div class="log-row log-reject">
          <div class="log-top"><strong>Drop-one test</strong><span>2-of-2 enforced</span></div>
          <div>Server alone cannot reconstruct the real ML-DSA signing key, so the protocol aborts.</div>
        </div>
      `;
      return;
    }

    setStatus('working', 'Both parties are participating. Combining shares and signing with standard ML-DSA-65…');
    const result = await thresholdSign(message, currentKeypair);
    renderSteps(result.steps);

    jointArtifactText.textContent = `σ = ${bytesToHex(result.signature, 20)}…`;
    const verifies = result.signatureVerifiesWithStandardMLDSA;
    // The signature is genuinely valid — but the key WAS reconstructed to make it,
    // so distributed-trust was NOT enforced. The banner must not read as an
    // unqualified "success"; pair the green signature result with an amber caveat.
    setStatus(
      verifies ? 'warning' : 'danger',
      verifies
        ? 'Signature is valid — but this build combined the key to make it. Custody achieved; key-non-reconstruction NOT achieved.'
        : 'The signature failed standard verification.',
    );

    renderStats([
      { label: 'Scenario', value: '2-of-2 custody' },
      { label: 'Signature', value: `${result.signature.length} bytes` },
      { label: 'Sign time', value: formatTime(result.signTimeMs) },
      { label: 'Verifier', value: verifies ? 'PASS' : 'FAIL' },
    ]);
    setVerdict(
      verdictSig,
      verifies ? 'good' : 'bad',
      'Signature valid',
      verifies ? 'PASS — standard FIPS 204 verifier accepts' : 'FAIL — verifier rejected',
    );
    // This is the honest core: the key was combined in one place, so the hard
    // property is NOT achieved. Red, always, on a successful escrow sign.
    setVerdict(
      verdictTrust,
      'bad',
      'Distributed-trust enforced',
      'NOT achieved — key was reconstructed to sign',
    );
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
    setStatus('working', 'Timing standalone signing versus the reconstruct-then-sign path…');
    const stats = await comparisonBenchmark(6);
    renderStats([
      { label: 'Scenario', value: '2-of-2 custody' },
      { label: 'Iterations', value: String(stats.iterations) },
      { label: 'Standalone', value: formatTime(stats.standaloneAvgTimeMs) },
      { label: 'Reconstruct+sign', value: formatTime(stats.reconstructThenSignAvgTimeMs) },
      { label: 'Overhead', value: `×${stats.overheadFactor}` },
      { label: 'Measured', value: 'Wall-clock only' },
    ]);
    protocolLog.innerHTML = `
      <div class="log-row log-ok">
        <div class="log-top"><strong>Measured timing</strong><span>Overhead ×${stats.overheadFactor}</span></div>
        <div>Only genuinely-measured wall-clock time is shown: standard signing vs combining the two byte shares and then signing. This build runs no real MPC, so no "bytes exchanged" figure is reported.</div>
      </div>
    `;
    setStatus('success', 'Timing complete. These are measured wall-clock numbers, not simulated MPC traffic.');
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

// ---------------------------------------------------------------------------
// Exhibit 2 — interactive round trace (illustrative choreography, real toy math)
// ---------------------------------------------------------------------------

let traceRound: RoundTrace = computeRound();
let traceStep = 0;

function fmtPoly(p: number[]): string {
  return `[${p.map((v) => (v >= 0 ? ` ${v}` : `${v}`)).join(', ')}]`;
}

interface TraceStepDef {
  title: string;
  next: string;
  render(r: RoundTrace): string;
}

const TRACE_STEPS: TraceStepDef[] = [
  {
    title: 'Round · Step 1 — sample nonce shares',
    next: 'Next: combine into commitment w',
    render: (r) => `
      <p>Each party independently samples a fresh random <strong>nonce share</strong>. Neither shares it with the other yet.</p>
      <div class="trace-flow">
        <div class="trace-party trace-server"><span class="trace-tag">SERVER</span><code>y^S = ${fmtPoly(r.yServer)}</code></div>
        <div class="trace-party trace-phone"><span class="trace-tag">PHONE</span><code>y^P = ${fmtPoly(r.yPhone)}</code></div>
      </div>
      <p class="small-note">The nonce masks the secret later, so the response leaks nothing.</p>`,
  },
  {
    title: 'Round · Step 2 — commitment w = A·y',
    next: 'Next: take the high bits w₁',
    render: (r) => `
      <p>The parties jointly form the public commitment <code>w</code>. (Illustrative: modelled here as the sum of the two nonce shares.)</p>
      <div class="trace-flow">
        <div class="trace-party trace-server"><span class="trace-tag">SERVER</span><code>y^S = ${fmtPoly(r.yServer)}</code></div>
        <span class="trace-op" aria-hidden="true">+</span>
        <div class="trace-party trace-phone"><span class="trace-tag">PHONE</span><code>y^P = ${fmtPoly(r.yPhone)}</code></div>
      </div>
      <div class="trace-result trace-shared"><span class="trace-tag">SHARED</span><code>w = ${fmtPoly(r.w)}</code></div>`,
  },
  {
    title: 'Round · Step 3 — high bits w₁',
    next: 'Next: derive the challenge c',
    render: (r) => `
      <p>Only the <strong>high bits</strong> of w survive — the low bits are dropped as noise. This rounding is non-linear, which is what makes ML-DSA hard to split.</p>
      <div class="trace-result trace-shared"><span class="trace-tag">w</span><code>${fmtPoly(r.w)}</code></div>
      <div class="trace-result trace-highlight"><span class="trace-tag">w₁ = HighBits(w)</span><code>${fmtPoly(r.w1)}</code></div>`,
  },
  {
    title: 'Round · Step 4 — Fiat–Shamir challenge c',
    next: 'Next: compute the responses z',
    render: (r) => `
      <p>Hashing w₁ (and the message) yields the <strong>challenge</strong> c — here a small ±1 polynomial. Both parties derive the same c.</p>
      <div class="trace-result trace-shared"><span class="trace-tag">w₁</span><code>${fmtPoly(r.w1)}</code></div>
      <div class="trace-result trace-highlight"><span class="trace-tag">c = H(w₁, msg)</span><code>${fmtPoly(r.c)}</code></div>`,
  },
  {
    title: 'Round · Step 5 — responses z = y + c·s₁',
    next: 'Next: check the norm bound',
    render: (r) => `
      <p>Each party computes its <strong>response share</strong> locally: nonce plus challenge times its secret-key share <code>s₁^i</code>. The nonce hides the secret term.</p>
      <div class="trace-flow">
        <div class="trace-party trace-server"><span class="trace-tag">SERVER</span><code>z^S = y^S + c·s₁^S = ${fmtPoly(r.zServer)}</code></div>
        <div class="trace-party trace-phone"><span class="trace-tag">PHONE</span><code>z^P = y^P + c·s₁^P = ${fmtPoly(r.zPhone)}</code></div>
      </div>
      <div class="trace-result trace-shared"><span class="trace-tag">z = z^S + z^P</span><code>${fmtPoly(r.z)}</code></div>`,
  },
  {
    title: 'Round · Step 6 — infinity-norm check',
    next: 'Start a fresh round',
    render: (r) => {
      const ok = r.accepted;
      return `
      <p>A <strong>secure comparison</strong> checks that the largest coefficient of z stays under the bound <code>β = ${TOY_Z_BOUND}</code> — without revealing z if it fails.</p>
      <div class="trace-result ${ok ? 'trace-accept' : 'trace-reject'}">
        <span class="trace-tag">|z|∞ = ${r.zNorm} ${ok ? '&lt;' : '≥'} β = ${TOY_Z_BOUND}</span>
        <code>${ok ? '✓ ACCEPT — publish z; the round succeeds' : '✕ REJECT — abort; both parties restart with fresh randomness'}</code>
      </div>
      <p class="small-note">${ok
        ? 'This round was accepted. In a real scheme z would now be published and the signature verifies with the standard verifier.'
        : 'This round was rejected. Press “Fresh randomness (restart)” to see the coordinated do-over that makes threshold ML-DSA expensive.'}</p>`;
    },
  },
];

function renderTrace(): void {
  const shown = TRACE_STEPS.slice(0, traceStep);
  if (shown.length === 0) {
    traceStage.innerHTML = '<p class="small-note trace-placeholder">Press <strong>Reveal round 1</strong> to begin. Each press advances one step of the protocol and animates the numbers moving between the SERVER and PHONE columns.</p>';
  } else {
    traceStage.innerHTML = shown
      .map((step, i) => `
        <div class="trace-card${i === shown.length - 1 ? ' trace-card-new' : ''}">
          <div class="trace-card-title">${escapeHtml(step.title)}</div>
          ${step.render(traceRound)}
        </div>`)
      .join('');
  }
  if (traceStep >= TRACE_STEPS.length) {
    traceNextButton.textContent = traceRound.accepted ? 'Round accepted — start a new round' : 'Round rejected — restart with fresh randomness';
  } else {
    traceNextButton.textContent = traceStep === 0
      ? 'Reveal round 1: sample nonces'
      : TRACE_STEPS[traceStep - 1].next;
  }
}

function advanceTrace(): void {
  if (traceStep >= TRACE_STEPS.length) {
    // Completed a round — draw a fresh one and restart the walkthrough.
    traceRound = computeRound();
    traceStep = 0;
  }
  traceStep += 1;
  renderTrace();
}

function resetTrace(): void {
  traceRound = computeRound();
  traceStep = 0;
  renderTrace();
}

// ---------------------------------------------------------------------------
// What's-real panel — escrow vs. ideal contrast experiment
// ---------------------------------------------------------------------------

let contrastMode: 'escrow' | 'ideal' = 'escrow';

function renderContrast(): void {
  contrastEscrowButton.setAttribute('aria-pressed', String(contrastMode === 'escrow'));
  contrastIdealButton.setAttribute('aria-pressed', String(contrastMode === 'ideal'));

  const serverBytes = '2f a1 7c 04 e9 …';
  const phoneBytes = 'd1 63 88 fb 12 …';

  if (contrastMode === 'escrow') {
    contrastView.innerHTML = `
      <div class="contrast-row">
        <div class="contrast-share"><span class="contrast-tag">SERVER share</span><code>${serverBytes}</code></div>
        <span class="contrast-op" aria-hidden="true">+</span>
        <div class="contrast-share"><span class="contrast-tag">PHONE share</span><code>${phoneBytes}</code></div>
      </div>
      <div class="contrast-key contrast-key-live">
        <span class="contrast-tag">Full secret key buffer</span>
        <code>ff 04 f4 ff fb … <span class="contrast-flag">◉ MATERIALIZED IN MEMORY</span></code>
      </div>
      <p class="small-note"><strong>This build (escrow):</strong> to sign, both shares are combined into the whole secret key in one place. It lights up red because at that instant a single machine holds the entire key — the exact thing a real threshold scheme must never allow. This is honest split-custody, not threshold signing.</p>`;
  } else {
    contrastView.innerHTML = `
      <div class="contrast-row">
        <div class="contrast-share"><span class="contrast-tag">SERVER share</span><code>${serverBytes}</code></div>
        <span class="contrast-op" aria-hidden="true">+</span>
        <div class="contrast-share"><span class="contrast-tag">PHONE share</span><code>${phoneBytes}</code></div>
      </div>
      <div class="contrast-key contrast-key-crossed">
        <span class="contrast-tag">Full secret key buffer</span>
        <code><s>ff 04 f4 ff fb …</s> <span class="contrast-flag contrast-flag-ok">✓ NEVER MATERIALIZES</span></code>
      </div>
      <p class="small-note"><strong>Real threshold (never combine):</strong> the parties run an MPC protocol so each only ever computes its own share of the response z. The full key buffer on the right is <em>never</em> assembled anywhere — that is the property this build does not achieve, and the open research problem the landscape table catalogues.</p>`;
  }
}

// ---------------------------------------------------------------------------
// Exhibit 1 — aborts / restart-cost micro-demo
// ---------------------------------------------------------------------------

function runAbortsDemo(): void {
  const { attempts, rejections } = computeUntilAccepted();
  const rows = attempts
    .map((a, i) => {
      const accepted = a.accepted;
      return `
        <div class="abort-row ${accepted ? 'abort-accept' : 'abort-reject'}">
          <span class="abort-icon" aria-hidden="true">${accepted ? '✓' : '↻'}</span>
          <span class="abort-label">Attempt ${i + 1}</span>
          <code>|z|∞ = ${a.zNorm} ${accepted ? '&lt;' : '≥'} β=${TOY_Z_BOUND}</code>
          <span class="abort-state">${accepted ? 'ACCEPT' : 'REJECT — both parties discard & restart'}</span>
        </div>`;
    })
    .join('');
  abortsView.innerHTML = `
    <div class="abort-counter"><strong>${rejections}</strong> coordinated restart${rejections === 1 ? '' : 's'} before one round was accepted.</div>
    ${rows}
    <p class="small-note">Every REJECT above is a full round both parties threw away. In a single signer that is cheap; across parties it multiplies the messaging cost — the ×overhead you can measure with “Run quick benchmark”.</p>`;
}

// ---------------------------------------------------------------------------
// Live additive-share combine (real bytes from the split key)
// ---------------------------------------------------------------------------

let shareByteIndex = 0;
let shareCombined = false;

function currentShareBytes(): { server: number; phone: number; key: number } | null {
  if (!keypair) return null;
  const s = keypair.serverShare.secretKeyShare;
  const p = keypair.phoneShare.secretKeyShare;
  const idx = shareByteIndex % s.length;
  const server = s[idx];
  const phone = p[idx];
  return { server, phone, key: (server + phone) % 256 };
}

function renderShareDemo(): void {
  const bytes = currentShareBytes();
  if (!bytes) {
    shareServerByte.textContent = '—';
    sharePhoneByte.textContent = '—';
    shareResultByte.textContent = '?';
    return;
  }
  shareServerByte.textContent = String(bytes.server);
  sharePhoneByte.textContent = String(bytes.phone);
  if (shareCombined) {
    shareResultByte.textContent = String(bytes.key);
    shareResultByte.classList.add('share-byte-revealed');
    shareCombineNote.textContent = `${bytes.server} + ${bytes.phone} = ${bytes.server + bytes.phone}, and ${bytes.server + bytes.phone} mod 256 = ${bytes.key}. That is byte ${shareByteIndex % (keypair?.serverShare.secretKeyShare.length ?? 1)} of the real ML-DSA-65 secret key — recovered only by summing both shares.`;
  } else {
    shareResultByte.textContent = '?';
    shareResultByte.classList.remove('share-byte-revealed');
    shareCombineNote.textContent = 'Each share is uniform on 0–255, so neither byte alone tells you anything. Only their sum mod 256 recovers the secret byte.';
  }
}

updatePhoneToggleButton();
renderTrace();
renderContrast();
resetVerdicts();
renderShareDemo();

traceNextButton.addEventListener('click', () => {
  advanceTrace();
});

traceResetButton.addEventListener('click', () => {
  resetTrace();
});

contrastEscrowButton.addEventListener('click', () => {
  contrastMode = 'escrow';
  renderContrast();
});

contrastIdealButton.addEventListener('click', () => {
  contrastMode = 'ideal';
  renderContrast();
});

abortsRunButton.addEventListener('click', () => {
  runAbortsDemo();
});

shareCombineButton.addEventListener('click', () => {
  shareCombined = true;
  renderShareDemo();
});

shareRerollButton.addEventListener('click', () => {
  shareByteIndex += 1;
  shareCombined = false;
  renderShareDemo();
});

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
