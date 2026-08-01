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

    <nav class="guided-path panel" aria-label="Suggested learning path">
      <span class="guided-path-label">START HERE — a 5-stop path</span>
      <ol class="guided-path-steps">
        <li><a href="#stop-sharing"><span class="guided-num">1</span> Hold the one real idea: additive sharing</a></li>
        <li><a href="#stop-hard"><span class="guided-num">2</span> See why it's hard: aborts &amp; restarts</a></li>
        <li><a href="#stop-walk"><span class="guided-num">3</span> Walk one round, value by value</a></li>
        <li><a href="#stop-ideal"><span class="guided-num">4</span> Watch the ideal: never combine the key</a></li>
        <li><a href="#stop-live"><span class="guided-num">5</span> Sign live — and read both verdicts</a></li>
      </ol>
      <p class="small-note guided-path-note">New here? Follow 1→5 in order. Each stop builds the intuition for the next; the research table and benchmark are optional depth once you've walked the path.</p>
    </nav>

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

    <section id="stop-sharing" class="panel share-demo-panel" aria-labelledby="share-demo-heading">
      <p class="stop-badge"><span class="stop-badge-num">1</span> Start here</p>
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

      <div id="stop-ideal" class="contrast-experiment">
        <p class="stop-badge"><span class="stop-badge-num">4</span> The ideal path</p>
        <h4 id="contrast-heading">Feel the difference: escrow vs. a real threshold scheme</h4>
        <p class="small-note">
          Both paths start from the same two byte shares. Watch what happens to the full secret key
          buffer. Toggle to compare — then press <strong>Play the ideal round</strong> to watch the
          never-combine path animate end to end.
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

        <div id="stop-hard" class="aborts-demo">
          <p class="stop-badge"><span class="stop-badge-num">2</span> Why it's hard</p>
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

      <article id="stop-walk" class="panel exhibit trace-exhibit">
        <p class="stop-badge"><span class="stop-badge-num">3</span> Walk a round</p>
        <h3>Exhibit 2 — Walk a signing round, one step at a time</h3>
        <p class="small-note">
          <strong>Illustrative choreography</strong> — this shows the <em>shape</em> of a real two-party
          lattice signing round. The tiny numbers below are computed live with genuine modular /
          additive-sharing math on toy 3-coefficient polynomials (mod ${TOY_Q}), so you can watch the
          actual values flow between the two parties. It does <em>not</em> produce the signature the live
          demo emits — that still comes from the honest combine-then-sign path. Simplified numbers, real math.
        </p>
        <p class="small-note caveat-note" role="note">
          <strong>Honest caveat about this trace:</strong> to keep the numbers legible it abstracts two
          things a real ML-DSA round does. The commitment is modelled as <code>w = y^S + y^P</code> rather
          than <code>w = A·y</code> (the public matrix A is elided), and the challenge is applied as a
          single scalar <code>c[0]</code> instead of a full sparse polynomial. So the trace faithfully shows
          the <em>structure</em> — masked exchange, rounding, rejection — but not the full matrix/polynomial
          algebra. Everything else (the additive sharing and modular arithmetic) is computed for real.
        </p>
        <div class="button-row trace-controls">
          <button id="trace-next" class="primary-button" type="button" aria-controls="trace-stage">Reveal round 1: sample nonces</button>
          <button id="trace-reset" class="secondary-button" type="button" aria-controls="trace-stage">Fresh randomness (restart)</button>
        </div>
        <div id="trace-stage" class="trace-stage" tabindex="0" role="region" aria-label="Round-by-round signing trace" aria-live="polite">
          <div class="trace-lanes" aria-hidden="false">
            <div class="trace-lane trace-lane-server">
              <span class="trace-lane-head">SERVER</span>
              <div id="trace-lane-server-slots" class="trace-lane-slots"></div>
            </div>
            <div class="trace-lane trace-lane-channel">
              <span class="trace-lane-head">SHARED CHANNEL</span>
              <div id="trace-lane-channel-slots" class="trace-lane-slots trace-channel-slots"></div>
            </div>
            <div class="trace-lane trace-lane-phone">
              <span class="trace-lane-head">PHONE</span>
              <div id="trace-lane-phone-slots" class="trace-lane-slots"></div>
            </div>
          </div>
          <div id="trace-flight-layer" class="trace-flight-layer" aria-hidden="true"></div>
          <div id="trace-narration" class="trace-narration">
            <p class="small-note trace-placeholder">Press <strong>Reveal round 1</strong> to begin. Each press advances one step; value chips physically travel from the SERVER and PHONE lanes into the shared channel as the arithmetic lands.</p>
          </div>
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
        <span id="stop-live" class="stop-anchor" aria-hidden="true"></span>
        <p class="stop-badge"><span class="stop-badge-num">5</span> Sign live</p>
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
        <p id="verdict-bridge" class="small-note verdict-bridge">Both cards describe the <strong>same run</strong>: run it and see for yourself. You stopped either party from signing alone (custody, green) — but to actually make the signature, one machine briefly held the whole reconstructed key (no key-non-reconstruction, red). Custody and distributed-trust are two different properties; this build earns the first, not the second.</p>
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
              <tr><td>Trilithium (2025/675)</td><td>2 + CRP <sup>&sect;</sup></td><td>UC, malicious</td><td>14 <sup>&para;</sup></td><td>Yes</td></tr>
              <tr><td>Quorus (2025/1163)</td><td>Any t-of-n (honest majority)</td><td>UC, malicious (abort)</td><td>16–29 online <sup>&para;</sup></td><td>Yes</td></tr>
              <tr><td>TOPCOAT (2024)</td><td>2</td><td>sim. malicious</td><td>3</td><td>No <sup>&dagger;</sup></td></tr>
              <tr><td>Hermine (2026/419)</td><td>Any t-of-n, N ≤ 64</td><td>Identifiable aborts + proactive</td><td>2 (partially non-interactive)</td><td>No <sup>&Dagger;</sup></td></tr>
              <tr><td>THED (2026/638)</td><td>Any t-of-n</td><td>FHE-based, passive</td><td>2</td><td>Yes</td></tr>
              <tr><td>Threshold Raccoon</td><td>t-of-n, N ≤ 1024</td><td>Standard lattice</td><td>3</td><td>No</td></tr>
            </tbody>
          </table>
        </div>
        <p class="small-note">
          No threshold ML-DSA construction is NIST-standardized as of 2026. This lab models the signing-side protocol only.
          Every figure above is taken from the cited paper. Where a paper does not state a number, the cell says so rather
          than estimating one.
        </p>
        <p class="small-note">
          <sup>&sect;</sup> Trilithium is two <em>signers</em> — a server and a phone — but its architecture also requires a
          Correlated Randomness Provider as a third entity. The paper's own concluding remarks call it "a three-party (Phone,
          Server, and CRP) protocol, providing security against a single malicious party." The CRP never runs an interactive
          signing round (its traffic is one-way and precomputable), but it is not optional, and the two-party server/phone
          framing this demo borrows omits it.
        </p>
        <p class="small-note">
          <sup>&para;</sup> Round counts are per signing <em>attempt</em>, so a rejected round multiplies them. Trilithium
          reports "3 rounds for key generation, 14 rounds for signing" (&sect;6). Quorus reports 29 online rounds
          (communication-optimised) or 16 (round-optimised) per SIGN invocation, and expects four to five invocations per
          signature. Earlier versions of this table gave Trilithium "5–8" and Quorus "6–10"; neither figure appears in
          either paper.
        </p>
        <p class="small-note">
          <sup>&dagger;</sup> TOPCOAT targets the pre-standard CRYSTALS-Dilithium submission, not FIPS 204 ML-DSA, and its
          paper states that "the verification algorithm in our scheme is different from the original Dilithium verification
          because we introduce additional components to the signature" — an extra hint component. Its ≈10 KB signatures are
          therefore not accepted by an unmodified FIPS 204 verifier; the paper makes no FIPS 204 compatibility claim.
          (Snetkov, Vakarjuk, Laud, <em>Discover Computing</em> 27(1):18, 2024, doi:10.1007/s10791-024-09449-2.)
        </p>
        <p class="small-note">
          <sup>&Dagger;</sup> Hermine outputs an ≈11 KB Raccoon signature, not an ML-DSA one, so it needs its own verifier.
          It supersedes the withdrawn ePrint 2025/871 ("Simple and Efficient Lattice Threshold Signatures with Identifiable
          Aborts"), which it extends to the two-round setting with proactive refresh, so older summaries giving that line a
          variable round count are stale.
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
            <dt>Proactive security / refresh</dt>
            <dd>Key shares are periodically re-randomised, so an attacker must break into enough parties within a single epoch rather than accumulating shares over time.</dd>
            <dt>Std compat (standard-compatible)</dt>
            <dd>"Yes" means the output is a normal FIPS 204 signature the unmodified verifier accepts — no special verifier needed. "No" means the scheme either targets a different base signature or changes the verification algorithm, so relying parties would need new verifier code.</dd>
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

    <section class="panel footer-panel" aria-label="Research anchors and related demos">
      <h3>Research anchors</h3>
      <p>
        Trilithium: Dufka, Kravtšenko, Laud, Snetkov (ePrint 2025/675). Quorus: Bienstock, de Castro, Escudero, Polychroniadou, Takahashi (ePrint 2025/1163). TOPCOAT: Snetkov, Vakarjuk, Laud — 2024 two-party HighBits compression over pre-standard CRYSTALS-Dilithium (Discover Computing 27(1):18). Hermine: an efficient lattice-based FROST-like threshold signature — Borin, Celi, del Pino, Espitau, Katsumata, Niot, Prest, Takemure (ePrint 2026/419), superseding the withdrawn ePrint 2025/871. Unmasking TRaccoon: del Pino, Katsumata, Niot, Reichle, Takemure (ePrint 2025/849).
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
  keypair = await distributedKeyGen((round, description, artifactBytes) => {
    // Label the figure as an ARTIFACT SIZE, not wire traffic. This build runs no
    // MPC, so it has no "bytes exchanged" to report and must not imply it does.
    const size = artifactBytes === null ? '' : ` (artifact: ${formatBytes(artifactBytes)})`;
    dkgLogs.push(`Step ${round}: ${description}${size}`);
  });
  renderMaskedShares(keypair);
  renderShareDemo();
  // The escrow contrast panel shows real split-key bytes; re-render now that they
  // exist. Skipped in `ideal` mode so a running animation is not torn down.
  if (contrastMode === 'escrow') {
    renderContrast();
  }

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
      setStatus(
        blocked ? 'warning' : 'danger',
        blocked
          ? 'The phone is disabled, so the 2-of-2 protocol cannot complete — the server\'s lone attempt was rejected by the standard verifier.'
          : 'CUSTODY BROKEN: the server signed alone and the standard verifier accepted it.',
      );
      renderStats([
        { label: 'Scenario', value: '2-of-2 custody' },
        { label: 'Signature', value: '—' },
        { label: 'Sign time', value: '—' },
        { label: 'Verifier', value: blocked ? 'Sign blocked' : 'Unexpected' },
      ]);
      setVerdict(verdictSig, 'bad', 'Signature valid', 'No signature — phone share missing');
      // Derived from the measured drop-one result, never asserted. `blocked` is
      // true only when the server's lone share actually produced a signature the
      // standard verifier REJECTED. If a single party ever did forge, this card
      // must go red rather than congratulate the demo on a property it lost.
      setVerdict(
        verdictTrust,
        blocked ? 'good' : 'bad',
        'Custody enforced',
        blocked
          ? 'PASS — server\'s lone share signed, and the standard verifier rejected it'
          : 'FAIL — a single party produced a signature the verifier ACCEPTED',
      );
      protocolLog.innerHTML = `
        <div class="log-row ${blocked ? 'log-reject' : 'log-ok'}">
          <div class="log-top"><strong>Drop-one test</strong><span>${blocked ? '2-of-2 enforced' : 'CUSTODY BROKEN'}</span></div>
          <div>${blocked
            ? 'The server signed with its own share alone (padding the phone half with zeros). The standard FIPS 204 verifier rejected the result, so one party cannot sign without the other.'
            : 'The server signed with its own share alone and the standard verifier ACCEPTED it. That must never happen — the 2-of-2 custody property is broken in this build.'}</div>
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

const traceLaneServer = getElement<HTMLDivElement>('#trace-lane-server-slots');
const traceLaneChannel = getElement<HTMLDivElement>('#trace-lane-channel-slots');
const traceLanePhone = getElement<HTMLDivElement>('#trace-lane-phone-slots');
const traceFlightLayer = getElement<HTMLDivElement>('#trace-flight-layer');
const traceNarration = getElement<HTMLDivElement>('#trace-narration');

const prefersReducedMotion = (): boolean =>
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;

/** A value chip placed in one of the three fixed lanes. */
interface Chip {
  lane: 'server' | 'phone' | 'channel';
  tone: 'server' | 'phone' | 'shared' | 'highlight' | 'accept' | 'reject';
  tag: string;
  value: string;
  /** If set, this chip flies from the given source lane into its lane on reveal. */
  flyFrom?: 'server' | 'phone';
}

interface TraceStepDef {
  title: string;
  next: string;
  narration(r: RoundTrace): string;
  chips(r: RoundTrace): Chip[];
}

const TRACE_STEPS: TraceStepDef[] = [
  {
    title: 'Step 1 — sample nonce shares',
    next: 'Next: values travel → commitment w',
    narration: () =>
      '<p>Each party independently samples a fresh random <strong>nonce share</strong> inside its own lane. Nothing has crossed the channel yet.</p>',
    chips: (r) => [
      { lane: 'server', tone: 'server', tag: 'y^S', value: fmtPoly(r.yServer) },
      { lane: 'phone', tone: 'phone', tag: 'y^P', value: fmtPoly(r.yPhone) },
    ],
  },
  {
    title: 'Step 2 — commitment w = A·y',
    next: 'Next: take the high bits w₁',
    narration: () =>
      '<p>Both nonce shares now <strong>travel across the shared channel</strong> and are summed into the public commitment <code>w</code>. (Illustrative: modelled as y^S + y^P; the matrix A is elided — see the caveat above.)</p>',
    chips: (r) => [
      { lane: 'server', tone: 'server', tag: 'y^S', value: fmtPoly(r.yServer) },
      { lane: 'phone', tone: 'phone', tag: 'y^P', value: fmtPoly(r.yPhone) },
      { lane: 'channel', tone: 'shared', tag: 'w = y^S + y^P', value: fmtPoly(r.w), flyFrom: 'server' },
    ],
  },
  {
    title: 'Step 3 — high bits w₁',
    next: 'Next: derive the challenge c',
    narration: () =>
      '<p>Only the <strong>high bits</strong> of w survive — the low bits drop as noise. This rounding is non-linear, which is exactly what makes ML-DSA hard to split.</p>',
    chips: (r) => [
      { lane: 'channel', tone: 'shared', tag: 'w', value: fmtPoly(r.w) },
      { lane: 'channel', tone: 'highlight', tag: 'w₁ = HighBits(w)', value: fmtPoly(r.w1) },
    ],
  },
  {
    title: 'Step 4 — Fiat–Shamir challenge c',
    next: 'Next: compute the responses z',
    narration: () =>
      '<p>Hashing w₁ (and the message) yields the shared <strong>challenge</strong> c — here a small ±1 polynomial. Both parties derive the same c from the channel.</p>',
    chips: (r) => [
      { lane: 'channel', tone: 'shared', tag: 'w₁', value: fmtPoly(r.w1) },
      { lane: 'channel', tone: 'highlight', tag: 'c = H(w₁, msg)', value: fmtPoly(r.c) },
    ],
  },
  {
    title: 'Step 5 — responses z = y + c·s₁',
    next: 'Next: check the norm bound',
    narration: () =>
      '<p>Each party computes its <strong>response share</strong> locally — nonce plus challenge times its own secret-key share s₁^i — then the two z-shares travel into the channel and are summed. The secret shares never leave their lanes.</p>',
    chips: (r) => [
      { lane: 'server', tone: 'server', tag: 'z^S = y^S + c·s₁^S', value: fmtPoly(r.zServer) },
      { lane: 'phone', tone: 'phone', tag: 'z^P = y^P + c·s₁^P', value: fmtPoly(r.zPhone) },
      { lane: 'channel', tone: 'shared', tag: 'z = z^S + z^P', value: fmtPoly(r.z), flyFrom: 'server' },
    ],
  },
  {
    title: 'Step 6 — infinity-norm check',
    next: 'Start a fresh round',
    narration: (r) => {
      const ok = r.accepted;
      return `<p>A <strong>secure comparison</strong> checks the largest coefficient of z stays under the bound <code>β = ${TOY_Z_BOUND}</code> — without revealing z if it fails.</p>
      <p class="small-note">${ok
        ? 'This round was accepted. In a real scheme z would now be published and the signature verifies with the standard verifier.'
        : 'This round was rejected. Press “Fresh randomness (restart)” to see the coordinated do-over that makes threshold ML-DSA expensive.'}</p>`;
    },
    chips: (r) => [
      { lane: 'channel', tone: 'shared', tag: 'z', value: fmtPoly(r.z) },
      {
        lane: 'channel',
        tone: r.accepted ? 'accept' : 'reject',
        tag: `|z|∞ = ${r.zNorm} ${r.accepted ? '<' : '≥'} β = ${TOY_Z_BOUND}`,
        value: r.accepted ? '✓ ACCEPT — publish z' : '✕ REJECT — both restart',
      },
    ],
  },
];

function chipHtml(chip: Chip, isNew: boolean): string {
  return `<div class="trace-chip trace-chip-${chip.tone}${isNew && !chip.flyFrom ? ' trace-chip-pop' : ''}" data-lane="${chip.lane}">
      <span class="trace-tag">${escapeHtml(chip.tag)}</span>
      <code>${escapeHtml(chip.value)}</code>
    </div>`;
}

/**
 * Animate a landing chip flying from a source party lane into the channel.
 * Uses a transient clone in the fixed flight layer; the real chip is hidden
 * until the flight lands, then revealed. Respects prefers-reduced-motion.
 */
function flyChipIntoChannel(from: 'server' | 'phone'): void {
  const target = traceLaneChannel.querySelector<HTMLElement>('.trace-chip[data-fly="1"]');
  if (!target) return;
  const source = (from === 'server' ? traceLaneServer : traceLanePhone).querySelector<HTMLElement>('.trace-chip');
  if (!source || prefersReducedMotion()) {
    target.classList.remove('trace-chip-hidden');
    return;
  }
  const stageRect = traceStage.getBoundingClientRect();
  const srcRect = source.getBoundingClientRect();
  const dstRect = target.getBoundingClientRect();
  const clone = target.cloneNode(true) as HTMLElement;
  clone.classList.remove('trace-chip-hidden');
  clone.classList.add('trace-flight-chip');
  clone.style.left = `${srcRect.left - stageRect.left}px`;
  clone.style.top = `${srcRect.top - stageRect.top}px`;
  clone.style.width = `${dstRect.width}px`;
  traceFlightLayer.appendChild(clone);
  // Force layout, then translate to the destination.
  void clone.getBoundingClientRect();
  clone.style.transform = `translate(${dstRect.left - srcRect.left}px, ${dstRect.top - srcRect.top}px)`;
  clone.style.opacity = '1';
  const finish = (): void => {
    target.classList.remove('trace-chip-hidden');
    clone.remove();
  };
  clone.addEventListener('transitionend', finish, { once: true });
  // Safety fallback if transitionend does not fire.
  window.setTimeout(finish, 700);
}

function renderTrace(): void {
  traceFlightLayer.innerHTML = '';
  if (traceStep === 0) {
    traceLaneServer.innerHTML = '';
    traceLanePhone.innerHTML = '';
    traceLaneChannel.innerHTML = '';
    traceNarration.innerHTML =
      '<p class="small-note trace-placeholder">Press <strong>Reveal round 1</strong> to begin. Each press advances one step; value chips physically travel from the SERVER and PHONE lanes into the shared channel as the arithmetic lands.</p>';
    traceNextButton.textContent = 'Reveal round 1: sample nonces';
    return;
  }

  const def = TRACE_STEPS[traceStep - 1];
  const chips = def.chips(traceRound);

  const buckets: Record<'server' | 'phone' | 'channel', string[]> = { server: [], phone: [], channel: [] };
  let flyingFrom: 'server' | 'phone' | null = null;
  for (const chip of chips) {
    const isFly = Boolean(chip.flyFrom);
    let html = chipHtml(chip, true);
    if (isFly) {
      flyingFrom = chip.flyFrom!;
      // Mark the landing chip so the flight animation can find and reveal it.
      html = html.replace('class="trace-chip', 'data-fly="1" class="trace-chip trace-chip-hidden');
    }
    buckets[chip.lane].push(html);
  }
  traceLaneServer.innerHTML = buckets.server.join('') || '<span class="trace-lane-empty">—</span>';
  traceLanePhone.innerHTML = buckets.phone.join('') || '<span class="trace-lane-empty">—</span>';
  traceLaneChannel.innerHTML = buckets.channel.join('') || '<span class="trace-lane-empty">shared values appear here</span>';

  traceNarration.innerHTML = `<p class="trace-step-title">${escapeHtml(def.title)}</p>${def.narration(traceRound)}`;

  if (flyingFrom) {
    // Wait a frame so the lanes have laid out, then fly.
    requestAnimationFrame(() => flyChipIntoChannel(flyingFrom!));
  }

  if (traceStep >= TRACE_STEPS.length) {
    traceNextButton.textContent = traceRound.accepted ? 'Round accepted — start a new round' : 'Round rejected — restart with fresh randomness';
  } else {
    traceNextButton.textContent = def.next;
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

/**
 * The first five bytes of the REAL split secret key, plus their genuine sum
 * mod 256. Returns null until distributed key generation has run, so the panel
 * shows a placeholder rather than fabricated hex.
 */
function contrastKeyBytes(): { server: string; phone: string; key: string } | null {
  if (!keypair) return null;
  const s = keypair.serverShare.secretKeyShare.slice(0, 5);
  const p = keypair.phoneShare.secretKeyShare.slice(0, 5);
  const hex = (b: Uint8Array): string => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join(' ');
  const combined = Uint8Array.from(s, (v, i) => (v + p[i]) % 256);
  return { server: hex(s), phone: hex(p), key: hex(combined) };
}

function renderContrast(): void {
  contrastEscrowButton.setAttribute('aria-pressed', String(contrastMode === 'escrow'));
  contrastIdealButton.setAttribute('aria-pressed', String(contrastMode === 'ideal'));

  // These must be the REAL split-key bytes, and the key row must be their actual
  // sum mod 256 — this panel sits directly under the widget that teaches
  // `server + phone (mod 256) = key byte`, so a learner can and will check the
  // arithmetic. Hardcoded hex that does not add up is a lie the page tells about
  // its own primitive. Before the keypair exists we show placeholders instead of
  // inventing bytes.
  const contrast = contrastKeyBytes();
  const serverBytes = contrast ? `${contrast.server} …` : '— (generating key…)';
  const phoneBytes = contrast ? `${contrast.phone} …` : '— (generating key…)';
  const keyBytes = contrast ? `${contrast.key} …` : '—';

  if (contrastMode === 'escrow') {
    contrastView.innerHTML = `
      <div class="contrast-row">
        <div class="contrast-share"><span class="contrast-tag">SERVER share</span><code>${serverBytes}</code></div>
        <span class="contrast-op" aria-hidden="true">+</span>
        <div class="contrast-share"><span class="contrast-tag">PHONE share</span><code>${phoneBytes}</code></div>
      </div>
      <div class="contrast-key contrast-key-live">
        <span class="contrast-tag">Full secret key buffer</span>
        <code>${keyBytes} <span class="contrast-flag">◉ MATERIALIZED IN MEMORY</span></code>
      </div>
      <p class="small-note"><strong>This build (escrow):</strong> to sign, both shares are combined into the whole secret key in one place. It lights up red because at that instant a single machine holds the entire key — the exact thing a real threshold scheme must never allow. This is honest split-custody, not threshold signing.</p>`;
  } else {
    contrastView.innerHTML = `
      <p class="small-note"><strong>Real threshold (never combine)</strong> — this is the positive picture: what threshold signing <em>should</em> look like, animated. Press play to watch each party keep its secret in its own lane while only masked z-shares cross the channel.</p>
      <div class="button-row ideal-controls">
        <button id="ideal-play" class="secondary-button" type="button" aria-controls="ideal-stage">▶ Play the ideal round</button>
      </div>
      <div id="ideal-stage" class="ideal-stage" role="region" aria-label="Ideal threshold round animation" aria-live="polite">
        <div class="ideal-lanes">
          <div class="ideal-lane ideal-lane-server">
            <span class="ideal-lane-head">SERVER (holds s₁^S only)</span>
            <div id="ideal-server-slot" class="ideal-slot"></div>
          </div>
          <div class="ideal-lane ideal-lane-channel">
            <span class="ideal-lane-head">SHARED CHANNEL (only masked z-shares cross)</span>
            <div id="ideal-channel-slot" class="ideal-slot ideal-channel-slot"></div>
          </div>
          <div class="ideal-lane ideal-lane-phone">
            <span class="ideal-lane-head">PHONE (holds s₁^P only)</span>
            <div id="ideal-phone-slot" class="ideal-slot"></div>
          </div>
        </div>
        <div id="ideal-flight-layer" class="ideal-flight-layer" aria-hidden="true"></div>
        <div id="ideal-keybuf" class="ideal-keybuf">
          <span class="contrast-tag">Full secret key buffer</span>
          <code><s>ff 04 f4 ff fb …</s> <span class="contrast-flag contrast-flag-ok">✓ NEVER ASSEMBLED</span></code>
        </div>
        <p id="ideal-caption" class="small-note ideal-caption">Press <strong>Play the ideal round</strong>. Watch the greyed key buffer at the bottom: in this path it is never filled in — the whole point of a real threshold scheme.</p>
      </div>`;
    wireIdealStage();
  }
}

// ---------------------------------------------------------------------------
// Ideal-threshold animated sequence (the positive counterpart to escrow):
// each party computes z^i locally, the z-shares fly across the channel, and
// only their SUM z is published — the full key buffer is never assembled.
// ---------------------------------------------------------------------------

let idealPlaying = false;

interface IdealStep {
  caption: string;
  render(): { server?: string; phone?: string; channel?: string; fly?: 'server' | 'phone'; keyState?: 'idle' | 'never' };
}

function idealChip(tone: string, tag: string, value: string): string {
  return `<div class="ideal-chip ideal-chip-${tone}"><span class="contrast-tag">${escapeHtml(tag)}</span><code>${escapeHtml(value)}</code></div>`;
}

const IDEAL_STEPS: IdealStep[] = [
  {
    caption: 'Each party samples its own nonce share y^i locally. Secrets never leave the lane they live in.',
    render: () => ({
      server: idealChip('server', 'y^S (local)', '[ 4, -3, 7]'),
      phone: idealChip('phone', 'y^P (local)', '[-2, 5, -1]'),
      keyState: 'never',
    }),
  },
  {
    caption: 'Each party computes its response share z^i = y^i + c·s₁^i — using only its OWN secret-key share. The other party never sees s₁^i.',
    render: () => ({
      server: idealChip('server', 'z^S = y^S + c·s₁^S', '[ 6, -1, 8]'),
      phone: idealChip('phone', 'z^P = y^P + c·s₁^P', '[-3, 4, 0]'),
      keyState: 'never',
    }),
  },
  {
    caption: 'Only the masked z-shares travel across the channel. A z-share reveals nothing on its own — the nonce hides the secret term.',
    render: () => ({
      server: idealChip('server', 'z^S', '[ 6, -1, 8]'),
      phone: idealChip('phone', 'z^P', '[-3, 4, 0]'),
      channel: idealChip('shared', 'z = z^S + z^P (published)', '[ 3, 3, 8]'),
      fly: 'server',
      keyState: 'never',
    }),
  },
  {
    caption: 'Only the SUM z is published — and it verifies under the standard FIPS 204 verifier. The full secret key buffer below was never assembled anywhere. THAT is real threshold signing.',
    render: () => ({
      server: idealChip('server', 's₁^S', '(never revealed)'),
      phone: idealChip('phone', 's₁^P', '(never revealed)'),
      channel: idealChip('accept', 'z published ✓ verifies', '[ 3, 3, 8]'),
      keyState: 'never',
    }),
  },
];

function idealSetKeyBuf(state: 'idle' | 'never'): void {
  const buf = document.querySelector<HTMLDivElement>('#ideal-keybuf');
  if (!buf) return;
  buf.classList.toggle('ideal-keybuf-never', state === 'never');
}

function idealFly(from: 'server' | 'phone'): void {
  const layer = document.querySelector<HTMLDivElement>('#ideal-flight-layer');
  const stage = document.querySelector<HTMLDivElement>('#ideal-stage');
  const target = document.querySelector<HTMLElement>('#ideal-channel-slot .ideal-chip');
  const source = document.querySelector<HTMLElement>(`#ideal-${from}-slot .ideal-chip`);
  if (!layer || !stage || !target || !source) return;
  if (prefersReducedMotion()) return;
  const stageRect = stage.getBoundingClientRect();
  const srcRect = source.getBoundingClientRect();
  const dstRect = target.getBoundingClientRect();
  target.style.visibility = 'hidden';
  const clone = target.cloneNode(true) as HTMLElement;
  clone.style.visibility = 'visible';
  clone.classList.add('ideal-flight-chip');
  clone.style.left = `${srcRect.left - stageRect.left}px`;
  clone.style.top = `${srcRect.top - stageRect.top}px`;
  clone.style.width = `${dstRect.width}px`;
  layer.appendChild(clone);
  void clone.getBoundingClientRect();
  clone.style.transform = `translate(${dstRect.left - srcRect.left}px, ${dstRect.top - srcRect.top}px)`;
  const finish = (): void => {
    target.style.visibility = 'visible';
    clone.remove();
  };
  clone.addEventListener('transitionend', finish, { once: true });
  window.setTimeout(finish, 700);
}

function renderIdealStep(i: number): void {
  const serverSlot = document.querySelector<HTMLDivElement>('#ideal-server-slot');
  const phoneSlot = document.querySelector<HTMLDivElement>('#ideal-phone-slot');
  const channelSlot = document.querySelector<HTMLDivElement>('#ideal-channel-slot');
  const caption = document.querySelector<HTMLParagraphElement>('#ideal-caption');
  if (!serverSlot || !phoneSlot || !channelSlot || !caption) return;
  const step = IDEAL_STEPS[i];
  const state = step.render();
  serverSlot.innerHTML = state.server ?? '';
  phoneSlot.innerHTML = state.phone ?? '';
  channelSlot.innerHTML = state.channel ?? '<span class="trace-lane-empty">masked z-shares appear here</span>';
  caption.innerHTML = step.caption;
  idealSetKeyBuf(state.keyState ?? 'never');
  if (state.fly) requestAnimationFrame(() => idealFly(state.fly!));
}

async function playIdeal(): Promise<void> {
  if (idealPlaying) return;
  const playButton = document.querySelector<HTMLButtonElement>('#ideal-play');
  idealPlaying = true;
  if (playButton) playButton.disabled = true;
  const delay = prefersReducedMotion() ? 350 : 1200;
  for (let i = 0; i < IDEAL_STEPS.length; i += 1) {
    renderIdealStep(i);
    await new Promise((resolve) => window.setTimeout(resolve, delay));
  }
  idealPlaying = false;
  if (playButton) {
    playButton.disabled = false;
    playButton.textContent = '↻ Replay the ideal round';
  }
}

function wireIdealStage(): void {
  const playButton = document.querySelector<HTMLButtonElement>('#ideal-play');
  if (playButton) playButton.addEventListener('click', () => void playIdeal());
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
  idealPlaying = false;
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
