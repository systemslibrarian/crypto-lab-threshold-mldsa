# crypto-lab-threshold-mldsa

## What It Is

This repository demonstrates the central threshold-signing question for post-quantum cryptography:

- Can multiple parties cooperate to produce a single valid ML-DSA signature?
- Can the verifier remain unchanged and still accept that signature under standard FIPS 204 verification?
- Why is this harder than threshold Schnorr or threshold BLS?

The demo answers them from two directions at once, because no single browser demo can have both halves. The **ML-DSA-65 path** keeps real FIPS 204 parameters and emits a signature the unmodified standard verifier accepts — and pays for it by combining the two additive key shares in one place, so it is split custody rather than threshold signing. The **never-combine path** gives up standard compatibility and real parameters and, in exchange, actually runs a two-party protocol in which the full secret is never assembled: a module-SIS Fiat–Shamir-with-aborts signature at toy dimensions (`n = 64`, `k = l = 2`) with its own verifier, real per-party rejection sampling, and real aborts. You can run it, and you can break it. Both paths are labelled for exactly what they are (see "What's Real and What's Simulated" below). The research direction it draws on:

- **Trilithium** — Dufka, Kravtšenko, Laud, Snetkov, ePrint 2025/675
- **Quorus** — Bienstock, de Castro, Escudero, Polychroniadou, Takahashi, ePrint 2025/1163
- **TOPCOAT** — Snetkov, Vakarjuk, Laud, 2024 two-party HighBits compression approach, targeting pre-standard CRYSTALS-Dilithium rather than FIPS 204 ML-DSA ([Discover Computing 27(1):18](https://doi.org/10.1007/s10791-024-09449-2))
- **Hermine: An Efficient Lattice-based FROST-like Threshold Signature** — Borin, Celi, del Pino, Espitau, Katsumata, Niot, Prest, Takemure, [ePrint 2026/419](https://eprint.iacr.org/2026/419) — supersedes the withdrawn ePrint 2025/871, extending it to two rounds with proactive refresh
- **Unmasking TRaccoon** — del Pino, Katsumata, Niot, Reichle, Takemure, ePrint 2025/849
- **THED** — Park, Passelègue, Stehlé, ePrint 2026/638
- **Threshold Raccoon** — del Pino, Katsumata, Maller, Mouhartem, Prest, Saarinen, EUROCRYPT 2024

A guided **"Start here — a 5-stop path"** strip sits at the top so a newcomer follows one intuition-building route (additive sharing → why it's hard → walk a round → watch the ideal → sign live) instead of landing on the dense research table first. The live UI includes five exhibits, plus three hands-on teaching widgets layered on top of the honesty framing:

1. Why threshold ML-DSA is harder than classical threshold signatures — with an interactive **"why aborts make it expensive"** micro-demo that runs rounds until one is accepted and counts the coordinated restarts.
2. An **animated step-by-step protocol walkthrough** with fixed SERVER / SHARED CHANNEL / PHONE lanes: as you advance a round, value chips physically travel from the party lanes into the channel — nonce shares into `w`, then `w₁` high bits, the Fiat–Shamir challenge `c`, and the z-shares summing into `z` — with a live infinity-norm accept/reject check. The tiny numbers are computed with genuine toy modular / additive-sharing math (illustrative choreography, real arithmetic), and an on-screen honest caveat notes the two abstractions (`w = y^S + y^P` not `A·y`; challenge applied as a single scalar). Includes an inline glossary of the lattice jargon.
3. Interactive two-party (split-custody) signing, with each step labelled real or illustrative, and **two separate result indicators** — *Signature valid* (green) vs *Distributed-trust enforced* (red) — plus a plain-language bridging sentence spelling out that both cards describe the **same run** (custody achieved, key-non-reconstruction not).
4. A comparison table of the 2024–2026 threshold ML-DSA research landscape, with a glossary for the security column (UC, malicious, identifiable aborts, FHE-based, proactive security, std compat) and footnotes recording where a scheme does *not* verify under an unmodified FIPS 204 verifier.
5. Real-world applications for post-quantum multi-party signing.

Two additional interactive panels make the honesty concrete: a **live additive-share combiner** (click to sum one real key byte's two shares mod 256) and an **escrow-vs-never-combine contrast experiment**. The escrow view shows the full-key buffer light up red when combined. The never-combine view **executes a real two-party protocol** at toy lattice parameters:

- Each party samples its own secret share `s^i` and publishes only `t^i = A·s^i`. The sum `s = s^S + s^P` is never formed by anyone — each share lives in a closure the other party and the page cannot read, so the guarantee is structural rather than a promise in a comment.
- Signing runs for real: nonces, commitments `w^i = A·y^i`, a SHAKE256 Fiat–Shamir challenge via `SampleInBall`, per-party rejection sampling against `‖z^i‖∞ < γ₁ − β`, and genuine coordinated aborts (mean 2.5 attempts per signature, measured).
- A verifier written for this scheme recomputes `A·z − c·t`, re-derives the challenge, and checks `‖z‖∞ < 2(γ₁ − β)`. Its verdict is what the page reports.
- **You can break it.** *Corrupt the phone's z-share (over the bound)* pushes one coefficient past `γ₁ − β`; the receiving party's norm check rejects it and **no signature is emitted**. *Corrupt it by one unit* changes the smallest coefficient by 1 — small enough that the norm check waves it through, so the Fiat–Shamir recomputation is what catches it. The verdict names which check fired, from the run.
- Its parameters carry **no security** and its signatures are **not FIPS 204** — the panel says so on screen, in the panel, before you run it.

> This repo is **educational, not production-safe**. No threshold ML-DSA scheme is NIST-standardized as of 2026.

## When to Use It

Use this demo when you want to:

- understand why threshold lattice signatures are more complicated than threshold Schnorr or BLS
- study the structure of a two-party ML-DSA protocol in a browser-only environment
- see additive secret sharing applied to ML-DSA-flavored key components
- run a genuine never-combine two-party lattice signing protocol end to end at toy parameters, and watch a corrupted z-share get rejected by the norm check or by the Fiat–Shamir check depending on how hard you push
- compare the measured wall-clock cost of the combine-then-sign path against standalone signing
- explain threshold post-quantum signing to engineers, students, auditors, or security teams
- explore future design ideas for root CAs, validator networks, recovery flows, and enterprise approvals
- Do NOT use this repository for production signing systems, HSM deployments, or compliance-sensitive infrastructure — it is a teaching demo.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-threshold-mldsa](https://systemslibrarian.github.io/crypto-lab-threshold-mldsa/)**

A guided 5-stop "Start here" path leads newcomers through the material in intuition-building order. The live UI walks through five exhibits: why threshold ML-DSA is harder than classical threshold signatures (with an interactive rejection/restart micro-demo), an **animated** round-by-round protocol walkthrough with fixed party/channel lanes where value chips travel across the channel as you advance (every step labelled real or illustrative, with an on-screen honest caveat and a jargon glossary), interactive two-party split-custody signing with separate *Signature valid* / *Distributed-trust enforced* indicators and a plain-language bridge explaining they describe one run, a comparison table of the 2024–2026 threshold ML-DSA research landscape, and real-world applications for post-quantum multi-party signing. A live additive-share combiner and an escrow-vs-ideal contrast experiment — the latter a playable animation of the never-combine ideal path — make the key-non-reconstruction gap tangible. The math is genuine ML-DSA-65 from `@noble/post-quantum`, so every emitted signature verifies under the unmodified standard FIPS 204 verifier.

## What Can Go Wrong

Threshold ML-DSA remains an active research area, and several practical issues remain:

- **No NIST threshold standard yet.** Verifier compatibility exists in research papers, but the threshold protocols themselves are not standardized.
- **Rejection sampling compounds coordination cost.** If a signing attempt is rejected, all parties must regenerate fresh randomness.
- **Communication overhead matters.** Even efficient two-party designs exchange far more than standalone signing.
- **Malicious security is difficult.** Semi-honest approximations are not enough for real-world adversaries.
- **Non-linear gadgets are tricky.** HighBits, LowBits, MakeHint, and norm checks need careful MPC treatment.
- **Implementation pitfalls remain.** Timing leaks, replay handling, message binding, transcript consistency, and abort accountability all matter.
- **This demo simplifies MPC internals.** It is meant to teach the protocol shape and compatibility goal, not to serve as a hardened implementation.

## Real-World Usage

If threshold ML-DSA matures and standardizes, likely deployment targets include:

- **post-quantum root CA protection** across multiple HSMs or organizations
- **blockchain validator signing** without single-node compromise risk
- **government and enterprise approval workflows** with t-of-n control
- **social recovery and emergency access** for long-lived user credentials
- **distributed randomness beacons** and other collective authorization systems

For now, production systems generally use classical threshold schemes such as FROST or threshold ECDSA while tracking post-quantum migration plans.

A reasonable forward-looking timeline is:

- **2026–2027:** research consolidation and cryptanalysis
- **2027–2028:** possible draft threshold standards or profiles
- **2028–2030:** early production rollouts if the field stabilizes

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-threshold-mldsa
cd crypto-lab-threshold-mldsa
npm install
npm run dev
```

## Related Demos
- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — single-party ML-DSA (FIPS 204) signing, the primitive this threshold demo distributes.
- [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) — the classical threshold signature (FROST over Ed25519) that lattice schemes are compared against.
- [crypto-lab-threshold-decrypt](https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/) — `t-of-n` threshold cryptography applied to decryption instead of signing.
- [crypto-lab-vss-gate](https://systemslibrarian.github.io/crypto-lab-vss-gate/) — the verifiable secret sharing that underpins distributed key generation.
- [crypto-lab-hybrid-sign](https://systemslibrarian.github.io/crypto-lab-hybrid-sign/) — composite Ed25519 + ML-DSA-65 signatures for the PQC migration path.

## What's Real and What's Simulated

A cryptography demo earns trust by being precise about its own limits. This one draws a hard line:

**Real (standard FIPS 204):**

- Key generation, signing, and verification use `@noble/post-quantum`'s ML-DSA-65.
- The public key and every emitted signature are genuine and verify under the **unmodified** standard verifier.
- All randomness comes from the Web Crypto CSPRNG — there is no `Math.random` anywhere in `src/`.
- Additive secret sharing is real: each share on its own is uniform and reveals nothing about the secret.

**Real, but at toy parameters (`src/toy-threshold.ts`):**

- The never-combine path is an executed two-party protocol, not an animation: real nonces, real commitments, a real SHAKE256 Fiat–Shamir challenge, real per-party rejection sampling with real aborts, and a verifier that really recomputes `A·z − c·t`.
- The full secret `s = s^S + s^P` is never assembled anywhere in it.
- Its parameters (`n = 64`, `q = 8380417`, `k = l = 2`, `η = 2`, `τ = 8`, `γ₁ = 4096`) carry **no security**, and it is **not FIPS 204** — its signatures need the verifier in this repo and no standard one will accept them.

**Simulated (for teaching):**

- In the ML-DSA-65 path, the round-by-round nonce / `w₁` / challenge / `z` exchanges are *choreography*. They show the protocol's shape but do not produce the signature, and each step is explicitly labelled real or illustrative.
- That path runs no MPC, so it reports no "bytes exchanged" figure — inventing one would be a fabricated measurement.
- **To emit a standard FIPS 204 signature, the demo combines the two additive byte shares into the full secret key in one place** and calls the standard signer. That path therefore does **not** achieve real key-non-reconstruction.

Bottom line: the ML-DSA-65 path has real parameters and a standard-verifiable signature but only illustrates distributed trust; the toy path genuinely enforces distributed trust but at dimensions too small to secure anything. Having both at once is the open research problem this lab exists to explain, and the lab shows you each half rather than blurring them together.

## Stack

Browser-based educational demo of ML-DSA (NIST FIPS 204, the standardized post-quantum digital signature algorithm) held in two-party split custody. The app illustrates the *shape* of a Trilithium-style two-party signing flow, but the emitted signature is produced by combining the two additive byte shares of the genuine secret key in one place and calling the standard signer — so it still verifies with the unmodified ML-DSA verifier while being honest that it does not enforce key-non-reconstruction.

Stack: Vite + TypeScript strict + vanilla CSS + `@noble/post-quantum/ml-dsa`. No backends.

## Verification

```bash
npm run build    # typecheck (tsc) + production build
npm test         # vitest crypto unit tests (KATs / round-trip / forgery-rejection)
npm run verify   # end-to-end verification suite (exits non-zero on failure)
```

`npm test` runs focused crypto unit tests: additive byte/polynomial sharing round-trips,
that the recombined shares are bound to **this** public key (and that a foreign public key
is rejected — the regression that guards the old share/key disconnect), that a single party
cannot forge, forgery/tamper rejection by the standard verifier, and that no fabricated MPC
byte counts leak into results. `npm run verify` additionally checks the no-`Math.random`
rule and the honesty disclosures. `build`, `test`, and `verify` all run on every push and
pull request via GitHub Actions (`.github/workflows/ci.yml`).

## Repo Description

> Browser-based educational demo of ML-DSA-65 (FIPS 204) in two-party split custody — the genuine secret key is additively shared between server and phone so neither party can sign alone, and combining both shares produces a signature that verifies with the standard verifier. It teaches the *shape* of Trilithium-style (2025) threshold lattice signing and explains why it is harder than classical threshold signatures. It does **not** achieve key-non-reconstruction: to sign, the two shares are combined in one place — closing that gap is the open research problem. Research status: no NIST threshold standard yet, expected 2027+.

## Suggested GitHub Topics

```text
cryptography
post-quantum
ml-dsa
threshold-signatures
distributed-signing
multi-party-computation
trilithium
lattice-cryptography
fips-204
mpc
browser-demo
educational
typescript
vite
```

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
