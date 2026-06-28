# crypto-lab-threshold-mldsa

## What It Is

This repository demonstrates the central threshold-signing question for post-quantum cryptography:

- Can multiple parties cooperate to produce a single valid ML-DSA signature?
- Can the verifier remain unchanged and still accept that signature under standard FIPS 204 verification?
- Why is this harder than threshold Schnorr or threshold BLS?

The demo answers those questions with an educational two-party simulation based on the current research direction:

- **Trilithium** — Dufka, Kravtsenko, Laud, Snetkov, ePrint 2025/675
- **Quorus** — Borin et al., ePrint 2025/1163
- **TOPCOAT** — 2024 two-party HighBits compression approach
- **Dufka–Kravtsenko identifiable aborts** — ePrint 2025/871
- **del Pino–Prest unmasking TRaccoon** — ePrint 2025/849
- **THED** — ePrint 2026/638
- **Threshold Raccoon** — Saarinen, EUROCRYPT 2024

The live UI includes five exhibits:

1. Why threshold ML-DSA is harder than classical threshold signatures
2. A Trilithium-style step-by-step protocol walkthrough
3. Interactive two-party signing with restart-on-rejection behavior
4. A comparison table of the 2024–2026 threshold ML-DSA research landscape
5. Real-world applications for post-quantum multi-party signing

> This repo is **educational, not production-safe**. No threshold ML-DSA scheme is NIST-standardized as of 2026.

## When to Use It

Use this demo when you want to:

- understand why threshold lattice signatures are more complicated than threshold Schnorr or BLS
- study the structure of a two-party ML-DSA protocol in a browser-only environment
- see additive secret sharing applied to ML-DSA-flavored key components
- compare communication rounds, byte cost, and restart behavior against standalone signing
- explain threshold post-quantum signing to engineers, students, auditors, or security teams
- explore future design ideas for root CAs, validator networks, recovery flows, and enterprise approvals
- Do NOT use this repository for production signing systems, HSM deployments, or compliance-sensitive infrastructure — it is a teaching demo.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-threshold-mldsa](https://systemslibrarian.github.io/crypto-lab-threshold-mldsa/)**

The live UI walks through five exhibits: why threshold ML-DSA is harder than classical threshold signatures, a Trilithium-style step-by-step protocol walkthrough, interactive two-party signing with restart-on-rejection behavior, a comparison table of the 2024–2026 threshold ML-DSA research landscape, and real-world applications for post-quantum multi-party signing. The math is genuine ML-DSA-65 from `@noble/post-quantum`, so every emitted signature verifies under the unmodified standard FIPS 204 verifier.

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

**Simulated (for teaching):**

- The round-by-round nonce / `w₁` / challenge / `z` exchanges are *choreography*. They show the protocol's shape but do not produce the signature.
- The "secure norm check" reveals the combined value in the clear instead of running real MPC.
- Rejections are injected so you can watch restart-on-reject behavior.
- **To actually sign, the demo reconstructs the full secret key in one place** and calls the standard signer. It therefore does **not** achieve real key-non-reconstruction — the central property a production threshold scheme must provide.

Bottom line: the ML-DSA math is real and the output is a valid FIPS 204 signature; the *distributed-trust* property is illustrated, not enforced. Closing that gap is the open research problem this lab exists to explain.

## Stack

Browser-based educational demo of threshold signature protocols for ML-DSA (NIST FIPS 204, the standardized post-quantum digital signature algorithm). The app simulates a simplified two-party signing flow inspired by Trilithium, where Server and Phone cooperatively produce a signature that still verifies with the standard ML-DSA verifier.

Stack: Vite + TypeScript strict + vanilla CSS + `@noble/post-quantum/ml-dsa`. No backends.

## Verification

```bash
npm run build    # typecheck (tsc) + production build
npm run verify   # run the verification suite (exits non-zero on failure)
```

`npm run verify` is the project's test gate: it checks additive sharing, distributed key
generation, two-party signing, standard-verifier compatibility, tamper rejection, the
single-party block, the no-`Math.random` rule, and the honesty disclosures. Both `build`
and `verify` run on every push and pull request via GitHub Actions (`.github/workflows/ci.yml`).

## Repo Description

> Browser-based educational demo of threshold ML-DSA (FIPS 204) — two-party distributed signing where neither party holds the complete secret key. Produces signatures that verify with standard ML-DSA. Inspired by Trilithium (2025). Shows why threshold lattice signatures are harder than classical. Research status: no NIST standard yet, expected 2027+.

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

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
