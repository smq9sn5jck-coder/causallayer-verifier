# CausalLayer Verifier Threat Model

> **Status:** Draft (v0.1)
> **Author:** CausalLayer
> **Date:** 2026-05-14

This document defines the threat model for the CausalLayer post-incident attribution verification protocol. It specifies what the protocol protects against, what it assumes, and how an adversary might attempt to defeat it.

---

## 1. System Boundaries and Assets

The verification protocol spans three components:

1. **The Engine (Private):** The hosted service that receives incident descriptions and produces signed attribution certificates.
2. **The Anchor Log (Public):** The `causallayer-anchor-log` GitHub repository, which hosts the canonical public key, the daily Merkle anchors, and the OpenTimestamps proofs.
3. **The Verifier (Client-side):** The standalone npm package (`causallayer-verifier`) or the in-browser GitHub Pages site, run by a third party (e.g., an insurer, auditor, or opposing counsel).

### Assets to Protect

- **Authenticity:** A certificate claiming to be from CausalLayer must have actually been produced by CausalLayer.
- **Non-repudiation:** CausalLayer cannot deny having produced a certificate that it actually produced.
- **Append-only History:** CausalLayer cannot retroactively alter or delete a daily anchor once published.
- **Timestamp Integrity:** The claimed date of an anchor must be cryptographically bounded by a public witness (Bitcoin).

---

## 2. Threat Actors

We consider three classes of adversaries:

### 2.1. The Malicious Claimant (External)
A party submitting a claim to an insurer who wishes to forge a CausalLayer certificate to secure a payout or shift liability.
- **Capabilities:** Can read the public anchor log, run the verifier, and submit arbitrary inputs to the engine (if they have an account).
- **Goal:** Produce a certificate that the verifier accepts as `VALID` and `AUTHORITATIVE`, but which the engine did not produce.

### 2.2. The Malicious Insurer/Vendor (External)
A party who holds a genuine CausalLayer certificate but wishes to alter its contents (e.g., changing the fault allocation from 50% to 0%) before presenting it to a counterparty or regulator.
- **Capabilities:** Same as the claimant, plus possession of genuine signed certificates.
- **Goal:** Alter a genuine certificate such that the verifier still accepts it.

### 2.3. The Compromised Engine (Internal)
CausalLayer itself, acting maliciously (e.g., under coercion, insider threat, or post-breach), attempting to rewrite history to cover up a past attribution error or favour a specific client.
- **Capabilities:** Full control over the engine, the private signing key, and the GitHub account hosting the anchor log.
- **Goal:** Retroactively alter a previously published anchor without detection, or issue a backdated certificate that appears to have been anchored in the past.

---

## 3. Attack Vectors and Mitigations

### 3.1. Forgery of a Certificate (Claimant/Vendor)

**Attack:** The adversary constructs a JSON certificate with a favourable fault allocation and signs it with their own Ed25519 key.
**Mitigation:** The verifier checks the signature against the canonical public key published in the anchor log. The verifier will reject the signature.

**Attack:** The adversary copies a genuine signature from an old certificate and pastes it onto a modified certificate.
**Mitigation:** The signature is over the canonicalised JSON body. Any modification to the body invalidates the signature.

**Attack:** The adversary modifies the certificate and recomputes the Merkle root, hoping the verifier only checks the root.
**Mitigation:** The verifier checks both the Merkle root *and* the Ed25519 signature over the canonical body.

### 3.2. Retroactive History Rewrite (Compromised Engine)

**Attack:** CausalLayer deletes a daily anchor from the GitHub repository to repudiate a past certificate.
**Mitigation:** The repository is public. Any third party who cloned the repository or saved the anchor JSON locally retains the cryptographic proof. CausalLayer cannot force third parties to delete their copies.

**Attack:** CausalLayer force-pushes to the GitHub repository to replace a past anchor with a new one containing a different Merkle root.
**Mitigation:** Branch protection rules prohibit force-pushes. Even if GitHub branch protection is bypassed (e.g., by repository admin), the original anchor was OpenTimestamped. The new anchor will have a different hash and will require a new OpenTimestamps proof, which can only be anchored to a *current* Bitcoin block, proving the rewrite occurred after the fact.

**Attack:** CausalLayer issues a new certificate today, but claims it was issued a year ago, and attempts to insert it into a year-old anchor.
**Mitigation:** Inserting a new leaf changes the Merkle root of the year-old anchor. This invalidates the Ed25519 signature on the anchor (requiring a re-sign) and invalidates the OpenTimestamps proof (requiring a new proof, which will bear today's date, exposing the backdating).

### 3.3. Key Compromise

**Attack:** An adversary steals the CausalLayer private signing key and issues fraudulent certificates.
**Mitigation:** The private key is held in offline custody and is never exposed to the cloud environment. If compromised, CausalLayer will publish a `KEY-ROTATION-{date}.md` post-mortem and rotate the canonical public key. Certificates signed by the compromised key after the rotation date will be rejected by verifiers. Certificates signed before the rotation date remain verifiable via their OpenTimestamps proofs (which prove they existed before the compromise was declared).

### 3.4. Verifier Manipulation

**Attack:** An adversary hosts a modified version of the in-browser verifier that always returns `VALID`, and tricks a counterparty into using it.
**Mitigation:** The canonical verifier is hosted on the `causallayer-anchor-log` GitHub Pages origin. Users are instructed to verify the URL. For high-stakes audits, users should use the standalone npm package or run the verifier script locally.

---

## 4. Out of Scope

The following threats are explicitly out of scope for this cryptographic protocol:

- **Engine Accuracy:** The protocol proves *that* CausalLayer issued a specific attribution; it does not prove that the attribution is *correct*. Accuracy is a function of the engine's methodology, not its cryptography.
- **Input Spoofing:** If an insurer submits a deliberately false incident description to the engine, the engine will produce a validly signed certificate based on that false premise. The protocol does not verify the truth of the real-world events described in the input.
- **GitHub Compromise (Availability):** If GitHub goes offline or the repository is deleted, new verifications cannot fetch the public key or anchors. However, any party who previously saved the key and anchors can continue to verify offline indefinitely.
