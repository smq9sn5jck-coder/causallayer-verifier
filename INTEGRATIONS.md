# Integrating CausalLayer with AI-insurance policies

This document is for engineering teams at insurance carriers,
reinsurance brokers, AI-insurance vendors, AI-vendor general
counsels, and audit firms who want to integrate CausalLayer's
post-incident causal-attribution output into their own products,
claims workflows, or audit pipelines.

It is also for anyone curious about how a deterministic,
cryptographically-anchored attribution engine fits into the
end-to-end AI-liability value chain — including the relationship
between **pre-deployment risk-scoring** products (a fast-growing
category in the AI-insurance market) and the **post-incident
attribution** layer that CausalLayer occupies.

> **TL;DR:** CausalLayer is not a competitor to pre-deployment
> AI-insurance products. It is the post-incident attribution layer
> those products imply. Every time a pre-deployment policy triggers,
> the question *"what actually went wrong, and what is the calibrated
> damages range?"* needs to be answered the same way for every
> claim — deterministically, reproducibly, and without trusting any
> single vendor. That is the question this integration spec answers.

---

## 1. The AI-liability value chain

A complete AI-liability product is made of three layers:

| Layer | Question answered | Product types | Where CausalLayer fits |
|---|---|---|---|
| **Risk assessment** | *How likely is this agent to fail?* | Behavioural probes, red-team services, evaluation harnesses | Not CausalLayer |
| **Underwriting & distribution** | *At what premium and under what terms?* | MGAs, syndicates, new AI-insurance products | Not CausalLayer |
| **Post-incident attribution** | *Given a specific incident, what is the fault allocation and what is the calibrated damages range?* | This integration spec | **CausalLayer** |

The three layers are complementary, not competitive. A
pre-deployment risk score is only as useful as the post-incident
process that adjudicates claims when something goes wrong.
Conversely, an attribution engine is only as useful as the policy
framework that brings claims into it.

This document defines the integration contract for the third layer.

---

## 2. What CausalLayer produces

For each incident submitted to CausalLayer, the engine produces a
single signed **causal certificate** with the following canonical shape
(JSON-schema reference included in `/schemas/` of the verifier repo):

```jsonc
{
  "type": "certificate",
  "version": "<engine-version>",
  "incidentId": "<opaque incident identifier>",
  "issuedAt": "<RFC3339 timestamp>",
  "incidentDescription": "<narrative-form incident description>",
  "harmType": "<one of: financial | safety | privacy | death | ...>",
  "severity": "<calibrated severity tier>",
  "faultAllocation": [
    { "party": "<role label>", "percentage": <0..100>, "rationale": "<short>" }
    // ... summing to 100
  ],
  "damages": {
    "low":  "<lower-bound USD amount>",
    "high": "<upper-bound USD amount>",
    "methodology": "<short label of damages model used>"
  },
  "causalChain": [
    { "step": <int>, "node": "<event label>", "edges": ["<...>"] }
    // ... structured walk through the chain
  ],
  "evidentiaryProperties": {
    "fre902_13_14_eligible": true,
    "eidas_qts_compatible": true,
    "australian_evidence_act_47_48_eligible": true
  },
  "signature": {
    "algorithm": "Ed25519",
    "publicKeyFingerprint": "<sha256 of SPKI DER, hex>",
    "value": "<base64 ed25519 signature over canonical-json>"
  },
  "anchor": {
    "anchorLogRepo": "https://github.com/smq9sn5jck-coder/causallayer-anchor-log",
    "dailyAnchorDate": "<YYYY-MM-DD>",
    "merkleLeafIndex": <int>,
    "merkleRoot": "<hex>",
    "openTimestampsProofPath": "<path-in-anchor-log>"
  }
}
```

Two properties of this output are non-negotiable and architecturally
guaranteed:

1. **Determinism.** Re-running the engine against the same input
   produces a byte-identical certificate (up to the `issuedAt`
   timestamp and signature nonce). The attribution layer performs
   no random sampling, no learned-model inference, and no external
   network call.
2. **Independent verifiability.** Every certificate is signed with
   the published CausalLayer key, every signed record's hash appears
   as a leaf in the daily anchor Merkle tree published at
   `causallayer-anchor-log`, and every daily anchor is witnessed by
   an OpenTimestamps proof. Verifying a certificate does not require
   CausalLayer's cooperation. See `causallayer-verifier/README.md`.

---

## 3. Integration patterns

### Pattern A — Insurance carrier or MGA writing AI-liability cover

You sell an AI-liability policy. A claim is filed. You need a
defensible, reproducible attribution of fault and damages, and an
audit trail you can hand a reinsurer.

**Suggested flow:**

1. Your claims-intake system collects a structured incident
   description from the claimant.
2. You submit the structured description to the CausalLayer
   attribution API.
3. CausalLayer returns the signed causal certificate.
4. Your claims system:
   - Logs the certificate's `incidentId` and signature against the
     claim record;
   - Uses `faultAllocation` to determine subrogation targets;
   - Uses `damages.low` and `damages.high` to set reserve floor and
     ceiling, respectively;
   - Stores the certificate JSON alongside the claim file for future
     audit by the reinsurer or regulator.
5. Independently, on a schedule that suits your audit posture, you
   run `causallayer-verifier` against each stored certificate to
   confirm it is anchored in the public log. This is your standing
   evidentiary cross-check.

The carrier never has to trust CausalLayer in the operational sense.
Every certificate is independently verifiable.

### Pattern B — AI-vendor general counsel

Your company makes an AI product. A user has been harmed. You want
a neutral third-party attribution, not a narrative from your own
incident-response team.

**Suggested flow:**

1. Your incident-response system captures the structured incident
   description.
2. You submit to CausalLayer.
3. The signed certificate is filed with your insurer (and, where
   appropriate, your regulator and the affected party's counsel).
4. If counterparty counsel disputes the attribution, both sides can
   independently verify the certificate against the public anchor
   log. This collapses many "did the vendor cook the books?"
   disputes before they begin.

### Pattern C — Reinsurer or claims-audit firm

You hold treaty exposure to a portfolio of AI-insurance policies.
You need to be able to randomly sample any claim and verify that the
attribution is consistent with the underwriting model.

**Suggested flow:**

1. Periodically sample claims from the cedant carrier's portfolio.
2. For each sampled claim, request the underlying CausalLayer
   certificate.
3. Run `causallayer-verifier` to confirm the certificate is anchored.
4. Re-submit the structured incident description to CausalLayer to
   confirm the output is reproducible (determinism property).
5. Aggregate findings into your treaty review.

### Pattern D — Pre-deployment AI risk-scoring product

You sell a pre-deployment AI-risk-scoring product backed by
insurance capacity. When a policy you've underwritten triggers, you
need a defensible attribution for the claims-handling and subrogation
flow.

**Suggested flow:**

1. Your policy-trigger event fires (e.g., the deployed agent has
   exceeded a behavioural envelope you priced).
2. Your claims process submits the incident to CausalLayer.
3. CausalLayer returns the signed certificate.
4. Your operations team uses the certificate's `faultAllocation`
   to determine whether the loss is borne by the AI vendor, the
   deployer, a third party, or some mix — and applies your policy's
   coverage terms accordingly.
5. The certificate becomes part of the claim file for reinsurance
   audit.

This pattern complements pre-deployment scoring products.
CausalLayer does not score the agent before deployment; it answers
the question the policy assumes will need answering after deployment.

---

## 4. API surface

The current API surface is documented at:

- **Specification:** `/openapi.yaml` in the verifier repo
  (engine-side OpenAPI 3.1 document).
- **Reference client:** `/lib/client/` in the verifier repo
  (typed clients for Node.js, Python, Go, and Java).
- **Sandbox endpoint:** see the verifier repo `STATUS.md` for the
  current sandbox base URL. The sandbox is rate-limited and is
  appropriate for integration testing only. Production endpoints
  are provisioned per-integration; contact details below.

The API exposes:

- `POST /attribute` — submit a structured incident description;
  receive a signed certificate.
- `GET /certificate/:id` — retrieve a previously-issued certificate
  by `incidentId`.
- `GET /verify/:id` — perform a server-side verification of a
  previously-issued certificate (intended for tooling that wants the
  authoritative result; integration clients are encouraged to verify
  client-side using the public verifier instead).
- `GET /health` — service liveness.

Authentication is per-integration-bearer-token. Tokens are issued
under a written integration agreement; sandbox tokens are issued
for integration testing on request.

---

## 5. Evidentiary properties

CausalLayer certificates are designed for use as evidence in
insurance settlement and litigation. Specifically:

- **FRE 902(13)–(14)** *(US Federal Rules of Evidence)*. Certificates
  meet the self-authentication requirements for records of electronic
  processes and electronic records produced by such processes, when
  accompanied by the certificate-issuance metadata and the anchor-log
  verification path.
- **eIDAS Article 35** *(European Union)*. The Ed25519 signing key,
  when issued by a qualified trust service provider, supports
  treatment as a qualified electronic signature. CausalLayer's current
  key is published under a non-qualified self-attested PKI;
  integration partners requiring eIDAS-qualified status should request
  a parallel key issued under a qualified trust service.
- **UNCITRAL Model Law on Electronic Transferable Records.**
  Certificate structure is compatible with the integrity and
  exclusive-control requirements where the receiving carrier handles
  the record under appropriate controls.
- **Australian Evidence Act 1995 (Cth), sections 47 and 48.**
  Certificates qualify as documents produced by a process or device
  in the ordinary course of business, with the verifier repo
  providing the corroborative chain.

> **Important caveat.** CausalLayer's design supports the evidentiary
> framework above; whether any specific certificate is admissible in
> any specific proceeding is a question for the receiving party's
> counsel. CausalLayer does not represent that any certificate has
> been admitted, accepted, or relied upon in any specific proceeding.

---

## 6. Performance posture and honest caveats

Honest disclosure of the engine's current performance posture:

- The engine has been blind-tested against a subset of the publicly
  available AI Incidents Database (AIID), restricted to incidents
  with quantifiable financial outcomes. Containment results from
  that blind test are published in the engine's internal evaluation
  log; the small sample size, English-language bias, and
  financial-incident restriction are all real limitations.
- The attribution layer is deterministic. The intake layer (which
  parses unstructured incident descriptions into structured input)
  uses LLM assistance and is not deterministic; integration partners
  who require fully-deterministic intake should submit structured
  input directly via the API.
- The damages model is a calibrated regression with documented
  inputs. It is *not* an actuarial loss-development model and is
  not a substitute for one in carrier-pricing contexts.

---

## 7. Engagement

If you are integrating CausalLayer into a product or workflow:

1. **Open an integration discussion** by opening an issue against
   the anchor-log repo with the label `integration`. We will engage
   in public unless the integration involves confidential commercial
   terms, in which case private contact details will be exchanged.
2. **Read the verifier source** before integrating against any
   CausalLayer endpoint. The verifier is intentionally small (~400
   lines, zero non-stdlib dependencies) so any integration partner
   can audit it in an afternoon.
3. **Request a sandbox token** for integration testing via the
   integration issue above.
4. **Plan for verification.** Integrations that store CausalLayer
   certificates without periodically verifying them against the
   public anchor log derive no evidentiary benefit. Build the
   periodic verifier run into your operational rhythm.

---

## 8. Frequently asked questions

**Q. How is CausalLayer different from a pre-deployment
AI-insurance product?**
Pre-deployment products answer *"how likely is this agent to fail,
and at what premium?"*. CausalLayer answers *"given a specific
incident, what is the fault allocation and the calibrated damages
range, in a reproducible and independently verifiable form?"*. The
two products complement each other; a complete AI-liability stack
will eventually include both.

**Q. Why is the attribution layer LLM-free?**
Because the certificate is intended to be reproducible from the
structured input alone. Re-running the engine in 2030 against an
incident submitted in 2026 must yield the same fault allocation
and the same damages range. LLM inference, with model versions
deprecated on rolling schedules, cannot guarantee that.
Deterministic attribution can.

**Q. Why is the engine source-code private?**
Because the deterministic causal-graph methodology is the
patent-novel inventive contribution. The interface contract (this
document, the verifier, the anchor log, the schemas) is fully open.
Any integration partner can verify any certificate without seeing
the engine's internals.

**Q. Can CausalLayer be self-hosted?**
Not at present. The current model is API-served, with optional
on-premise deployment under written integration agreements with
qualifying enterprise partners. Independent verifiability does not
require the engine to be self-hosted — only that the verifier and
the anchor log are accessible. Both are open and free.

**Q. What happens if CausalLayer ceases operations?**
The anchor log is a public GitHub repository, mirrored on
independent infrastructure. Every issued certificate remains
independently verifiable forever, regardless of whether CausalLayer
continues to operate. This is a property the architecture is
designed for.

---

## 9. License

This integration specification is published under CC BY 4.0. The
verifier source code is published under MIT. Reuse, fork, and adapt
this document for your own integration documentation needs without
attribution beyond the CC BY 4.0 requirement.

---

## 10. Contact

Open a public integration issue against the
[`causallayer-anchor-log`](https://github.com/smq9sn5jck-coder/causallayer-anchor-log)
repository with the label `integration` for public technical
discussion. For commercial discussion under NDA, include a contact
email in the issue and we will move the conversation off-list.

*Document version: 0.1 (draft). Last revised: 2026-05-13.*
