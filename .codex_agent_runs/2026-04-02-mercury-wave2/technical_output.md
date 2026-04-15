## 1. Top 5 Insights
- MERCURY’s strongest current design choice is its honesty about the proof boundary: it proves integrity of captured evidence inside its own boundary, not the truth of external market facts. That is a real strength, but it also means production credibility depends on completeness, retention, and publication discipline, not signatures alone.
- As currently documented, `Proof Package v1` and `Publication Profile v1` are sufficient as pilot abstractions and naming anchors, but not yet sufficient as production contracts. They still describe what the package/profile should contain, not the normative rules that make two independent implementations reach the same trust decision.
- The biggest credibility gap is publication semantics. “External witness or immutable publication step” is weaker than a real transparency-log model; it does not by itself address delayed publication, split-view behavior, or selective omission. Inference from RFC 9162 and Sigstore: production trust needs append-only continuity, consistency proofs, and independent monitoring.
- Shipping one Rust verifier plus CLI first is the right verifier strategy. But a verifier is only truly independent if trust anchors, rotation state, freshness rules, and failure modes are defined outside the operator-controlled package; otherwise “independent verification” collapses during compromise or dispute.
- MERCURY’s real evidentiary bottleneck is not receipt signing, it is evidence completeness over time. A package can be cryptographically valid yet still fail a real investigation if key artifacts were never captured, later became unavailable, were redacted without precise equivalence rules, or cannot be placed into a defensible event chronology.

## 2. Top 3 Risks
- Selective omission is the largest production credibility risk. If MERCURY cannot show source coverage, checkpoint freshness, and monitorable publication continuity, a reviewer cannot distinguish “no event happened” from “the system failed to capture or publish it.”
- `Proof Package v1` currently risks proving integrity of an incomplete story. Without explicit required artifact classes, completeness claims, and machine-verifiable redaction semantics, “verifier-equivalent” can become a policy label rather than a technical fact.
- Verifier independence is still too operator-dependent. If the same operator controls signing, publication, bundled trust anchors, and verifier distribution, then a key compromise or incident can undermine the whole trust story at once.

## 3. Top 3 Stronger Technical Ideas
- Make `Publication Profile v1` a real transparency profile: append-only Merkle log semantics, signed tree heads/checkpoints, inclusion plus consistency proofs, maximum publication delay, outage/shutdown rules, and independent monitors. CT, Sigstore, and emerging SCITT work are the right reference patterns.
- Add explicit completeness semantics to `Proof Package v1`: required artifact classes by workflow, coverage of source sequence ranges, gap receipts, late/correction/supersession records, and a verifier result that distinguishes `valid-and-complete` from `valid-but-incomplete`. SLSA’s completeness flags are a useful model.
- Add long-term evidence durability as a first-class trust feature: offline or threshold root, separate online signing roles, RFC 3161 timestamping, and RFC 4998-style renewal/re-sealing for archived proofs. That is what makes multi-year retention credible instead of merely signed.

## 4. Concrete Doc or Roadmap Changes
- In [TECHNICAL_ARCHITECTURE.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/TECHNICAL_ARCHITECTURE.md) and [VERIFIER_SDK_RESEARCH.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/VERIFIER_SDK_RESEARCH.md), replace “should include” lists with a normative `Proof Package v1` contract: canonical encoding, hash/signature suites, required vs optional members, embedded vs external artifact rules, and machine-readable verifier outcomes.
- Expand `Publication Profile v1` from a descriptive checklist into a protocol profile: checkpoint numbering, freshness/MMD-style publication bounds, inclusion and consistency proof format, witness quorum rules, replay semantics, log shutdown behavior, and how clients detect stale publication.
- Add a new “Coverage and Completeness” subsection to the proof model. It should define which artifact classes are mandatory for each pilot workflow and what the verifier reports when one is missing, withheld, undecryptable, or intentionally redacted.
- Add a dedicated chronology/causality contract: `event_time`, `capture_time`, `checkpoint_time`, `publication_time`, source sequence numbers, clock source/uncertainty, idempotency semantics, parent-edge types, and `void`/`corrected_by`/`supersedes` transitions.
- Pull a minimal trust-root design forward into the pre-pilot path: offline root or threshold root, online receipt/checkpoint signer separation, out-of-band trust-anchor publication, revocation freshness policy, and conformance vectors that a third party can run.
- Add “long-term validation and archive renewal” before production claims, not as a distant trust-network feature. If MERCURY will be used for retained supervisory evidence, the roadmap should explicitly cover timestamp renewal, crypto-agility, and proof-package re-sealing.

## 5. Sources
- [TECHNICAL_ARCHITECTURE.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/TECHNICAL_ARCHITECTURE.md)
- [THREAT_MODEL.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/THREAT_MODEL.md)
- [VERIFIER_SDK_RESEARCH.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/VERIFIER_SDK_RESEARCH.md)
- [IMPLEMENTATION_ROADMAP.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/IMPLEMENTATION_ROADMAP.md)
- [POC_DESIGN.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/POC_DESIGN.md)
- [RFC 9162: Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html)
- [Sigstore Security Model](https://docs.sigstore.dev/about/security/)
- [The Update Framework Specification v1.0.34](https://theupdateframework.github.io/specification/latest/index.html)
- [RFC 3161: Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161.html)
- [RFC 4998: Evidence Record Syntax](https://www.rfc-editor.org/rfc/rfc4998.html)
- [C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html)
- [SLSA Provenance](https://slsa.dev/spec/v0.2/provenance)
- [IETF SCITT Architecture Draft](https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/draft-ietf-scitt-architecture.html)