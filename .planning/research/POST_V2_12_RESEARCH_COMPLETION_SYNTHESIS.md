# Post-v2.12 Research Completion Synthesis

**Date:** 2026-03-28
**Purpose:** Merge the post-`v2.12` planning tracks into one authoritative
milestone ladder that is comprehensive enough for ARC to eventually claim it
has achieved the ideas laid out in `docs/research/DEEP_RESEARCH_1.md`.

## Inputs

- `docs/research/DEEP_RESEARCH_1.md`
- `.planning/research/PORTABLE_CREDENTIAL_PORTABILITY_PLAN_POST_V2.12.md`
- `.planning/research/POST_V2_12_ECONOMIC_MARKET_ENDGAME.md`
- agent planning output on multi-cloud attestation and appraisal contracts
- agent planning output on enterprise IAM standards profiles and public
  certification marketplace governance

## Synthesis Decision

The remaining research deltas break into two broad ladders:

1. **Ecosystem legibility and trust substrate completion**
   - standards-native portable credentials
   - generic verifier and wallet interop
   - multi-cloud attestation appraisal
   - enterprise IAM standards profiles
   - public certification and discovery governance
2. **Economic-market endgame**
   - credit and exposure state
   - bonded autonomy and capital-backed execution
   - liability-market quote, bind, and claim orchestration

The roadmap should complete the ecosystem legibility ladder first. ARC cannot
honestly claim the research endgame if the project still lacks standards-native
credential portability, multi-cloud verifier credibility, or a public trust
market substrate.

## Approved Milestone Sequence

### v2.13 Portable Credential Format and Lifecycle Convergence

Close the remaining standards-native issuance and lifecycle gap with an
external SD-JWT VC path, bounded selective disclosure, and portable status and
metadata.

### v2.14 OID4VP Verifier and Wallet Interop

Add a real standards-native verifier surface with same-device and cross-device
wallet flows and at least one externally qualified wallet round trip.

### v2.15 Multi-Cloud Attestation and Appraisal Contracts

Split raw attestation evidence from ARC appraisal semantics, add AWS Nitro and
Google adapters beside Azure, and bind appraised evidence back into issuance,
governed execution, and underwriting.

### v2.16 Enterprise Authorization and IAM Standards Profiles

Publish one normative ARC profile for authorization details, transaction
context, sender-constrained semantics, and enterprise reviewer evidence.

### v2.17 ARC Certify Public Discovery Marketplace and Governance

Turn certification into a governed public discovery and transparency layer
without making listing presence equal runtime admission or implicit trust.

### v2.18 Credit, Exposure, and Capital Policy

Turn underwriting outputs into a canonical exposure ledger, explainable credit
scorecards, and signed capital-facility policies.

### v2.19 Bonded Autonomy and Facility Execution

Add reserve locks, bond contracts, autonomy tier gates, and loss or recovery
state so economically sensitive autonomy can be capital-backed.

### v2.20 Liability Marketplace and Claims Network

Add provider registry, quote and bind artifacts, claim packages, and dispute
workflows so ARC can orchestrate insured agent actions across org boundaries.

## Claim Boundary

ARC can only honestly claim that it has achieved the research vision after
`v2.20` closes. Earlier milestones materially improve the substrate, but they
do not close the full endgame on their own.

## Persistent Guardrails

- ARC remains a control plane and evidence layer unless product posture
  intentionally changes into a regulated role.
- Public discovery must not silently become runtime trust.
- External standards interop must derive from ARC truth instead of creating a
  second mutable authority system.
- Cross-provider appraisal must normalize only stable common semantics and keep
  vendor-specific claims namespaced.
- Credit, bond, and liability artifacts must remain separate from canonical
  execution receipts.
