# Summary 102-01

Defined ARC's first explicit portable normalized-claim vocabulary for runtime
attestation results.

Implemented:

- typed normalized claim codes, categories, confidence, freshness, and
  provenance in `crates/arc-core/src/appraisal.rs`
- structured `normalizedClaims` alongside the legacy flat
  `normalizedAssertions` map for migration-safe compatibility
- a versioned claim-vocabulary artifact covering the currently shared portable
  claim set across Azure MAA, AWS Nitro, and Google Confidential VM

This gives ARC one auditable portable claim catalog without pretending all
vendor-specific evidence is universally equivalent.
