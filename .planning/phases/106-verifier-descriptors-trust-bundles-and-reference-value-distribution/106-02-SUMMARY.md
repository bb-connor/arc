# Summary 106-02

Defined ARC's signed reference-value distribution and replacement semantics in
`crates/arc-core/src/appraisal.rs`.

Implemented:

- `arc.runtime-attestation.reference-values.v1` as the signed
  descriptor-bound measurement package
- explicit `active`, `superseded`, and `revoked` lifecycle states
- fail-closed validation for stale, duplicate, mismatched, or ambiguous
  reference-value state

This makes measurement distribution portable and auditable without hiding
freshness or replacement boundaries.
