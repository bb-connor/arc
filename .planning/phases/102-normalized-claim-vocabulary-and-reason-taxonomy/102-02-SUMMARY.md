# Summary 102-02

Defined the structured reason taxonomy used by portable appraisal results.

Implemented:

- typed reason groups and dispositions in `crates/arc-core/src/appraisal.rs`
- structured `reasons` objects alongside compatibility `reasonCodes`
- a versioned reason-taxonomy artifact spanning verification, compatibility,
  freshness, measurement, debug-posture, and policy semantics

This keeps explanation semantics shared and replay-safe across verifier
families instead of leaving reasons as one flat internal enum.
