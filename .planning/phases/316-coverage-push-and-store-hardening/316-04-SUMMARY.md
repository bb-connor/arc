# Summary 316-04

Phase `316` added a fourth measured coverage wave aimed at two bounded crates
whose remaining gaps were concentrated in portable validation and fail-closed
policy logic: `arc-federation` and `arc-appraisal`.

The implemented coverage wave added new tests in:

- `arc-federation`
- `arc-appraisal`

Measured gains from targeted tarpaulin runs:

- `arc-federation`: `262/450` -> `439/450` (`+177`)
- `arc-appraisal`: `546/726` -> `721/726` (`+175`)

Verification that passed during this wave:

- `cargo test -p arc-federation`
- `cargo test -p arc-appraisal`
- targeted tarpaulin run for `arc-federation`
- targeted tarpaulin run for `arc-appraisal`
- `git diff --check -- crates/arc-federation/src/lib.rs crates/arc-appraisal/src/lib.rs`

The added `arc-federation` tests cover activation exchange boundary validation,
anti-eclipse quorum enforcement, conflict/state mismatches, reputation-clearing
failure cases, and qualification-matrix case-level misconfiguration checks.

The added `arc-appraisal` tests cover verifier descriptor validation, reference
value lifecycle guards, trust-bundle structure and signature failures, import
policy fail-closed reasons, normalized-claim stringification, appraisal-result
construction guards, and the AWS Nitro / unsupported-schema appraisal branches.

Even with these measured deltas, the workspace estimate only moves from the
previous `68.29%` to about `69.10%`, so phase `316` remains in progress. The
next execution wave still needs to land in a materially larger remaining
surface if the phase is going to approach the required `80%+` gate.
