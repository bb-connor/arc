# Summary 316-19

Phase `316` then pivoted the next coverage wave into the `arc-cli`
trust-control HTTP service auth/error paths instead of adding more store-local
tests.

The implemented coverage wave added new tests in:

- `crates/arc-cli/tests/capability_lineage.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave8 cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave8 cargo test -p arc-cli --test capability_lineage`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave8 cargo test -p arc-cli cli_entrypoint_tests --bin arc`
- `git diff --check -- crates/arc-cli/src/cli/runtime.rs crates/arc-cli/src/cli/dispatch.rs crates/arc-cli/tests/capability_lineage.rs`

This wave added three behaviorally meaningful trust-service integration tests
on top of the existing lineage snapshot test:

- unauthorized `GET /v1/authority` and `POST /v1/authority` requests are
  rejected, while an authorized rotation advances the authority generation
- `/v1/capabilities/issue` rejects malformed `subjectPublicKey` input
- `/v1/capabilities/issue` rejects conflicting runtime-attestation workload
  bindings

Those cases exercise live trust-control handler behavior through the spawned ARC
service instead of asserting helper-only branches.

Coverage measurement note:

- `CARGO_TARGET_DIR=/tmp/arc-phase316-wave19-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-cli --test capability_lineage --json --output-path /tmp/arc-phase316-wave19-coverage.json`
  completed, but reported `0/38380` lines because this integration path drives
  the trust service through a spawned child binary and the per-test shortcut is
  not a trustworthy comparable lane for workspace gating
- the canonical workspace tarpaulin rerun remains the authoritative measurement
  for this phase and is still in progress, so the latest completed comparable
  full-workspace result remains `72.42%`

This wave improves the right production surface for the stalled coverage gate,
but phase `316` remains open until the comparable workspace lane finishes and
confirms the real coverage movement.
