# Summary 316-05

Phase `316` added a fifth measured coverage wave aimed at the standalone
attestation surface in `arc-control-plane`, which the last full workspace
baseline had barely exercised at the crate level even though the file already
contained a bounded verification harness.

The implemented coverage wave added new tests in:

- `arc-control-plane`

Measured gains from the targeted tarpaulin run:

- `arc-control-plane` crate total: `118/981` -> `749/981` (`+631`)
- `arc-control-plane/src/attestation.rs`: `0/839` -> `737/839`

Verification that passed during this wave:

- `cargo test -p arc-control-plane --lib`
- targeted tarpaulin run for `arc-control-plane --lib`
- `git diff --check -- crates/arc-control-plane/src/attestation.rs`

The added `arc-control-plane` tests cover verifier-policy validation, adapter
identity helpers, OIDC/JWK parsing and resolution edges, metadata fetch/parse
error paths, AWS Nitro document guardrails, and enterprise attestation negative
paths plus non-native appraisal rejection branches.

`cargo test -p arc-control-plane` still fails in the existing
`runtime_boundaries` integration test, but that failure points at unrelated
`arc-cli` runtime-boundary work already present in the dirty worktree and is
outside the attestation write set. The attestation wave itself verified cleanly
with the `--lib` lane.

Even with this measured delta, the workspace estimate only moves from the
previous `69.10%` to about `70.56%`, so phase `316` remains in progress. The
next execution wave still needs another large bounded surface if the phase is
going to get materially closer to the required `80%+` floor.
