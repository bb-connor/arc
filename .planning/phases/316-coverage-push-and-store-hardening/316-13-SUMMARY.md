# Summary 316-13

Phase `316` added a thirteenth coverage wave focused on the still-weak
`arc-policy` validator surface in `validate.rs`.

The implemented coverage wave added new tests in:

- `arc-policy/src/validate.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-policy`
- `cargo test -p arc-policy`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-policy-validate-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-policy --json --summary-only --output-path /tmp/arc-phase316-policy-validate-coverage.json`
- `git diff --check -- crates/arc-policy/src/validate.rs`

Measured local coverage from the refreshed `llvm-cov` lane:

- `arc-policy` crate total: `3501/4287` -> `3918/4571` lines (`+417`,
  `85.71%`)
- `arc-policy/src/validate.rs`: isolated workspace baseline `341/580` ->
  refreshed crate-local summary `793/864` lines (`+452`, `91.78%`)

This wave exercises the validator's high-branch policy edges instead of adding
low-signal happy paths: posture state and transition validation, unknown
capability and budget warnings, detection threshold ordering, reputation
scoring and tier-scope errors, and runtime-assurance tier/verifier guardrails
now have direct coverage through parsed policy fixtures.

Applying the measured `arc-policy` replacement delta on top of the isolated
workspace `llvm-cov` baseline and the earlier `arc-acp-proxy` plus
`arc-settle` waves moves the estimated local workspace total to
`97878/138547` (`70.65%`). Phase `316` still remains open.
