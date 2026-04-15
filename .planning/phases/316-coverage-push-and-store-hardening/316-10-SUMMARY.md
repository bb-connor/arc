# Summary 316-10

Phase `316` added a tenth coverage wave focused on the bounded but completely
uncovered `arc-acp-proxy` attestation and telemetry surfaces.

The implemented coverage wave added new tests in:

- `arc-acp-proxy/src/tests/all.rs`

Verification that passed during this wave:

- `cargo test -p arc-acp-proxy`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-acp-proxy-llvm cargo llvm-cov -p arc-acp-proxy --json --summary-only --output-path /tmp/arc-phase316-acp-proxy-coverage.json`
- `git diff --check -- crates/arc-acp-proxy/src/tests/all.rs`

Measured local coverage from the refreshed `llvm-cov` lane:

- `arc-acp-proxy` crate total: `483/1298` -> `1036/1298` lines (`+553`, `79.82%`)
- `arc-acp-proxy/src/compliance.rs`: `0/172` -> `158/172` lines (`91.86%`)
- `arc-acp-proxy/src/kernel_checker.rs`: `0/105` -> `96/105` lines (`91.43%`)
- `arc-acp-proxy/src/kernel_signer.rs`: `0/150` -> `90/150` lines (`60.00%`)
- `arc-acp-proxy/src/telemetry.rs`: `0/224` -> `209/224` lines (`93.30%`)

The new tests cover fail-closed capability checking for missing, malformed,
future, expired, and wildcard tokens; compliance certificate empty-session,
signature, chain, scope, budget, guard, lightweight, and full-bundle
verification paths; kernel receipt signing with append and checkpoint behavior
for supported, unsupported, and empty-batch stores; and telemetry conversion,
session/compliance events, default config, logging export, JSONL export, and
export failure handling.

This wave also established a trustworthy local `llvm-cov` workspace baseline
for the current dirty tree: the earlier isolated full-workspace run measured
`95842/137683` lines (`69.61%`). Applying the measured `arc-acp-proxy` delta
to that baseline moves the estimated local workspace total to `96395/137683`
(`70.01%`), so phase `316` remains open and no commit or phase advance was
made.
